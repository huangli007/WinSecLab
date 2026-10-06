using System.Diagnostics;
using WinSecLab.Core.Engines.Dynamic;
using WinSecLab.Core.Engines.Reports;
using WinSecLab.Core.Engines.Rules;
using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins;
using WinSecLab.Core.Storage;

namespace WinSecLab.Core.Engines.Analysis;

/// <summary>一次分析请求。UI 与 CLI 都构造这个对象，保证两端行为完全一致。</summary>
public sealed class PipelineRequest
{
    public required TestProject Project { get; init; }
    public required ProjectLayout Layout { get; init; }
    public required ProjectDatabase Database { get; init; }
    /// <summary>静态分析对象：项目内留存的样本（保证"测的是哪一份"可追溯）。</summary>
    public required string TargetPath { get; init; }

    /// <summary>
    /// 动态阶段实际启动的路径。默认与 <see cref="TargetPath"/> 相同；
    /// 若样本被复制进项目目录，则应传入原始安装路径 —— 换目录启动会改变程序行为。
    /// </summary>
    public string? ExecutionTargetPath { get; init; }

    public required IReadOnlyCollection<TestTaskKind> Tasks { get; init; }

    public AnalysisOptions Options { get; init; } = new();

    /// <summary>相关性关键词（程序名 / 产品名 / 公司名），用于文件与注册表事件过滤。</summary>
    public IReadOnlyList<string> RelevanceKeywords { get; init; } = Array.Empty<string>();

    /// <summary>是否在分析结束后自动生成报告。</summary>
    public bool GenerateReport { get; init; } = true;
    public string? AnalystName { get; init; }
    public string? Organization { get; init; }

    public Action<string> Log { get; init; } = _ => { };
    /// <summary>进度 0..1，-1 表示不确定。</summary>
    public Action<double, string> Progress { get; init; } = (_, _) => { };
    /// <summary>运行期事件实时回调（UI 事件流用）。</summary>
    public Action<MonitorEvent>? OnEvent { get; init; }
    public Action<string, string>? OnArtifact { get; init; }

    public CancellationToken CancellationToken { get; init; }
}

/// <summary>单个插件的执行记录 —— 让"谁跑了、跑了多久、产出几条证据"完全可追溯。</summary>
public sealed class PluginRunRecord
{
    public string PluginId { get; set; } = "";
    public string PluginName { get; set; } = "";
    public TestTaskKind Task { get; set; }
    public bool Success { get; set; }
    public bool Skipped { get; set; }
    public string Summary { get; set; } = "";
    public string? Error { get; set; }
    public TimeSpan Duration { get; set; }
    public int EvidenceCount { get; set; }
    public int FindingCount { get; set; }
    public List<string> Warnings { get; set; } = new();
    public List<string> Artifacts { get; set; } = new();

    public string StatusText => Skipped ? "已跳过" : Success ? "完成" : "失败";
}

public sealed class PipelineReport
{
    public required AnalysisResult Result { get; init; }
    public List<string> Log { get; } = new();
    public List<string> Warnings { get; } = new();
    public List<string> Errors { get; } = new();
    /// <summary>编排说明（谁替代了谁、谁缺失被跳过）。</summary>
    public List<string> PlanNotes { get; } = new();
    public List<PluginStatus> Plugins { get; } = new();
    public List<PluginRunRecord> PluginRuns { get; } = new();
    public List<string> ReportFiles { get; } = new();
    public List<string> Artifacts { get; } = new();
    public List<string> RuleErrors { get; } = new();
    public TimeSpan Duration { get; set; }
    public bool Success { get; set; }
    public string? FatalError { get; set; }

    public IReadOnlyList<Finding> Findings => Result.Findings;
    public int SeverityCount(Severity s) => Result.Findings.Count(f => f.Severity == s);
    public int TotalFindings => Result.Findings.Count;
    public int PluginCount => PluginRuns.Count;
    public int FailedPluginCount => PluginRuns.Count(r => !r.Success && !r.Skipped);
    public int SkippedPluginCount => PluginRuns.Count(r => r.Skipped);
}

/// <summary>
/// §4 Core Orchestrator / §5 分析流程的实现。
///
/// 一次 <see cref="RunAsync"/> 走完六步：
///   ① 探测插件 → 编排执行计划（替代型顶替内置、补充型并行）
///   ② 静态阶段：PE / 依赖 / 签名 / 熵 / .NET / 字符串 / YARA
///   ③ 动态阶段：启动会话（进程 / 文件 / 注册表 / 网络 / 代理）+ 整理证据 + 外部实时采集工具
///   ④ 关联阶段：规则引擎跨证据归纳 → Findings
///   ⑤ 图谱阶段：SecurityGraph 构建与布局
///   ⑥ 产物阶段：落盘证据 / 事件 / 发现 / 报告
///
/// 贯穿原则（对照 §25）：每一步都留证据；插件失败不影响整体；任何"跳过"都写明原因。
/// </summary>
public sealed class AnalyzerPipeline
{
    private readonly PluginHost _host;

    public AnalyzerPipeline(PluginHost? host = null) => _host = host ?? new PluginHost();

    public PluginHost Host => _host;

    /// <summary>把 Profile 展开成任务集合。</summary>
    public static IReadOnlyCollection<TestTaskKind> ResolveTasks(TestProfileKind profile)
    {
        var def = TestProfileDefinition.All.FirstOrDefault(p => p.Kind == profile);
        return def?.Tasks ?? TestProfileDefinition.All[0].Tasks;
    }

    public async Task<PipelineReport> RunAsync(PipelineRequest request)
    {
        var sw = Stopwatch.StartNew();
        var ct = request.CancellationToken;

        EvidenceFactory.Reset();

        var result = new AnalysisResult
        {
            ProjectId = request.Project.Id,
            Project = request.Project,
            GeneratedAt = DateTime.Now,
        };

        var report = new PipelineReport { Result = result };
        void Log(string msg) { report.Log.Add(msg); request.Log(msg); }
        void Warn(string msg) { report.Warnings.Add(msg); request.Log("[警告] " + msg); }
        void Progress(double p, string m) => request.Progress(p, m);

        try
        {
            request.Layout.CreateAll();
            request.Project.RootDirectory = request.Layout.Root;

            // ══════════════════ ① 编排 ══════════════════
            Progress(0.01, "探测插件与外部工具");
            var tasks = request.Tasks.Distinct().ToList();
            var plan = _host.BuildPlan(tasks, request.Options);

            report.PlanNotes.AddRange(plan.Notes);
            report.Plugins.AddRange(plan.Plugins);
            foreach (var n in plan.Notes) Log(n);
            Log($"执行计划：{plan.Steps.Count} 个步骤，覆盖 {tasks.Count} 个任务");

            var disabledRuns = plan.Plugins.Where(p => !p.Enabled).Select(p => p.Name).ToList();
            if (disabledRuns.Count > 0) Warn($"以下插件已被用户禁用，本次未参与：{string.Join("、", disabledRuns)}");
            if (_host.LoadErrors.Count > 0)
            {
                foreach (var e in _host.LoadErrors) Warn($"外部插件加载问题：{e}");
            }

            // ══════════════════ ② 静态阶段 ══════════════════
            var staticSteps = plan.Steps.Where(s => !IsDynamicPhaseStep(s.Task)
                                                 && s.Task is not (TestTaskKind.ToolCorrelation or TestTaskKind.DeepAnalysis))
                                        .ToList();

            for (var i = 0; i < staticSteps.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var step = staticSteps[i];
                var pct = 0.02 + 0.40 * i / Math.Max(1, staticSteps.Count);
                Progress(pct, $"静态分析：{step.Plugin.Name}");
                var record = await ExecuteAsync(step, request, result, 0.0, ct).ConfigureAwait(false);
                report.PluginRuns.Add(record);
            }

            // ══════════════════ ②b 应用类型识别（§3.2） ══════════════════
            Progress(0.43, "识别应用运行类型");
            DetectRuntimeKind(request, result, Log, Warn);

            // ══════════════════ ③ 动态阶段 ══════════════════
            var dynamicSteps = plan.Steps.Where(s => IsDynamicPhaseStep(s.Task)).ToList();
            var dynamicTasks = tasks.Where(DynamicSession.IsDynamicTask).ToList();

            if (dynamicTasks.Count > 0)
            {
                Progress(0.44, "准备动态会话");
                await RunDynamicPhaseAsync(request, result, report, dynamicSteps, dynamicTasks, Log, Warn, Progress, ct)
                    .ConfigureAwait(false);
            }
            else if (dynamicSteps.Count > 0)
            {
                // 勾了网络/动态类插件但没勾动态任务：直接说明，而不是给个空结果
                Warn("未勾选任何需要动态会话的任务，动态与网络类插件已跳过。");
                foreach (var s in dynamicSteps)
                {
                    report.PluginRuns.Add(new PluginRunRecord
                    {
                        PluginId = s.Plugin.Id,
                        PluginName = s.Plugin.Name,
                        Task = s.Task,
                        Success = true,
                        Skipped = true,
                        Summary = "本次未启用动态会话，已跳过。",
                    });
                }
            }

            // ══════════════════ ④ 关联阶段（由 builtin.correlation 插件承担） ══════════════════
            // 必须在动态阶段之后：关联要看到完整的动态证据。
            var correlationSteps = plan.Steps.Where(s => s.Task == TestTaskKind.ToolCorrelation).ToList();
            foreach (var step in correlationSteps)
            {
                ct.ThrowIfCancellationRequested();
                Progress(0.80, "规则引擎关联分析");
                report.PluginRuns.Add(await ExecuteAsync(step, request, result, 0.0, ct).ConfigureAwait(false));
            }

            if (correlationSteps.Count == 0)
                Log("已按勾选跳过「规则关联与图谱」，本次不生成发现项。");

            Progress(0.86, "汇总分析结果");

            // ══════════════════ ⑥ 深度分析工作流 ══════════════════
            foreach (var step in plan.Steps.Where(s => s.Task == TestTaskKind.DeepAnalysis))
            {
                ct.ThrowIfCancellationRequested();
                Progress(0.88, $"深度分析工作流：{step.Plugin.Name}");
                report.PluginRuns.Add(await ExecuteAsync(step, request, result, 0.0, ct).ConfigureAwait(false));
            }

            // ══════════════════ ⑦ 落盘与报告 ══════════════════
            Progress(0.90, "保存证据与发现");

            // 先把"上一轮快照"取出来（Persist 会写入本轮快照，之后再取就取到本轮了）
            AnalysisSnapshot? baselineSnapshot = null;
            try
            {
                baselineSnapshot = request.Database.GetLatestSnapshot();
            }
            catch (Exception ex)
            {
                Log($"读取历史快照失败（跳过对比）：{ex.Message}");
            }

            Persist(request, result, report, Log, Warn);

            // 与上次对比（回归测试）—— 有基线才做，第一轮就说明"无基线"
            ComparisonResult? comparison = null;
            try
            {
                var currentSnapshot = RunComparer.Capture(result, result.Events.FirstOrDefault()?.SessionId);
                comparison = RunComparer.Compare(baselineSnapshot, currentSnapshot);
                if (baselineSnapshot is not null)
                {
                    Log($"与上次对比：新增 {comparison.Added.Count} / 消失 {comparison.Removed.Count} "
                        + $"/ 变化 {comparison.Changed.Count}（对比基线 {baselineSnapshot.CapturedAt:yyyy-MM-dd HH:mm}）");
                }
            }
            catch (Exception ex)
            {
                Warn($"对比分析失败：{ex.Message}");
            }

            if (request.GenerateReport && request.Options.AutoGenerateReport)
            {
                Progress(0.94, "生成报告");
                try
                {
                    var engine = new ReportEngine();
                    var reportResult = engine.Generate(result, new ReportOptions
                    {
                        OutputDirectory = request.Layout.Reports,
                        Title = $"Windows 应用程序安全测试报告 — {request.Project.Name}",
                        Subtitle = Path.GetFileName(request.TargetPath),
                        AnalystName = request.AnalystName,
                        Organization = request.Organization ?? "WinSecLab",
                        DocumentId = request.Project.Id,
                        IncludeEvidenceAppendix = true,
                        IncludeSecurityGraph = true,
                        Comparison = comparison,
                    });

                    report.ReportFiles.AddRange(reportResult.Files);
                    foreach (var w in reportResult.Warnings) Warn($"报告生成：{w}");
                    foreach (var f in reportResult.Files)
                    {
                        Log($"报告已生成：{f}");
                        request.OnArtifact?.Invoke("report", f);
                    }
                }
                catch (Exception ex)
                {
                    Warn($"报告生成失败：{ex.Message}");
                }
            }

            // 项目统计回写
            try
            {
                request.Project.UpdatedAt = DateTime.Now;
                request.Database.SaveProject(request.Project);
            }
            catch (Exception ex) { Warn($"项目信息回写失败：{ex.Message}"); }

            report.Success = true;
            Progress(1.0, "分析完成");
        }
        catch (OperationCanceledException)
        {
            report.Success = false;
            report.FatalError = "分析已被用户取消。";
            Warn(report.FatalError);
        }
        catch (Exception ex)
        {
            report.Success = false;
            report.FatalError = $"{ex.GetType().Name}: {ex.Message}";
            report.Errors.Add(report.FatalError);
            Log($"[致命错误] {report.FatalError}");
        }
        finally
        {
            sw.Stop();
            report.Duration = sw.Elapsed;

            // 结束事件与耗时对用户很重要，放到最后统一落一次
            try
            {
                request.Database.AddNote("system",
                    $"分析{(report.Success ? "完成" : "中止")}：任务 {request.Tasks.Count} 个，"
                    + $"插件 {report.PluginCount} 个（失败 {report.FailedPluginCount} / 跳过 {report.SkippedPluginCount}），"
                    + $"证据 {report.Result.Evidence.Count} 条，发现 {report.TotalFindings} 个，"
                    + $"耗时 {report.Duration.TotalSeconds:F1}s");
            }
            catch { }
        }

        return report;
    }

    /// <summary>
    /// §3.2 自动识别应用类型。放在静态阶段之后、动态阶段之前：
    /// 识别结果决定"要不要做 .NET 元数据解析""建议接哪些外部工具"，
    /// 用户也能在启动目标之前就知道这是个什么程序。
    /// </summary>
    private static void DetectRuntimeKind(PipelineRequest request, AnalysisResult result,
        Action<string> log, Action<string> warn)
    {
        // PE 结果可能为空：用户可能只勾了 .NET 分析 / 字符串提取，没勾 PE 分析任务。
        // 但"应用类型识别"是分析流程的基础（决定建议哪些分析器与工具），不能因为
        // 某个可选任务没勾就整体失效 —— 所以这里在缺失时主动补一次轻量 PE 解析。
        var pe = result.Pe;
        if (pe is not { IsValidPe: true })
        {
            try
            {
                pe = new WinSecLab.Core.Engines.Static.PeAnalyzer()
                    .Analyze(request.TargetPath, computeSignature: false);
                result.Pe = pe;
            }
            catch (Exception ex)
            {
                warn($"PE 补解析失败，跳过应用类型识别：{ex.Message}");
                return;
            }
        }

        if (pe is not { IsValidPe: true })
        {
            warn("PE 未解析成功，跳过应用类型识别。");
            return;
        }

        try
        {
            var detection = new WinSecLab.Core.Engines.Static.AppTypeDetector()
                .Detect(pe, result.DotNet, result.Strings);

            request.Project.Detection = detection;
            request.Project.Target.Runtime = detection.Runtime;
            request.Database.SaveProject(request.Project);

            log($"应用类型识别：{detection.DisplayName}（置信度 {detection.ConfidencePercent}%，"
                + $"{detection.Signals.Count} 条信号）");

            if (detection.RecommendedAnalyzers.Count > 0)
                log("  建议分析器：" + string.Join("、", detection.RecommendedAnalyzers));
            if (detection.RecommendedTools.Count > 0)
                log("  建议外部工具：" + string.Join("、", detection.RecommendedTools));
        }
        catch (Exception ex)
        {
            warn($"应用类型识别失败（不影响其它结论）：{ex.Message}");
        }
    }

    // ─────────────────────────────── 动态阶段 ───────────────────────────────

    private async Task RunDynamicPhaseAsync(PipelineRequest request, AnalysisResult result, PipelineReport report,
        List<PluginExecution> dynamicSteps, List<TestTaskKind> dynamicTasks,
        Action<string> log, Action<string> warn, Action<double, string> progress, CancellationToken ct)
    {
        var session = new AnalysisSession
        {
            Id = $"{request.Project.Id}-S{DateTime.Now:yyyyMMdd-HHmmss}",
            ProjectId = request.Project.Id,
            Name = $"动态测试 {DateTime.Now:MM-dd HH:mm}",
            Profile = request.Project.Profile,
            StartedAt = DateTime.Now,
            Tasks = dynamicTasks.ToList(),
        };

        using var dynamicSession = new DynamicSession(request.Project.Id, request.Database, session);

        dynamicSession.EventPublished += e => request.OnEvent?.Invoke(e);
        dynamicSession.ProgressChanged += (p, m) => progress(0.46 + p * 0.28, m);

        var launchPath = string.IsNullOrWhiteSpace(request.ExecutionTargetPath)
            ? request.TargetPath
            : request.ExecutionTargetPath!;

        var ok = await dynamicSession.StartAsync(launchPath, dynamicTasks, request.Options,
            request.RelevanceKeywords, ct).ConfigureAwait(false);

        if (!ok)
        {
            warn($"动态会话启动失败：{session.FailureReason ?? "未知原因"}");
            session.Phase = SessionPhase.Failed;
            request.Database.SaveSession(session);
        }
        else
        {
            log($"动态会话已启动：会话 {session.Id}，任务 {string.Join("、", dynamicTasks)}");

            var runSeconds = Math.Max(3, request.Options.TargetRunSeconds);
            var pollMs = 250;
            var waitedMs = 0;

            while (waitedMs < runSeconds * 1000)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(pollMs, ct).ConfigureAwait(false);
                waitedMs += pollMs;

                if (dynamicSession.ShouldStopEarly)
                {
                    log($"被测程序已退出（{waitedMs / 1000.0:F1}s），提前结束会话，不再等待剩余 {runSeconds - waitedMs / 1000.0:F1}s。");
                    break;
                }

                progress(0.46 + 0.26 * waitedMs / (runSeconds * 1000.0),
                    $"动态监控中 {waitedMs / 1000.0:F0}/{runSeconds}s —— 请在被测程序里执行需要观察的操作");
            }

            try
            {
                await dynamicSession.StopAsync(request.Options, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                warn($"动态会话收尾时出错：{ex.Message}");
            }
        }

        // 把会话采集到的东西汇总进结果包。
        // 注意：LiveBuffer 是"待落盘"的暂存区，会被定时器定期清空，
        // 所以这里要以数据库里本会话的记录为准，LiveBuffer 只作为写库失败时的兜底。
        var events = request.Database.GetEvents(sessionId: session.Id);
        if (events.Count == 0 && dynamicSession.RecentEvents.Count > 0)
        {
            warn("未从数据库读回事件，改用内存中的最近事件（可能不完整）。");
            events = dynamicSession.RecentEvents.ToList();
        }
        result.Events.AddRange(events);
        result.Connections.AddRange(dynamicSession.Connections);
        result.DnsObservations.AddRange(dynamicSession.DnsObservations);
        result.Http.AddRange(dynamicSession.HttpHistory);
        result.ProcessTree.AddRange(dynamicSession.ProcessTree);

        session.EventCount = events.Count;
        request.Database.SaveSession(session);

        foreach (var w in dynamicSession.Warnings) warn(w);

        log($"动态会话结束：事件 {events.Count} 条，连接 {result.Connections.Count} 条，"
            + $"DNS {result.DnsObservations.Count} 条，HTTP {result.Http.Count} 条，进程树 {result.ProcessTree.Count} 个节点");

        // 会话产物落盘
        try
        {
            foreach (var artifact in dynamicSession.ExportArtifacts(request.Layout))
            {
                report.Artifacts.Add(artifact);
                request.OnArtifact?.Invoke("dynamic", artifact);
            }
        }
        catch (Exception ex)
        {
            warn($"会话产物导出失败：{ex.Message}");
        }

        // 运行期插件 + 网络类外部工具都在这里执行（它们读的是同一份会话数据）
        progress(0.76, "整理运行期证据");
        var sessionContext = BuildSessionContext(dynamicSession, request, session,
            (kind, path) => { report.Artifacts.Add(path); request.OnArtifact?.Invoke(kind, path); });

        foreach (var step in dynamicSteps)
        {
            ct.ThrowIfCancellationRequested();
            progress(0.76, $"运行期分析：{step.Plugin.Name}");

            var record = await ExecuteAsync(step, request, result, 0.0, ct, sessionContext).ConfigureAwait(false);
            report.PluginRuns.Add(record);
        }
    }

    private static bool IsDynamicPhaseStep(TestTaskKind task) =>
        DynamicSession.IsDynamicTask(task);

    // ─────────────────────────────── 插件执行 ───────────────────────────────

    private async Task<PluginRunRecord> ExecuteAsync(PluginExecution step, PipelineRequest request,
        AnalysisResult result, double progressBase, CancellationToken ct, DynamicSessionContext? sessionContext = null)
    {
        var record = new PluginRunRecord
        {
            PluginId = step.Plugin.Id,
            PluginName = step.Plugin.Name,
            Task = step.Task,
        };

        var sw = Stopwatch.StartNew();
        var evidenceBefore = result.Evidence.Count;
        var findingsBefore = result.Findings.Count;
        var logCount = 0;

        var context = new PluginContext
        {
            Project = request.Project,
            Layout = request.Layout,
            Database = request.Database,
            TargetPath = request.TargetPath,
            Task = step.Task,
            Result = result,
            Session = sessionContext,
            // 插件日志统一汇入管线日志，加插件前缀便于分辨来源，并限制单插件日志量
            Log = msg =>
            {
                if (Interlocked.Increment(ref logCount) > 400) return;
                request.Log($"[{step.Plugin.Id}] {msg}");
            },
            Progress = (p, m) =>
            {
                if (p >= 0) request.Progress(progressBase + p * 0.05, m);
            },
            SearchDirectories = new List<string> { Path.GetDirectoryName(request.TargetPath) ?? "" },
            Options = request.Options,
            CancellationToken = ct,
        };

        try
        {
            var runResult = await step.Plugin.AnalyzeAsync(context).ConfigureAwait(false);

            sw.Stop();
            record.Duration = sw.Elapsed;
            record.Success = runResult.Success;
            record.Skipped = runResult.IsSkipped;
            record.Summary = runResult.Summary;
            record.Error = runResult.Error;
            record.Warnings.AddRange(runResult.Warnings);
            record.Artifacts.AddRange(runResult.Artifacts);

            // 插件没显式给证据时，把返回值里的证据补进去（统一出口，保证不漏证据）
            if (runResult.Evidence.Count > 0)
            {
                result.Evidence.AddRange(runResult.Evidence);
                try { request.Database.SaveEvidence(runResult.Evidence); } catch { }
            }
            if (runResult.Findings.Count > 0) result.Findings.AddRange(runResult.Findings);

            record.EvidenceCount = result.Evidence.Count - evidenceBefore;
            record.FindingCount = result.Findings.Count - findingsBefore;

            foreach (var a in runResult.Artifacts)
            {
                request.OnArtifact?.Invoke(step.Plugin.Id, a);
            }

            var summary = $"{step.Plugin.Name}：{record.StatusText} — {record.Summary}（{record.Duration.TotalSeconds:F1}s）";
            request.Log(summary);

            if (!string.IsNullOrEmpty(runResult.Error))
                request.Log($"  [错误] {runResult.Error}");
            foreach (var w in runResult.Warnings) request.Log($"  [警告] {w}");
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            record.Duration = sw.Elapsed;
            record.Success = false;
            record.Error = "已取消";
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            record.Duration = sw.Elapsed;
            record.Success = false;
            record.Error = $"{ex.GetType().Name}: {ex.Message}";
            record.Summary = "插件执行异常";
            request.Log($"{step.Plugin.Name}：异常 — {record.Error}");
        }

        return record;
    }

    /// <summary>
    /// 把已结束的动态会话包装成插件可见的只读上下文。
    /// 运行期插件读的是"同一份事件流"，因此这里只暴露读取入口，
    /// PublishEvent 在会话结束后返回 false（事件不再入队），而不是伪装成功。
    /// </summary>
    private static DynamicSessionContext BuildSessionContext(DynamicSession session, PipelineRequest request,
        AnalysisSession model, Action<string, string> onArtifact)
    {
        var proxy = session.Proxy;
        return new DynamicSessionContext
        {
            SessionId = model.Id,
            RootProcessId = model.RootProcessId,
            RootProcessPath = model.LaunchedProcessPath
                             ?? request.ExecutionTargetPath
                             ?? request.TargetPath,
            IsInTargetTree = pid => session.Connections.Any(c => c.ProcessId == pid && c.IsFromTargetTree)
                                    || session.ProcessTree.Any(t => t.Pid == pid),
            PublishEvent = _ => false,
            RegisterArtifact = onArtifact,
            Proxy = proxy is null ? null : new HttpProxyServerHandle
            {
                Port = proxy.Port,
                Snapshot = () => session.HttpHistory,
                Stop = () => { /* 代理生命周期由 DynamicSession 管理 */ },
                ReplayAsync = proxy.ReplayAsync,
            },
            ProbeConnections = (_, pid, _) => session.Connections.Where(c => c.ProcessId == pid).ToList(),
            BufferedEvents = session.RecentEvents.ToList(),
        };
    }

    // ─────────────────────────────── 落盘 ───────────────────────────────

    private static void Persist(PipelineRequest request, AnalysisResult result, PipelineReport report,
        Action<string> log, Action<string> warn)
    {
        var db = request.Database;

        Try(() => db.SaveProject(request.Project), "项目记录");
        if (result.Pe is not null) Try(() => db.SavePeImage(result.Pe!), "PE 分析");
        if (result.DotNet is not null) Try(() => db.SaveDotNet(request.TargetPath, result.DotNet!), ".NET 元数据");
        if (result.Dependencies.Count > 0) Try(() => db.SaveDependencies(result.Dependencies), "依赖清单");
        if (result.Strings.Count > 0) Try(() => db.SaveStrings(result.Strings), "字符串");

        // 证据去重后落库：补充型外部工具与内置引擎可能产出同名证据，用 Id 兜底
        if (result.Evidence.Count > 0)
        {
            var distinct = result.Evidence
                .GroupBy(e => e.Id, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();
            if (distinct.Count != result.Evidence.Count)
            {
                log($"证据去重：{result.Evidence.Count} → {distinct.Count} 条");
                result.Evidence.Clear();
                result.Evidence.AddRange(distinct);
            }
            Try(() => db.SaveEvidence(result.Evidence), "证据");
        }

        if (result.Events.Count > 0) Try(() => db.SaveEvents(result.Events), "监控事件");
        if (result.Connections.Count > 0) Try(() => db.SaveConnections(result.Connections), "网络连接");
        if (result.DnsObservations.Count > 0) Try(() => db.SaveDnsObservations(result.DnsObservations), "DNS 观测");
        if (result.Http.Count > 0) Try(() => db.SaveHttpExchanges(result.Http), "HTTP 事务");

        // YARA 结果在插件里已落库，这里只做去重（内置 + 外部可能重复命中同一规则同一文件）
        if (result.YaraMatches.Count > 0)
        {
            var deduped = result.YaraMatches
                .GroupBy(m => $"{m.RuleName}|{m.FilePath}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderBy(m => m.IsBuiltinLightweight ? 1 : 0).First())
                .ToList();
            if (deduped.Count != result.YaraMatches.Count)
                log($"YARA 结果去重：{result.YaraMatches.Count} → {deduped.Count} 条（同一规则同一文件只保留一条，优先外部引擎）");
            result.YaraMatches.Clear();
            result.YaraMatches.AddRange(deduped);
        }

        if (result.Findings.Count > 0) Try(() => db.SaveFindings(result.Findings), "安全发现");

        // 存一份本轮快照，供下次分析做「与上次对比」（回归测试的核心诉求）
        Try(() =>
        {
            var snapshot = RunComparer.Capture(result, result.Events.FirstOrDefault()?.SessionId);
            db.SaveSnapshot(snapshot);
            log($"已保存本轮快照 {snapshot.Id}（发现 {snapshot.TotalFindings} 项），下次分析可做对比。");
        }, "分析快照");

        void Try(Action action, string what)
        {
            try { action(); }
            catch (Exception ex) { warn($"{what}保存失败：{ex.Message}"); }
        }
    }
}
