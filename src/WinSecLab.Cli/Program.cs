using System.Text;
using WinSecLab.Core.Engines.Analysis;
using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins;
using WinSecLab.Core.Storage;

namespace WinSecLab.Cli;

/// <summary>
/// wsx —— WinSecLab 命令行。
///
/// 存在意义：GUI 适合"看着做"，CLI 适合"重复做"。安全测试里大量工作是同一套流程反复跑，
/// 所以两条路径共用 <see cref="AnalyzerPipeline"/> —— CLI 不是简化版实现，而是同一引擎的另一个入口。
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintHelp();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var options = CliOptions.Parse(args.Skip(1));

        try
        {
            return command switch
            {
                "analyze" or "scan" => await RunAnalyzeAsync(options).ConfigureAwait(false),
                "monitor" => await RunMonitorAsync(options).ConfigureAwait(false),
                "report" => RunReport(options),
                "projects" or "list" => RunProjects(options),
                "plugins" => RunPlugins(options),
                "doctor" => RunDoctor(options),
                "help" => Help(),
                _ => Unknown(command),
            };
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("已取消。");
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"执行失败：{ex.GetType().Name}: {ex.Message}");
            if (options.Has("--verbose")) Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    // ═════════════════════════════════ analyze ═════════════════════════════════

    private static async Task<int> RunAnalyzeAsync(CliOptions options)
    {
        var target = options.Positional.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(target))
        {
            Console.Error.WriteLine("用法：wsx analyze <目标文件> [选项]");
            return 2;
        }
        if (!File.Exists(target))
        {
            Console.Error.WriteLine($"目标文件不存在：{target}");
            return 2;
        }

        var workspace = new WorkspaceService(options.Get("--workspace"));
        var settings = workspace.LoadSettings();

        TestProject project;
        ProjectLayout layout;
        ProjectDatabase db;

        var reuseId = options.Get("--project");
        if (!string.IsNullOrWhiteSpace(reuseId))
        {
            var opened = workspace.OpenProject(reuseId!);
            if (opened is null)
            {
                Console.Error.WriteLine($"找不到项目：{reuseId}");
                return 2;
            }
            (project, layout, db) = opened.Value;
            Console.WriteLine($"复用项目 {project.Id} — {project.Name}");
            target = project.PrimaryTargetPath ?? target;
        }
        else
        {
            Console.WriteLine($"导入目标：{Path.GetFileName(target)}");
            var outcome = workspace.CreateProject(target,
                name: options.Get("--name"),
                description: options.Get("--description"),
                profile: ParseProfile(options.Get("--profile") ?? settings.DefaultProfile),
                author: settings.AnalystName,
                authorization: options.Get("--authorization"));

            if (!outcome.Success || outcome.Project is null || outcome.Layout is null)
            {
                Console.Error.WriteLine($"项目创建失败：{outcome.Error}");
                return 1;
            }

            foreach (var w in outcome.Warnings) Console.WriteLine($"  · {w}");

            project = outcome.Project;
            layout = outcome.Layout;
            db = new ProjectDatabase(layout);
            target = project.PrimaryTargetPath ?? target;
            Console.WriteLine($"项目已创建：{project.Id} — {project.Name}");
            Console.WriteLine($"项目目录：{layout.Root}");
        }

        var tasks = options.Has("--tasks")
            ? ParseTasks(options.Get("--tasks")!)
            : AnalyzerPipeline.ResolveTasks(project.Profile).ToList();

        var isDynamic = new Func<TestTaskKind, bool>(WinSecLab.Core.Engines.Dynamic.DynamicSession.IsDynamicTask);
        if (options.Has("--static-only")) tasks = tasks.Where(t => !isDynamic(t)).ToList();
        if (options.Has("--dynamic-only")) tasks = tasks.Where(isDynamic).ToList();

        if (tasks.Count == 0)
        {
            Console.Error.WriteLine("任务集合为空，无可执行内容。");
            return 2;
        }

        var analysisOptions = BuildAnalysisOptions(options, settings);

        // 执行路径与"分析的样本"可能不是同一个文件：样本以副本留存用于取证，执行走原始安装位置
        var (executionTarget, execWarning) = WorkspaceService.ResolveExecutionTarget(project);
        if (execWarning is not null) Console.WriteLine($"  · {execWarning}");

        Console.WriteLine($"测试 Profile：{project.Profile}（{tasks.Count} 个任务）");
        Console.WriteLine($"任务：{string.Join(", ", tasks)}");
        Console.WriteLine($"样本路径：{target}");
        if (!string.Equals(executionTarget, target, StringComparison.OrdinalIgnoreCase))
            Console.WriteLine($"执行路径：{executionTarget}");
        Console.WriteLine();

        var pipeline = new AnalyzerPipeline();
        var host = pipeline.Host;
        var extraPlugins = host.LoadExternalPlugins(workspace.PluginsRoot);

        var consoleWidth = SafeConsoleWidth();
        var request = new PipelineRequest
        {
            Project = project,
            Layout = layout,
            Database = db,
            TargetPath = target,
            ExecutionTargetPath = executionTarget,
            Tasks = tasks,
            Options = analysisOptions,
            GenerateReport = !options.Has("--no-report"),
            AnalystName = settings.AnalystName,
            Organization = settings.Organization,
            RelevanceKeywords = BuildKeywords(project, target).ToList(),
            Log = msg => Console.WriteLine("  " + msg),
            Progress = (p, m) =>
            {
                if (!options.Has("--quiet") && p >= 0)
                    Console.Write($"\r  [{p * 100,3:F0}%] {Truncate(m, Math.Max(20, consoleWidth - 12)),-0}");
            },
        };

        Console.WriteLine($"插件注册 {host.Plugins.Count} 个（其中外部程序集 {extraPlugins} 个）");
        Console.WriteLine();

        var report = await pipeline.RunAsync(request).ConfigureAwait(false);
        Console.WriteLine();

        // ───────────────────────────── 结果汇总 ─────────────────────────────
        PrintSeparator();
        Console.WriteLine(report.Success ? "分析完成" : $"分析未完成：{report.FatalError}");
        Console.WriteLine($"总耗时 {report.Duration.TotalSeconds:F1}s");

        if (report.PlanNotes.Count > 0 && !options.Has("--quiet"))
        {
            Console.WriteLine();
            Console.WriteLine("编排决策：");
            foreach (var n in report.PlanNotes.Take(20)) Console.WriteLine($"  · {n}");
        }

        Console.WriteLine();
        Console.WriteLine("插件执行：");
        foreach (var r in report.PluginRuns)
        {
            var mark = r.Skipped ? "—" : r.Success ? "✓" : "✗";
            Console.WriteLine($"  {mark} {r.PluginName,-24} {r.Duration.TotalSeconds,6:F1}s  证据 {r.EvidenceCount,4}  {Truncate(r.Summary, 90)}");
            if (!string.IsNullOrEmpty(r.Error)) Console.WriteLine($"      错误：{r.Error}");
        }

        Console.WriteLine();
        Console.WriteLine("发现统计：");
        Console.WriteLine($"  严重 {report.SeverityCount(Severity.Critical)} / 高 {report.SeverityCount(Severity.High)} "
                          + $"/ 中 {report.SeverityCount(Severity.Medium)} / 低 {report.SeverityCount(Severity.Low)} "
                          + $"/ 提示 {report.SeverityCount(Severity.Info)}；合计 {report.TotalFindings} 个");

        if (report.Findings.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("主要发现：");
            foreach (var f in report.Findings.Take(options.Int("--top", 10)))
            {
                Console.WriteLine($"  [{f.Severity}] {f.Id}  {f.Title}");
                if (!string.IsNullOrWhiteSpace(f.Target))
                    Console.WriteLine($"        对象：{Truncate(f.Target!, 92)}");
            }
            if (report.Findings.Count > options.Int("--top", 10))
                Console.WriteLine($"  …还有 {report.Findings.Count - options.Int("--top", 10)} 条，见报告。");
        }

        Console.WriteLine();
        Console.WriteLine($"证据 {report.Result.Evidence.Count} 条 · 事件 {report.Result.Events.Count} 条 · "
                          + $"连接 {report.Result.Connections.Count} 条 · HTTP {report.Result.Http.Count} 条 · "
                          + $"YARA {report.Result.YaraMatches.Count} 条 · 图谱 {report.Result.GraphNodes.Count} 节点");

        if (report.Warnings.Count > 0 && !options.Has("--quiet"))
        {
            Console.WriteLine();
            Console.WriteLine($"警告 {report.Warnings.Count} 条（前 15 条）：");
            foreach (var w in report.Warnings.Take(15)) Console.WriteLine($"  · {Truncate(w, 110)}");
        }

        if (report.ReportFiles.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("报告产物：");
            foreach (var f in report.ReportFiles) Console.WriteLine($"  {f}");
        }

        Console.WriteLine();
        Console.WriteLine($"项目目录：{layout.Root}");

        if (options.Has("--json"))
        {
            var jsonPath = Path.Combine(layout.Reports, $"wsx-result-{DateTime.Now:yyyyMMdd-HHmmss}.json");
            WriteJsonSummary(jsonPath, report, target);
            Console.WriteLine($"JSON 摘要：{jsonPath}");
        }

        return report.Success ? 0 : 1;
    }

    // ═════════════════════════════════ monitor ═════════════════════════════════

    private static async Task<int> RunMonitorAsync(CliOptions options)
    {
        // monitor 就是"只跑动态任务"的 analyze，刻意复用同一路径，避免两套实现漂移
        options.Set("--dynamic-only", "true");
        Console.WriteLine("== 仅动态监控模式（跳过静态分析） ==\n");
        return await RunAnalyzeAsync(options).ConfigureAwait(false);
    }

    // ═════════════════════════════════ report ═════════════════════════════════

    private static int RunReport(CliOptions options)
    {
        var id = options.Positional.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(id))
        {
            Console.Error.WriteLine("用法：wsx report <项目编号>");
            return 2;
        }

        var workspace = new WorkspaceService(options.Get("--workspace"));
        var opened = workspace.OpenProject(id);
        if (opened is null)
        {
            Console.Error.WriteLine($"找不到项目：{id}");
            return 2;
        }

        var (project, layout, db) = opened.Value;

        var result = new AnalysisResult
        {
            ProjectId = project.Id,
            Project = project,
            Pe = db.GetPeImages().FirstOrDefault(),
            Findings = db.GetFindings(limit: 5000),
            Evidence = db.GetEvidence(limit: 5000),
            Events = db.GetEvents(),
            Connections = db.GetConnections(),
            DnsObservations = db.GetDnsObservations(),
            Http = db.GetHttpExchanges(),
            YaraMatches = db.GetYaraMatches(),
        };

        Console.WriteLine($"项目 {project.Id} — {project.Name}");
        Console.WriteLine($"读入：发现 {result.Findings.Count} 个，证据 {result.Evidence.Count} 条，"
                          + $"事件 {result.Events.Count} 条，连接 {result.Connections.Count} 条");

        try
        {
            var (nodes, edges) = WinSecLab.Core.Engines.Analysis.SecurityGraphBuilder.Build(result);
            result.GraphNodes.AddRange(nodes);
            result.GraphEdges.AddRange(edges);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  图谱重建失败（报告仍会生成）：{ex.Message}");
        }

        var settings = workspace.LoadSettings();
        var engine = new WinSecLab.Core.Engines.Reports.ReportEngine();
        var report = engine.Generate(result, new WinSecLab.Core.Engines.Reports.ReportOptions
        {
            OutputDirectory = layout.Reports,
            Title = $"Windows 应用程序安全测试报告 — {project.Name}",
            Subtitle = project.Target.FileName,
            DocumentId = project.Id,
            AnalystName = settings.AnalystName,
            Organization = settings.Organization,
        });

        foreach (var f in report.Files) Console.WriteLine($"  已生成：{f}");
        foreach (var w in report.Warnings) Console.WriteLine($"  警告：{w}");
        return report.Files.Count > 0 ? 0 : 1;
    }

    // ═════════════════════════════════ projects ═════════════════════════════════

    private static int RunProjects(CliOptions options)
    {
        var workspace = new WorkspaceService(options.Get("--workspace"));

        // 删除项目：必须显式给 --delete <编号> 才会执行（破坏性操作不默认触发）
        var deleteTarget = options.Get("--delete");
        if (!string.IsNullOrWhiteSpace(deleteTarget))
            return RunDeleteProject(workspace, deleteTarget, options.Has("--permanent"));

        var projects = workspace.ListProjects();

        Console.WriteLine($"工作区：{workspace.Root}");
        Console.WriteLine();

        if (projects.Count == 0)
        {
            Console.WriteLine("暂无项目。用 wsx analyze <目标文件> 创建第一个项目。");
            return 0;
        }

        Console.WriteLine($"{"项目编号",-18} {"名称",-26} {"版本",-14} {"运行时",-12} {"更新时间",-20}");
        PrintSeparator('-', 94);
        foreach (var p in projects)
        {
            Console.WriteLine($"{p.Id,-18} {Truncate(p.Name, 24),-26} {Truncate(p.Target.FileVersion ?? "-", 12),-14} "
                              + $"{p.Target.Runtime,-12} {p.UpdatedAt:yyyy-MM-dd HH:mm:ss}");
        }
        Console.WriteLine();
        Console.WriteLine($"共 {projects.Count} 个项目。");
        Console.WriteLine("删除项目：wsx projects --delete <项目编号>（默认移入回收站，加 --permanent 彻底删除）");
        return 0;
    }

    /// <summary>
    /// 删除项目。默认移入回收站（可从系统回收站恢复），--permanent 才彻底删除。
    /// </summary>
    private static int RunDeleteProject(WorkspaceService workspace, string projectId, bool permanent)
    {
        var outcome = workspace.DeleteProject(projectId, permanent);

        if (!outcome.Success)
        {
            Console.Error.WriteLine($"删除失败：{outcome.Error}");
            return 1;
        }

        if (outcome.Permanent)
            Console.WriteLine($"已彻底删除项目 {outcome.ProjectName}（不可恢复）。");
        else
            Console.WriteLine($"已把项目 {outcome.ProjectName} 移入回收站（可从系统回收站恢复）。");

        return 0;
    }

    // ═════════════════════════════════ plugins ═════════════════════════════════

    private static int RunPlugins(CliOptions options)
    {
        var workspace = new WorkspaceService(options.Get("--workspace"));
        var host = new PluginHost();
        host.LoadExternalPlugins(workspace.PluginsRoot);

        if (options.Has("--refresh")) ExternalToolLocator.InvalidateCache();

        Console.WriteLine("插件与外部工具探测：");
        Console.WriteLine();

        var statuses = host.ProbeAll();
        foreach (var group in statuses.GroupBy(s => s.Kind))
        {
            Console.WriteLine($"── {DescribeKind(group.Key)} ──");
            foreach (var s in group.OrderByDescending(s => s.Available).ThenBy(s => s.Id))
            {
                Console.WriteLine($"  {(s.Available ? "✓" : "·")} {s.Id,-14} {s.Name,-26} {Truncate(s.AvailabilityText, 62)}");
                if (!s.Available && s.InstallHint.Length > 0)
                    Console.WriteLine($"      → 安装：{Truncate(s.InstallHint, 96)}");
            }
            Console.WriteLine();
        }

        if (host.LoadErrors.Count > 0)
        {
            Console.WriteLine("加载问题：");
            foreach (var e in host.LoadErrors) Console.WriteLine($"  · {e}");
            Console.WriteLine();
        }

        Console.WriteLine($"可用 {statuses.Count(s => s.Available)} / 共 {statuses.Count} 个插件。"
                          + "外部工具缺失时相关任务由内置引擎兜底，不会导致分析失败。");
        return 0;
    }

    // ═════════════════════════════════ doctor ═════════════════════════════════

    private static int RunDoctor(CliOptions options)
    {
        Console.WriteLine("WinSecLab 环境体检");
        PrintSeparator();
        Console.WriteLine();

        var workspace = new WorkspaceService(options.Get("--workspace"));
        var settings = workspace.LoadSettings();

        Console.WriteLine("【工作区】");
        Console.WriteLine($"  路径            {workspace.Root}");
        Console.WriteLine($"  可写            {(CanWrite(workspace.Root) ? "是" : "否 —— 请检查权限或用 --workspace 指定其它目录")}");
        Console.WriteLine($"  已有项目        {workspace.ListProjects().Count} 个");
        Console.WriteLine($"  规则目录        {workspace.RulesRoot}");
        Console.WriteLine($"  插件目录        {workspace.PluginsRoot}");
        Console.WriteLine();

        Console.WriteLine("【运行环境】");
        var env = WorkspaceService.CaptureEnvironment();
        Console.WriteLine($"  机器 / 用户     {env.MachineName} / {env.UserName}");
        Console.WriteLine($"  操作系统        {env.OsVersion}");
        Console.WriteLine($"  运行时          {env.DotNetVersion}");
        Console.WriteLine($"  逻辑处理器      {env.LogicalProcessors}");
        Console.WriteLine($"  管理员权限      {(env.IsElevated ? "是 —— 可做 WMI 实时事件、抓包、Procmon" : "否 —— 进程事件退化为轮询，抓包 / Procmon 不可用")}");
        Console.WriteLine($"  网卡            {env.NetworkInterfaces.Count} 个");
        Console.WriteLine();

        Console.WriteLine("【外部工具】");
        var host = new PluginHost();
        var statuses = host.ProbeAll().Where(s => s.Kind == PluginKind.ExternalToolAdapter).ToList();
        foreach (var s in statuses.OrderByDescending(s => s.Available).ThenBy(s => s.Id))
            Console.WriteLine($"  {(s.Available ? "✓" : "·")} {s.Name,-26} {Truncate(s.AvailabilityText, 58)}");
        Console.WriteLine($"  可用 {statuses.Count(s => s.Available)} / {statuses.Count} —— 缺失不影响内置引擎工作。");
        Console.WriteLine();

        Console.WriteLine("【当前设置】");
        Console.WriteLine($"  Profile         {settings.DefaultProfile}");
        Console.WriteLine($"  目标运行时长    {settings.TargetRunSeconds}s");
        Console.WriteLine($"  优先外部工具    {(settings.PreferExternalTools ? "是" : "否")}");
        Console.WriteLine($"  复制样本入项目  {(settings.CopyTargetIntoProject ? "是" : "否")}");
        Console.WriteLine($"  自动生成报告    {(settings.AutoGenerateReport ? "是" : "否")}");
        Console.WriteLine();

        Console.WriteLine("【内置能力】");
        Console.WriteLine($"  内置检测规则    {WinSecLab.Core.Engines.Rules.BuiltinRules.All.Count} 条");
        Console.WriteLine($"  内置 YARA 规则  {WinSecLab.Core.Engines.Static.YaraAnalyzer.BuiltinRules.Count} 条");
        Console.WriteLine($"  测试任务        {TestTaskDefinition.All.Count} 个");
        Console.WriteLine($"  测试 Profile    {TestProfileDefinition.All.Count} 个（{string.Join(", ", TestProfileDefinition.All.Select(p => p.Name))}）");
        Console.WriteLine();

        Console.WriteLine("提示：本平台仅限对已获授权的软件进行安全测试。");
        return 0;
    }

    // ═════════════════════════════════ 辅助 ═════════════════════════════════

    private static AnalysisOptions BuildAnalysisOptions(CliOptions options, WorkspaceSettings settings)
    {
        var o = new AnalysisOptions
        {
            PreferExternalTools = !options.Has("--no-external") && settings.PreferExternalTools,
            TargetRunSeconds = options.Int("--run-seconds", settings.TargetRunSeconds),
            AutoGenerateReport = settings.AutoGenerateReport,
            StringMinLength = options.Int("--min-string-length", 6),
            YaraMaxFiles = options.Int("--yara-max-files", 13),
            ProcmonCaptureSeconds = options.Int("--procmon-seconds", 20),
            TsharkCaptureSeconds = options.Int("--tshark-seconds", 20),
            EnableIlSpyDecompile = options.Has("--ilspy-decompile"),
            EnableGhidraHeadless = options.Has("--ghidra-headless"),
            HttpProxyPort = options.Int("--proxy-port", 8877),
            KillTargetOnSessionEnd = !options.Has("--keep-target"),
        };

        if (options.Get("--yara-rules") is string yaraDir) o.YaraRulesDirectory = yaraDir;
        return o;
    }

    private static IEnumerable<string> BuildKeywords(TestProject project, string targetPath)
    {
        var keywords = new List<string>();
        void Add(string? s)
        {
            if (!string.IsNullOrWhiteSpace(s)) keywords.Add(s!.Trim());
        }

        Add(Path.GetFileNameWithoutExtension(targetPath));
        Add(Path.GetFileName(targetPath));
        Add(project.Target.ProductName);
        Add(project.Target.CompanyName);
        Add(project.Name);
        Add(project.Target.FileDescription);

        return keywords.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static TestProfileKind ParseProfile(string raw) =>
        Enum.TryParse<TestProfileKind>(raw, ignoreCase: true, out var p) ? p : TestProfileKind.DesktopApplication;

    private static List<TestTaskKind> ParseTasks(string raw)
    {
        var list = new List<TestTaskKind>();
        foreach (var part in raw.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (Enum.TryParse<TestTaskKind>(part, ignoreCase: true, out var t)) list.Add(t);
            else Console.Error.WriteLine($"  未知任务：{part}（已忽略）");
        }
        return list;
    }

    private static void WriteJsonSummary(string path, PipelineReport report, string target)
    {
        var payload = new
        {
            target,
            projectId = report.Result.ProjectId,
            success = report.Success,
            durationSeconds = Math.Round(report.Duration.TotalSeconds, 2),
            findings = report.Findings.Select(f => new
            {
                f.Id,
                f.RuleId,
                f.Title,
                severity = f.Severity.ToString(),
                confidence = f.Confidence.ToString(),
                f.Category,
                f.Target,
                evidenceCount = f.EvidenceIds.Count,
            }),
            counts = new
            {
                evidence = report.Result.Evidence.Count,
                events = report.Result.Events.Count,
                connections = report.Result.Connections.Count,
                http = report.Result.Http.Count,
                yara = report.Result.YaraMatches.Count,
                graphNodes = report.Result.GraphNodes.Count,
                graphEdges = report.Result.GraphEdges.Count,
            },
            plugins = report.PluginRuns.Select(r => new
            {
                id = r.PluginId,
                name = r.PluginName,
                task = r.Task.ToString(),
                skipped = r.Skipped,
                success = r.Success,
                durationSeconds = Math.Round(r.Duration.TotalSeconds, 2),
                evidence = r.EvidenceCount,
                summary = r.Summary,
                error = r.Error,
            }),
            warnings = report.Warnings,
            planNotes = report.PlanNotes,
            reports = report.ReportFiles,
        };

        File.WriteAllText(path, WinSecLab.Core.Serialization.WslJson.Serialize(payload, indented: true),
            new UTF8Encoding(false));
    }

    private static bool IsHelp(string arg) => arg is "-h" or "--help" or "help" or "/?";

    private static int Help()
    {
        PrintHelp();
        return 0;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"未知命令：{command}");
        Console.Error.WriteLine("运行 wsx help 查看用法。");
        return 2;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
wsx —— WinSecLab Windows 应用程序安全测试平台（命令行）

用法：
  wsx analyze <目标文件> [选项]      创建/复用项目并执行完整分析
  wsx monitor <目标文件> [选项]      仅执行动态监控（等价于 analyze --dynamic-only）
  wsx report  <项目编号>             基于已落库结果重新生成报告
  wsx projects                       列出工作区内的项目
  wsx projects --delete <编号>        删除项目（默认移入回收站，可恢复）
  wsx projects --delete <编号> --permanent
                                     彻底删除项目（不可恢复）
  wsx plugins [--refresh]            列出插件并探测外部工具
  wsx doctor                         环境体检（工作区 / 权限 / 外部工具）
  wsx help                           显示本帮助

常用选项：
  --project <编号>        复用已有项目（不新建）
  --name <名称>           新项目名称（默认取文件名）
  --profile <类型>        Basic | DesktopApplication | DotNetApplication | FullSecurityAssessment
  --tasks <列表>          自定义任务，逗号分隔（如 PeAnalysis,StringsScan,ProcessMonitor）
  --run-seconds <秒>      动态会话时长（默认取工作区设置，60s）
  --static-only           只跑静态任务
  --dynamic-only          只跑动态任务
  --no-report             不生成报告（仅落库）
  --no-external           不调用任何外部工具，仅用内置引擎
  --keep-target           会话结束后不结束被测进程
  --workspace <目录>      指定工作区（默认 %USERPROFILE%\Documents\WinSecLab）
  --yara-rules <目录>     追加用户 YARA 规则目录
  --procmon-seconds <秒>  启用 Process Monitor 全系统采集（需管理员 + 已安装）
  --tshark-seconds <秒>   启用 tshark 抓包（需管理员 + Npcap + 已安装）
  --ilspy-decompile       启用 ilspycmd 反编译导出（仅 .NET 目标，产物较多）
  --ghidra-headless       启用 Ghidra headless 分析（很慢，慎用）
  --top <N>               控制台显示的发现条数（默认 10）
  --json                  额外输出 JSON 摘要
  --quiet                 减少进度输出
  --verbose               出错时打印完整堆栈

说明：
  未安装的外部工具不会导致任务失败 —— 相关任务由内置引擎兜底，并在报告中标注"已跳过"。
  本平台仅限对已获授权的软件进行安全测试（§25 授权使用）。
""");
    }

    private static void PrintSeparator(char c = '=', int width = 78) => Console.WriteLine(new string(c, width));

    private static string Truncate(string text, int max) =>
        max <= 0 || text.Length <= max ? text : text[..Math.Max(0, max - 1)] + "…";

    private static string DescribeKind(PluginKind kind) => kind switch
    {
        PluginKind.Builtin => "内置引擎（零外部依赖）",
        PluginKind.ExternalToolAdapter => "外部工具适配器",
        _ => "外部程序集插件",
    };

    private static bool CanWrite(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, $".write-probe-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int SafeConsoleWidth()
    {
        try { return Math.Clamp(Console.WindowWidth, 60, 200); }
        catch { return 100; }
    }
}

/// <summary>极简参数解析：--key value / --key=value / --flag / 位置参数。够用即可，不引入第三方 CLI 库。</summary>
internal sealed class CliOptions
{
    private readonly Dictionary<string, string?> _named = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Positional { get; } = new();

    public static CliOptions Parse(IEnumerable<string> args)
    {
        var options = new CliOptions();
        var array = args.ToArray();

        for (var i = 0; i < array.Length; i++)
        {
            var arg = array[i];
            if (!arg.StartsWith('-'))
            {
                options.Positional.Add(arg);
                continue;
            }

            var key = arg;
            string? value = null;

            var eq = arg.IndexOf('=');
            if (eq > 0)
            {
                key = arg[..eq];
                value = arg[(eq + 1)..];
            }
            else if (i + 1 < array.Length && !array[i + 1].StartsWith('-'))
            {
                value = array[i + 1];
                i++;
            }

            options._named[key] = value ?? "true";
        }

        return options;
    }

    public bool Has(string key) => _named.ContainsKey(key);

    /// <summary>取字符串值；纯 flag（无值）返回 null。</summary>
    public string? Get(string key) =>
        _named.TryGetValue(key, out var v) && v != "true" ? v : null;

    public int Int(string key, int fallback = 0) =>
        _named.TryGetValue(key, out var v) && int.TryParse(v, out var n) ? n : fallback;

    /// <summary>供内部命令改写选项（例如 monitor 复用 analyze 时注入 --dynamic-only）。</summary>
    public void Set(string key, string value) => _named[key] = value;
}
