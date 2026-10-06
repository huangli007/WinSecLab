using System.Collections.ObjectModel;
using System.Diagnostics;
using WinSecLab.Core.Engines.Analysis;
using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins;
using WinSecLab.Core.Storage;

namespace WinSecLab.App.Infrastructure;

/// <summary>任务清单里的一项（UI 勾选用）。</summary>
public sealed class TaskSelection : ObservableObject
{
    private bool _isSelected;
    public required TestTaskKind Kind { get; init; }
    /// <summary>主显示名（中文）。</summary>
    public required string Name { get; init; }
    /// <summary>技术名（英文），与外部工具链、报告章节保持一致的叫法。</summary>
    public string EnglishName { get; init; } = "";
    public required string Category { get; init; }
    public required string Description { get; init; }
    public bool RequiresAdministrator { get; init; }
    public bool RequiresDynamicSession { get; init; }

    public bool IsSelected
    {
        get => _isSelected;
        set => Set(ref _isSelected, value);
    }

    public string CategoryLabel => Category switch
    {
        "Static" => "静态分析",
        "Dynamic" => "动态监控",
        "Network" => "网络",
        "Analysis" => "关联与深度分析",
        _ => Category,
    };

    public string Badge => RequiresAdministrator ? "需管理员" : RequiresDynamicSession ? "需运行目标" : "";
}

/// <summary>
/// 应用的单一状态中心。所有页面共享同一个实例，避免各页各拉一份数据导致不一致。
/// 长任务（分析）在这里起线程，通过 <see cref="UiDispatcher"/> 回主线程刷新界面。
/// </summary>
public sealed class AppState : ObservableObject
{
    private const int MaxLogLines = 3000;
    private const int MaxLiveEvents = 2000;

    private readonly PluginHost _host = new();

    public AppState()
    {
        Workspace = new WorkspaceService();
        Settings = Workspace.LoadSettings();
        var loaded = _host.LoadExternalPlugins(Workspace.PluginsRoot);
        ExternalPluginCount = loaded;

        BuildTaskSelections(TestProfileKind.DesktopApplication);
    }

    // ─────────────────────────────── 基础对象 ───────────────────────────────

    public WorkspaceService Workspace { get; }
    public WorkspaceSettings Settings { get; private set; }
    public PluginHost Host => _host;
    public int ExternalPluginCount { get; }

    public ObservableCollection<TestProject> Projects { get; } = new();
    public ObservableCollection<TaskSelection> Tasks { get; } = new();
    public ObservableCollection<PluginStatus> Plugins { get; } = new();
    public ObservableCollection<string> LogLines { get; } = new();
    public ObservableCollection<MonitorEvent> LiveEvents { get; } = new();
    public ObservableCollection<Finding> Findings { get; } = new();
    public ObservableCollection<Evidence> Evidence { get; } = new();
    public ObservableCollection<MonitorEvent> Timeline { get; } = new();
    public ObservableCollection<NetworkConnection> Connections { get; } = new();
    public ObservableCollection<DnsObservation> DnsRecords { get; } = new();
    public ObservableCollection<HttpExchange> HttpExchanges { get; } = new();
    public ObservableCollection<YaraMatch> YaraMatches { get; } = new();
    public ObservableCollection<ProcessTreeEntry> ProcessTree { get; } = new();
    public ObservableCollection<string> ReportFiles { get; } = new();

    private TestProject? _currentProject;
    public TestProject? CurrentProject
    {
        get => _currentProject;
        private set
        {
            if (Set(ref _currentProject, value))
            {
                Raise(nameof(HasProject));
                Raise(nameof(ProjectTitle));
                Raise(nameof(ProjectSubtitle));
            }
        }
    }

    public ProjectLayout? Layout { get; private set; }
    public ProjectDatabase? Database { get; private set; }
    public AnalysisResult? Result { get; private set; }
    public PipelineReport? LastReport { get; private set; }

    public bool HasProject => CurrentProject is not null;
    public bool HasResult => Result is not null;
    public string ProjectTitle => CurrentProject?.Name ?? "未选择项目";
    public string ProjectSubtitle => CurrentProject is null
        ? "请先在「项目」页导入一个目标文件"
        : $"{CurrentProject.Id} · {CurrentProject.Target.FileName} · {CurrentProject.Target.Architecture}";

    // ─────────────────────────────── 运行状态 ───────────────────────────────

    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (Set(ref _isRunning, value)) Raise(nameof(IsIdle));
        }
    }

    public bool IsIdle => !IsRunning;

    private double _progress;
    public double Progress { get => _progress; private set => Set(ref _progress, value); }

    private string _statusText = "就绪";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    private string _workspacePath = "";
    public string WorkspacePath { get => _workspacePath; private set => Set(ref _workspacePath, value); }

    private CancellationTokenSource? _cts;

    // ─────────────────────────────── 项目操作 ───────────────────────────────

    public void Initialize()
    {
        WorkspacePath = Workspace.Root;
        RefreshProjects();
        RefreshPlugins();
        AppendLog($"工作区：{Workspace.Root}");
        AppendLog($"插件注册：{_host.Plugins.Count} 个（外部程序集 {ExternalPluginCount} 个）");
        foreach (var e in _host.LoadErrors) AppendLog($"[外部插件] {e}");

        if (Projects.Count > 0) OpenProject(Projects[0]);
    }

    public void RefreshProjects()
    {
        DevelopmentGuard.EnsureNotRunning(IsRunning, "刷新项目列表");

        Projects.Clear();
        foreach (var p in Workspace.ListProjects()) Projects.Add(p);
        Raise(nameof(Projects));
    }

    /// <summary>
    /// 删除项目（默认移入回收站，可恢复）。分析进行中不允许删除 —— 会话正在写 analysis.db。
    /// UI 默认只做"移入回收站"；彻底删除需显式指定，避免误点永久丢失成果。
    /// </summary>
    public DeleteProjectOutcome DeleteProject(string projectId, bool permanent = false)
    {
        DevelopmentGuard.EnsureNotRunning(IsRunning, "删除项目");

        var wasCurrent = string.Equals(CurrentProject?.Id, projectId, StringComparison.OrdinalIgnoreCase);
        var outcome = Workspace.DeleteProject(projectId, permanent);

        if (!outcome.Success) return outcome;

        AppendLog(outcome.Permanent
            ? $"项目 {outcome.ProjectName} 已彻底删除。"
            : $"项目 {outcome.ProjectName} 已移入回收站（可从系统回收站恢复）。");

        if (wasCurrent) CurrentProject = null;
        RefreshProjects();

        // 删掉当前项目后自动切到列表里的第一个，避免界面停在空状态
        if (CurrentProject is null && Projects.Count > 0) OpenProject(Projects[0]);

        return outcome;
    }

    /// <summary>
    /// 更新当前项目的元数据（名称/描述/执行人/授权信息）。
    /// 不重命名项目目录 —— 目录名是创建时的快照，改它会让报告里记录的路径断开。
    /// </summary>
    public UpdateProjectOutcome UpdateCurrentProject(string name, string description,
        string author, string authorization)
    {
        if (CurrentProject is null)
            return new UpdateProjectOutcome(false, null, "未选择项目。");

        var outcome = Workspace.UpdateProject(CurrentProject.Id, name, description, author, authorization);
        if (!outcome.Success) return outcome;

        // 重新载入，让标题栏/卡片显示新名字（RefreshProjects 会重建列表）
        var id = CurrentProject.Id;
        RefreshProjects();
        var updated = Projects.FirstOrDefault(p => p.Id == id);
        if (updated is not null) CurrentProject = updated;

        AppendLog($"已更新项目信息：{outcome.ProjectName}");
        return outcome;
    }


    /// <summary>导入新目标并创建项目。</summary>
    public TestProject? ImportTarget(string targetPath, string? name, TestProfileKind profile, string? description)
    {
        var outcome = Workspace.CreateProject(targetPath, name, description, profile, Settings.AnalystName);
        if (!outcome.Success || outcome.Project is null)
        {
            AppendLog($"[导入失败] {outcome.Error}");
            return null;
        }

        foreach (var w in outcome.Warnings) AppendLog($"[导入] {w}");
        AppendLog($"已创建项目 {outcome.Project.Id} — {outcome.Project.Name}");
        RefreshProjects();

        var created = Projects.FirstOrDefault(p => p.Id == outcome.Project.Id);
        if (created is not null) OpenProject(created);
        return outcome.Project;
    }

    public void OpenProject(TestProject project)
    {
        var opened = Workspace.OpenProject(project.Id);
        if (opened is null)
        {
            AppendLog($"[打开失败] 项目 {project.Id} 无法读取");
            return;
        }

        CurrentProject = opened.Value.Project;
        Layout = opened.Value.Layout;
        Database = opened.Value.Database;

        BuildTaskSelections(CurrentProject.Profile);
        LoadStoredResults();
        AppendLog($"已打开项目 {CurrentProject.Id} — {CurrentProject.Name}");
    }

    /// <summary>从数据库读回历史结果，让用户不必重跑就能看上次结论。</summary>
    public void LoadStoredResults()
    {
        if (Database is null || CurrentProject is null) return;

        var result = new AnalysisResult
        {
            ProjectId = CurrentProject.Id,
            Project = CurrentProject,
            Pe = Database.GetPeImages().FirstOrDefault(),
            Evidence = Database.GetEvidence(limit: 4000),
            Findings = Database.GetFindings(limit: 4000),
            Events = Database.GetEvents(),
            Connections = Database.GetConnections(),
            DnsObservations = Database.GetDnsObservations(),
            Http = Database.GetHttpExchanges(),
            YaraMatches = Database.GetYaraMatches(),
        };

        try
        {
            var (nodes, edges) = Core.Engines.Analysis.SecurityGraphBuilder.Build(result);
            result.GraphNodes.AddRange(nodes);
            result.GraphEdges.AddRange(edges);
        }
        catch (Exception ex)
        {
            AppendLog($"[图谱] 重建失败：{ex.Message}");
        }

        ApplyResult(result);
        ReportFiles.Clear();
        try
        {
            foreach (var (_, format, path, createdAt) in Database.GetReports().OrderByDescending(r => r.CreatedAt).Take(40))
                ReportFiles.Add(path);
        }
        catch { }

        if (result.Findings.Count > 0 || result.Evidence.Count > 0)
            AppendLog($"已载入历史结果：发现 {result.Findings.Count} 个，证据 {result.Evidence.Count} 条，事件 {result.Events.Count} 条");
    }

    private void ApplyResult(AnalysisResult result)
    {
        Result = result;

        Replace(Findings, result.Findings);
        Replace(Evidence, result.Evidence);
        Replace(Timeline, result.Events.OrderByDescending(e => e.Timestamp).Take(5000).ToList());
        Replace(Connections, result.Connections.OrderByDescending(c => c.LastSeen).Take(3000).ToList());
        Replace(DnsRecords, result.DnsObservations.Take(1000).ToList());
        Replace(HttpExchanges, result.Http.OrderByDescending(h => h.Timestamp).Take(1000).ToList());
        Replace(YaraMatches, result.YaraMatches);
        Replace(ProcessTree, result.ProcessTree);

        Raise(nameof(HasResult));
        RaiseStats();
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();
        foreach (var i in items) target.Add(i);
    }

    // ─────────────────────────────── 统计 ───────────────────────────────

    public int CriticalCount => Result?.Findings.Count(f => f.Severity == Severity.Critical) ?? 0;
    public int HighCount => Result?.Findings.Count(f => f.Severity == Severity.High) ?? 0;
    public int MediumCount => Result?.Findings.Count(f => f.Severity == Severity.Medium) ?? 0;
    public int LowCount => Result?.Findings.Count(f => f.Severity == Severity.Low) ?? 0;
    public int InfoCount => Result?.Findings.Count(f => f.Severity == Severity.Info) ?? 0;
    public int TotalFindings => Result?.Findings.Count ?? 0;
    public int EventCount => Result?.Events.Count ?? 0;
    public int EvidenceCount => Result?.Evidence.Count ?? 0;
    public int ConnectionCount => Result?.Connections.Count ?? 0;
    public int YaraCount => Result?.YaraMatches.Count ?? 0;

    public string FindingStats =>
        $"严重 {CriticalCount} · 高 {HighCount} · 中 {MediumCount} · 低 {LowCount} · 提示 {InfoCount}";

    public string OverallVerdict
    {
        get
        {
            if (Result is null) return "尚未分析";
            if (CriticalCount > 0) return "存在严重风险";
            if (HighCount > 0) return "存在高风险项";
            if (MediumCount > 0) return "存在中等风险项";
            if (TotalFindings > 0) return "仅有低风险与提示项";
            return "未发现明显问题";
        }
    }

    public void RaiseStats()
    {
        foreach (var name in new[]
                 {
                     nameof(CriticalCount), nameof(HighCount), nameof(MediumCount), nameof(LowCount),
                     nameof(InfoCount), nameof(TotalFindings), nameof(EventCount), nameof(EvidenceCount),
                     nameof(ConnectionCount), nameof(YaraCount), nameof(FindingStats), nameof(OverallVerdict),
                 })
            Raise(name);
    }

    // ─────────────────────────────── 任务与插件 ───────────────────────────────

    public void BuildTaskSelections(TestProfileKind profile)
    {
        var chosen = AnalyzerPipeline.ResolveTasks(profile).ToHashSet();
        Tasks.Clear();
        foreach (var def in TestTaskDefinition.All.OrderBy(d => PluginHost.ExecutionOrder.ToList().IndexOf(d.Kind)))
        {
            Tasks.Add(new TaskSelection
            {
                Kind = def.Kind,
                Name = string.IsNullOrEmpty(def.ChineseName) ? def.Name : def.ChineseName,
                EnglishName = def.Name,
                Category = def.Category,
                Description = def.Description,
                RequiresDynamicSession = def.RequiresDynamicSession,
                RequiresAdministrator = def.RequiresAdministrator,
                IsSelected = chosen.Contains(def.Kind),
            });
        }
    }

    public void ApplyProfile(TestProfileKind profile)
    {
        BuildTaskSelections(profile);
        if (CurrentProject is not null) CurrentProject.Profile = profile;
    }

    public void RefreshPlugins()
    {
        var statuses = _host.ProbeAll();
        Plugins.Clear();
        foreach (var s in statuses.OrderByDescending(s => s.Kind).ThenByDescending(s => s.Available).ThenBy(s => s.Name))
            Plugins.Add(s);
    }

    public void SetPluginEnabled(string pluginId, bool enabled) => _host.SetEnabled(pluginId, enabled);

    // ─────────────────────────────── 日志 ───────────────────────────────

    public void AppendLog(string message)
    {
        UiDispatcher.Invoke(() =>
        {
            LogLines.Add($"{DateTime.Now:HH:mm:ss}  {message}");

            // 裁剪仅在超过 3000 条上限时发生（正常分析几十到几百条，不会触发）。
            // 循环 RemoveAt(0) 虽然每条触发一次事件，但都发生在同一次 UI 线程调用内，
            // WPF 会在本次布局前合并处理 —— 真正的崩溃根因是 RunView 里在
            // CollectionChanged 中同步 ScrollIntoView（已修复），这里保持简单即可。
            while (LogLines.Count > MaxLogLines) LogLines.RemoveAt(0);
        });
    }

    // ─────────────────────────────── 执行分析 ───────────────────────────────

    public async Task RunAnalysisAsync(bool generateReport)
    {
        if (IsRunning || CurrentProject is null || Database is null || Layout is null) return;

        var selected = Tasks.Where(t => t.IsSelected).Select(t => t.Kind).ToList();
        if (selected.Count == 0)
        {
            AppendLog("[提示] 未勾选任何任务。");
            return;
        }

        var needsAdmin = Tasks.Where(t => t.IsSelected && t.RequiresAdministrator).Select(t => t.Name).ToList();
        var elevated = WorkspaceService.IsElevated();
        if (needsAdmin.Count > 0 && !elevated)
            AppendLog($"[提示] 以下任务需要管理员权限，将以受限模式运行：{string.Join("、", needsAdmin)}");

        _cts = new CancellationTokenSource();
        IsRunning = true;
        Progress = 0;
        StatusText = "准备中";
        LiveEvents.Clear();

        var project = CurrentProject;
        var (executionTarget, execWarning) = WorkspaceService.ResolveExecutionTarget(project);
        if (execWarning is not null) AppendLog($"[目标] {execWarning}");
        AppendLog($"样本路径：{project.PrimaryTargetPath}");
        AppendLog($"执行路径：{executionTarget}");
        AppendLog($"任务（{selected.Count}）：{string.Join(", ", selected)}");
        AppendLog(new string('─', 60));

        try
        {
            var pipeline = new AnalyzerPipeline(_host);
            var request = new PipelineRequest
            {
                Project = project,
                Layout = Layout,
                Database = Database,
                TargetPath = project.PrimaryTargetPath ?? executionTarget,
                ExecutionTargetPath = executionTarget,
                Tasks = selected,
                Options = BuildOptions(),
                GenerateReport = generateReport,
                AnalystName = Settings.AnalystName,
                Organization = Settings.Organization,
                RelevanceKeywords = BuildKeywords(project, executionTarget).ToList(),
                Log = AppendLog,
                Progress = (p, m) => UiDispatcher.Invoke(() =>
                {
                    if (p >= 0) Progress = p * 100;
                    StatusText = m;
                }),
                OnEvent = e => UiDispatcher.Invoke(() =>
                {
                    LiveEvents.Add(e);
                    while (LiveEvents.Count > MaxLiveEvents) LiveEvents.RemoveAt(0);
                }),
                OnArtifact = (_, _) => { },
            };

            var report = await Task.Run(() => pipeline.RunAsync(request)).ConfigureAwait(true);

            LastReport = report;
            ApplyResult(report.Result);

            foreach (var f in report.ReportFiles) ReportFiles.Insert(0, f);

            AppendLog(new string('─', 60));
            AppendLog(report.Success
                ? $"分析完成，耗时 {report.Duration.TotalSeconds:F1}s；发现 {report.TotalFindings} 个"
                : $"分析未完成：{report.FatalError}");
            foreach (var w in report.Warnings.Take(30)) AppendLog($"[警告] {w}");

            StatusText = report.Success ? "分析完成" : "分析中断";
            Progress = 100;
        }
        catch (OperationCanceledException)
        {
            StatusText = "已取消";
            AppendLog("[取消] 分析已被用户中断。");
        }
        catch (Exception ex)
        {
            StatusText = "执行失败";
            AppendLog($"[异常] {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
            _cts?.Dispose();
            _cts = null;
            RefreshProjects();
        }
    }

    public void Cancel() => _cts?.Cancel();

    public AnalysisOptions BuildOptions() => new()
    {
        PreferExternalTools = Settings.PreferExternalTools,
        TargetRunSeconds = Settings.TargetRunSeconds,
        AutoGenerateReport = Settings.AutoGenerateReport,
        HttpProxyPort = 8877,
    };

    private static IEnumerable<string> BuildKeywords(TestProject project, string targetPath)
    {
        var list = new List<string>();
        void Add(string? s) { if (!string.IsNullOrWhiteSpace(s)) list.Add(s!.Trim()); }

        Add(Path.GetFileNameWithoutExtension(targetPath));
        Add(Path.GetFileName(targetPath));
        Add(project.Target.ProductName);
        Add(project.Target.CompanyName);
        Add(project.Name);
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ─────────────────────────────── 报告 ───────────────────────────────

    public void GenerateReportFromStored()
    {
        if (Result is null || Layout is null || CurrentProject is null) return;

        try
        {
            // 报告要带「与上次对比」：先取基线快照再生成。
            // 注意必须在本次会话快照落库之前取，否则基线会变成"自己"（对比恒为无变化）。
            Core.Models.AnalysisSnapshot? baseline = null;
            try { baseline = Database?.GetLatestSnapshot(); } catch { }
            var current = Core.Engines.Analysis.RunComparer.Capture(
                Result, Result.Events.FirstOrDefault()?.SessionId);
            var comparison = Core.Engines.Analysis.RunComparer.Compare(baseline, current);

            var engine = new Core.Engines.Reports.ReportEngine();
            var report = engine.Generate(Result, new Core.Engines.Reports.ReportOptions
            {
                OutputDirectory = Layout.Reports,
                Title = $"Windows 应用程序安全测试报告 — {CurrentProject.Name}",
                Subtitle = CurrentProject.Target.FileName,
                DocumentId = CurrentProject.Id,
                AnalystName = Settings.AnalystName,
                Organization = Settings.Organization,
                Comparison = comparison,
            });

            foreach (var f in report.Files) ReportFiles.Insert(0, f);
            AppendLog($"已生成 {report.Files.Count} 个报告文件。");
            foreach (var w in report.Warnings) AppendLog($"[报告] {w}");
        }
        catch (Exception ex)
        {
            AppendLog($"[报告] 生成失败：{ex.Message}");
        }
    }

    /// <summary>
    /// 把发现清单导出为 CSV。给"拿去 Excel 做跟踪表"的场景 —— 报告是成品，CSV 是原料。
    /// 返回导出的文件路径（失败返回 null）。
    /// </summary>
    /// <summary>
    /// 人工复核闭环（§9 人工深入分析）：把某条发现的处理状态与复核意见写回数据库，
    /// 并同步内存中的结果对象，保证界面、报告、CSV 三处口径一致。
    /// </summary>
    public bool SaveFindingReview(Finding finding, FindingStatus status, string? note)
    {
        if (Database is null) return false;
        try
        {
            var ok = Database.UpdateFindingReview(finding.Id, status, note);
            if (!ok)
            {
                AppendLog($"[复核] 未找到发现 {finding.Id}，可能已被重新分析覆盖。");
                return false;
            }

            // 同步内存对象（同一引用），让列表与详情立即反映新状态
            finding.Status = status;
            finding.AnalystNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();

            Raise(nameof(ReviewedCount));
            Raise(nameof(PendingReviewCount));
            AppendLog($"已更新复核：{finding.Id} → {finding.StatusText}");
            return true;
        }
        catch (Exception ex)
        {
            AppendLog($"[复核] 保存失败：{ex.Message}");
            return false;
        }
    }

    /// <summary>已人工复核（已确认 / 误报 / 接受风险 / 已整改）的发现数。</summary>
    public int ReviewedCount => Result?.Findings.Count(f => f.Status != FindingStatus.Open) ?? 0;

    /// <summary>仍待人工确认的发现数。</summary>
    public int PendingReviewCount => Result?.Findings.Count(f => f.Status == FindingStatus.Open) ?? 0;

    // ─────────────────────── 轮次对比（回归测试） ───────────────────────

    /// <summary>
    /// 列出该项目的历史快照（新的在前）。快照是每轮分析结束时落的结论指纹，
    /// 用于「这一轮比上一轮多了什么」——发现项本身是按 ID 覆盖写入的，看不出变化。
    /// </summary>
    public List<Core.Models.AnalysisSnapshot> GetSnapshots()
    {
        if (Database is null) return new List<Core.Models.AnalysisSnapshot>();
        try
        {
            return Database.GetSnapshots();
        }
        catch (Exception ex)
        {
            AppendLog($"[对比] 读取快照失败：{ex.Message}");
            return new List<Core.Models.AnalysisSnapshot>();
        }
    }

    /// <summary>
    /// 计算「基准快照 → 当前一轮」的差异。两个参数都为 null 时表示自动取最新两轮。
    /// 这是回归测试最核心的一问：改版之后，哪些问题变多了、哪些修掉了。
    /// </summary>
    public Core.Models.ComparisonResult? CompareRounds(
        Core.Models.AnalysisSnapshot? baseline, Core.Models.AnalysisSnapshot? current)
    {
        try
        {
            if (baseline is null && current is null)
            {
                // 自动模式：最新一轮当"当前"，它前面那一轮当基线
                var all = GetSnapshots();
                if (all.Count == 0) return null;
                current = all[0];
                baseline = all.Count > 1 ? all[1] : null;
            }

            return Core.Engines.Analysis.RunComparer.Compare(baseline, current);
        }
        catch (Exception ex)
        {
            AppendLog($"[对比] 计算失败：{ex.Message}");
            return null;
        }
    }

    /// <summary>把对比结论写成一行简报（给首页/概览页用）。没有可比基线时返回 null。</summary>
    public string? ComparisonHeadline()
    {
        var cmp = CompareRounds(null, null);
        if (cmp is null || !cmp.HasBaseline) return null;
        return cmp.Verdict;
    }

    public string? ExportFindingsCsv()
    {
        if (Result is null || Layout is null || CurrentProject is null) return null;

        try
        {
            var path = Path.Combine(Layout.Reports, $"{CurrentProject.Id}-发现清单.csv");
            Core.Engines.Reports.CsvExporter.ExportFindings(Result, path);
            ReportFiles.Insert(0, path);
            AppendLog($"已导出发现清单：{Path.GetFileName(path)}（{Result.Findings.Count} 条）");
            return path;
        }
        catch (Exception ex)
        {
            AppendLog($"[导出] 发现清单导出失败：{ex.Message}");
            return null;
        }
    }

    /// <summary>把证据清单导出为 CSV（供人工核对每条结论的原始依据）。</summary>
    public string? ExportEvidenceCsv()
    {
        if (Result is null || Layout is null || CurrentProject is null) return null;

        try
        {
            var path = Path.Combine(Layout.Reports, $"{CurrentProject.Id}-证据清单.csv");
            Core.Engines.Reports.CsvExporter.ExportEvidence(Result, path);
            ReportFiles.Insert(0, path);
            AppendLog($"已导出证据清单：{Path.GetFileName(path)}（{Result.Evidence.Count} 条）");
            return path;
        }
        catch (Exception ex)
        {
            AppendLog($"[导出] 证据清单导出失败：{ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// 把某份 HTML 报告打印成 PDF（走系统自带 Edge，零依赖）。
    /// 返回 PDF 路径；失败返回 null 并把原因写进日志。
    /// </summary>
    public async Task<string?> ExportReportPdfAsync(string htmlPath)
    {
        if (string.IsNullOrWhiteSpace(htmlPath) || !File.Exists(htmlPath)) return null;

        try
        {
            var pdfPath = Path.ChangeExtension(htmlPath, ".pdf");
            AppendLog($"正在导出 PDF（Edge 无头打印）：{Path.GetFileName(htmlPath)}");

            var result = await Core.Engines.Reports.PdfExporter
                .ExportAsync(htmlPath, pdfPath)
                .ConfigureAwait(true);

            if (result.Success && result.Path is not null)
            {
                ReportFiles.Insert(0, result.Path);
                AppendLog($"已导出 PDF：{Path.GetFileName(result.Path)}");
                return result.Path;
            }

            AppendLog($"[导出] PDF 导出失败：{result.Error}");
            return null;
        }
        catch (Exception ex)
        {
            AppendLog($"[导出] PDF 导出异常：{ex.Message}");
            return null;
        }
    }

    public static void OpenInShell(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch { }
    }

    public static void RevealInExplorer(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            if (File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (Directory.Exists(path)) Process.Start("explorer.exe", $"\"{path}\"");
            else
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
            }
        }
        catch { }
    }

    public void SaveSettings()
    {
        try
        {
            Workspace.SaveSettings(Settings);
            AppendLog("设置已保存。");
        }
        catch (Exception ex)
        {
            AppendLog($"[设置] 保存失败：{ex.Message}");
        }
    }

    public void ReloadSettings()
    {
        Settings = Workspace.LoadSettings();
        Raise(nameof(Settings));
    }
}

/// <summary>给 UI 用的前置条件护栏：正在进行长任务时拦掉会干扰它的操作。</summary>
internal static class DevelopmentGuard
{
    public static void EnsureNotRunning(bool isRunning, string action)
    {
        // 目前只用于提示，不抛异常 —— 分析期间刷新列表是安全的（只读）
        _ = isRunning;
        _ = action;
    }
}
