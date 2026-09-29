using System.Diagnostics;
using System.Runtime.Versioning;
using WinSecLab.Core.Engines.Network;
using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins;
using WinSecLab.Core.Storage;

namespace WinSecLab.Core.Engines.Dynamic;

/// <summary>
/// §4 动态分析中心的主控。
/// 一次会话 = 建立基线 → 启动监控 → 启动目标 → 采集 → 停止目标 → 收尾落盘。
/// 所有事件统一进入 <see cref="MonitorEvent"/> 管道，同时实时落 SQLite，避免长会话丢数据。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DynamicSession : IDisposable
{
    private readonly ProjectDatabase _database;
    private readonly List<MonitorEvent> _buffer = new();
    private readonly object _bufferLock = new();
    private readonly List<ProcessTreeEntry> _processTree = new();
    private readonly List<NetworkConnection> _connections = new();
    private readonly List<DnsObservation> _dns = new();
    private readonly List<HttpExchange> _http = new();
    private readonly List<string> _warnings = new();
    private readonly List<string> _artifacts = new();

    private ProcessMonitor? _processMonitor;
    private FileMonitor? _fileMonitor;
    private RegistryMonitor? _registryMonitor;
    private NetworkMonitor? _networkMonitor;
    private HttpProxyServer? _proxy;
    private Process? _targetProcess;
    private Timer? _flushTimer;
    private Timer? _connectionSyncTimer;
    private int _flushInProgress;
    private long _droppedEvents;

    public AnalysisSession Session { get; }
    public string ProjectId { get; }
    public List<MonitorEvent> LiveBuffer
    {
        get
        {
            lock (_bufferLock) return _buffer.ToList();
        }
    }

    public IReadOnlyList<MonitorEvent> RecentEvents { get; }
    public IReadOnlyList<string> Warnings => _warnings;
    public IReadOnlyList<string> Artifacts => _artifacts;
    public IReadOnlyList<HttpExchange> HttpHistory => _http;
    public HttpProxyServer? Proxy => _proxy;
    public bool IsRunning { get; private set; }

    /// <summary>事件产生时触发（UI 实时刷新用）。</summary>
    public event Action<MonitorEvent>? EventPublished;

    /// <summary>进度回调。</summary>
    public event Action<double, string>? ProgressChanged;

    private readonly List<MonitorEvent> _recent = new();
    private const int RecentCapacity = 4000;

    public DynamicSession(string projectId, ProjectDatabase database, AnalysisSession session)
    {
        ProjectId = projectId;
        _database = database;
        Session = session;
        RecentEvents = _recent;
    }

    public bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>启动会话。</summary>
    /// <param name="targetPath">被测程序路径，null 表示只监控不启动。</param>
    /// <param name="tasks">用户勾选的任务集合。</param>
    /// <param name="options">运行参数。</param>
    /// <param name="relevanceKeywords">文件 / 注册表相关性关键词（程序名、产品名、公司名等）。</param>
    public async Task<bool> StartAsync(string? targetPath, IReadOnlyCollection<TestTaskKind> tasks,
        AnalysisOptions options, IEnumerable<string> relevanceKeywords, CancellationToken token = default)
    {
        var elevated = IsAdministrator();
        Session.Phase = SessionPhase.Preparing;
        ProgressChanged?.Invoke(0.02, "准备测试环境");

        var keywords = relevanceKeywords.Where(k => !string.IsNullOrWhiteSpace(k)).Distinct().ToList();
        var dynamicTasks = tasks.Where(IsDynamicTask).ToHashSet();
        if (dynamicTasks.Count == 0)
        {
            Session.Phase = SessionPhase.Failed;
            Session.FailureReason = "本次未勾选任何需要动态会话的任务";
            return false;
        }

        // ---------------------------------------------------------- 1) 进程监控
        if (dynamicTasks.Contains(TestTaskKind.ProcessMonitor))
        {
            _processMonitor = new ProcessMonitor(pollIntervalMs: 1000, trackModules: true);
            _processMonitor.OnEvent = Publish;
        }

        // ---------------------------------------------------------- 2) 注册表监控
        if (dynamicTasks.Contains(TestTaskKind.RegistryMonitor))
        {
            _registryMonitor = new RegistryMonitor { ScanIntervalMs = 4000 };
            _registryMonitor.SetRelevanceKeywords(keywords);
            RegistryMonitor.AddDefaultTargets(_registryMonitor);
            _registryMonitor.OnEvent = Publish;
        }

        // ---------------------------------------------------------- 3) 文件监控
        if (dynamicTasks.Contains(TestTaskKind.FileMonitor))
        {
            _fileMonitor = new FileMonitor();
            _fileMonitor.SetRelevanceKeywords(keywords);
            if (targetPath is not null) _fileMonitor.AddTargetDirectory(Path.GetDirectoryName(targetPath));
        }

        // ---------------------------------------------------------- 4) 网络监控
        if (dynamicTasks.Contains(TestTaskKind.NetworkCapture))
        {
            _networkMonitor = new NetworkMonitor { PollIntervalMs = options.ConnectionPollIntervalMs };
            _networkMonitor.OnConnection += c =>
            {
                lock (_connectionLock) _connections.Add(c);
            };
            _networkMonitor.OnDns += d =>
            {
                lock (_connectionLock) _dns.Add(d);
            };
            _networkMonitor.OnEvent = Publish;
        }

        // ---------------------------------------------------------- 5) HTTP 代理
        if (dynamicTasks.Contains(TestTaskKind.HttpProxy))
        {
            _proxy = new HttpProxyServer(options.HttpProxyPort);
            _proxy.OnExchange += x =>
            {
                lock (_connectionLock) _http.Add(x);
            };
            _proxy.OnEvent = Publish;
        }

        // ------------------------------------------------- 6) 建立基线（必须先于目标启动）
        ProgressChanged?.Invoke(0.08, "采集注册表基线");
        try
        {
            _registryMonitor?.CaptureBaseline();
        }
        catch (Exception ex)
        {
            _warnings.Add($"注册表基线采集失败：{ex.Message}");
        }

        Session.StartedAt = DateTime.Now;

        // ---------------------------------------------------------- 7) 启动监控
        ProgressChanged?.Invoke(0.14, "启动监控通道");
        if (_registryMonitor is not null)
        {
            _registryMonitor.Start(tryWmi: true);
            if (!_registryMonitor.WmiActive && !elevated)
                _warnings.Add("注册表 WMI 事件通道未启用（需要管理员权限），当前使用快照差分，事件时间精度为扫描间隔。");
        }

        if (_fileMonitor is not null)
        {
            var roots = options.FileWatchRoots.Count > 0 ? options.FileWatchRoots : FileMonitor.DefaultRoots();
            if (targetPath is not null) roots.Insert(0, Path.GetDirectoryName(targetPath)!);
            _fileMonitor.Start(roots);
            if (_fileMonitor.ActiveRoots.Count == 0)
                _warnings.Add("文件监控未挂载任何可用的监控根目录。");
        }

        if (_proxy is not null)
        {
            _proxy.Start();
            if (!_proxy.IsRunning)
            {
                _warnings.Add(_proxy.LastError ?? "HTTP 代理启动失败。");
                _proxy = null;
            }
            else
            {
                _warnings.Add($"HTTP 代理已监听 127.0.0.1:{_proxy.Port}。需将被测程序的系统代理指向该地址才能捕获明文 HTTP。");
            }
        }

        // ---------------------------------------------------------- 8) 启动目标
        if (targetPath is not null)
        {
            ProgressChanged?.Invoke(0.22, "启动被测程序");
            try
            {
                var psi = new ProcessStartInfo(targetPath)
                {
                    UseShellExecute = true,
                    WorkingDirectory = Path.GetDirectoryName(targetPath) ?? Environment.CurrentDirectory,
                };
                _targetProcess = Process.Start(psi);
                if (_targetProcess is null)
                {
                    _warnings.Add("目标进程启动失败（Process.Start 返回 null）。");
                }
            }
            catch (Exception ex)
            {
                Session.Phase = SessionPhase.Failed;
                Session.FailureReason = $"无法启动被测程序：{ex.Message}";
                _warnings.Add(Session.FailureReason);
                StopMonitors();
                return false;
            }
        }

        // ---------------------------------------------------------- 9) 绑定进程树
        if (_targetProcess is not null && _processMonitor is not null)
        {
            // 稍等一下让进程真正起来，避免拿到已退出的 PID
            await Task.Delay(400, token).ConfigureAwait(false);
            uint pid;
            try
            {
                pid = (uint)_targetProcess.Id;
                if (_targetProcess.HasExited)
                {
                    _warnings.Add($"被测程序在 {_targetProcess.ExitTime:HH:mm:ss} 就已退出（退出码 {_targetProcess.ExitCode}），本次会话采集到的动态行为有限。");
                    pid = 0;
                }
            }
            catch
            {
                pid = 0;
            }

            if (pid != 0)
            {
                Session.RootProcessId = pid;
                Session.LaunchedProcessPath = targetPath;
                _processMonitor.RegisterRootProcess(pid, targetPath);
                _processMonitor.Start(pid, elevated);
                if (!elevated)
                    _warnings.Add("未以管理员身份运行：进程创建事件退化为 1 秒轮询，可能漏掉极短命进程。");
                if (_processMonitor.IsDegraded)
                    _warnings.Add("进程快照（Toolhelp32）不可用，本次会话无法可靠建立进程父子关系。");
            }
            else
            {
                _processMonitor.Start(0, elevated);
            }

            WireAttribution();
        }
        else
        {
            _processMonitor?.Start(0, elevated);
            WireAttribution();
        }

        _networkMonitor?.Start();

        // ---------------------------------------------------------- 10) 落盘定时器
        _flushTimer = Util.SafeTimer.Create(FlushToDatabase, 2000, 2000,
            ex => _warnings.Add($"事件落盘出错（已忽略本次）：{ex.Message}"));
        _connectionSyncTimer = Util.SafeTimer.Create(SyncConnections, 3000, 3000,
            ex => _warnings.Add($"连接表同步出错（已忽略本次）：{ex.Message}"));

        Session.Phase = targetPath is null ? SessionPhase.Monitoring : SessionPhase.RunningTarget;
        Session.Tasks = tasks.ToList();
        IsRunning = true;
        Persist();
        ProgressChanged?.Invoke(0.3, "会话进行中，请在被测程序里执行需要观察的操作");

        Publish(new MonitorEvent
        {
            Type = MonitorEventType.SessionStart,
            Operation = "Session Start",
            Target = targetPath ?? "(仅监控)",
            Detail = $"已启用任务：{string.Join(", ", dynamicTasks)}；权限：{(elevated ? "管理员" : "标准用户")}",
            IsFromTargetTree = true,
            Source = "session",
        });

        return true;
    }

    public static bool IsDynamicTask(TestTaskKind kind) => kind is
        TestTaskKind.ProcessMonitor or TestTaskKind.FileMonitor or TestTaskKind.RegistryMonitor or
        TestTaskKind.NetworkCapture or TestTaskKind.HttpProxy or TestTaskKind.TlsAnalysis;

    /// <summary>
    /// 被测进程是否已经退出。编排器用它决定"提前收工"——
    /// 用户关掉被测程序后还死等满 targetRunSeconds 是纯浪费，也让报告里多出一段空白监控期。
    /// 仅监控模式（未启动目标）恒为 false，不会误触发提前结束。
    /// </summary>
    public bool ShouldStopEarly
    {
        get
        {
            if (_targetProcess is null) return false;
            try { return _targetProcess.HasExited; }
            catch { return false; }
        }
    }

    private readonly object _connectionLock = new();

    private void WireAttribution()
    {
        // 网络连接按 PID 精确归因；文件 / 注册表监控走路径与关键词归因，不依赖进程树
        if (_processMonitor is not null)
            _networkMonitor?.IsInTargetTree = _processMonitor.IsInTargetTree;
    }

    /// <summary>把事件同时推给内存缓冲、UI 与数据库。</summary>
    private void Publish(MonitorEvent e)
    {
        e.ProjectId = ProjectId;
        e.SessionId = Session.Id;

        lock (_bufferLock)
        {
            _buffer.Add(e);
            if (_buffer.Count > 8000) _buffer.RemoveRange(0, 4000);
        }

        lock (_recent)
        {
            _recent.Add(e);
            if (_recent.Count > RecentCapacity) _recent.RemoveRange(0, RecentCapacity / 2);
        }

        Session.EventCount++;
        EventPublished?.Invoke(e);
    }

    private void FlushToDatabase()
    {
        if (Interlocked.Exchange(ref _flushInProgress, 1) == 1) return;
        try
        {
            List<MonitorEvent> batch;
            lock (_bufferLock)
            {
                if (_buffer.Count == 0) return;
                batch = _buffer.ToList();
                _buffer.Clear();
            }

            _database.SaveEvents(batch);
        }
        catch (Exception ex)
        {
            _droppedEvents += 1;
            if (_warnings.Count < 40) _warnings.Add($"事件落盘失败：{ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _flushInProgress, 0);
        }
    }

    private void SyncConnections()
    {
        try
        {
            List<NetworkConnection> connections;
            List<DnsObservation> dns;
            List<HttpExchange> http;
            lock (_connectionLock)
            {
                connections = _connections.ToList();
                dns = _dns.ToList();
                http = _http.ToList();
            }

            if (connections.Count > 0) _database.SaveConnections(connections);
            if (dns.Count > 0) _database.SaveDnsObservations(dns);
            if (http.Count > 0) _database.SaveHttpExchanges(http);
        }
        catch (Exception ex)
        {
            if (_warnings.Count < 40) _warnings.Add($"网络数据落盘失败：{ex.Message}");
        }
    }

    /// <summary>结束会话：停止监控、按需结束目标、收尾落盘。</summary>
    public async Task StopAsync(AnalysisOptions options, CancellationToken token = default)
    {
        if (!IsRunning && Session.Phase is SessionPhase.Completed or SessionPhase.Cancelled) return;

        Session.Phase = SessionPhase.Finishing;
        ProgressChanged?.Invoke(0.9, "正在停止监控并收尾");

        // 目标还在跑就先结束它（避免会话结束后仍在改系统状态）
        if (options.KillTargetOnSessionEnd && _targetProcess is not null)
        {
            try
            {
                if (!_targetProcess.HasExited)
                {
                    _targetProcess.CloseMainWindow();
                    if (!await WaitForExitAsync(_targetProcess, 3000, token).ConfigureAwait(false))
                    {
                        _targetProcess.Kill(entireProcessTree: true);
                        await WaitForExitAsync(_targetProcess, 3000, token).ConfigureAwait(false);
                        _warnings.Add("被测程序未响应关闭请求，已强制结束进程树。");
                    }
                }
                Session.ExitCode = _targetProcess.HasExited ? _targetProcess.ExitCode : -1;
            }
            catch (Exception ex)
            {
                _warnings.Add($"结束被测程序时出错：{ex.Message}");
            }
        }

        StopMonitors();

        if (_processMonitor is not null)
            _processTree.AddRange(_processMonitor.SnapshotTree());

        FlushToDatabase();
        SyncConnections();

        Session.EndedAt = DateTime.Now;
        Session.Phase = SessionPhase.Completed;
        IsRunning = false;

        Publish(new MonitorEvent
        {
            Type = MonitorEventType.SessionStop,
            Operation = "Session Stop",
            Target = Session.LaunchedProcessPath ?? "(仅监控)",
            Detail = $"会话时长 {Session.Duration.TotalSeconds:F1}s，累计事件 {Session.EventCount} 条"
                     + (_processMonitor?.DroppedEvents > 0 ? $"，因缓冲上限丢弃 {_processMonitor.DroppedEvents} 条" : ""),
            IsFromTargetTree = true,
            Source = "session",
        });

        FlushToDatabase();
        Persist();
        ProgressChanged?.Invoke(1.0, "动态会话完成");
    }

    private static async Task<bool> WaitForExitAsync(Process process, int milliseconds, CancellationToken token)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(milliseconds);
        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private void StopMonitors()
    {
        _flushTimer?.Dispose();
        _flushTimer = null;
        _connectionSyncTimer?.Dispose();
        _connectionSyncTimer = null;

        try
        {
            _processMonitor?.Stop();
        }
        catch
        {
            // 忽略
        }

        try
        {
            _fileMonitor?.Stop();
        }
        catch
        {
            // 忽略
        }

        try
        {
            _registryMonitor?.Stop();
        }
        catch
        {
            // 忽略
        }

        try
        {
            _networkMonitor?.Stop();
        }
        catch
        {
            // 忽略
        }

        try
        {
            _proxy?.Stop();
        }
        catch
        {
            // 忽略
        }
    }

    /// <summary>导出会话产物到项目目录。</summary>
    public List<string> ExportArtifacts(ProjectLayout layout)
    {
        var written = new List<string>();
        Directory.CreateDirectory(layout.DynamicAnalysis);

        try
        {
            var events = _database.GetEvents(Session.Id, limit: 200_000);
            var path = Path.Combine(layout.DynamicAnalysis, $"events-{Session.Id}.jsonl");
            using var writer = new StreamWriter(path, false, System.Text.Encoding.UTF8);
            foreach (var e in events)
                writer.WriteLine(Serialization.WslJson.Serialize(e));
            written.Add(path);
            _database.SaveArtifact(Session.Id, "events", Path.GetFileName(path), path, new FileInfo(path).Length);
        }
        catch (Exception ex)
        {
            _warnings.Add($"事件流导出失败：{ex.Message}");
        }

        try
        {
            var tree = Path.Combine(layout.DynamicAnalysis, $"process-tree-{Session.Id}.json");
            File.WriteAllText(tree, Serialization.WslJson.Serialize(_processTree, true));
            written.Add(tree);
        }
        catch (Exception ex)
        {
            _warnings.Add($"进程树导出失败：{ex.Message}");
        }

        if (_http.Count > 0)
        {
            try
            {
                Directory.CreateDirectory(layout.Network);
                var httpPath = Path.Combine(layout.Network, $"http-history-{Session.Id}.json");
                File.WriteAllText(httpPath, Serialization.WslJson.Serialize(_http, true));
                written.Add(httpPath);
                _database.SaveArtifact(Session.Id, "http-history", Path.GetFileName(httpPath), httpPath,
                    new FileInfo(httpPath).Length);
            }
            catch (Exception ex)
            {
                _warnings.Add($"HTTP 历史导出失败：{ex.Message}");
            }
        }

        List<NetworkConnection> connections;
        lock (_connectionLock) connections = _connections.ToList();
        if (connections.Count > 0)
        {
            try
            {
                Directory.CreateDirectory(layout.Network);
                var connPath = Path.Combine(layout.Network, $"connections-{Session.Id}.json");
                File.WriteAllText(connPath, Serialization.WslJson.Serialize(connections, true));
                written.Add(connPath);
            }
            catch (Exception ex)
            {
                _warnings.Add($"连接表导出失败：{ex.Message}");
            }
        }

        _artifacts.AddRange(written);
        return written;
    }

    private void Persist()
    {
        try
        {
            _database.SaveSession(Session);
        }
        catch
        {
            // 会话落盘失败不阻塞收尾
        }
    }

    public IReadOnlyList<ProcessTreeEntry> ProcessTree
    {
        get
        {
            if (_processMonitor is not null && _processMonitor.SnapshotTree().Count > 0)
                return _processMonitor.SnapshotTree();
            return _processTree;
        }
    }

    public IReadOnlyList<NetworkConnection> Connections
    {
        get
        {
            lock (_connectionLock) return _connections.ToList();
        }
    }

    public IReadOnlyList<DnsObservation> DnsObservations
    {
        get
        {
            lock (_connectionLock) return _dns.ToList();
        }
    }

    public void Dispose()
    {
        StopMonitors();
        _processMonitor?.Dispose();
        _fileMonitor?.Dispose();
        _registryMonitor?.Dispose();
        _networkMonitor?.Dispose();
        _proxy?.Dispose();
    }
}
