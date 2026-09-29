using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Dynamic;

/// <summary>
/// §4/§5 进程监控。
/// 两条路径：优先用 WMI 的进程创建/退出事件（需要管理员，实时且不漏），
/// 拿不到权限时退化为 1 秒轮询 diff（无提权也能跑，但可能漏掉极短命进程）。
/// 进程树是后续所有归因判定（文件/注册表/网络归属）的基础。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessMonitor : IDisposable
{
    private readonly ConcurrentDictionary<uint, ProcNode> _nodes = new();
    private readonly int _pollIntervalMs;
    private bool _degraded;

    /// <summary>
    /// 分析器自身进程已加载的模块路径集合。
    ///
    /// 为什么必须有这个基线：分析器本身可能运行在带有代码注入的环境里
    /// （例如各类沙箱 / EDR / 应用虚拟化会把一个代理 DLL 注入到所有子进程）。
    /// 这类模块会出现在被测进程中，但它们来自分析环境而不是被测程序 ——
    /// 不加排除就会把环境噪声当成"DLL 劫持"高危急报。
    /// </summary>
    private readonly HashSet<string> _analyzerModules = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _trackModules;
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;
    private Timer? _pollTimer;
    private Timer? _moduleTimer;
    private readonly ConcurrentDictionary<uint, HashSet<string>> _knownModules = new();
    private volatile bool _wmiActive;
    private int _eventBudget = 100_000;
    private uint _rootPid;
    private long _sequence;

    public string Source { get; private set; } = "polling";
    public bool IsElevated { get; private set; }

    /// <summary>底层进程快照不可用（受限环境），本次会话的进程跟踪能力降级。</summary>
    public bool IsDegraded => _degraded;
    public long DroppedEvents { get; private set; }

    /// <summary>事件出口。返回 false 表示下游已饱和，监控端会丢弃事件。</summary>
    public Action<MonitorEvent>? OnEvent { get; set; }

    public ProcessMonitor(int pollIntervalMs = 1000, bool trackModules = true)
    {
        _pollIntervalMs = Math.Max(250, pollIntervalMs);
        _trackModules = trackModules;
    }

    private sealed class ProcNode
    {
        public uint Pid;
        public uint ParentPid;
        public string Name = "";
        public string? Path;
        public DateTime StartTime = DateTime.Now;
        public bool IsInTargetTree;
        public int Depth;
        public bool StopReported;
    }

    public void Start(uint rootPid, bool elevated)
    {
        _rootPid = rootPid;
        IsElevated = elevated;

        CaptureAnalyzerModuleBaseline();

        // 先把当前进程表整体灌入，得到正确父子关系
        SnapshotExistingProcesses();

        if (elevated)
        {
            _wmiActive = TryStartWmi();
            Source = _wmiActive ? "wmi-events" : "polling";
        }

        // WMI 事件也可能漏（如某些容器 / 受限环境），轮询同时作为兜底与补漏
        _pollTimer = Util.SafeTimer.Create(PollOnce, _pollIntervalMs, _pollIntervalMs);

        if (_trackModules)
            _moduleTimer = Util.SafeTimer.Create(PollModules, 2000, 2000);
    }

    /// <summary>把外部启动的根进程登记进树（Start 时它已经存在，WMI 事件不会再有）。</summary>
    public void RegisterRootProcess(uint pid, string processPath)
    {
        var node = new ProcNode
        {
            Pid = pid,
            ParentPid = 0,
            Name = Path.GetFileName(processPath),
            Path = processPath,
            StartTime = DateTime.Now,
            IsInTargetTree = true,
            Depth = 0,
        };
        _nodes[pid] = node;

        Publish(new MonitorEvent
        {
            Type = MonitorEventType.ProcessStart,
            ProcessId = pid,
            ProcessName = node.Name,
            ProcessPath = node.Path,
            Operation = "Process Start (root)",
            Target = node.Path ?? node.Name,
            IsFromTargetTree = true,
            Detail = $"被测目标根进程 pid={pid}",
            Source = Source,
        });
    }

    private bool TryStartWmi()
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();

            var startQuery = new WqlEventQuery(
                "SELECT * FROM Win32_ProcessStartTrace");
            _startWatcher = new ManagementEventWatcher(scope, startQuery);
            _startWatcher.EventArrived += (_, e) => OnWmiProcessEvent(e, start: true);
            _startWatcher.Start();

            var stopQuery = new WqlEventQuery(
                "SELECT * FROM Win32_ProcessStopTrace");
            _stopWatcher = new ManagementEventWatcher(scope, stopQuery);
            _stopWatcher.EventArrived += (_, e) => OnWmiProcessEvent(e, start: false);
            _stopWatcher.Start();
            return true;
        }
        catch (Exception)
        {
            try
            {
                _startWatcher?.Dispose();
                _stopWatcher?.Dispose();
            }
            catch
            {
                // 忽略清理失败
            }
            _startWatcher = null;
            _stopWatcher = null;
            return false;
        }
    }

    private void OnWmiProcessEvent(EventArrivedEventArgs e, bool start)
    {
        try
        {
            var pid = Convert.ToUInt32(e.NewEvent.Properties["ProcessID"].Value);
            var parentPid = Convert.ToUInt32(e.NewEvent.Properties["ParentProcessID"].Value);
            var name = e.NewEvent.Properties["ProcessName"].Value?.ToString() ?? "";

            if (start)
                HandleProcessStart(pid, parentPid, name, "wmi");
            else
                HandleProcessStop(pid, name);
        }
        catch
        {
            // 事件属性缺失（进程已退出），忽略
        }
    }

    /// <summary>记录分析器自身加载的模块，用于把"环境注入"从被测程序行为里剔除。</summary>
    private void CaptureAnalyzerModuleBaseline()
    {
        try
        {
            using var self = Process.GetCurrentProcess();
            foreach (ProcessModule module in self.Modules)
            {
                var path = module.FileName;
                if (!string.IsNullOrEmpty(path)) _analyzerModules.Add(path);
            }
        }
        catch
        {
            // 拿不到就退化为"不做排除"，不影响其它功能
        }
    }

    /// <summary>
    /// 一次性灌入当前进程表以获得正确的父子关系。
    /// 走 Toolhelp32 单次快照，不做逐进程 WMI 查询 —— 后者在几百进程的机器上
    /// 会产生几百次 WMI 往返，把会话启动拖到几十秒以上（实测踩过）。
    /// </summary>
    private void SnapshotExistingProcesses()
    {
        var snapshot = Util.ProcessSnapshot.Capture();
        if (snapshot.Count == 0)
        {
            _degraded = true;
            return;
        }

        foreach (var entry in snapshot)
        {
            if (entry.Pid == 0) continue;

            // 已经登记过的节点（尤其是 RegisterRootProcess 建立的根节点）不能被覆盖 ——
            // 否则根进程会丢掉路径、目标树标记和 depth，导致整个进程树归因失效。
            if (_nodes.ContainsKey(entry.Pid)) continue;

            _nodes[entry.Pid] = new ProcNode
            {
                Pid = entry.Pid,
                ParentPid = entry.ParentPid,
                Name = entry.Name,
                // 初始快照不解析模块路径：几百次 MainModule 查询同样很贵，
                // 而且这些进程不属于目标进程树，路径价值很低。目标进程的路径由 RegisterRootProcess 单独给出。
                Path = null,
                IsInTargetTree = false,
                Depth = -1,
            };
        }
    }

    private static string? SafeMainModule(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private void PollOnce()
    {
        try
        {
            var snapshot = Util.ProcessSnapshot.Capture();
            var alive = new HashSet<uint>(snapshot.Count);
            var pathBudget = 20;

            foreach (var entry in snapshot)
            {
                var pid = entry.Pid;
                if (pid == 0) continue;
                alive.Add(pid);

                if (!_nodes.ContainsKey(pid))
                {
                    // 新出现的进程：父进程号直接从快照拿，无需再查 WMI
                    HandleProcessStart(pid, entry.ParentPid, entry.Name, "polling");
                }
                else if (_nodes.TryGetValue(pid, out var node) && node.Path is null)
                {
                    // 路径解析按预算限量：只为进程树内 / 刚发现的节点补路径，
                    // 避免每秒对几百个进程各开一次句柄查 MainModule（这是另一个隐形性能坑）。
                    if (pathBudget > 0 && (node.IsInTargetTree || node.Depth >= 0))
                    {
                        try
                        {
                            using var process = Process.GetProcessById((int)pid);
                            node.Path = SafeMainModule(process);
                            pathBudget--;
                        }
                        catch
                        {
                            // 受保护进程取不到路径，属正常情况
                        }
                    }
                }
            }

            foreach (var pid in _nodes.Keys.ToList())
            {
                if (alive.Contains(pid) || pid == _rootPid) continue;
                if (_nodes.TryGetValue(pid, out var node) && !node.StopReported)
                    HandleProcessStop(pid, node.Name);
            }
        }
        catch (Exception)
        {
            // 轮询过程中进程大量进出会导致异常，属正常情况
        }
    }

    private static string SafeProcessName(Process p)
    {
        try
        {
            return p.ProcessName + ".exe";
        }
        catch
        {
            return "unknown.exe";
        }
    }

    private void HandleProcessStart(uint pid, uint parentPid, string name, string source)
    {
        if (!_nodes.TryGetValue(parentPid, out var parent))
        {
            // 父进程在被监控之前就存在，补一条占位记录
            parent = new ProcNode { Pid = parentPid, Name = $"pid-{parentPid}", IsInTargetTree = parentPid == _rootPid };
            _nodes.TryAdd(parentPid, parent);
        }

        var inTree = parentPid == _rootPid || parent.IsInTargetTree;
        var node = new ProcNode
        {
            Pid = pid,
            ParentPid = parentPid,
            Name = name,
            Path = TryGetProcessPath(pid),
            StartTime = DateTime.Now,
            IsInTargetTree = inTree,
            Depth = inTree ? parent.Depth + 1 : -1,
        };
        _nodes[pid] = node;

        var type = inTree && node.Depth > 0 ? MonitorEventType.ChildProcess : MonitorEventType.ProcessStart;
        Publish(new MonitorEvent
        {
            Type = type,
            ProcessId = pid,
            ProcessName = name,
            ProcessPath = node.Path,
            ParentProcessId = parentPid,
            Operation = type == MonitorEventType.ChildProcess ? "Child Process Create" : "Process Start",
            Target = node.Path ?? name,
            IsFromTargetTree = inTree,
            Depth = node.Depth,
            Detail = inTree
                ? $"父进程 {parent.Name} (pid={parentPid})，层级 {node.Depth}"
                : $"系统进程，父 {parent.Name} (pid={parentPid})",
            Source = source,
        });
    }

    private void HandleProcessStop(uint pid, string name)
    {
        if (!_nodes.TryGetValue(pid, out var node))
        {
            node = new ProcNode { Pid = pid, Name = name };
            _nodes[pid] = node;
        }

        node.StopReported = true;
        Publish(new MonitorEvent
        {
            Type = MonitorEventType.ProcessStop,
            ProcessId = pid,
            ProcessName = node.Name,
            ProcessPath = node.Path,
            ParentProcessId = node.ParentPid,
            Operation = "Process Stop",
            Target = node.Path ?? node.Name,
            IsFromTargetTree = node.IsInTargetTree,
            Depth = node.Depth,
            Detail = $"运行时长 {(DateTime.Now - node.StartTime).TotalSeconds:F1}s",
            Source = Source,
        });

        _knownModules.TryRemove(pid, out _);
    }

    private static string? TryGetProcessPath(uint pid)
    {
        try
        {
            using var p = Process.GetProcessById((int)pid);
            return SafeMainModule(p);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// DLL 加载监控。.NET 没有公开的 ETW 消费者，这里对目标进程树轮询模块列表做 diff。
    /// 会漏掉「加载后立刻卸载」的 DLL，误差在报告里明确标注。
    /// </summary>
    private void PollModules()
    {
        if (!_nodes.TryGetValue(_rootPid, out _)) return;

        foreach (var node in _nodes.Values.Where(n => n.IsInTargetTree))
        {
            try
            {
                using var process = Process.GetProcessById((int)node.Pid);
                var modules = process.Modules;
                var known = _knownModules.GetOrAdd(node.Pid, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));

                foreach (ProcessModule module in modules)
                {
                    var path = module.FileName;
                    if (string.IsNullOrEmpty(path)) continue;
                    if (!known.Add(path)) continue;

                    var fromWritable = Util.PathSemantics.IsUserWritable(path);
                    var inherited = _analyzerModules.Contains(path);
                    var suspicious = fromWritable && !inherited;

                    Publish(new MonitorEvent
                    {
                        Type = MonitorEventType.DllLoad,
                        ProcessId = node.Pid,
                        ProcessName = node.Name,
                        ProcessPath = node.Path,
                        Operation = "Load Module",
                        Target = path,
                        IsFromTargetTree = true,
                        Depth = node.Depth,
                        IsSuspicious = suspicious,
                        SuspicionReason = suspicious ? "从用户可写目录加载模块" : null,
                        Detail = $"模块大小 {module.ModuleMemorySize / 1024} KB，来源 {Source + "+module-poll"}"
                                 + (inherited ? "；[已排除] 该模块同时存在于分析器自身进程中，判定为分析环境注入/继承，不计入被测程序行为" : ""),
                        Source = Source + "+module-poll",
                    });
                }
            }
            catch (Exception)
            {
                // 32/64 位不匹配、进程已退出、权限不足都会抛，属预期
            }
        }
    }

    public bool IsInTargetTree(uint pid) => _nodes.TryGetValue(pid, out var n) && n.IsInTargetTree;

    /// <summary>把归因结论固化到事件上，供后续规则引擎使用。</summary>
    private void Publish(MonitorEvent e)
    {
        e.Sequence = Interlocked.Increment(ref _sequence);
        if (Interlocked.Decrement(ref _eventBudget) < 0)
        {
            Interlocked.Increment(ref _eventBudget);
            DroppedEvents++;
            return;
        }

        var handler = OnEvent;
        if (handler is null)
        {
            Interlocked.Increment(ref _eventBudget);
            return;
        }

        try
        {
            handler(e);
        }
        catch
        {
            // 下游异常不应影响监控线程
        }
    }

    /// <summary>进程树快照，报告里用于展示父子关系。</summary>
    public IReadOnlyList<ProcessTreeEntry> SnapshotTree() =>
        _nodes.Values
            .Where(n => n.IsInTargetTree)
            .OrderBy(n => n.StartTime)
            .Select(n => new ProcessTreeEntry
            {
                Pid = n.Pid,
                ParentPid = n.ParentPid,
                Name = n.Name,
                Path = n.Path,
                Depth = n.Depth,
                StartTime = n.StartTime,
            })
            .ToList();

    public void Stop()
    {
        _pollTimer?.Dispose();
        _pollTimer = null;
        _moduleTimer?.Dispose();
        _moduleTimer = null;

        try
        {
            _startWatcher?.Stop();
            _startWatcher?.Dispose();
        }
        catch
        {
            // 忽略
        }

        try
        {
            _stopWatcher?.Stop();
            _stopWatcher?.Dispose();
        }
        catch
        {
            // 忽略
        }

        _startWatcher = null;
        _stopWatcher = null;
    }

    public void Dispose() => Stop();
}

// ProcessTreeEntry 已上移到 Models/Domain.cs —— 它是领域模型，UI / 报告 / 图谱都要用，
// 不该由 Engines.Dynamic 独占定义（避免 Models → Engines 的反向依赖）。
