using System.Collections.Concurrent;
using System.Runtime.Versioning;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Dynamic;

/// <summary>
/// §4/§5 文件监控。
/// FileSystemWatcher 不携带发起进程的 PID，因此这里采用「监控根目录 + 关键词相关性过滤 + 时间窗归因」：
/// 只有当目标进程树处于存活状态、且路径与目标特征相关（或落在目标目录内）时才产出事件。
/// 需要逐条精确 PID 归因时，请启用 Procmon 适配器（§5）。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FileMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<FileEventCandidate> _pending = new();
    private readonly HashSet<string> _keywords = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _targetDirectories = new();
    private readonly List<string> _noisePaths = new();
    private readonly ConcurrentQueue<string> _warnings = new();
    private Timer? _flushTimer;
    private int _eventBudget = 100_000;
    private long _sequence;
    private int _suppressedCount;
    private readonly int _maxEventsPerSecond;
    private int _emittedThisSecond;

    public bool IncludeAllEvents { get; set; }
    public Action<MonitorEvent>? OnEvent { get; set; }
    public Func<uint, bool>? IsInTargetTree { get; set; }
    public List<string> ActiveRoots { get; } = new();
    public int SuppressedCount => _suppressedCount;

    /// <summary>处理过程中出现的非致命问题（定时器回调异常等），供会话汇总上报。</summary>
    public IReadOnlyCollection<string> Warnings => _warnings;

    private sealed class FileEventCandidate
    {
        public DateTime Timestamp;
        public MonitorEventType Type;
        public string Path = "";
        public string? OldPath;
    }

    public FileMonitor(int maxEventsPerSecond = 400)
    {
        _maxEventsPerSecond = Math.Max(20, maxEventsPerSecond);
        _noisePaths.AddRange(new[]
        {
            @"\AppData\Local\Temp\WinSecLab",
            @"\AppData\Roaming\Microsoft\Windows\Recent",
            @"\AppData\Local\Microsoft\Windows\INetCache",
            @"\AppData\Local\Microsoft\Windows\WebCache",
            @"\AppData\Local\CrashDumps",
            @"\AppData\Local\Packages\",
            @"\AppData\Local\Temp\Diagnostics",
            @"\AppData\Roaming\Mozilla\Firefox\Profiles",
            @"\$Recycle.Bin",
        });
    }

    /// <summary>关键词用于判定「这个文件事件是否与目标应用有关」。</summary>
    public void SetRelevanceKeywords(IEnumerable<string> keywords)
    {
        foreach (var k in keywords)
        {
            if (string.IsNullOrWhiteSpace(k) || k.Length < 3) continue;
            _keywords.Add(k);
        }
    }

    public void AddTargetDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return;
        _targetDirectories.Add(directory);
    }

    /// <summary>默认监控根：目标目录（递归）+ 用户可写的高危写入位置。</summary>
    public static List<string> DefaultRoots()
    {
        var roots = new List<string>();
        void Add(string path)
        {
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path) && !roots.Contains(path))
                roots.Add(path);
        }

        Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        Add(Path.GetTempPath());
        Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        return roots;
    }

    public void Start(IEnumerable<string> roots, bool recursive = true)
    {
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = recursive,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName |
                                   NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Security,
                    InternalBufferSize = 64 * 1024,
                    Filter = "*",
                };

                watcher.Created += (_, e) => Enqueue(MonitorEventType.FileCreate, e.FullPath, null);
                watcher.Changed += (_, e) => Enqueue(MonitorEventType.FileWrite, e.FullPath, null);
                watcher.Deleted += (_, e) => Enqueue(MonitorEventType.FileDelete, e.FullPath, null);
                watcher.Renamed += (_, e) => Enqueue(MonitorEventType.FileRename, e.FullPath, e.OldFullPath);
                watcher.Error += (_, _) => { /* 缓冲区溢出，静默降级 */ };
                watcher.EnableRaisingEvents = true;

                _watchers.Add(watcher);
                ActiveRoots.Add(root);
            }
            catch (Exception)
            {
                // 目录不可访问（如受保护的系统目录），跳过
            }
        }

        _flushTimer = Util.SafeTimer.Create(Flush, 250, 250,
            ex => _warnings.Enqueue($"文件事件处理出错（已忽略）：{ex.Message}"));
    }

    private void Enqueue(MonitorEventType type, string path, string? oldPath)
    {
        _pending.Enqueue(new FileEventCandidate
        {
            Timestamp = DateTime.Now,
            Type = type,
            Path = path,
            OldPath = oldPath,
        });
    }

    private void Flush()
    {
        _emittedThisSecond = 0;
        var relevantCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        while (_pending.TryDequeue(out var candidate))
        {
            if (_emittedThisSecond >= _maxEventsPerSecond)
            {
                _suppressedCount++;
                continue;
            }

            if (!IsRelevant(candidate, relevantCache))
            {
                _suppressedCount++;
                continue;
            }

            // FileSystemWatcher 不提供发起进程，无法用 PID 归因；
            // 这里只按"路径是否落在目标目录"给出可辩护的判断，而不是无条件当成目标进程树的动作。
            var inTree = _targetDirectories.Any(dir =>
                candidate.Path.StartsWith(dir, StringComparison.OrdinalIgnoreCase));
            var writable = PathSemantics.IsUserWritable(candidate.Path);

            Emit(new MonitorEvent
            {
                Type = candidate.Type,
                ProcessId = 0,
                ProcessName = "(按路径归因)",
                Operation = DescribeOperation(candidate.Type),
                Target = candidate.Path,
                IsFromTargetTree = inTree,
                IsSuspicious = writable && IsSensitiveLocation(candidate.Path),
                SuspicionReason = writable && IsSensitiveLocation(candidate.Path)
                    ? "在用户可写目录产生文件变更（需 Procmon 确认发起进程）"
                    : null,
                Detail = candidate.OldPath is not null ? $"原路径：{candidate.OldPath}" : null,
                Source = "builtin-fsw",
            });
        }
    }

    private bool IsRelevant(FileEventCandidate candidate, Dictionary<string, bool> cache)
    {
        if (IncludeAllEvents) return true;

        // 1) 目标目录内的一切变更都算相关
        foreach (var dir in _targetDirectories)
        {
            if (candidate.Path.StartsWith(dir, StringComparison.OrdinalIgnoreCase)) return true;
        }

        // 2) 排除已知的噪声目录。
        //    注意：这里存的是路径片段而不是正则 —— 用 Regex.IsMatch 匹配 @"\AppData\Local\Temp"
        //    会因为 \A、\L 之类的转义序列直接抛 RegexParseException，把整个事件线程打挂。
        foreach (var noise in _noisePaths)
        {
            if (candidate.Path.Contains(noise, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        // 3) 路径中包含目标特征关键词
        if (cache.TryGetValue(candidate.Path, out var cached)) return cached;

        var fileName = Path.GetFileName(candidate.Path);
        var relevant = false;
        foreach (var keyword in _keywords)
        {
            if (candidate.Path.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                relevant = true;
                break;
            }
        }

        // 4) 落在自启动 / 计划任务目录，即使与关键词无关也要记录（持久化行为）
        if (!relevant && IsPersistenceLocation(candidate.Path)) relevant = true;

        // 5) 可执行文件落地在可写目录，值得记录
        if (!relevant && writableExtension(fileName) && PathSemantics.IsUserWritable(candidate.Path))
        {
            if (candidate.Type is MonitorEventType.FileCreate or MonitorEventType.FileRename) relevant = true;
        }

        cache[candidate.Path] = relevant;
        return relevant;

        static bool writableExtension(string name) =>
            name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".scr", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPersistenceLocation(string path) =>
        path.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Startup\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Microsoft\Windows\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Tasks", StringComparison.OrdinalIgnoreCase) && path.EndsWith(".job", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\System32\Tasks", StringComparison.OrdinalIgnoreCase);

    internal static bool IsSensitiveLocation(string path)
    {
        if (path.Contains(@"\Microsoft\Windows\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase)) return true;
        if (path.Contains(@"\System32\Tasks", StringComparison.OrdinalIgnoreCase)) return true;
        if (path.Contains(@"\System32\drivers", StringComparison.OrdinalIgnoreCase)) return true;
        if (path.Contains(@"\Windows\Temp", StringComparison.OrdinalIgnoreCase)) return true;
        if (path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) &&
            Path.GetExtension(path).Equals(".dll", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string DescribeOperation(MonitorEventType type) => type switch
    {
        MonitorEventType.FileCreate => "CreateFile",
        MonitorEventType.FileWrite => "WriteFile",
        MonitorEventType.FileDelete => "DeleteFile",
        MonitorEventType.FileRename => "RenameFile",
        _ => "FileOp",
    };

    private void Emit(MonitorEvent e)
    {
        if (Interlocked.Decrement(ref _eventBudget) < 0)
        {
            Interlocked.Increment(ref _eventBudget);
            _suppressedCount++;
            return;
        }
        e.Sequence = Interlocked.Increment(ref _sequence);
        _emittedThisSecond++;
        OnEvent?.Invoke(e);
    }

    public void Stop()
    {
        _flushTimer?.Dispose();
        _flushTimer = null;

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch
            {
                // 忽略
            }
        }
        _watchers.Clear();
        Flush();
    }

    public void Dispose() => Stop();
}
