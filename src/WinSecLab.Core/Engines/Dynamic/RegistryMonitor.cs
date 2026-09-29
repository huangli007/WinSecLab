using System.Collections.Concurrent;
using System.Management;
using System.Runtime.Versioning;
using Microsoft.Win32;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Dynamic;

/// <summary>
/// §4/§5 注册表监控。
/// 双通道：WMI 的 RegistryTreeChangeEvent 给出「何时发生了变化」，
/// 快照差分给出「具体是哪个键、哪个值、变成了什么」。
/// 只读注册表，绝不写入 —— 与 §25「可重复测试 / 人工可验证」一致。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryMonitor : IDisposable
{
    private readonly List<WatchTarget> _targets = new();
    private readonly HashSet<string> _suspendedPrefixes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _keywords = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, Dictionary<string, string?>> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private ManagementEventWatcher? _hklmWatcher;
    private ManagementEventWatcher? _hkcuWatcher;
    private Timer? _scanTimer;
    private volatile bool _scanRequested = true;
    private volatile bool _scanning;
    private long _sequence;
    private int _budget = 60_000;
    private string? _appSpecificHiveRoot;

    public Action<MonitorEvent>? OnEvent { get; set; }
    public bool WmiActive { get; private set; }
    public int WatchedKeyCount { get; private set; }
    public bool BaselineCaptured { get; private set; }
    public string? BaselineNote { get; private set; }
    public List<string> ActiveTargets { get; } = new();

    /// <summary>单次快照允许枚举的键上限，超过则截断并在报告里标注。</summary>
    public int MaxKeysPerScan { get; set; } = 60_000;
    public int ScanIntervalMs { get; set; } = 4000;

    private sealed class WatchTarget
    {
        public RegistryHive Hive;
        public string SubKey = "";
        public bool Recursive;
        public int MaxDepth = 8;
        public bool CaptureValues = true;
        public bool KeyNamesOnly;
        public string Label = "";

        public string FullPath => $"{DescribeHive(Hive)}\\{SubKey}".TrimEnd('\\');
    }

    public void SetRelevanceKeywords(IEnumerable<string> keywords)
    {
        foreach (var k in keywords)
        {
            if (string.IsNullOrWhiteSpace(k) || k.Length < 3) continue;
            _keywords.Add(k);
        }
    }

    /// <summary>这些前缀下的键不参与监控（体积巨大且与目标无关）。</summary>
    public void SuspendPath(params string[] paths)
    {
        foreach (var path in paths) _suspendedPrefixes.Add(path);
    }

    public void AddTarget(RegistryHive hive, string subKey, bool recursive, bool captureValues, string label)
    {
        _targets.Add(new WatchTarget
        {
            Hive = hive,
            SubKey = subKey,
            Recursive = recursive,
            CaptureValues = captureValues,
            Label = label,
        });
    }

    /// <summary>默认监控面：自启动、服务、IFEO、Winlogon、AppInit、环境变量，以及用户/机器 Software 下的应用键。</summary>
    public static void AddDefaultTargets(RegistryMonitor monitor)
    {
        const string cv = @"SOFTWARE\Microsoft\Windows\CurrentVersion";

        monitor.AddTarget(RegistryHive.CurrentUser, @"Software", true, captureValues: false, "HKCU\\Software（键结构）");
        monitor.AddTarget(RegistryHive.LocalMachine, $@"{cv}\Run", false, true, "HKLM Run 自启动");
        monitor.AddTarget(RegistryHive.LocalMachine, $@"{cv}\RunOnce", false, true, "HKLM RunOnce 自启动");
        monitor.AddTarget(RegistryHive.LocalMachine, $@"{cv}\RunOnceEx", false, true, "HKLM RunOnceEx");
        monitor.AddTarget(RegistryHive.CurrentUser, $@"{cv}\Run", false, true, "HKCU Run 自启动");
        monitor.AddTarget(RegistryHive.CurrentUser, $@"{cv}\RunOnce", false, true, "HKCU RunOnce 自启动");
        monitor.AddTarget(RegistryHive.LocalMachine, $@"{cv}\Explorer\Shell Folders", false, true, "HKLM Shell Folders");
        monitor.AddTarget(RegistryHive.LocalMachine, $@"{cv}\Explorer\Browser Helper Objects", false, true, "HKLM BHO");
        monitor.AddTarget(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", false, true, "WOW6432 Run 自启动");
        monitor.AddTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", false, false, "服务列表（键名）");
        monitor.AddTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false, true, "Winlogon");
        monitor.AddTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", true, false, "IFEO（键名）");
        monitor.AddTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", false, true, "AppInit_DLLs");
        monitor.AddTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", false, true, "Session Manager");
        monitor.AddTarget(RegistryHive.CurrentUser, "Environment", false, true, "HKCU 环境变量");

        monitor.SuspendPath(
            @"HKEY_CURRENT_USER\Software\Classes",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudStore",
            @"HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
    }

    public void Start(bool tryWmi = true)
    {
        CaptureBaseline();

        if (tryWmi)
            WmiActive = TryStartWmi();

        _scanTimer = Util.SafeTimer.Create(ScanIfNeeded, ScanIntervalMs, ScanIntervalMs);

        // WMI 事件到达时立刻触发一次扫描，把「定时」与「事件」两条时间线对齐
        if (WmiActive)
            _scanRequested = true;
    }

    private bool TryStartWmi()
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\default");
            scope.Connect();

            _hklmWatcher = new ManagementEventWatcher(scope, new WqlEventQuery(
                "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SOFTWARE'"));
            _hklmWatcher.EventArrived += (_, _) => _scanRequested = true;
            _hklmWatcher.Start();

            _hkcuWatcher = new ManagementEventWatcher(scope, new WqlEventQuery(
                "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_CURRENT_USER' AND RootPath='Software'"));
            _hkcuWatcher.EventArrived += (_, _) => _scanRequested = true;
            _hkcuWatcher.Start();
            return true;
        }
        catch (Exception)
        {
            try
            {
                _hklmWatcher?.Dispose();
                _hkcuWatcher?.Dispose();
            }
            catch
            {
                // 忽略
            }
            _hklmWatcher = null;
            _hkcuWatcher = null;
            return false;
        }
    }

    /// <summary>
    /// 采集基线。快照差分必须在目标启动前建立基线，否则首次扫描会把「原有状态」误报成新增。
    /// </summary>
    public void CaptureBaseline()
    {
        var snapshot = new Dictionary<string, Dictionary<string, string?>>(StringComparer.OrdinalIgnoreCase);
        var keyCount = 0;

        foreach (var target in _targets)
        {
            try
            {
                using var baseKey = OpenBaseKey(target.Hive);
                using var root = baseKey.OpenSubKey(target.SubKey, writable: false);
                if (root is null) continue;

                if (target.Recursive)
                    WalkRecursive(root, target.FullPath, target, snapshot, ref keyCount);
                else
                    CaptureKey(root, target.FullPath, target, snapshot);

                ActiveTargets.Add(target.Label);
            }
            catch (Exception)
            {
                // 权限不足的目标键直接跳过
            }
        }

        // 目标应用专属键（HKCU\Software\<AppName> 之类）：从基线起就纳入监控
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            try
            {
                using var baseKey = OpenBaseKey(hive);
                using var software = baseKey.OpenSubKey("Software", writable: false);
                if (software is null) continue;

                foreach (var subName in software.GetSubKeyNames())
                {
                    if (!MatchesKeyword(subName)) continue;
                    using var sub = software.OpenSubKey(subName, writable: false);
                    if (sub is null) continue;
                    WalkRecursive(sub, $"{DescribeHive(hive)}\\Software\\{subName}",
                        new WatchTarget { Hive = hive, CaptureValues = true, Recursive = true },
                        snapshot, ref keyCount);
                    _appSpecificHiveRoot ??= $"{DescribeHive(hive)}\\Software\\{subName}";
                }
            }
            catch (Exception)
            {
                // 忽略
            }
        }

        _baseline = snapshot;
        WatchedKeyCount = snapshot.Count;
        BaselineCaptured = true;
        BaselineNote = snapshot.Count == 0
            ? "基线为空：注册表监控目标均不可访问（可能缺少权限）"
            : $"基线共 {snapshot.Count} 个键";
    }

    private void ScanIfNeeded()
    {
        if (!_scanRequested || _scanning) return;
        _scanRequested = false;
        _scanning = true;
        try
        {
            var current = new Dictionary<string, Dictionary<string, string?>>(StringComparer.OrdinalIgnoreCase);
            var keyCount = 0;

            foreach (var target in _targets)
            {
                try
                {
                    using var baseKey = OpenBaseKey(target.Hive);
                    using var root = baseKey.OpenSubKey(target.SubKey, writable: false);
                    if (root is null) continue;
                    if (target.Recursive)
                        WalkRecursive(root, target.FullPath, target, current, ref keyCount);
                    else
                        CaptureKey(root, target.FullPath, target, current);
                }
                catch
                {
                    // 忽略本轮访问失败
                }
            }

            if (_appSpecificHiveRoot is not null)
            {
                var parts = _appSpecificHiveRoot.Split('\\', 2);
                var hive = parts[0] == "HKEY_CURRENT_USER" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
                try
                {
                    using var baseKey = OpenBaseKey(hive);
                    using var root = baseKey.OpenSubKey(parts[1], writable: false);
                    if (root is not null)
                        WalkRecursive(root, _appSpecificHiveRoot,
                            new WatchTarget { Hive = hive, CaptureValues = true, Recursive = true }, current, ref keyCount);
                }
                catch
                {
                    // 忽略
                }
            }

            Diff(_baseline, current);
            _baseline = current;
        }
        catch (Exception)
        {
            // 差分失败不影响下一次
        }
        finally
        {
            _scanning = false;
        }
    }

    private void WalkRecursive(RegistryKey key, string path, WatchTarget target,
        Dictionary<string, Dictionary<string, string?>> sink, ref int keyCount, int depth = 0)
    {
        if (keyCount >= MaxKeysPerScan) return;
        if (depth > target.MaxDepth) return;
        if (_suspendedPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase))) return;

        CaptureKey(key, path, target, sink);
        keyCount++;

        string[] children;
        try
        {
            children = key.GetSubKeyNames();
        }
        catch
        {
            return;
        }

        foreach (var child in children)
        {
            if (keyCount >= MaxKeysPerScan) return;
            try
            {
                using var sub = key.OpenSubKey(child, writable: false);
                if (sub is null) continue;
                WalkRecursive(sub, $"{path}\\{child}", target, sink, ref keyCount, depth + 1);
            }
            catch
            {
                // 单个子键访问失败不影响其他
            }
        }
    }

    private void CaptureKey(RegistryKey key, string path, WatchTarget target,
        Dictionary<string, Dictionary<string, string?>> sink)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (target.CaptureValues || MatchesKeyword(path))
        {
            try
            {
                foreach (var valueName in key.GetValueNames())
                {
                    var raw = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    values[valueName] = FormatValue(raw);
                }
            }
            catch
            {
                // 值读取失败（权限 / 类型不支持）
            }
        }
        sink[path] = values;
    }

    private static string? FormatValue(object? raw) => raw switch
    {
        null => null,
        byte[] bytes => bytes.Length <= 64
            ? Convert.ToHexString(bytes)
            : $"<binary {bytes.Length} bytes>",
        string[] arr => string.Join(" | ", arr.Take(20)),
        _ => raw.ToString(),
    };

    private void Diff(
        Dictionary<string, Dictionary<string, string?>> before,
        Dictionary<string, Dictionary<string, string?>> after)
    {
        // 新增的键
        foreach (var (path, values) in after)
        {
            if (!before.ContainsKey(path))
            {
                Emit(new MonitorEvent
                {
                    Type = MonitorEventType.RegistryCreate,
                    Operation = "RegCreateKey",
                    Target = path,
                    Detail = values.Count > 0 ? $"含 {values.Count} 个值" : "空键",
                    IsSuspicious = IsPersistencePath(path),
                    SuspicionReason = IsPersistencePath(path) ? "新建注册表键落在自启动 / 持久化位置" : null,
                    Source = "builtin-regdiff",
                });
                continue;
            }

            foreach (var (valueName, newValue) in values)
            {
                if (!before[path].TryGetValue(valueName, out var oldValue)) continue;
                if (string.Equals(oldValue, newValue, StringComparison.Ordinal)) continue;

                Emit(new MonitorEvent
                {
                    Type = MonitorEventType.RegistrySet,
                    Operation = "RegSetValue",
                    Target = $"{path}\\{valueName}",
                    Detail = $"旧值：{Truncate(oldValue)} → 新值：{Truncate(newValue)}",
                    IsSuspicious = IsPersistencePath(path),
                    SuspicionReason = IsPersistencePath(path) ? "修改了持久化相关的注册表值" : null,
                    Source = "builtin-regdiff",
                });
            }

            foreach (var (valueName, _) in before[path])
            {
                if (values.ContainsKey(valueName)) continue;
                Emit(new MonitorEvent
                {
                    Type = MonitorEventType.RegistryDelete,
                    Operation = "RegDeleteValue",
                    Target = $"{path}\\{valueName}",
                    Source = "builtin-regdiff",
                });
            }
        }

        // 被删除的键
        foreach (var (path, _) in before)
        {
            if (after.ContainsKey(path)) continue;
            Emit(new MonitorEvent
            {
                Type = MonitorEventType.RegistryDelete,
                Operation = "RegDeleteKey",
                Target = path,
                Source = "builtin-regdiff",
            });
        }
    }

    private static string Truncate(string? value) =>
        string.IsNullOrEmpty(value) ? "(空)" : value.Length > 160 ? value[..160] + "…" : value;

    /// <summary>自启动 / 持久化的高价值位置。</summary>
    public static bool IsPersistencePath(string path)
    {
        var p = path.ToLowerInvariant();
        return p.Contains(@"\currentversion\run") ||
               p.Contains(@"\currentversion\runonce") ||
               p.Contains(@"\services\") ||
               p.Contains(@"\winlogon") ||
               p.Contains(@"image file execution options") ||
               p.Contains(@"\currentversion\windows") ||
               p.Contains(@"\policies\explorer\run") ||
               p.Contains(@"\session manager\") ||
               p.Contains(@"\environment") && p.EndsWith(@"\path", StringComparison.Ordinal) ||
               p.Contains(@"\shell folders") ||
               p.Contains(@"\browser helper objects") ||
               p.Contains(@"\shellserviceobjectdelayload") ||
               p.Contains(@"\appinit_dlls");
    }

    private bool MatchesKeyword(string text)
    {
        foreach (var keyword in _keywords)
        {
            if (text.Contains(keyword, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static RegistryKey OpenBaseKey(RegistryHive hive) =>
        hive == RegistryHive.CurrentUser
            ? RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64)
            : RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);

    internal static string DescribeHive(RegistryHive hive) => hive switch
    {
        RegistryHive.CurrentUser => "HKEY_CURRENT_USER",
        RegistryHive.LocalMachine => "HKEY_LOCAL_MACHINE",
        RegistryHive.ClassesRoot => "HKEY_CLASSES_ROOT",
        RegistryHive.Users => "HKEY_USERS",
        RegistryHive.CurrentConfig => "HKEY_CURRENT_CONFIG",
        _ => hive.ToString(),
    };

    private void Emit(MonitorEvent e)
    {
        if (Interlocked.Decrement(ref _budget) < 0)
        {
            Interlocked.Increment(ref _budget);
            return;
        }
        e.Sequence = Interlocked.Increment(ref _sequence);
        OnEvent?.Invoke(e);
    }

    public void Stop()
    {
        _scanTimer?.Dispose();
        _scanTimer = null;

        try
        {
            _hklmWatcher?.Stop();
            _hklmWatcher?.Dispose();
            _hkcuWatcher?.Stop();
            _hkcuWatcher?.Dispose();
        }
        catch
        {
            // 忽略
        }

        _hklmWatcher = null;
        _hkcuWatcher = null;
    }

    public void Dispose() => Stop();
}
