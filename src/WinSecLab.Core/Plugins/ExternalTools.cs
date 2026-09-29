using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Plugins;

/// <summary>
/// 外部工具在分析流程中的角色。这个区分决定了"要不要抢走内置引擎的任务归属"。
/// </summary>
public enum ToolRole
{
    /// <summary>替代型：与内置引擎能力等价，优先用工具，内置引擎让位（避免同一结论重复计数）。</summary>
    Substitutive,
    /// <summary>补充型：提供内置引擎拿不到的信息（PID 级归因、真实报文、反编译源码），与内置结果并行执行并交叉验证。</summary>
    Additive,
}

/// <summary>
/// §16/§17 外部工具描述符。平台不重复实现 Ghidra / x64dbg / Wireshark 这类成熟工具，
/// 而是声明「我需要什么、去哪找、怎么调用」，由 <see cref="ExternalToolLocator"/> 自动探测。
/// </summary>
public sealed class ExternalToolDescriptor
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    /// <summary>工具类别（Static / Dynamic / Network / Analysis），用于 UI 分组。</summary>
    public required string Category { get; init; }

    /// <summary>替代型还是补充型，见 <see cref="ToolRole"/>。</summary>
    public ToolRole Role { get; init; } = ToolRole.Additive;

    /// <summary>可执行文件候选名（按优先级）。大小写不敏感。</summary>
    public required string[] ExecutableNames { get; init; }

    /// <summary>显式探测目录（支持 %ENV% 展开）。</summary>
    public string[] ProbeDirectories { get; init; } = Array.Empty<string>();

    /// <summary>目录 glob（取最新版本，例如 %ProgramFiles%\Ghidra*）。</summary>
    public string[] ProbeGlobs { get; init; } = Array.Empty<string>();

    /// <summary>注册表 App Paths 键（默认值即完整 exe 路径）。</summary>
    public string[] RegistryAppPaths { get; init; } = Array.Empty<string>();

    /// <summary>注册表卸载项匹配关键字 —— 命中后读 InstallLocation。</summary>
    public string[] RegistryUninstallKeywords { get; init; } = Array.Empty<string>();

    /// <summary>输出版本号的命令行参数。</summary>
    public string VersionArgument { get; init; } = "--version";

    /// <summary>本工具能增强哪些测试任务。</summary>
    public required TestTaskKind[] Capabilities { get; init; }

    public bool RequiresAdministrator { get; init; }
    public string InstallHint { get; init; } = "";
    public string Homepage { get; init; } = "";
    public string Author { get; init; } = "";

    /// <summary>平台实际如何调用它（展示给用户，避免"黑盒自动化"的错觉）。</summary>
    public string InvocationHint { get; init; } = "";
}

/// <summary>定位结果。</summary>
public sealed class ToolLocation
{
    public bool Found { get; init; }
    public string? ExecutablePath { get; init; }
    public string? Version { get; init; }
    /// <summary>发现途径：显式配置 / 项目工具目录 / PATH / 默认安装目录 / 注册表 / 未找到。</summary>
    public string Source { get; init; } = "未找到";
    public List<string> Searched { get; init; } = new();

    public static ToolLocation Missing(List<string> searched) =>
        new() { Found = false, Searched = searched };
}

/// <summary>内置的外部工具清单（§17 的 /plugins 目录在代码中的等价物）。</summary>
public static class ExternalToolCatalog
{
    public static IReadOnlyList<ExternalToolDescriptor> All { get; } = new List<ExternalToolDescriptor>
    {
        new()
        {
            Id = "yara",
            Name = "YARA",
            Category = "Static",
            ExecutableNames = new[] { "yara64.exe", "yara.exe" },
            ProbeDirectories = new[] { @"%ProgramFiles%\YARA", @"%ProgramFiles(x86)%\YARA", @"%LOCALAPPDATA%\Programs\YARA", @"C:\Tools\YARA", @"C:\yara" },
            ProbeGlobs = new[] { @"C:\Tools\yara*", @"%USERPROFILE%\scoop\apps\yara\current" },
            RegistryAppPaths = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\yara64.exe" },
            VersionArgument = "--version",
            Capabilities = new[] { TestTaskKind.YaraScan },
            Role = ToolRole.Substitutive,
            InstallHint = "下载 yara64.exe（github.com/VirusTotal/yara/releases）解压到 C:\\Tools\\YARA，或 scoop install yara。",
            Homepage = "https://github.com/VirusTotal/yara",
            Author = "VirusTotal",
            InvocationHint = "yara64.exe -s -m -r <规则目录> <目标文件>；未安装时使用内置轻量规则引擎。",
        },
        new()
        {
            Id = "wireshark",
            Name = "Wireshark / tshark",
            Category = "Network",
            ExecutableNames = new[] { "tshark.exe" },
            ProbeDirectories = new[] { @"%ProgramFiles%\Wireshark", @"%ProgramFiles(x86)%\Wireshark" },
            RegistryAppPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\tshark.exe",
            },
            RegistryUninstallKeywords = new[] { "Wireshark" },
            VersionArgument = "--version",
            Capabilities = new[] { TestTaskKind.NetworkCapture, TestTaskKind.TlsAnalysis },
            RequiresAdministrator = true,
            InstallHint = "安装 Wireshark（勾选 Npcap），或用 winget install WiresharkFoundation.Wireshark。",
            Homepage = "https://www.wireshark.org/",
            Author = "Wireshark Foundation",
            InvocationHint = "dumpcap 抓包到 PCAP，再 tshark -r 解析 TLS SNI / 证书；未安装时仅做连接表观测。",
        },
        new()
        {
            Id = "procmon",
            Name = "Process Monitor",
            Category = "Dynamic",
            ExecutableNames = new[] { "Procmon64.exe", "Procmon.exe", "Procmon64a.exe", "Procmon.exe" },
            ProbeDirectories = new[]
            {
                @"C:\Tools\Procmon", @"C:\Tools\ProcessMonitor", @"%USERPROFILE%\Downloads",
                @"%ProgramFiles%\Process Monitor", @"C:\Sysinternals",
            },
            RegistryAppPaths = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Procmon64.exe" },
            VersionArgument = "/?",
            Capabilities = new[] { TestTaskKind.ProcessMonitor, TestTaskKind.FileMonitor, TestTaskKind.RegistryMonitor },
            RequiresAdministrator = true,
            InstallHint = "下载 Sysinternals Process Monitor（live.sysinternals.com/Procmon64.exe）放到 C:\\Tools\\Procmon。",
            Homepage = "https://learn.microsoft.com/sysinternals/downloads/procmon",
            Author = "Microsoft Sysinternals",
            InvocationHint = "/Quiet /Minimized /BackingFile x.pml 启动，/Terminate 停止，再 /OpenLog x.pml /SaveAs x.csv 导出后解析。",
        },
        new()
        {
            Id = "ghidra",
            Name = "Ghidra",
            Category = "Analysis",
            ExecutableNames = new[] { "analyzeHeadless.bat", "ghidraRun.bat" },
            ProbeDirectories = new[] { @"C:\Tools\ghidra", @"C:\ghidra", @"%ProgramFiles%\Ghidra" },
            ProbeGlobs = new[] { @"C:\Tools\ghidra_*", @"C:\ghidra_*", @"%USERPROFILE%\ghidra_*" },
            VersionArgument = "help",
            Capabilities = new[] { TestTaskKind.DeepAnalysis },
            InstallHint = "下载 Ghidra 发行版解压到 C:\\Tools\\ghidra（需 JDK 21+）。",
            Homepage = "https://ghidra-sre.org/",
            Author = "NSA",
            InvocationHint = "analyzeHeadless <项目目录> <项目名> -import <目标> -postScript <导出脚本>；平台只管理工程与脚本，不自行反编译。",
        },
        new()
        {
            Id = "ilspy",
            Name = "ILSpy (ilspycmd)",
            Category = "Analysis",
            ExecutableNames = new[] { "ilspycmd.exe" },
            ProbeDirectories = new[] { @"%USERPROFILE%\.dotnet\tools", @"C:\Tools\ILSpy" },
            ProbeGlobs = new[] { @"%USERPROFILE%\.dotnet\tools" },
            RegistryAppPaths = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ilspycmd.exe" },
            VersionArgument = "--version",
            Capabilities = new[] { TestTaskKind.DotNetAnalysis },
            InstallHint = "dotnet tool install -g ilspycmd（需要 .NET SDK）。",
            Homepage = "https://github.com/icsharpcode/ILSpy",
            Author = "ICSharpCode",
            InvocationHint = "ilspycmd -l c 列类型，ilspycmd -o <目录> 导出反编译源码；未安装时使用内置元数据解析。",
        },
        new()
        {
            Id = "x64dbg",
            Name = "x64dbg",
            Category = "Analysis",
            ExecutableNames = new[] { "x64dbg.exe", "x32dbg.exe" },
            ProbeDirectories = new[] { @"C:\Tools\x64dbg", @"C:\x64dbg", @"%ProgramFiles%\x64dbg" },
            ProbeGlobs = new[] { @"C:\Tools\x64dbg*", @"%USERPROFILE%\Downloads\x64dbg*" },
            VersionArgument = "--help",
            Capabilities = new[] { TestTaskKind.DeepAnalysis },
            InstallHint = "下载 x64dbg 快照解压到 C:\\Tools\\x64dbg。",
            Homepage = "https://x64dbg.com/",
            Author = "mrexodia",
            InvocationHint = "平台生成启动脚本与工作目录，调试会话由人工在 GUI 中进行（§25 人工可验证）。",
        },
        new()
        {
            Id = "dependencies",
            Name = "Dependencies",
            Category = "Static",
            ExecutableNames = new[] { "Dependencies.exe" },
            ProbeDirectories = new[] { @"C:\Tools\Dependencies", @"C:\Tools\lucasg", @"%LOCALAPPDATA%\Microsoft\WinGet\Links" },
            ProbeGlobs = new[] { @"C:\Tools\Dependencies*", @"C:\Tools\lucasg*" },
            VersionArgument = "-help",
            Capabilities = new[] { TestTaskKind.DependencyScan },
            InstallHint = "下载 Dependencies_x64_Release.zip（github.com/lucasg/Dependencies）解压到 C:\\Tools\\Dependencies。",
            Homepage = "https://github.com/lucasg/Dependencies",
            Author = "lucasg",
            InvocationHint = "Dependencies.exe -chain -modules <目标> 输出依赖链，与内置解析结果交叉验证。",
        },
        new()
        {
            Id = "procexp",
            Name = "Process Explorer",
            Category = "Dynamic",
            ExecutableNames = new[] { "procexp64.exe", "procexp.exe" },
            ProbeDirectories = new[] { @"C:\Tools\Sysinternals", @"C:\Sysinternals", @"%ProgramFiles%\Sysinternals" },
            VersionArgument = "/?",
            Capabilities = new[] { TestTaskKind.DeepAnalysis },
            RequiresAdministrator = true,
            InstallHint = "下载 Sysinternals Process Explorer 到 C:\\Tools\\Sysinternals。",
            Homepage = "https://learn.microsoft.com/sysinternals/downloads/process-explorer",
            Author = "Microsoft Sysinternals",
            InvocationHint = "作为人工核查补充：平台给出目标 PID 与时间线，人工在 Process Explorer 中核对。",
        },
        new()
        {
            Id = "sigcheck",
            Name = "Sigcheck",
            Category = "Static",
            ExecutableNames = new[] { "sigcheck64.exe", "sigcheck.exe" },
            ProbeDirectories = new[] { @"C:\Tools\Sysinternals", @"C:\Sysinternals", @"%ProgramFiles%\Sysinternals" },
            VersionArgument = "/?",
            Capabilities = new[] { TestTaskKind.DigitalSignature },
            InstallHint = "下载 Sysinternals Sigcheck 到 C:\\Tools\\Sysinternals。",
            Homepage = "https://learn.microsoft.com/sysinternals/downloads/sigcheck",
            Author = "Microsoft Sysinternals",
            InvocationHint = "sigcheck64.exe -a -h -nobanner -c <目标> 输出 CSV，与内置 WinVerifyTrust 结果交叉验证。",
        },
        new()
        {
            Id = "strings",
            Name = "Sysinternals Strings",
            Category = "Static",
            ExecutableNames = new[] { "strings64.exe", "strings.exe" },
            ProbeDirectories = new[] { @"C:\Tools\Sysinternals", @"C:\Sysinternals", @"%ProgramFiles%\Sysinternals" },
            VersionArgument = "/?",
            Capabilities = new[] { TestTaskKind.StringsScan },
            InstallHint = "下载 Sysinternals Strings 到 C:\\Tools\\Sysinternals。",
            Homepage = "https://learn.microsoft.com/sysinternals/downloads/strings",
            Author = "Microsoft Sysinternals",
            InvocationHint = "strings64.exe -accepteula -n 6 <目标>，用于校验内置提取器的召回率。",
        },
    };

    public static ExternalToolDescriptor? Get(string id) =>
        All.FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// 外部工具定位器。探测顺序刻意从「最可信」到「最宽松」：
/// 显式配置 → 项目工具目录 → PATH → 默认安装目录 / glob → 注册表。
/// 全过程只读文件系统与注册表，不写任何东西。
/// </summary>
[SupportedOSPlatform("windows")]
public static class ExternalToolLocator
{
    private static readonly Dictionary<string, ToolLocation> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, object> Probes = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object CacheLock = new();

    /// <summary>清空缓存（用户新装了工具后可手动触发重新探测）。</summary>
    public static void InvalidateCache()
    {
        lock (CacheLock) Cache.Clear();
    }

    /// <summary>额外搜索目录（用户显式指定，优先级最高）。</summary>
    public static List<string> ExtraSearchDirectories { get; } = new();

    public static ToolLocation Locate(ExternalToolDescriptor descriptor, bool probeVersion = true)
    {
        lock (CacheLock)
        {
            if (Cache.TryGetValue(descriptor.Id, out var cached)) return cached;
        }

        // 同一工具只探测一次 —— UI 会并行探测所有插件，没有这把锁就会重复跑外部进程
        object gate;
        lock (CacheLock)
        {
            if (!Probes.TryGetValue(descriptor.Id, out var existing))
            {
                existing = new object();
                Probes[descriptor.Id] = existing;
            }
            gate = existing;
        }

        lock (gate)
        {
            lock (CacheLock)
            {
                if (Cache.TryGetValue(descriptor.Id, out var cachedAgain)) return cachedAgain;
            }

            var location = ProbeCore(descriptor, probeVersion);
            lock (CacheLock) Cache[descriptor.Id] = location;
            return location;
        }
    }

    private static ToolLocation ProbeCore(ExternalToolDescriptor descriptor, bool probeVersion)
    {
        var searched = new List<string>();
        string? found = null;
        var source = "未找到";

        // 1. 显式配置目录（用户在设置里指定的路径，或项目自己的 tools 目录）
        foreach (var dir in ExtraSearchDirectories.Concat(descriptor.ProbeDirectories.Select(Expand)))
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
            searched.Add(dir);
            found = MatchInDirectory(dir, descriptor.ExecutableNames);
            if (found is not null) { source = dir == null ? "默认安装目录" : "默认安装目录"; break; }
        }

        // 2. glob（取最新修改的匹配目录 —— 多版本共存时优先新版本）
        if (found is null)
        {
            foreach (var pattern in descriptor.ProbeGlobs)
            {
                var expanded = Expand(pattern);
                var root = Path.GetDirectoryName(expanded);
                var leaf = Path.GetFileName(expanded);
                if (string.IsNullOrEmpty(root) || string.IsNullOrEmpty(leaf) || !Directory.Exists(root)) continue;
                try
                {
                    var dirs = Directory.GetDirectories(root, leaf)
                        .OrderByDescending(SafeWriteTime)
                        .ToList();
                    foreach (var d in dirs)
                    {
                        searched.Add(d);
                        found = MatchInDirectory(d, descriptor.ExecutableNames);
                        if (found is not null) { source = "默认安装目录"; break; }
                    }
                    // glob 本身可能直接指向一个目录（无通配符）
                    if (found is null && Directory.Exists(expanded))
                    {
                        found = MatchInDirectory(expanded, descriptor.ExecutableNames);
                        if (found is not null) source = "默认安装目录";
                    }
                }
                catch { /* 权限不足的目录直接跳过 */ }
                if (found is not null) break;
            }
        }

        // 3. PATH
        if (found is null)
        {
            foreach (var name in descriptor.ExecutableNames)
            {
                var onPath = FindOnPath(name);
                if (onPath is not null) { found = onPath; source = "PATH"; break; }
            }
            searched.Add("PATH");
        }

        // 4. 注册表 App Paths
        if (found is null)
        {
            foreach (var sub in descriptor.RegistryAppPaths)
            {
                var p = ReadAppPath(sub);
                if (p is not null && File.Exists(p))
                {
                    found = p;
                    source = "注册表 App Paths";
                    searched.Add(@"HKLM\" + sub);
                    break;
                }
            }
        }

        // 5. 注册表卸载项 → InstallLocation
        if (found is null && descriptor.RegistryUninstallKeywords.Length > 0)
        {
            foreach (var kw in descriptor.RegistryUninstallKeywords)
            {
                var loc = FindByUninstallKeyword(kw);
                if (loc is null) continue;
                searched.Add($"卸载项匹配「{kw}」→ {loc}");
                found = MatchInDirectory(loc, descriptor.ExecutableNames);
                if (found is not null) { source = "注册表卸载项"; break; }
            }
        }

        var location = new ToolLocation
        {
            Found = found is not null,
            ExecutablePath = found,
            Source = source,
            Searched = searched,
            Version = found is not null && probeVersion ? ProbeVersion(found, descriptor.VersionArgument) : null,
        };

        return location;
    }

    private static string? MatchInDirectory(string dir, string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var direct = Path.Combine(dir, name);
                if (File.Exists(direct)) return direct;
                // 大小写不一致的情况（Windows 上少见，但网络盘/下载目录可能）
                var hit = Directory.EnumerateFiles(dir)
                    .FirstOrDefault(f => string.Equals(Path.GetFileName(f), name, StringComparison.OrdinalIgnoreCase));
                if (hit is not null) return hit;
            }
            catch { }
        }
        return null;
    }

    public static string? FindOnPath(string exeName)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var full = Path.Combine(dir.Trim('"'), exeName);
                if (File.Exists(full)) return full;
            }
            catch { }
        }
        return null;
    }

    private static string? ReadAppPath(string subKeyPath)
    {
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
                    if (key?.GetValue(null) is string s && !string.IsNullOrWhiteSpace(s))
                        return s.Trim('"');
                }
                catch { }
            }
        }
        return null;
    }

    private static string? FindByUninstallKeyword(string keyword)
    {
        var roots = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };
        foreach (var root in roots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var uninstall = baseKey.OpenSubKey(root, writable: false);
                if (uninstall is null) continue;
                foreach (var sub in uninstall.GetSubKeyNames())
                {
                    using var app = uninstall.OpenSubKey(sub, writable: false);
                    if (app?.GetValue("DisplayName") is not string displayName) continue;
                    if (!displayName.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;
                    if (app.GetValue("InstallLocation") is string loc && Directory.Exists(loc))
                        return loc;
                }
            }
            catch { }
        }
        return null;
    }

    /// <summary>跑一次 `exe &lt;arg&gt;` 抓版本号。失败一律返回 null，绝不让探测把分析流程拖住。</summary>
    public static string? ProbeVersion(string exePath, string argument, int timeoutMs = 2500)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = argument,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;

            var sb = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data is not null && sb.Length < 4000) sb.AppendLine(e.Data); };
            p.ErrorDataReceived += (_, e) => { if (e.Data is not null && sb.Length < 4000) sb.AppendLine(e.Data); };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return null;
            }
            p.WaitForExit(500);

            var text = sb.ToString();
            var line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .FirstOrDefault(l => l.Length > 0 && !l.StartsWith("Usage", StringComparison.OrdinalIgnoreCase)
                                     && !l.StartsWith("用法", StringComparison.Ordinal));
            if (string.IsNullOrWhiteSpace(line)) return null;
            return line.Length > 200 ? line[..200] : line;
        }
        catch
        {
            return null;
        }
    }

    private static string Expand(string path) => Environment.ExpandEnvironmentVariables(path);

    private static DateTime SafeWriteTime(string dir)
    {
        try { return Directory.GetLastWriteTimeUtc(dir); } catch { return DateTime.MinValue; }
    }

    /// <summary>把探测结果转成 UI 直接可渲染的插件状态。</summary>
    public static PluginStatus ToStatus(ExternalToolDescriptor descriptor, ToolLocation location, bool enabled)
    {
        return new PluginStatus
        {
            Id = descriptor.Id,
            Name = descriptor.Name,
            Version = location.Version ?? "未探测",
            Kind = PluginKind.ExternalToolAdapter,
            Description = (descriptor.Role == ToolRole.Substitutive
                    ? "【替代型】与内置引擎能力等价，检测到后优先由工具执行。"
                    : "【补充型】提供内置引擎拿不到的数据，与内置结果并行并交叉验证。")
                + descriptor.InvocationHint,
            Author = descriptor.Author,
            Homepage = descriptor.Homepage,
            Available = location.Found,
            AvailabilityText = location.Found
                ? $"已检测到（{location.Source}）：{location.ExecutablePath}"
                : "未检测到 —— 将自动降级为内置引擎",
            ExecutablePath = location.ExecutablePath,
            Capabilities = descriptor.Capabilities.Select(c => c.ToString()).ToList(),
            InstallHint = descriptor.InstallHint,
            Enabled = enabled,
            LastChecked = DateTime.Now,
        };
    }
}
