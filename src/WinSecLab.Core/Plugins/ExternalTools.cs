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

    /// <summary>
    /// 版本探测是否要先加 <c>-accepteula</c>。
    ///
    /// Sysinternals 系工具第一次运行会先弹授权页（EULA），授权文本会被当成"版本号"显示出来。
    /// 加 -accepteula 后才会直接输出真正的版本行；纯 GUI 工具（Process Explorer）则完全
    /// 不该起进程，见 <see cref="AlwaysProbeFromFileResource"/>。
    /// </summary>
    public bool AcceptEulaForVersion { get; init; }

    /// <summary>
    /// 强制只用 PE 文件版本资源探测，绝不启动进程。
    ///
    /// 用于纯 GUI 程序（如 Process Explorer）：<c>/?</c> 不会打印到控制台，而是弹一个窗口，
    /// 既拿不到版本号又会被安全软件当成异常行为拦截。读文件版本资源零副作用、毫秒级返回。
    /// </summary>
    public bool AlwaysProbeFromFileResource { get; init; }

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
            // GUI 程序：/? 弹的是窗口而不是控制台输出，且会被安全软件拦。只读文件版本资源。
            VersionArgument = "/?",
            AlwaysProbeFromFileResource = true,
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
            ProbeDirectories = new[] { @"C:\Tools\ghidra", @"C:\Tools\ghidra\support", @"C:\ghidra", @"C:\ghidra\support", @"%ProgramFiles%\Ghidra" },
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
            ProbeDirectories = new[] { @"C:\Tools\x64dbg", @"C:\Tools\x64dbg\x64", @"C:\Tools\x64dbg\release\x64", @"C:\x64dbg", @"%ProgramFiles%\x64dbg" },
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
            InvocationHint = "Dependencies.exe -imports <目标> 输出直接导入表，与内置解析结果交叉验证。",
        },
        new()
        {
            Id = "procexp",
            Name = "Process Explorer",
            Category = "Dynamic",
            ExecutableNames = new[] { "procexp64.exe", "procexp.exe" },
            ProbeDirectories = new[] { @"C:\Tools\Sysinternals", @"C:\Sysinternals", @"%ProgramFiles%\Sysinternals" },
            // GUI 程序：/? 弹窗口而非输出文本 —— 只读文件版本资源，避免版本号显示成 EULA 标题。
            VersionArgument = "/?",
            AlwaysProbeFromFileResource = true,
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
            // 控制台程序，但输出是 UTF-16LE 且首次运行先弹 EULA 页 —— 加 -accepteula。
            AcceptEulaForVersion = true,
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
            // 控制台程序，但首次运行先弹 EULA 页 —— 加 -accepteula。
            AcceptEulaForVersion = true,
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
            Version = found is not null && probeVersion ? ProbeVersion(descriptor, found) : null,
        };

        return location;
    }

    /// <summary>
    /// 在目录内找可执行文件：先看直接子文件，再看一级子目录。
    ///
    /// 为什么要下一级：解压式发行版（x64dbg、Ghidra 等）普遍把主程序放在
    /// release\x64\ 或 bin\ 这类子目录里，只看直接子文件会全部漏判。
    /// 刻意只递归一层 —— 深度够覆盖常见布局，又不会在大目录上把探测拖成秒级。
    /// </summary>
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

        // 一级子目录（release\x64\、bin\ 之类）
        try
        {
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                foreach (var name in names)
                {
                    try
                    {
                        var p = Path.Combine(sub, name);
                        if (File.Exists(p)) return p;
                        var hit = Directory.EnumerateFiles(sub)
                            .FirstOrDefault(f => string.Equals(Path.GetFileName(f), name, StringComparison.OrdinalIgnoreCase));
                        if (hit is not null) return hit;
                    }
                    catch { }
                }
            }
        }
        catch { }

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
    /// <summary>
    /// 探测外部工具的版本号。三级策略，按"可信度 + 安全性"排序：
    /// 1) PE 文件版本资源 —— 不启动进程，毫秒级，不受安全软件影响，且是发布者**主动声明**的版本
    ///    （纯 GUI 工具的**唯一**可行路径）；
    /// 2) 命令行 --version / /? —— 起子进程拿输出，但工具自身输出未必是版本号
    ///    （实测 Dependencies 的 -help 首行是描述文本，会把正确的文件版本盖掉）；
    /// 3) 文件名里的版本号 —— 兜底（x64dbg 快照、Ghidra 解压目录名常带版本）。
    /// </summary>
    public static string? ProbeVersion(ExternalToolDescriptor descriptor, string exePath, int timeoutMs = 2500)
    {
        // 1) 文件版本资源。GUI 工具（AlwaysProbeFromFileResource）到此为止 —— 起进程只会弹窗或被拦。
        var fromFile = TryReadFileVersion(exePath);
        if (descriptor.AlwaysProbeFromFileResource) return fromFile;

        // 文件版本资源可用就直接采信：它是发布者填的版本，比解析工具输出可靠得多。
        if (!string.IsNullOrWhiteSpace(fromFile) && LooksLikeVersion(fromFile)) return fromFile;

        // 2) 命令行输出
        var fromCli = ProbeVersionViaCli(exePath, descriptor, timeoutMs);

        return fromCli ?? fromFile ?? TryParseVersionFromPath(exePath);
    }

    /// <summary>
    /// 判断一段文本是否"像版本号"（形如 1.10.0 / 17.14 / 4.5.5.1234）。
    /// 文件版本资源里的 Description 字段常被发布者塞进说明文字，这类要判为不可信。
    /// </summary>
    internal static bool LooksLikeVersion(string text)
    {
        var t = text.Trim();
        if (t.Length == 0 || t.Length > 40) return false;
        return System.Text.RegularExpressions.Regex.IsMatch(t, @"^\d+(\.\d+){0,3}$");
    }

    /// <summary>
    /// 读取 PE 的版本资源（FileVersion / ProductVersion）。
    /// 用 <see cref="FileVersionInfo"/> 即可，无需解析 PE 结构。这条路对任何 Win32 exe 都适用，
    /// 且完全不起进程 —— 对会被安全软件拦的调试类工具尤其重要。
    /// </summary>
    private static string? TryReadFileVersion(string exePath)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(exePath);
            var v = info.ProductVersion?.Trim();
            if (string.IsNullOrWhiteSpace(v)) v = info.FileVersion?.Trim();
            if (string.IsNullOrWhiteSpace(v)) return null;
            // 有些工具版本资源是 "1.0.0.0" 之外的杂乱串，限制长度并去掉换行
            v = v.Replace("\r", " ").Replace("\n", " ").Trim();
            if (v.Length == 0) return null;
            // 文件名本身就叫版本（例如 "1.0"）或全是 0 的占位，视为无效
            if (v.All(c => c == '0' || c == '.')) return null;
            return v.Length > 120 ? v[..120] : v;
        }
        catch
        {
            return null;
        }
    }

    private static string? ProbeVersionViaCli(string exePath, ExternalToolDescriptor descriptor, int timeoutMs)
    {
        try
        {
            var arg = descriptor.VersionArgument;
            if (descriptor.AcceptEulaForVersion)
                arg = $"-accepteula {arg}".Trim();

            // 不能固定用 UTF-8 或 Unicode 读：实测同一套 Sysinternals 工具编码并不一致
            // （sigcheck 是 UTF-16LE，strings 是 UTF-8/ASCII）。这里按原始字节读回来自动嗅探。
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arg,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.Latin1,  // 逐字节透传，不做替换
                StandardErrorEncoding = Encoding.Latin1,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;

            // 同步读：走 OutputDataReceived 异步回调会踩时序坑 —— 带超时的 WaitForExit(ms)
            // 不等异步缓冲排空，短命令（yara --version）经常在回调执行前就返回，字节数恒为 0。
            // stdout / stderr 必须**并行**读：串行读 stdout 时若 stderr 缓冲写满，进程会阻塞等写入，
            // 双方互等成死锁。
            static List<byte> Drain(Stream stream)
            {
                var buf = new List<byte>(4096);
                try
                {
                    var chunk = new byte[1024];
                    int n;
                    while (buf.Count < 8000 && (n = stream.Read(chunk, 0, chunk.Length)) > 0)
                        buf.AddRange(chunk.AsSpan(0, n).ToArray());
                }
                catch { }
                return buf;
            }

            var stdoutTask = Task.Run(() => Drain(p.StandardOutput.BaseStream));
            var stderrTask = Task.Run(() => Drain(p.StandardError.BaseStream));

            if (!Task.WaitAll(new Task[] { stdoutTask, stderrTask }, timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return null;
            }
            try { p.WaitForExit(500); } catch { }

            var bytes = stdoutTask.Result;
            bytes.AddRange(stderrTask.Result);
            return PickVersionLine(DecodeToolOutput(bytes.ToArray()));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 自动判断工具控制台输出是 UTF-16LE 还是 UTF-8。
    ///
    /// 为什么要嗅探：实测同一套 Sysinternals 工具编码并不统一 —— sigcheck 输出 UTF-16LE
    /// （所以按 UTF-8 读会变成 "S i g c h e c k"），strings 却是 UTF-8。硬编码任何一种都会错。
    /// 判据：UTF-16LE 的 ASCII 文本每隔一个字节就是 0x00；UTF-8 则是连续非零字节。
    /// 同时处理 BOM。
    /// </summary>
    internal static string DecodeToolOutput(byte[] raw)
    {
        if (raw.Length == 0) return string.Empty;

        // 显式 BOM
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
            return Encoding.Unicode.GetString(raw, 2, raw.Length - 2);
        if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
            return Encoding.UTF8.GetString(raw, 3, raw.Length - 3);

        // 采样前 512 字节统计奇偶位为 0 的比例
        var sample = Math.Min(raw.Length, 512);
        int zerosOnOdd = 0, zerosOnEven = 0;
        for (var i = 0; i < sample; i++)
        {
            if (raw[i] != 0) continue;
            if ((i & 1) == 1) zerosOnOdd++; else zerosOnEven++;
        }
        var oddRatio = (double)zerosOnOdd / sample;
        // UTF-16LE 的 ASCII 文本：奇数位约一半是 0x00
        if (oddRatio > 0.25 && zerosOnOdd > zerosOnEven * 3)
            return Encoding.Unicode.GetString(raw).TrimStart('\uFEFF', '\0');

        // 回退 UTF-8（对纯 ASCII 与 UTF-8 中文都正确）
        var text = Encoding.UTF8.GetString(raw).TrimStart('\uFEFF', '\0');
        return text.Contains('\uFFFD') ? Encoding.Default.GetString(raw) : text;
    }

    /// <summary>
    /// 从工具输出里挑出真正的版本行。
    ///
    /// 排除项来自实测：EULA 授权页（"SYSINTERNALS SOFTWARE LICENSE TERMS"）、
    /// 用法标题（Usage / 用法）、空行。Sysinternals 的惯例是首行形如
    /// "Sigcheck v2.92 - File version and signature viewer"，含 " v&lt;数字&gt;"。
    /// </summary>
    /// <summary>
    /// 清理一行文本：先剥 BOM / NUL，再 trim 空白。
    ///
    /// 顺序不能反：UTF-16LE 解码后 BOM 会留在行首，此时行首字符不是空白，
    /// 先 Trim() 什么也去不掉，剥完 BOM 才露出真正的空格（实测 sigcheck 首行是这样）。
    /// </summary>
    private static string CleanLine(string line) =>
        line.Trim('\uFEFF', '\0', '\r', '\n', ' ', '\t').Trim();

    internal static string? PickVersionLine(string text)
    {
        foreach (var raw in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var l = CleanLine(raw);
            if (l.Length == 0) continue;
            if (l.StartsWith("Usage", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("用法", StringComparison.Ordinal)) continue;
            if (l.Contains("LICENSE TERMS", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.Contains("EULA", StringComparison.OrdinalIgnoreCase)) continue;
            // EULA 页的典型句子
            if (l.StartsWith("This program", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("By using", StringComparison.OrdinalIgnoreCase)) continue;

            // 优先直接返回带 " v<数字>" 的行（Sysinternals 风格）
            if (System.Text.RegularExpressions.Regex.IsMatch(l, @"\bv\d+\.\d+"))
                return l.Length > 200 ? l[..200] : l;
        }

        // 没有明显版本行，退回第一条像样的文本
        var fallback = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(CleanLine)
            .FirstOrDefault(l => l.Length > 0
                && !l.StartsWith("Usage", StringComparison.OrdinalIgnoreCase)
                && !l.StartsWith("用法", StringComparison.Ordinal)
                && !l.Contains("LICENSE TERMS", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrWhiteSpace(fallback)) return null;
        return fallback.Length > 200 ? fallback[..200] : fallback;
    }

    /// <summary>兜底：从路径片段里抠版本号，例如 "C:\Tools\ghidra_12.1.4_PUBLIC" → "12.1.4"。</summary>
    private static string? TryParseVersionFromPath(string exePath)
    {
        try
        {
            var m = System.Text.RegularExpressions.Regex.Match(
                exePath, @"[_\-\s]v?(\d+\.\d+(?:\.\d+)*)");
            return m.Success ? m.Groups[1].Value : null;
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
