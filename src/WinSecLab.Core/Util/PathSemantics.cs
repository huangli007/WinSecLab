namespace WinSecLab.Core.Util;

/// <summary>路径语义判定：是否用户可写、是否系统目录。提权与 DLL 劫持判断的基础。</summary>
public static class PathSemantics
{
    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 = Path.Combine(WindowsDir, "System32");
    private static readonly string SysWow64 = Path.Combine(WindowsDir, "SysWOW64");
    private static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Temp = Path.GetTempPath();

    private static readonly string[] UserWritableRoots =
    {
        AppData, LocalAppData, ProgramData, Temp, UserProfile,
        @"C:\Users\Public", @"C:\Windows\Temp", @"C:\ProgramData",
    };

    /// <summary>普通用户无需提权即可写入的目录 —— 从这些位置加载代码是高风险信号。</summary>
    public static bool IsUserWritable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var full = SafeFullPath(path);

        // Windows 目录受 ACL 保护
        if (IsWindowsDirectory(full)) return false;

        // Program Files 必须按"任意盘符"判断，不能只比对系统盘的 ProgramFiles。
        // 否则 D:\Program Files\<厂商>\... 会被误判为"用户可写"，
        // 把正常安装的程序目录直接报成 DLL 劫持 / 提权风险 —— 实测踩过这个假阳性。
        if (IsProgramFiles(full)) return false;

        foreach (var root in UserWritableRoots)
        {
            if (string.IsNullOrEmpty(root)) continue;
            if (full.StartsWith(EnsureTrailingSeparator(root), StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (full.StartsWith(EnsureTrailingSeparator(ProgramData), StringComparison.OrdinalIgnoreCase)) return true;
        if (full.StartsWith(EnsureTrailingSeparator(Path.Combine(WindowsDir, "Temp")), StringComparison.OrdinalIgnoreCase)) return true;
        if (full.StartsWith(EnsureTrailingSeparator(UserProfile), StringComparison.OrdinalIgnoreCase)) return true;

        // 其余盘符路径（D:\Tools、C:\ 根目录、UNC 共享等）默认 ACL 允许普通用户创建文件
        return true;
    }

    public static bool IsWindowsDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var full = SafeFullPath(path);
        return full.StartsWith(EnsureTrailingSeparator(WindowsDir), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 是否落在 Program Files 下。按路径段判断，覆盖**任意盘符**的
    /// <c>X:\Program Files</c> 与 <c>X:\Program Files (x86)</c> ——
    /// 多盘机器上程序装在 D 盘是常态，只认系统盘会把整类目录判错。
    /// </summary>
    public static bool IsProgramFiles(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var full = SafeFullPath(path);

        if (full.StartsWith(EnsureTrailingSeparator(ProgramFiles), StringComparison.OrdinalIgnoreCase) ||
            full.StartsWith(EnsureTrailingSeparator(ProgramFilesX86), StringComparison.OrdinalIgnoreCase))
            return true;

        return ProgramFilesSegment.IsMatch(full);
    }

    /// <summary>匹配 X:\Program Files\... 或 X:\Program Files (x86)\...（不区分大小写）。</summary>
    private static readonly System.Text.RegularExpressions.Regex ProgramFilesSegment = new(
        @"^[A-Za-z]:\\Program Files( \(x86\))?(\\|$)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase |
        System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>是否 Windows 自带 / 已知的系统库，不算第三方依赖风险。</summary>
    public static bool IsKnownSystemLibrary(string moduleName)
    {
        var name = Path.GetFileName(moduleName).ToLowerInvariant();
        if (name.StartsWith("api-ms-win-", StringComparison.Ordinal)) return true;
        if (name.StartsWith("ext-ms-", StringComparison.Ordinal)) return true;
        return KnownSystemModules.Contains(name);
    }

    private static readonly HashSet<string> KnownSystemModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll", "gdi32full.dll",
        "advapi32.dll", "shell32.dll", "shlwapi.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
        "comctl32.dll", "comdlg32.dll", "msvcrt.dll", "ucrtbase.dll", "msvcp_win.dll",
        "ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "crypt32.dll", "bcrypt.dll",
        "ncrypt.dll", "secur32.dll", "sspicli.dll", "rpcrt4.dll", "version.dll", "psapi.dll",
        "setupapi.dll", "cfgmgr32.dll", "imm32.dll", "winmm.dll", "msimg32.dll", "dwmapi.dll",
        "uxtheme.dll", "d3d11.dll", "d3d9.dll", "dxgi.dll", "opengl32.dll", "glu32.dll",
        "userenv.dll", "profapi.dll", "winspool.drv", "wintrust.dll", "mpr.dll", "netapi32.dll",
        "iphlpapi.dll", "dnsapi.dll", "cryptui.dll", "wbemprox.dll", "wmiutils.dll",
        "ntoskrnl.exe", "hal.dll", "ntmarta.dll", "wevtapi.dll", "wtsapi32.dll", "sxs.dll",
        "propsys.dll", "winsta.dll", "authz.dll", "normaliz.dll", "schannel.dll", "cabinet.dll",
        "clbcatq.dll", "mscoree.dll", "windows.storage.dll", "shcore.dll", "twinapi.dll",
        "twinapi.appcore.dll", "powrprof.dll", "dnsapi.dll", "wlanapi.dll", "samcli.dll",
    };

    /// <summary>DLL 搜索顺序里容易被劫持的「当前目录」风险提示。</summary>
    public static bool IsDllHijackProneDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory)) return false;
        return IsUserWritable(directory);
    }

    public static string SafeFullPath(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path;
        }
    }

    private static string EnsureTrailingSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;

    /// <summary>把长路径压缩成报告中更易读的形式（保留盘符与末两级）。</summary>
    public static string Shorten(string? path, int maxLength = 72)
    {
        if (string.IsNullOrEmpty(path)) return "-";
        if (path.Length <= maxLength) return path;
        var parts = path.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 3) return path;
        var head = parts[0];
        var tail = string.Join(Path.DirectorySeparatorChar, parts.Skip(Math.Max(1, parts.Length - 2)));
        return $"{head}{Path.DirectorySeparatorChar}...{Path.DirectorySeparatorChar}{tail}";
    }

    /// <summary>与目标程序同目录、且在被测程序启动时可能被搜索到的可写 DLL（劫持风险预筛）。</summary>
    public static IEnumerable<string> EnumerateWritableDllsIn(string directory, int max = 200)
    {
        if (!Directory.Exists(directory)) yield break;
        var count = 0;
        foreach (var file in Directory.EnumerateFiles(directory, "*.dll", SearchOption.TopDirectoryOnly))
        {
            if (count++ >= max) yield break;
            yield return file;
        }
    }
}
