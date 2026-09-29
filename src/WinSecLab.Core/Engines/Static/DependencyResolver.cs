using System.Diagnostics;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Static;

/// <summary>
/// §3.3 Dependencies —— 解析导入表并定位磁盘上的实际 DLL。
/// 关键是标出「从用户可写目录加载」的依赖：这是 DLL 劫持与提权路径的经典入口。
/// </summary>
public sealed class DependencyResolver
{
    private static readonly string SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 = Path.Combine(SystemRoot, "System32");
    private static readonly string SysWow64 = Path.Combine(SystemRoot, "SysWOW64");

    public List<DependencyInfo> Resolve(PeImageInfo pe, IEnumerable<string>? searchDirectories = null)
    {
        var results = new List<DependencyInfo>();
        var targetDir = Path.GetDirectoryName(pe.FilePath) ?? "";
        var extraDirs = (searchDirectories ?? Array.Empty<string>()).Where(Directory.Exists).ToList();

        foreach (var module in pe.Imports.OrderBy(m => m.ModuleName, StringComparer.OrdinalIgnoreCase))
        {
            var info = new DependencyInfo { Name = module.ModuleName };

            // api-ms-win-* 是 API Set 虚拟模块，物理上不存在对应文件（或仅在 ApisetSchema 里）
            if (PathSemantics.IsKnownSystemLibrary(module.ModuleName))
            {
                info.IsSystemLibrary = true;
                var resolved = LocateInSystem(module.ModuleName, pe.Is64Bit);
                if (resolved is not null)
                {
                    info.ResolvedPath = resolved;
                    info.IsPresent = true;
                    info.SearchSource = resolved.StartsWith(SysWow64, StringComparison.OrdinalIgnoreCase) ? "SysWOW64" : "System32";
                    FillMetadata(info, resolved, computeHash: false);
                }
                else
                {
                    info.IsPresent = false;
                    info.SearchSource = "API Set / 虚拟模块";
                }
                results.Add(info);
                continue;
            }

            // 1) 与被测程序同目录（Windows 默认搜索顺序最高优先级之一）
            var sameDir = Path.Combine(targetDir, module.ModuleName);
            if (File.Exists(sameDir))
            {
                info.ResolvedPath = sameDir;
                info.IsPresent = true;
                info.SearchSource = "应用目录";
                info.IsUserWritableLocation = PathSemantics.IsUserWritable(sameDir);
                FillMetadata(info, sameDir);
                results.Add(info);
                continue;
            }

            // 2) 显式子目录（dependencies/ 等）
            string? found = null;
            foreach (var dir in extraDirs)
            {
                var candidate = Path.Combine(dir, module.ModuleName);
                if (File.Exists(candidate))
                {
                    found = candidate;
                    info.SearchSource = "附加搜索目录";
                    break;
                }
            }

            // 3) 系统目录
            found ??= LocateInSystem(module.ModuleName, pe.Is64Bit);
            if (found is not null && info.SearchSource.Length == 0)
            {
                info.SearchSource = found.StartsWith(SysWow64, StringComparison.OrdinalIgnoreCase) ? "SysWOW64" : "System32";
                info.IsSystemLibrary = true;
            }

            if (found is not null)
            {
                info.ResolvedPath = found;
                info.IsPresent = true;
                if (!info.IsSystemLibrary)
                    info.IsUserWritableLocation = PathSemantics.IsUserWritable(found);
                FillMetadata(info, found);
            }
            else
            {
                info.IsPresent = false;
                info.SearchSource = "未找到";
            }

            results.Add(info);
        }

        return results;
    }

    private static string? LocateInSystem(string moduleName, bool is64Bit)
    {
        var primary = is64Bit ? System32 : SysWow64;
        var fallback = is64Bit ? SysWow64 : System32;

        var p = Path.Combine(primary, moduleName);
        if (File.Exists(p)) return p;

        p = Path.Combine(fallback, moduleName);
        if (File.Exists(p)) return p;

        return null;
    }

    private static void FillMetadata(DependencyInfo info, string path, bool computeHash = true)
    {
        try
        {
            var fvi = FileVersionInfo.GetVersionInfo(path);
            info.Version = string.IsNullOrWhiteSpace(fvi.FileVersion) ? fvi.ProductVersion : fvi.FileVersion;
            info.Company = string.IsNullOrWhiteSpace(fvi.CompanyName) ? null : fvi.CompanyName;
        }
        catch
        {
            // 无版本资源
        }

        try
        {
            var sign = SignatureVerifier.Verify(path);
            info.IsSigned = sign.IsSignatureValid;
        }
        catch
        {
            info.IsSigned = null;
        }

        if (computeHash)
            info.Sha256 = Hashing.Sha256File(path);
    }

    /// <summary>列出目标目录下所有 DLL 及其签名状态（用于识别随包分发的第三方组件）。</summary>
    public static List<SupplementaryFile> ListCoLocatedBinaries(string targetDirectory, int max = 400)
    {
        var list = new List<SupplementaryFile>();
        if (!Directory.Exists(targetDirectory)) return list;

        foreach (var file in Directory.EnumerateFiles(targetDirectory)
                     .Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                                 f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                                 f.EndsWith(".node", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                     .Take(max))
        {
            try
            {
                var fi = new FileInfo(file);
                list.Add(new SupplementaryFile
                {
                    Path = file,
                    FileName = fi.Name,
                    Size = fi.Length,
                    Sha256 = "",
                    Role = "同目录二进制",
                });
            }
            catch
            {
                // 文件被占用或无权限
            }
        }

        return list;
    }
}
