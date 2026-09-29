namespace WinSecLab.Core.Models;

/// <summary>单个 PE 节区信息（含熵值与内存权限）。</summary>
public sealed class PeSection
{
    public string Name { get; set; } = "";
    public uint VirtualAddress { get; set; }
    public uint VirtualSize { get; set; }
    public uint RawOffset { get; set; }
    public uint RawSize { get; set; }
    public uint Characteristics { get; set; }
    public double Entropy { get; set; }
    public double EntropyRatio { get; set; }

    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsReadable => (Characteristics & 0x40000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
    public bool IsInitializedData => (Characteristics & 0x00000040) != 0;

    /// <summary>形如 "R-X / RWX"，RWX 是重点嫌疑。</summary>
    public string Permissions =>
        string.Concat(IsReadable ? "R" : "-", IsWritable ? "W" : "-", IsExecutable ? "X" : "-");

    public bool IsWritableAndExecutable => IsWritable && IsExecutable;

    /// <summary>高熵阈值：7.2 以上通常意味着加壳 / 压缩 / 加密载荷。</summary>
    public bool IsHighEntropy => Entropy >= 7.2 && RawSize >= 4096;

    public double RawEntropyBits => Entropy * RawSize;
}

/// <summary>导入表中的函数。</summary>
public sealed class PeImportFunction
{
    public string Name { get; set; } = "";
    public ushort? Ordinal { get; set; }
    public bool ByOrdinal => string.IsNullOrEmpty(Name) || Name.StartsWith("Ordinal_", StringComparison.Ordinal);
}

/// <summary>按 DLL 归组的导入项。</summary>
public sealed class PeImportModule
{
    public string ModuleName { get; set; } = "";
    public List<PeImportFunction> Functions { get; set; } = new();
    public int FunctionCount => Functions.Count;
    public List<string> DelayLoadFunctions { get; set; } = new();
}

/// <summary>导出项。</summary>
public sealed class PeExport
{
    public string Name { get; set; } = "";
    public uint Ordinal { get; set; }
    public uint Rva { get; set; }
    public bool IsForwarder { get; set; }
    public string? ForwarderTarget { get; set; }
}

/// <summary>资源目录条目（资源类型摘要）。</summary>
public sealed class PeResourceEntry
{
    public string Type { get; set; } = "";
    public string? Name { get; set; }
    public uint Size { get; set; }
    public uint CodePage { get; set; }
    public string Language { get; set; } = "";
}

/// <summary>数字签名验证详情。</summary>
public sealed class SignatureInfo
{
    public SignatureStatus Status { get; set; } = SignatureStatus.Unavailable;
    public string StatusText { get; set; } = "未检测";
    public string? SignerSubject { get; set; }
    public string? SignerIssuer { get; set; }
    public string? SignerThumbprint { get; set; }
    public DateTime? NotBefore { get; set; }
    public DateTime? NotAfter { get; set; }
    public bool IsTimestamped { get; set; }
    public string? TimestampAuthority { get; set; }
    public List<string> ChainIssues { get; set; } = new();
    public long WinVerifyTrustResult { get; set; }

    public bool IsSignatureValid => Status is SignatureStatus.Valid or SignatureStatus.ValidButUntrusted;
    public string Display => SignerSubject is { Length: > 0 } s ? $"{StatusText} — {ShortName(s)}" : StatusText;

    private static string ShortName(string subject)
    {
        foreach (var part in subject.Split(','))
        {
            var t = part.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return t.Substring(3).Trim('"');
        }
        return subject;
    }
}

/// <summary>版本资源。</summary>
public sealed class FileVersionInfoLite
{
    public string? FileVersion { get; set; }
    public string? ProductVersion { get; set; }
    public string? ProductName { get; set; }
    public string? CompanyName { get; set; }
    public string? FileDescription { get; set; }
    public string? OriginalFileName { get; set; }
    public string? InternalName { get; set; }
    public string? LegalCopyright { get; set; }
    public bool IsDebugBuild { get; set; }
}

/// <summary>Rich Header 解析结果 —— 用于推断真实编译器 / 链接器版本并发现修补痕迹。</summary>
public sealed class RichHeaderInfo
{
    public bool Present { get; set; }
    public List<(uint ProductId, uint Build)> Entries { get; set; } = new();
    public uint XorKey { get; set; }
    /// <summary>重写工具（如 LordPE、CFF Explorer）常常清掉 Rich Header，缺失即为可疑信号。</summary>
    public bool Stripped => !Present;
    public string Summary { get; set; } = "";
}

/// <summary>一个 PE 文件的完整静态画像。</summary>
public sealed class PeImageInfo
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public string Sha256 { get; set; } = "";
    public string Md5 { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string ImpHash { get; set; } = "";
    public string? AuthentiHash { get; set; }

    public bool IsValidPe { get; set; }
    public string? ParseError { get; set; }

    public string Machine { get; set; } = "";
    public string Architecture { get; set; } = "";
    public bool Is64Bit { get; set; }
    public string Subsystem { get; set; } = "";
    public string ClrImageKind { get; set; } = "";
    public string Characteristics { get; set; } = "";
    public string DllCharacteristics { get; set; } = "";
    public DateTime? TimeDateStamp { get; set; }
    public bool TimeStampIsPlausible { get; set; } = true;
    /// <summary>MSVC /Brepro 可复现构建会把时间戳写成基于哈希的伪值，通常落在 1970–1990 年间。</summary>
    public bool IsReproducibleBuildStamp { get; set; }
    public ushort LinkerMajor { get; set; }
    public ushort LinkerMinor { get; set; }
    public string Compiler { get; set; } = "unknown";
    public string CompilerEvidence { get; set; } = "";
    public uint EntryPointRva { get; set; }
    public ulong ImageBase { get; set; }
    public bool IsDotNet { get; set; }
    public string? DotNetRuntimeVersion { get; set; }
    public string? DotNetFlags { get; set; }
    public bool IsSigned => Signature.IsSignatureValid;
    public bool IsNativeAot { get; set; }

    public bool IsDll { get; set; }
    public bool IsDriver { get; set; }
    public bool IsInstallerPackage { get; set; }
    public bool HasOverlay { get; set; }
    public long OverlaySize { get; set; }
    public double OverlayEntropy { get; set; }
    public double OverallEntropy { get; set; }

    public List<PeSection> Sections { get; set; } = new();
    public List<PeImportModule> Imports { get; set; } = new();
    public List<(string Module, string Function)> DelayImports { get; set; } = new();
    public List<PeExport> Exports { get; set; } = new();
    public List<PeResourceEntry> Resources { get; set; } = new();
    public List<string> DebugPaths { get; set; } = new();
    public List<string> LoadedPdbPaths { get; set; } = new();

    public SignatureInfo Signature { get; set; } = new();
    public FileVersionInfoLite Version { get; set; } = new();
    public RichHeaderInfo RichHeader { get; set; } = new();

    public int ImportedDllCount => Imports.Count;
    public int ImportedFunctionCount => Imports.Sum(m => m.FunctionCount);
    public int ExportCount => Exports.Count;
    public string ImportHashShort => ImpHash.Length > 16 ? ImpHash[..16] : ImpHash;
}

/// <summary>磁盘上的依赖 DLL 情况（§3.3 Dependencies）。</summary>
public sealed class DependencyInfo
{
    public string Name { get; set; } = "";
    public string? ResolvedPath { get; set; }
    public bool IsPresent { get; set; }
    public bool IsSystemLibrary { get; set; }
    /// <summary>是否从可写目录（AppData / Temp / ProgramData）加载 —— 提权/劫持的高危信号。</summary>
    public bool IsUserWritableLocation { get; set; }
    public string? Version { get; set; }
    public string? Company { get; set; }
    public bool? IsSigned { get; set; }
    public string SearchSource { get; set; } = "";
    public string? Sha256 { get; set; }
}

/// <summary>一条字符串命中，附带所在节区与偏移，便于回溯原始证据。</summary>
public sealed class StringHit
{
    public string Value { get; set; } = "";
    public long Offset { get; set; }
    public string Section { get; set; } = "";
    public bool IsUnicode { get; set; }
    public string Encoding => IsUnicode ? "UTF-16LE" : "ASCII";
    public string Category { get; set; } = "General";
}

/// <summary>.NET 程序集元数据摘要（§3.4）。</summary>
public sealed class DotNetAssemblyInfo
{
    public bool IsDotNet { get; set; }
    public string? AssemblyName { get; set; }
    public string? AssemblyVersion { get; set; }
    public string? TargetFramework { get; set; }
    public string? RuntimeVersion { get; set; }
    public string? ModuleName { get; set; }
    public bool IsExecutable { get; set; }
    public bool IsManagedEntryPoint { get; set; }
    public bool IsSingleFileBundle { get; set; }
    public bool IsReadyToRun { get; set; }
    public bool IsNativeAot { get; set; }
    public string? EntryPointToken { get; set; }

    public List<DotNetNamespace> Namespaces { get; set; } = new();
    public List<string> ReferencedAssemblies { get; set; } = new();
    public List<string> CustomAttributes { get; set; } = new();
    public List<string> Resources { get; set; } = new();
    public List<DotNetMethodRef> MethodReferences { get; set; } = new();

    public int TypeCount => Namespaces.Sum(n => n.Types.Count);
    public int MethodCount => Namespaces.Sum(n => n.Types.Sum(t => t.Methods.Count));
    public int FieldCount => Namespaces.Sum(n => n.Types.Sum(t => t.Fields.Count));
    public int PropertyCount => Namespaces.Sum(n => n.Types.Sum(t => t.Properties.Count));
    public int EventCount => Namespaces.Sum(n => n.Types.Sum(t => t.Events.Count));
    /// <summary>是否检测到可被 ILSpy/dnSpy 直接反编译的托管代码（相对 NativeAOT / 单文件加密）。</summary>
    public bool Decompilable { get; set; }
    public bool UsesObfuscation { get; set; }
    public List<string> ObfuscationHints { get; set; } = new();
}

public sealed class DotNetNamespace
{
    public string Name { get; set; } = "";
    public List<DotNetType> Types { get; set; } = new();
}

public sealed class DotNetType
{
    public string Name { get; set; } = "";
    public string FullName { get; set; } = "";
    public string Accessibility { get; set; } = "public";
    public bool IsInterface { get; set; }
    public bool IsEnum { get; set; }
    public bool IsValueType { get; set; }
    public bool IsDelegate { get; set; }
    public string? BaseType { get; set; }
    public List<string> Interfaces { get; set; } = new();
    public List<DotNetMember> Methods { get; set; } = new();
    public List<DotNetMember> Properties { get; set; } = new();
    public List<DotNetMember> Fields { get; set; } = new();
    public List<DotNetMember> Events { get; set; } = new();
}

public sealed class DotNetMember
{
    public string Name { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Accessibility { get; set; } = "";
    public string? Signature { get; set; }
}

public sealed class DotNetMethodRef
{
    public string Namespace { get; set; } = "";
    public string TypeName { get; set; } = "";
    public string MethodName { get; set; } = "";
    public string Display => string.IsNullOrEmpty(TypeName) ? MethodName : $"{TypeName}.{MethodName}";
}
