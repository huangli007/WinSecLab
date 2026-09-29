using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Static;

/// <summary>
/// §3.3 静态分析中心 —— PE 解析器。
/// 头部信息走 System.Reflection.PortableExecutable；导入 / 导出 / 资源 / Rich Header
/// 在 .NET 里没有公开 API，这里按 PE/COFF 规范自行解析，保证结果可回溯到文件偏移。
/// </summary>
public sealed class PeAnalyzer
{
    /// <summary>超过此大小则只做头部解析，避免把数 GB 的文件读进内存。</summary>
    public const long MaxFullParseSize = 384L * 1024 * 1024;

    public PeImageInfo Analyze(string filePath, bool computeSignature = true)
    {
        var info = new PeImageInfo
        {
            FilePath = PathSemantics.SafeFullPath(filePath),
            FileName = Path.GetFileName(filePath),
        };

        FileInfo fi;
        try
        {
            fi = new FileInfo(info.FilePath);
            if (!fi.Exists)
            {
                info.ParseError = "文件不存在或无法访问";
                return info;
            }
            info.FileSize = fi.Length;
        }
        catch (Exception ex)
        {
            info.ParseError = $"读取文件信息失败：{ex.Message}";
            return info;
        }

        var (sha256, md5, sha1) = Hashing.HashAll(info.FilePath);
        info.Sha256 = sha256;
        info.Md5 = md5;
        info.Sha1 = sha1;

        ReadVersionResource(info);
        if (computeSignature)
            info.Signature = SignatureVerifier.Verify(info.FilePath);

        if (info.FileSize > MaxFullParseSize)
        {
            info.ParseError = $"文件过大（{info.FileSize / 1024 / 1024} MB），已跳过深度 PE 解析";
            info.IsValidPe = false;
            return info;
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(info.FilePath);
        }
        catch (Exception ex)
        {
            info.ParseError = $"读取文件失败：{ex.Message}";
            return info;
        }

        try
        {
            ParseCore(info, bytes);
        }
        catch (BadImageFormatException)
        {
            info.IsValidPe = false;
            info.ParseError = "不是有效的 PE 文件（BadImageFormat）";
        }
        catch (Exception ex)
        {
            info.IsValidPe = false;
            info.ParseError = $"PE 解析失败：{ex.GetType().Name}: {ex.Message}";
        }

        info.OverallEntropy = Util.Entropy.Shannon(bytes.AsSpan(0, (int)Math.Min(bytes.Length, 4 * 1024 * 1024)));
        return info;
    }

    // ---------------------------------------------------------------- 主解析

    private static void ParseCore(PeImageInfo info, byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var headers = reader.PEHeaders;
        var coff = headers.CoffHeader;
        var opt = headers.PEHeader;

        if (coff is null || opt is null)
        {
            info.IsValidPe = false;
            info.ParseError = "缺少 COFF / Optional Header";
            return;
        }

        info.IsValidPe = true;
        info.Is64Bit = opt.Magic == PEMagic.PE32Plus;
        info.Machine = coff.Machine.ToString();
        info.Architecture = DescribeMachine(coff.Machine);
        info.Subsystem = opt.Subsystem.ToString();
        info.ClrImageKind = opt.Magic.ToString();
        info.Characteristics = DescribeCoffCharacteristics(coff.Characteristics);
        info.DllCharacteristics = DescribeDllCharacteristics(opt.DllCharacteristics);
        info.LinkerMajor = opt.MajorLinkerVersion;
        info.LinkerMinor = opt.MinorLinkerVersion;
        info.EntryPointRva = (uint)opt.AddressOfEntryPoint;
        info.ImageBase = opt.ImageBase;
        info.IsDll = headers.IsDll;
        info.IsDriver = coff.Characteristics.HasFlag(Characteristics.System);

        if (coff.TimeDateStamp > 0)
        {
            try
            {
                var ts = DateTimeOffset.FromUnixTimeSeconds(coff.TimeDateStamp).LocalDateTime;
                info.TimeDateStamp = ts;
                var now = DateTime.Now.AddDays(2);
                var floor = new DateTime(1992, 1, 1);
                info.TimeStampIsPlausible = ts >= floor && ts <= now;
                // MSVC /Brepro 与 Go 的确定性构建会写入基于哈希的伪时间戳
                info.IsReproducibleBuildStamp = !info.TimeStampIsPlausible && ts < floor;
            }
            catch (ArgumentOutOfRangeException)
            {
                info.TimeStampIsPlausible = false;
            }
        }

        // 节区 + 熵
        foreach (var section in headers.SectionHeaders)
        {
            var name = section.Name ?? "";
            var peSection = new PeSection
            {
                Name = name,
                VirtualAddress = (uint)section.VirtualAddress,
                VirtualSize = (uint)section.VirtualSize,
                RawOffset = (uint)section.PointerToRawData,
                RawSize = (uint)section.SizeOfRawData,
                Characteristics = (uint)section.SectionCharacteristics,
            };

            if (section.SizeOfRawData > 0 && section.PointerToRawData >= 0 &&
                section.PointerToRawData + section.SizeOfRawData <= bytes.Length)
            {
                var raw = bytes.AsSpan(section.PointerToRawData, section.SizeOfRawData);
                var sample = raw.Length > 8 * 1024 * 1024 ? raw[..(8 * 1024 * 1024)] : raw;
                peSection.Entropy = Util.Entropy.Shannon(sample);
                peSection.EntropyRatio = Util.Entropy.Ratio(peSection.Entropy);
            }
            info.Sections.Add(peSection);
        }

        // 导入表
        var importTable = ParseImports(bytes, headers, opt.ImportTableDirectory);
        info.Imports = importTable.Modules;
        info.DelayImports = importTable.DelayLoaded;

        // 导出表
        info.Exports = ParseExports(bytes, headers, opt.ExportTableDirectory);

        // 资源目录
        info.Resources = ParseResources(bytes, headers, opt.ResourceTableDirectory);

        // 调试信息（PDB 路径）
        ReadDebugInfo(reader, info);

        // Rich Header
        info.RichHeader = ReadRichHeader(bytes, headers.PEHeaderStartOffset);

        // .NET / NativeAOT
        info.IsDotNet = headers.CorHeader is not null;
        if (headers.CorHeader is not null)
        {
            var cor = headers.CorHeader;
            info.DotNetRuntimeVersion = $"{cor.MajorRuntimeVersion}.{cor.MinorRuntimeVersion}";
            var flags = new List<string>();
            if (cor.Flags.HasFlag(CorFlags.ILOnly)) flags.Add("ILOnly");
            if (cor.Flags.HasFlag(CorFlags.Requires32Bit)) flags.Add("Requires32Bit");
            if (cor.Flags.HasFlag(CorFlags.Prefers32Bit)) flags.Add("Prefers32Bit");
            if (cor.Flags.HasFlag(CorFlags.NativeEntryPoint)) flags.Add("NativeEntryPoint");
            if (cor.Flags.HasFlag(CorFlags.ILLibrary)) flags.Add("ILLibrary");
            info.DotNetFlags = string.Join(" | ", flags);
            info.IsNativeAot = cor.Flags.HasFlag(CorFlags.NativeEntryPoint);
        }

        // 覆盖区（overlay）
        ComputeOverlay(info, bytes);

        // 编译器推断
        InferCompiler(info, headers);

        // imphash
        info.ImpHash = Hashing.ImportHash(info.Imports.SelectMany(m => m.Functions.Select(f => (m.ModuleName, f.Name))));

        // 安装包特征
        info.IsInstallerPackage = DetectInstaller(info);
    }

    private static string DescribeMachine(Machine machine) => machine switch
    {
        Machine.Amd64 => "x64",
        Machine.I386 => "x86",
        Machine.Arm64 => "ARM64",
        Machine.Arm => "ARM",
        Machine.IA64 => "IA64",
        _ => machine.ToString(),
    };

    private static string DescribeCoffCharacteristics(Characteristics c)
    {
        var parts = new List<string>();
        if (c.HasFlag(Characteristics.ExecutableImage)) parts.Add("Executable");
        if (c.HasFlag(Characteristics.Dll)) parts.Add("DLL");
        if (c.HasFlag(Characteristics.System)) parts.Add("System");
        if (c.HasFlag(Characteristics.LargeAddressAware)) parts.Add("LargeAddressAware");
        if (c.HasFlag(Characteristics.Bit32Machine)) parts.Add("32BitMachine");
        if (c.HasFlag(Characteristics.BytesReversedLo)) parts.Add("BytesReversedLo");
        if (c.HasFlag(Characteristics.BytesReversedHi)) parts.Add("BytesReversedHi");
        return string.Join(" | ", parts);
    }

    /// <summary>直接用原始位掩码判断，避免跟随 .NET 枚举成员的改名。</summary>
    private static string DescribeDllCharacteristics(DllCharacteristics c)
    {
        var raw = (ushort)c;
        var parts = new List<string>();
        if ((raw & 0x0040) != 0) parts.Add("ASLR");
        if ((raw & 0x0100) != 0) parts.Add("DEP");
        if ((raw & 0x0080) != 0) parts.Add("ForceIntegrity");
        if ((raw & 0x0400) != 0) parts.Add("NoSEH");
        if ((raw & 0x0800) != 0) parts.Add("NoBind");
        if ((raw & 0x8000) != 0) parts.Add("TSAware");
        if ((raw & 0x0020) != 0) parts.Add("HighEntropyVA");
        if ((raw & 0x4000) != 0) parts.Add("CFG");
        if ((raw & 0x1000) != 0) parts.Add("AppContainer");
        if ((raw & 0x2000) != 0) parts.Add("WdmDriver");
        return string.Join(" | ", parts);
    }

    // ------------------------------------------------------------- 导入表

    private sealed record ImportTableResult(List<PeImportModule> Modules, List<(string Module, string Function)> DelayLoaded);

    private static ImportTableResult ParseImports(byte[] bytes, PEHeaders headers, DirectoryEntry importDir)
    {
        var modules = new List<PeImportModule>();
        var delayLoaded = new List<(string, string)>();

        if (importDir.Size <= 0 || importDir.RelativeVirtualAddress <= 0) return new(modules, delayLoaded);

        var descriptorOffset = RvaToOffset(headers, (uint)importDir.RelativeVirtualAddress);
        if (descriptorOffset < 0) return new(modules, delayLoaded);

        var ptrSize = headers.PEHeader!.Magic == PEMagic.PE32Plus ? 8 : 4;
        var ordinalFlag = ptrSize == 8 ? 0x8000000000000000UL : 0x80000000UL;

        for (var i = 0; i < 4096; i++)
        {
            var baseOffset = descriptorOffset + i * 20;
            if (baseOffset + 20 > bytes.Length) break;

            var originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(baseOffset));
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(baseOffset + 12));
            var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(baseOffset + 16));

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;
            if (nameRva == 0) break;

            var nameOffset = RvaToOffset(headers, nameRva);
            var moduleName = nameOffset >= 0 ? ReadAsciiZ(bytes, nameOffset, 512) : $"rva_{nameRva:X}";

            var module = new PeImportModule { ModuleName = moduleName };
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var thunkOffset = RvaToOffset(headers, thunkRva);

            if (thunkOffset >= 0)
            {
                for (var j = 0; j < 8192; j++)
                {
                    var to = thunkOffset + j * ptrSize;
                    if (to + ptrSize > bytes.Length) break;

                    var value = ptrSize == 8
                        ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(to))
                        : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(to));

                    if (value == 0) break;

                    if ((value & ordinalFlag) != 0)
                    {
                        module.Functions.Add(new PeImportFunction { Name = $"Ordinal_{value & 0xFFFF}", Ordinal = (ushort)(value & 0xFFFF) });
                    }
                    else
                    {
                        var hintNameOffset = RvaToOffset(headers, (uint)value);
                        if (hintNameOffset < 0 || hintNameOffset + 2 >= bytes.Length) break;
                        module.Functions.Add(new PeImportFunction { Name = ReadAsciiZ(bytes, hintNameOffset + 2, 512) });
                    }
                }
            }

            modules.Add(module);
        }

        // 延迟导入表
        var delayDir = headers.PEHeader.DelayImportTableDirectory;
        if (delayDir.Size > 0 && delayDir.RelativeVirtualAddress > 0)
        {
            var delayOffset = RvaToOffset(headers, (uint)delayDir.RelativeVirtualAddress);
            if (delayOffset >= 0)
            {
                for (var i = 0; i < 1024; i++)
                {
                    var b = delayOffset + i * 32;
                    if (b + 32 > bytes.Length) break;
                    var attributes = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(b));
                    var dllName = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(b + 4));
                    var importNameTable = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(b + 16));
                    if (dllName == 0 && importNameTable == 0) break;

                    var useRva = (attributes & 1) != 0;
                    var dllNameRva = useRva ? dllName : dllName - (uint)headers.PEHeader.ImageBase;
                    var dllOffset = RvaToOffset(headers, dllNameRva);
                    var dll = dllOffset >= 0 ? ReadAsciiZ(bytes, dllOffset, 512) : $"delay_rva_{dllName:X}";

                    var existing = modules.FirstOrDefault(m => string.Equals(m.ModuleName, dll, StringComparison.OrdinalIgnoreCase));
                    if (existing is null)
                    {
                        existing = new PeImportModule { ModuleName = dll };
                        modules.Add(existing);
                    }
                    existing.DelayLoadFunctions.Add(dll);
                    delayLoaded.Add((dll, "延迟加载"));
                }
            }
        }

        return new(modules, delayLoaded);
    }

    // ------------------------------------------------------------- 导出表

    private static List<PeExport> ParseExports(byte[] bytes, PEHeaders headers, DirectoryEntry exportDir)
    {
        var exports = new List<PeExport>();
        if (exportDir.Size <= 0 || exportDir.RelativeVirtualAddress <= 0) return exports;

        var offset = RvaToOffset(headers, (uint)exportDir.RelativeVirtualAddress);
        if (offset < 0 || offset + 40 > bytes.Length) return exports;

        var ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 16));
        var numberOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 20));
        var numberOfNames = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 24));
        var addressOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 28));
        var addressOfNames = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 32));
        var addressOfNameOrdinals = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 36));

        if (numberOfFunctions > 100_000) return exports;

        var funcOffset = RvaToOffset(headers, addressOfFunctions);
        var nameOffsetBase = RvaToOffset(headers, addressOfNames);
        var ordinalOffsetBase = RvaToOffset(headers, addressOfNameOrdinals);

        var byIndex = new Dictionary<uint, string>();
        if (nameOffsetBase >= 0 && ordinalOffsetBase >= 0)
        {
            for (var i = 0; i < numberOfNames; i++)
            {
                var no = nameOffsetBase + i * 4;
                var oo = ordinalOffsetBase + i * 2;
                if (no + 4 > bytes.Length || oo + 2 > bytes.Length) break;
                var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(no));
                var index = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(oo));
                var nOff = RvaToOffset(headers, nameRva);
                if (nOff >= 0) byIndex[index] = ReadAsciiZ(bytes, nOff, 512);
            }
        }

        if (funcOffset < 0) return exports;

        var exportSection = headers.SectionHeaders.FirstOrDefault(s =>
            addressOfFunctions >= (uint)s.VirtualAddress &&
            addressOfFunctions < (uint)s.VirtualAddress + (uint)Math.Max(s.VirtualSize, s.SizeOfRawData));

        for (var i = 0u; i < numberOfFunctions && i < 65_536; i++)
        {
            var fo = funcOffset + (int)i * 4;
            if (fo + 4 > bytes.Length) break;
            var rva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(fo));
            if (rva == 0) continue;

            var name = byIndex.TryGetValue(i, out var n) ? n : $"Ordinal_{ordinalBase + i}";
            var entry = new PeExport
            {
                Name = name,
                Ordinal = ordinalBase + i,
                Rva = rva,
            };

            // 前向导出：RVA 落在导出节内则指向一个 "DLL.Function" 字符串
            if (exportSection.Name is not null)
            {
                var secStart = (uint)exportSection.VirtualAddress;
                var secEnd = secStart + (uint)Math.Max(exportSection.VirtualSize, exportSection.SizeOfRawData);
                if (rva >= secStart && rva < secEnd)
                {
                    var fwdOffset = RvaToOffset(headers, rva);
                    if (fwdOffset >= 0)
                    {
                        var target = ReadAsciiZ(bytes, fwdOffset, 256);
                        if (target.Contains('.') && !target.Contains('/') && !target.Contains('\\'))
                        {
                            entry.IsForwarder = true;
                            entry.ForwarderTarget = target;
                        }
                    }
                }
            }

            exports.Add(entry);
        }

        return exports;
    }

    // ------------------------------------------------------------- 资源目录

    private static List<PeResourceEntry> ParseResources(byte[] bytes, PEHeaders headers, DirectoryEntry resourceDir)
    {
        var result = new List<PeResourceEntry>();
        if (resourceDir.Size <= 0 || resourceDir.RelativeVirtualAddress <= 0) return result;

        var rootOffset = RvaToOffset(headers, (uint)resourceDir.RelativeVirtualAddress);
        if (rootOffset < 0) return result;

        var budget = 500;
        WalkResourceDirectory(bytes, rootOffset, rootOffset, 0, new List<string>(), result, ref budget);
        return result;
    }

    private static void WalkResourceDirectory(byte[] bytes, int directoryOffset, int rootOffset, int level,
        List<string> path, List<PeResourceEntry> result, ref int budget)
    {
        if (level > 3 || budget <= 0) return;
        if (directoryOffset < 0 || directoryOffset + 16 > bytes.Length) return;

        var namedEntries = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(directoryOffset + 12));
        var idEntries = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(directoryOffset + 14));

        for (var i = 0; i < namedEntries + idEntries && budget > 0; i++)
        {
            var entryOffset = directoryOffset + 16 + i * 8;
            if (entryOffset + 8 > bytes.Length) return;

            var nameOrId = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(entryOffset));
            var offsetToData = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(entryOffset + 4));

            var label = (nameOrId & 0x80000000) != 0
                ? ReadUtf16Z(bytes, rootOffset + (int)(nameOrId & 0x7FFFFFFF), 128)
                : DescribeResourceId(level, nameOrId);

            var newPath = new List<string>(path) { label };

            if ((offsetToData & 0x80000000) != 0)
            {
                WalkResourceDirectory(bytes, rootOffset + (int)(offsetToData & 0x7FFFFFFF), rootOffset,
                    level + 1, newPath, result, ref budget);
            }
            else
            {
                var dataEntryOffset = rootOffset + (int)offsetToData;
                if (dataEntryOffset + 16 > bytes.Length) return;
                var dataRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(dataEntryOffset));
                var size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(dataEntryOffset + 4));
                var codePage = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(dataEntryOffset + 8));

                result.Add(new PeResourceEntry
                {
                    Type = newPath.Count > 0 ? newPath[0] : "UNKNOWN",
                    Name = newPath.Count > 2 ? string.Join(" / ", newPath.Skip(1)) : newPath.LastOrDefault(),
                    Size = size,
                    CodePage = codePage,
                    Language = newPath.Count >= 3 ? newPath[^1] : "",
                });
                budget--;
            }
        }
    }

    private static string DescribeResourceId(int level, uint id) => level switch
    {
        0 => id switch
        {
            1 => "CURSOR", 2 => "BITMAP", 3 => "ICON", 4 => "MENU", 5 => "DIALOG",
            6 => "STRING", 7 => "FONTDIR", 8 => "FONT", 9 => "ACCELERATOR", 10 => "RCDATA",
            11 => "MESSAGETABLE", 12 => "GROUP_CURSOR", 14 => "GROUP_ICON", 16 => "VERSION",
            17 => "DLGINCLUDE", 19 => "PLUGPLAY", 20 => "VXD", 21 => "ANICURSOR", 22 => "ANIICON",
            23 => "HTML", 24 => "MANIFEST",
            _ => id.ToString(),
        },
        1 => id == 0 ? "ID_0" : id.ToString(),
        _ => id.ToString(),
    };

    // ------------------------------------------------------------- 调试信息

    private static void ReadDebugInfo(PEReader reader, PeImageInfo info)
    {
        try
        {
            foreach (var entry in reader.ReadDebugDirectory())
            {
                if (entry.Type == DebugDirectoryEntryType.CodeView)
                {
                    try
                    {
                        var cv = reader.ReadCodeViewDebugDirectoryData(entry);
                        if (!string.IsNullOrWhiteSpace(cv.Path) && !info.DebugPaths.Contains(cv.Path))
                            info.DebugPaths.Add(cv.Path);
                    }
                    catch
                    {
                        // 个别编译器写入的 CodeView 记录不合法，忽略
                    }
                }
            }
        }
        catch
        {
            // 无调试目录
        }
    }

    // ------------------------------------------------------------ Rich Header

    /// <summary>
    /// Rich Header 位于 DOS stub 与 PE 头之间，用 "Rich" 之后的 4 字节做 XOR 密钥加密。
    /// 它是编译器指纹，同时也是「文件是否被工具重写过」的有力证据（多数重写工具会丢弃它）。
    /// </summary>
    internal static RichHeaderInfo ReadRichHeader(byte[] bytes, int peHeaderOffset)
    {
        var info = new RichHeaderInfo();
        var searchEnd = Math.Min(peHeaderOffset, bytes.Length);
        if (searchEnd <= 0x80) { info.Summary = "无 Rich Header（DOS stub 过短）"; return info; }

        var richOffset = -1;
        for (var i = 0x80; i + 8 <= searchEnd; i++)
        {
            if (bytes[i] == (byte)'R' && bytes[i + 1] == (byte)'i' && bytes[i + 2] == (byte)'c' && bytes[i + 3] == (byte)'h')
            {
                richOffset = i;
                break;
            }
        }

        if (richOffset < 0) { info.Summary = "无 Rich Header（被剥离或被非 MSVC 工具链生成）"; return info; }

        info.Present = true;
        if (richOffset + 8 > bytes.Length) return info;
        var xorKey = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(richOffset + 4));
        info.XorKey = xorKey;

        // 从 Rich 往前找 XOR 后的 "DanS" （DanS ^ key）
        var dansEncoded = 0x536E6144u ^ xorKey;
        var dansOffset = -1;
        for (var i = richOffset - 4; i >= 0x40; i -= 4)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)) == dansEncoded)
            {
                dansOffset = i;
                break;
            }
        }

        var start = dansOffset >= 0 ? dansOffset + 16 : richOffset;
        var entries = new List<(uint ProductId, uint Build)>();
        for (var i = start; i + 8 <= richOffset; i += 8)
        {
            // 每条 8 字节：comp.id = (productId << 16) | build，后跟使用次数，两者都 XOR 过
            var compId = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)) ^ xorKey;
            var productId = compId >> 16;
            var build = compId & 0xFFFF;
            if (compId == 0) continue;
            entries.Add((productId, build));
            if (entries.Count >= 256) break;
        }

        info.Entries = entries;
        info.Summary = entries.Count == 0
            ? "Rich Header 存在但无有效条目"
            : $"共 {entries.Count} 条编译单元记录，最高构建号 {entries.Max(e => e.Build)}";
        return info;
    }

    // --------------------------------------------------------------- Overlay

    private static void ComputeOverlay(PeImageInfo info, byte[] bytes)
    {
        long maxEnd = 0;
        foreach (var s in info.Sections)
        {
            var end = (long)s.RawOffset + s.RawSize;
            if (end > maxEnd) maxEnd = end;
        }

        if (maxEnd > 0 && bytes.Length > maxEnd)
        {
            info.HasOverlay = true;
            info.OverlaySize = bytes.Length - maxEnd;
            var overlaySpan = bytes.AsSpan((int)maxEnd);
            var sample = overlaySpan.Length > 8 * 1024 * 1024 ? overlaySpan[..(8 * 1024 * 1024)] : overlaySpan;
            info.OverlayEntropy = Util.Entropy.Shannon(sample);
        }
    }

    // ------------------------------------------------------------- 编译器推断

    private static void InferCompiler(PeImageInfo info, PEHeaders headers)
    {
        var evidence = new List<string>();
        var linker = $"{info.LinkerMajor}.{info.LinkerMinor}";

        // 1) 节区名 —— Go / Rust / Delphi 有极强的节区特征
        var sectionNames = info.Sections.Select(s => s.Name).ToList();
        if (sectionNames.Any(n => n is ".gopclntab" or ".go.buildinfo" or ".go.buildid") ||
            info.Imports.Any(m => m.ModuleName.Equals("go.exe", StringComparison.OrdinalIgnoreCase)))
        {
            info.Compiler = "Go (gc)";
            evidence.Add("存在 Go 专有节区 / 导入");
            return;
        }

        if (sectionNames.Any(n => n.Contains("rustc", StringComparison.OrdinalIgnoreCase)) ||
            sectionNames.Any(n => n.Contains("cargo", StringComparison.OrdinalIgnoreCase)))
        {
            info.Compiler = "Rust (rustc)";
            evidence.Add("存在 Rust 专有节区");
            return;
        }

        var importNames = info.Imports.SelectMany(m => m.Functions.Select(f => f.Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (sectionNames.Contains("CODE") && sectionNames.Contains("DATA") &&
            importNames.Any(n => n.Contains("System", StringComparison.Ordinal) || n.Contains("@SysUtils")))
        {
            info.Compiler = "Delphi / C++Builder";
            evidence.Add("CODE/DATA 节区 + Delphi 运行时导入");
            return;
        }

        if (info.IsDotNet)
        {
            info.Compiler = info.IsNativeAot ? "MSVC + .NET NativeAOT" : "MSVC + .NET (Roslyn)";
            evidence.Add($"CLR 头存在，运行时版本 {info.DotNetRuntimeVersion}");
            if (info.IsNativeAot) evidence.Add("CorFlags.NativeEntryPoint 置位（NativeAOT / 单文件）");
        }

        if (info.RichHeader.Present && info.RichHeader.Entries.Count > 0)
        {
            var builds = info.RichHeader.Entries.Select(e => (int)e.Build).Where(b => b > 1000).ToList();
            if (builds.Count > 0)
            {
                var maxBuild = builds.Max();
                var line = DescribeMsvcLine(linker, maxBuild);
                info.Compiler = info.IsDotNet && !info.IsNativeAot ? info.Compiler : $"{line}";
                evidence.Add($"Rich Header 构建号 {maxBuild}（{line}）");
            }
            else if (!info.IsDotNet)
            {
                info.Compiler = DescribeMsvcLine(linker, 0);
                evidence.Add("Rich Header 存在但无有效构建号");
            }
        }
        else if (!info.IsDotNet)
        {
            info.Compiler = DescribeMsvcLine(linker, 0);
            if (info.RichHeader.Stripped)
                evidence.Add("缺失 Rich Header（可能被重写工具处理过）");
        }

        if (info.Compiler.Contains("MSVC") && importNames.Any(n => n.StartsWith("__imp_", StringComparison.Ordinal)))
            evidence.Add("存在 __imp_ 前缀导入（MSVC 静态/动态运行时特征）");

        if (info.LinkerMajor is 0 or > 20 && !info.IsDotNet && info.Compiler == "unknown")
        {
            info.Compiler = "unknown";
            evidence.Add($"非典型链接器版本 {linker}");
        }
        else if (info.Compiler == "unknown")
        {
            info.Compiler = DescribeMsvcLine(linker, 0);
        }

        info.CompilerEvidence = string.Join("；", evidence);
    }

    /// <summary>链接器版本 + Rich 构建号 → 粗略的 MSVC 代号。刻意给出区间而非精确版本，避免误报。</summary>
    private static string DescribeMsvcLine(string linkerVersion, int maxBuild)
    {
        var major = linkerVersion.Split('.')[0];
        var map = major switch
        {
            "14" => "MSVC 14.x（Visual Studio 2015 – 2026）",
            "12" => "MSVC 12.0（Visual Studio 2013）",
            "11" => "MSVC 11.0（Visual Studio 2012）",
            "10" => "MSVC 10.0（Visual Studio 2010）",
            "9" => "MSVC 9.0（Visual Studio 2008）",
            "8" => "MSVC 8.0（Visual Studio 2005）",
            "7" => "MSVC 7.x（Visual Studio 2002/2003）",
            "6" => "MSVC 6.0（Visual Studio 6.0）",
            _ => "",
        };

        if (string.IsNullOrEmpty(map)) return "unknown";

        if (maxBuild > 0 && map.StartsWith("MSVC 14"))
        {
            var hint = maxBuild switch
            {
                >= 31_000 => "Visual Studio 2022 17.8+",
                >= 30_000 => "Visual Studio 2022 17.0+",
                >= 29_000 => "Visual Studio 2019 16.7+",
                >= 28_000 => "Visual Studio 2019 16.2+",
                >= 27_000 => "Visual Studio 2019 16.0+",
                >= 26_000 => "Visual Studio 2017 15.6+",
                >= 25_000 => "Visual Studio 2017 15.0+",
                >= 24_000 => "Visual Studio 2015",
                _ => "",
            };
            if (!string.IsNullOrEmpty(hint))
                return $"{map} — 构建号指向 {hint}";
        }

        return map;
    }

    private static bool DetectInstaller(PeImageInfo info)
    {
        var names = info.Imports.Select(m => m.ModuleName.ToLowerInvariant()).ToHashSet();
        var functions = info.Imports.SelectMany(m => m.Functions.Select(f => f.Name.ToLowerInvariant())).ToHashSet();
        return names.Any(n => n.Contains("msi.dll")) ||
               names.Contains("setupapi.dll") && functions.Any(f => f.Contains("setupdi")) ||
               names.Any(n => n is "nsis" or "inno" or "wix") ||
               functions.Any(f => f.Contains("msiopenpackage") || f.Contains("nsis"));
    }

    // ------------------------------------------------------------------ 辅助

    /// <summary>RVA → 文件偏移。</summary>
    internal static int RvaToOffset(PEHeaders headers, uint rva)
    {
        foreach (var section in headers.SectionHeaders)
        {
            var start = (uint)section.VirtualAddress;
            var size = (uint)Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (size == 0) size = (uint)section.SizeOfRawData;
            if (rva >= start && rva < start + size)
            {
                var delta = rva - start;
                if (delta >= section.SizeOfRawData && section.SizeOfRawData > 0)
                {
                    // 落在节的虚拟填充区（未初始化数据），没有对应的文件内容
                    return -1;
                }
                return section.PointerToRawData + (int)delta;
            }
        }

        // 有些文件把 rva 落在 headers 区
        if (rva < (uint)headers.PEHeaderStartOffset + 0x400)
            return (int)rva;

        return -1;
    }

    internal static string ReadAsciiZ(byte[] bytes, int offset, int maxLength)
    {
        if (offset < 0 || offset >= bytes.Length) return "";
        var end = offset;
        var limit = Math.Min(bytes.Length, offset + maxLength);
        while (end < limit && bytes[end] != 0) end++;
        return Encoding.ASCII.GetString(bytes, offset, end - offset);
    }

    internal static string ReadUtf16Z(byte[] bytes, int offset, int maxLength)
    {
        if (offset < 0 || offset + 1 >= bytes.Length) return "";
        var end = offset;
        var limit = Math.Min(bytes.Length - 1, offset + maxLength);
        while (end < limit && !(bytes[end] == 0 && bytes[end + 1] == 0)) end += 2;
        return Encoding.Unicode.GetString(bytes, offset, end - offset);
    }

    // -------------------------------------------------------- 版本资源读取

    private static void ReadVersionResource(PeImageInfo info)
    {
        try
        {
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(info.FilePath);
            info.Version = new FileVersionInfoLite
            {
                FileVersion = Nullify(vi.FileVersion),
                ProductVersion = Nullify(vi.ProductVersion),
                ProductName = Nullify(vi.ProductName),
                CompanyName = Nullify(vi.CompanyName),
                FileDescription = Nullify(vi.FileDescription),
                OriginalFileName = Nullify(vi.OriginalFilename),
                InternalName = Nullify(vi.InternalName),
                LegalCopyright = Nullify(vi.LegalCopyright),
                IsDebugBuild = vi.IsDebug,
            };
        }
        catch
        {
            // 版本资源缺失是常态（尤其是恶意样本），不视为错误
        }
    }

    private static string? Nullify(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
