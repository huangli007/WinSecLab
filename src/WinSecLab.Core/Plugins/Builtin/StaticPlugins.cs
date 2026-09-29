using WinSecLab.Core.Engines.Static;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Plugins.Builtin;

/// <summary>
/// §3.3 静态分析插件集合。全部是内置引擎，零外部依赖，开箱即用。
/// 每个插件只负责一个维度，产出统一 Evidence，规则引擎再跨维度关联。
/// </summary>
public sealed class PeAnalysisPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.pe";
    public string Name => "PE Analyzer";
    public string Version => "1.0";
    public string? Description => "解析 PE 头、节区、导入导出、资源、调试目录、Rich Header，并计算哈希指纹。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.PeAnalysis };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin("内置 PE 解析器（System.Reflection.PortableExecutable + 自实现导入/导出/资源解析）");

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var plugin = new PeAnalyzer();
        context.Progress(-1, "解析 PE 结构");
        var pe = await Task.Run(() => plugin.Analyze(context.TargetPath, context.Options.ComputeSignature), context.CancellationToken)
            .ConfigureAwait(false);

        if (string.IsNullOrEmpty(pe.Sha256) || !pe.IsValidPe)
        {
            return PluginRunResult.Fail(pe.ParseError ?? "PE 解析失败：文件不可读或不是有效的 PE 文件");
        }

        context.Result.Pe = pe;
        context.Database.SavePeImage(pe);

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Pe, "PE 结构画像", "builtin.pe", context.TargetPath,
                $"{pe.Architecture} / {pe.Subsystem} / {pe.Compiler}，{pe.Sections.Count} 个节区，导入 {pe.ImportedDllCount} 模块 / {pe.ImportedFunctionCount} 函数，导出 {pe.ExportCount}",
                pe, "pe", "static"),
        };

        if (pe.DebugPaths.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Pe, "调试目录（PDB 路径）", "builtin.pe",
                context.TargetPath, string.Join("；", pe.DebugPaths), pe.DebugPaths, "pe", "static"));
        }

        if (pe.RichHeader.Present || pe.RichHeader.Summary.Length > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Pe, "Rich Header / 编译器指纹", "builtin.pe",
                context.TargetPath,
                $"{pe.RichHeader.Summary}；推断编译器 {pe.Compiler}；依据：{pe.CompilerEvidence}",
                pe.RichHeader, "pe", "static"));
        }

        if (pe.Exports.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Pe, "导出函数表", "builtin.pe", context.TargetPath,
                $"{pe.Exports.Count} 个导出，其中前向导出 {pe.Exports.Count(e => e.IsForwarder)} 个",
                pe.Exports.Take(400).ToList(), "pe", "static"));
        }

        var resources = pe.Resources;
        if (resources.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Pe, "资源目录摘要", "builtin.pe", context.TargetPath,
                $"{resources.Count} 个资源条目，类型分布：{string.Join("、", resources.GroupBy(r => r.Type).Select(g => $"{g.Key}×{g.Count()}").Take(12))}",
                resources, "pe", "static"));
        }

        return PluginRunResult.Ok(
            $"PE 解析完成：{pe.Architecture} {pe.Subsystem}，{pe.Sections.Count} 节区 / {pe.ImportedDllCount} 导入模块 / {pe.ExportCount} 导出",
            evidence);
    }

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class DependencyPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.dependencies";
    public string Name => "Dependency Scanner";
    public string Version => "1.0";
    public string? Description => "解析导入表并定位磁盘上的实际 DLL，标出从用户可写目录加载的模块（DLL 劫持风险）。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.DependencyScan };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin("内置依赖解析器（导入表 + 本地/系统目录检索）");

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var pe = context.Result.Pe;
        if (pe is null) return PluginRunResult.Skipped("缺少 PE 解析结果，跳过依赖扫描");

        var resolver = new DependencyResolver();
        var directories = new List<string>(context.SearchDirectories);
        if (Directory.Exists(context.Layout.TargetDependencies)) directories.Add(context.Layout.TargetDependencies);

        var dependencies = await Task.Run(() => resolver.Resolve(pe, directories), context.CancellationToken)
            .ConfigureAwait(false);

        context.Result.Dependencies = dependencies;

        // 深哈希需要读盘，默认只做浅哈希，避免拖慢大量文件的分析
        if (context.Options.HashDependencies)
        {
            foreach (var dep in dependencies.Where(d => d.IsPresent && !d.IsSystemLibrary && d.ResolvedPath is not null))
            {
                if (context.Options.DeepDependencyHash || !dep.IsSystemLibrary)
                    dep.Sha256 = Hashing.Sha256File(dep.ResolvedPath!);
            }
        }

        context.Database.SaveDependencies(dependencies);

        var present = dependencies.Count(d => d.IsPresent);
        var writable = dependencies.Where(d => d.IsUserWritableLocation && !d.IsSystemLibrary).ToList();
        var missing = dependencies.Where(d => !d.IsPresent && !d.IsSystemLibrary).ToList();

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Dependency, "依赖解析结果", "builtin.dependencies",
                context.TargetPath,
                $"共 {dependencies.Count} 个导入模块：已解析 {present}，缺失 {missing.Count}，其中 {writable.Count} 个从用户可写目录解析",
                dependencies, "deps", "static"),
        };

        if (writable.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Dependency, "从用户可写目录解析的依赖",
                "builtin.dependencies", context.TargetPath,
                string.Join("；", writable.Take(12).Select(d => $"{d.Name} → {d.ResolvedPath}")),
                writable, "deps", "static", "dll-hijack"));
        }

        if (missing.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Dependency, "未解析的依赖模块",
                "builtin.dependencies", context.TargetPath,
                string.Join("；", missing.Take(20).Select(d => d.Name)),
                missing, "deps", "static"));
        }

        var coLocated = DependencyResolver.ListCoLocatedBinaries(Path.GetDirectoryName(context.TargetPath) ?? "");
        if (coLocated.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Dependency, "同目录二进制清单",
                "builtin.dependencies", Path.GetDirectoryName(context.TargetPath),
                $"目标目录下另有 {coLocated.Count} 个 exe/dll/node 模块",
                coLocated, "deps", "static"));
        }

        return PluginRunResult.Ok(
            $"依赖扫描完成：{dependencies.Count} 个模块，缺 {missing.Count} 个，可写目录加载 {writable.Count} 个",
            evidence);
    }

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class SignaturePlugin : IWinSecLabPlugin
{
    public string Id => "builtin.signature";
    public string Name => "Digital Signature Verifier";
    public string Version => "1.0";
    public string? Description => "WinVerifyTrust 权威校验 + 证书链、时间戳、签名者信息提取。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.DigitalSignature };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin("内置签名校验（wintrust.dll WinVerifyTrust + SignedCms）");

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var info = await Task.Run(() => SignatureVerifier.Verify(context.TargetPath), context.CancellationToken)
            .ConfigureAwait(false);

        if (context.Result.Pe is not null)
        {
            context.Result.Pe.Signature = info;
            context.Database.SavePeImage(context.Result.Pe);
        }

        var facts = new List<string>
        {
            $"状态：{info.StatusText}",
            $"WinVerifyTrust：0x{info.WinVerifyTrustResult:X8}",
        };
        if (info.SignerSubject is not null) facts.Add($"签名者：{info.SignerSubject}");
        if (info.SignerIssuer is not null) facts.Add($"签发者：{info.SignerIssuer}");
        if (info.NotBefore is not null) facts.Add($"有效期：{info.NotBefore:yyyy-MM-dd} ~ {info.NotAfter:yyyy-MM-dd}");
        facts.Add(info.IsTimestamped ? $"时间戳：{info.TimestampAuthority ?? "有"}" : "无时间戳签名");
        facts.AddRange(info.ChainIssues.Select(i => "链问题：" + i));

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Signature, "数字签名校验结果", "builtin.signature",
                context.TargetPath, string.Join("；", facts), info, "signature", "static"),
        };

        // 同目录的其它二进制也做一次快速签名普查，便于发现随包分发的未签名组件
        var directory = Path.GetDirectoryName(context.TargetPath);
        if (!string.IsNullOrEmpty(directory) && Directory.Exists(directory))
        {
            var siblings = new List<(string File, string Status, string? Signer)>();
            foreach (var file in Directory.EnumerateFiles(directory, "*.dll")
                         .Concat(Directory.EnumerateFiles(directory, "*.exe"))
                         .Where(f => !string.Equals(f, context.TargetPath, StringComparison.OrdinalIgnoreCase))
                         .Take(80))
            {
                try
                {
                    var sig = SignatureVerifier.Verify(file);
                    siblings.Add((Path.GetFileName(file), sig.StatusText, sig.SignerSubject));
                }
                catch
                {
                    // 单个文件校验失败不影响统计
                }
            }

            if (siblings.Count > 0)
            {
                context.Result.SiblingSignatures = siblings;
                var unsigned = siblings.Count(s => s.Status.Contains("未签名"));
                evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Signature, "同目录二进制签名普查",
                    "builtin.signature", directory,
                    $"共检查 {siblings.Count} 个文件，未签名 {unsigned} 个",
                    siblings, "signature", "static"));
            }
        }

        return PluginRunResult.Ok($"签名校验完成：{info.StatusText}", evidence);
    }

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class StringsPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.strings";
    public string Name => "Strings Extractor";
    public string Version => "1.0";
    public string? Description => "提取 ASCII / UTF-16 字符串并按 URL、域名、路径、命令、凭据、安全 API 等分类。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.StringsScan };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin("内置字符串提取器（按节区扫描，保留文件偏移）");

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var pe = context.Result.Pe;
        if (pe is null) return PluginRunResult.Skipped("缺少 PE 解析结果，跳过字符串提取");

        byte[] bytes;
        try
        {
            bytes = await File.ReadAllBytesAsync(context.TargetPath, context.CancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return PluginRunResult.Fail($"读取文件失败：{ex.Message}");
        }

        var extractor = new StringExtractor
        {
            MinLength = context.Options.StringMinLength,
            MaxResults = context.Options.MaxStrings,
        };

        context.Progress(-1, "提取字符串");
        var hits = await Task.Run(() => extractor.Extract(pe, bytes), context.CancellationToken).ConfigureAwait(false);
        context.Result.Strings = hits;
        context.Database.SaveStrings(hits);

        var evidence = new List<Evidence>();
        var groups = StringExtractor.GroupByCategory(hits);
        foreach (var (category, list) in groups)
        {
            // 只给有情报价值的类别单独建证据条目，General 用一条汇总
            var isInformative = category is not "General" and not "Format" and not "Json";
            if (!isInformative && category == "General")
            {
                evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Strings,
                    $"字符串提取总览（{hits.Count} 条）", "builtin.strings", context.TargetPath,
                    $"按类别分布：{string.Join("、", groups.Select(g => $"{g.Key}×{g.Value.Count}"))}",
                    groups.ToDictionary(g => g.Key, g => g.Value.Count), "strings", "static"));
                continue;
            }

            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Strings,
                $"字符串：{DescribeCategory(category)}（{list.Count} 条）", "builtin.strings", context.TargetPath,
                string.Join(" | ", list.Take(6).Select(s => Truncate(s.Value, 80))),
                list.Take(500).ToList(), "strings", "static", category));
        }

        return PluginRunResult.Ok($"字符串提取完成：{hits.Count} 条，覆盖 {groups.Count} 个类别", evidence);
    }

    private static string DescribeCategory(string category) => category switch
    {
        "URL" => "URL 地址",
        "Domain" => "域名",
        "IPAddress" => "IP 地址",
        "FilePath" => "文件路径",
        "Command" => "命令与宿主程序",
        "Credential" => "凭据相关关键字",
        "Crypto" => "加密算法",
        "Sql" => "SQL 语句",
        "RegistryPath" => "注册表路径",
        "SecurityApi" => "安全相关 API 名",
        "UserAgent" => "User-Agent",
        "Guid" => "GUID",
        _ => category,
    };

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class EntropyPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.entropy";
    public string Name => "Entropy Analyzer";
    public string Version => "1.0";
    public string? Description => "节区与 overlay 的 Shannon 熵值分析，识别加壳 / 加密 / 压缩载荷。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.EntropyScan };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin("内置熵值分析（PE 解析阶段已随节区计算）");

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var pe = context.Result.Pe;
        if (pe is null) return Task.FromResult(PluginRunResult.Skipped("缺少 PE 解析结果，跳过熵值分析"));

        var high = pe.Sections.Where(s => s.IsHighEntropy).ToList();
        var summary = new
        {
            overall = pe.OverallEntropy,
            threshold = context.Options.HighEntropyThreshold,
            sections = pe.Sections.Select(s => new { s.Name, s.Entropy, s.RawSize, s.Permissions, packed = s.IsHighEntropy }),
            overlay = new { pe.HasOverlay, pe.OverlaySize, pe.OverlayEntropy },
        };

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Entropy, "熵值分析", "builtin.entropy", context.TargetPath,
                $"整体熵 {pe.OverallEntropy}；{pe.Sections.Count} 个节区中 {high.Count} 个达到加壳阈值（≥{context.Options.HighEntropyThreshold}）"
                + (pe.HasOverlay ? $"；overlay {pe.OverlaySize / 1024} KB 熵 {pe.OverlayEntropy}" : "；无 overlay"),
                summary, "entropy", "static"),
        };

        if (high.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Entropy, "高熵节区（疑似加壳）", "builtin.entropy",
                context.TargetPath,
                string.Join("；", high.Select(s => $"{s.Name} 熵 {s.Entropy}（{Entropy.Describe(s.Entropy)}）")),
                high, "entropy", "static", "packed"));
        }

        return Task.FromResult(PluginRunResult.Ok(
            high.Count > 0 ? $"发现 {high.Count} 个高熵节区，疑似加壳" : $"熵值正常（整体 {pe.OverallEntropy}）",
            evidence));
    }

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class DotNetPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.dotnet";
    public string Name => ".NET Assembly Analyzer";
    public string Version => "1.0";
    public string? Description => "读取托管元数据，导出命名空间 / 类型 / 成员树、引用程序集与混淆迹象。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.DotNetAnalysis };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin("内置 .NET 元数据读取器（System.Reflection.Metadata）");

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var analyzer = new DotNetAnalyzer();
        var info = await Task.Run(() => analyzer.Analyze(context.TargetPath, context.Result.Pe), context.CancellationToken)
            .ConfigureAwait(false);

        if (!info.IsDotNet)
            return PluginRunResult.Skipped("目标不是 .NET 程序集（无 CLR 头），跳过托管分析");

        context.Result.DotNet = info;
        context.Database.SaveDotNet(context.TargetPath, info);

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.DotNet, "程序集标识", "builtin.dotnet", context.TargetPath,
                $"程序集 {info.AssemblyName} v{info.AssemblyVersion}，目标框架 {info.TargetFramework ?? "未知"}，"
                + $"运行时 {info.RuntimeVersion}，类型 {info.TypeCount} 个 / 方法 {info.MethodCount} 个",
                new { info.AssemblyName, info.AssemblyVersion, info.TargetFramework, info.RuntimeVersion,
                       info.IsReadyToRun, info.IsNativeAot, info.IsSingleFileBundle, info.IsManagedEntryPoint },
                "dotnet", "static"),
        };

        if (info.Namespaces.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.DotNet, "类型结构树", "builtin.dotnet",
                context.TargetPath,
                $"{info.Namespaces.Count} 个命名空间，{info.TypeCount} 个类型，{info.MethodCount} 个方法，"
                + $"{info.FieldCount} 个字段，{info.PropertyCount} 个属性，{info.EventCount} 个事件",
                info.Namespaces, "dotnet", "static"));
        }

        if (info.ReferencedAssemblies.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.DotNet, "引用程序集", "builtin.dotnet",
                context.TargetPath, string.Join("；", info.ReferencedAssemblies.Take(24)),
                info.ReferencedAssemblies, "dotnet", "static"));
        }

        if (info.MethodReferences.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.DotNet, "外部方法调用引用", "builtin.dotnet",
                context.TargetPath, $"共 {info.MethodReferences.Count} 条成员引用（可用于 API 审查）",
                info.MethodReferences.Take(1000).ToList(), "dotnet", "static"));
        }

        evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.DotNet,
            info.UsesObfuscation ? "混淆迹象" : "可反编译性评估", "builtin.dotnet", context.TargetPath,
            string.Join("；", info.ObfuscationHints),
            new { info.UsesObfuscation, info.ObfuscationHints, info.Decompilable, info.Resources },
            "dotnet", "static"));

        var verdict = info.UsesObfuscation
            ? "检出混淆特征，建议使用 ILSpy / dnSpyEx 并准备反混淆方案"
            : info.IsNativeAot
                ? "NativeAOT 产物，托管元数据有限，建议转 Ghidra 原生化分析"
                : "可尝试用 ILSpy / dnSpyEx 直接反编译为 C#";

        return PluginRunResult.Ok(
            $".NET 分析完成：{info.AssemblyName} v{info.AssemblyVersion}，{info.TypeCount} 类型 / {info.MethodCount} 方法。{verdict}",
            evidence);
    }

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}
