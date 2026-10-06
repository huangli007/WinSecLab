using System.Text;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Plugins.Builtin;

// ═══════════════════════════════════════════════════════════════════════════
//  Wireshark / tshark —— 链路层抓包 + TLS SNI
// ═══════════════════════════════════════════════════════════════════════════

/// <summary>
/// Wireshark 适配器。补的是内置网络监控完全做不到的一层：
/// 内置 <see cref="Engines.Network.NetworkMonitor"/> 只能看连接表（谁连了谁），
/// tshark 能给出真实报文、DNS 查询、TLS SNI —— 也就是"到底访问了哪个域名"。
/// 抓包需要 Npcap + 管理员，两者缺一就明确跳过。
/// </summary>
public sealed class WiresharkToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "wireshark";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var seconds = context.Options.TsharkCaptureSeconds;
        var log = new List<string> { $"Wireshark/tshark：{location.ExecutablePath}（{location.Source}）" };
        var dir = ToolDirectory(context, "wireshark");
        var exe = location.ExecutablePath!;

        // dumpcap 与 tshark 同目录分发，抓包必须用它（tshark 自身不适合长时抓包）
        var dumpcap = Path.Combine(Path.GetDirectoryName(exe) ?? "", "dumpcap.exe");
        if (!File.Exists(dumpcap))
        {
            return PluginRunResult.Skipped(
                $"找到 tshark 但同目录缺少 dumpcap.exe（{Path.GetDirectoryName(exe)}），无法抓包。"
                + "请使用 Wireshark 官方安装包完整安装，而不是只复制单个 tshark.exe。");
        }

        // 1) 网卡列表
        var ifaceResult = await ProcessRunner.RunAsync(exe, "-D", dir, 30_000, context.CancellationToken, log.Add)
            .ConfigureAwait(false);
        if (!ifaceResult.Started || ifaceResult.ExitCode != 0)
        {
            return PluginRunResult.Fail(
                $"tshark -D 失败（退出码 {ifaceResult.ExitCode}）：{FirstLines(ifaceResult.StdErr, 3)}"
                + " —— 多数情况是 Npcap 未安装或未以管理员身份运行。");
        }

        var interfaces = ParseInterfaces(ifaceResult.StdOut);
        if (interfaces.Count == 0)
            return PluginRunResult.Fail("tshark 未列出任何可用网卡，请确认已安装 Npcap。");

        var iface = PickInterface(interfaces, context.Options.TsharkInterfaceIndex);
        log.Add($"选用网卡：{iface.Index}. {iface.Description}");

        if (seconds > 0)
        {
            // 2) 抓包
            var pcap = Path.Combine(dir, "capture.pcapng");
            ToolArtifact.TryDelete(pcap);
            context.Progress(0.1, $"抓包 {seconds}s（网卡 {iface.Index}）");

            var capture = await ProcessRunner.RunAsync(dumpcap,
                $"-i {iface.Index} -a duration:{seconds} -w {ProcessRunner.Quote(pcap)} -q",
                dir, timeoutMs: (seconds + 30) * 1000, cancellationToken: context.CancellationToken, log: log.Add)
                .ConfigureAwait(false);

            if (!File.Exists(pcap))
            {
                return PluginRunResult.Fail(
                    $"dumpcap 未生成抓包文件（退出码 {capture.ExitCode}）：{FirstLines(capture.StdErr, 3)}");
            }
            return await AnalyzePcapAsync(context, exe, pcap, dir, iface, interfaces, location, log).ConfigureAwait(false);
        }

        // seconds == 0：不抓新包，但如果项目里已有 pcap 就解析它
        var existing = Directory.EnumerateFiles(dir, "*.pcap*").FirstOrDefault();
        if (existing is null)
            return PluginRunResult.Skipped("抓包时长配置为 0 且目录中没有已存在的 PCAP 文件，已跳过。");

        return await AnalyzePcapAsync(context, exe, existing, dir, iface, interfaces, location, log).ConfigureAwait(false);
    }

    private static async Task<PluginRunResult> AnalyzePcapAsync(PluginContext context, string tshark,
        string pcap, string dir, TsharkInterface iface, List<TsharkInterface> allInterfaces,
        ToolLocation location, List<string> log)
    {
        var evidence = new List<Evidence>();
        var artifacts = new List<string> { pcap };

        long size = 0;
        try { size = new FileInfo(pcap).Length; } catch { }

        // 3) DNS 查询（只取查询报文，避免把响应重复计一遍）
        context.Progress(0.55, "解析 DNS 查询");
        var dnsRun = await RunTshark(tshark, pcap, "dns.flags.response==0",
            new[] { "ip.src", "dns.qry.name", "udp.dstport" }, context, log).ConfigureAwait(false);
        var dnsQueries = ParseRows(dnsRun.StdOut);

        // 4) TLS SNI —— 回答"HTTPS 到底连了哪个域名"
        context.Progress(0.7, "解析 TLS SNI");
        var tlsRun = await RunTshark(tshark, pcap, "tls.handshake.extensions_server_name",
            new[] { "ip.dst", "tls.handshake.extensions_server_name" }, context, log).ConfigureAwait(false);
        var sniRows = ParseRows(tlsRun.StdOut);

        // 5) 协议分层概览
        context.Progress(0.85, "统计协议分层");
        var hierRun = await ProcessRunner.RunAsync(tshark,
            $"-r {ProcessRunner.Quote(pcap)} -q -z io,phs",
            dir, 120_000, context.CancellationToken, log.Add).ConfigureAwait(false);

        var dnsHosts = dnsQueries
            .Select(r => r.Count > 1 ? r[1] : "")
            .Where(h => h.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var sniHosts = sniRows
            .Select(r => r.Count > 1 ? r[1] : "")
            .Where(h => h.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 把观测到的域名并入项目的 DNS 记录，供后续规则引擎与报告使用
        var merged = 0;
        foreach (var host in dnsHosts.Concat(sniHosts).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var addresses = dnsQueries.Where(r => r.Count > 1 && string.Equals(r[1], host, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Count > 0 ? r[0] : "").Where(a => a.Length > 0).Distinct().ToList();
            context.Result.DnsObservations.Add(new DnsObservation
            {
                HostName = host,
                Addresses = addresses,
                RecordType = "A",
                ObservedAt = DateTime.Now,
                Source = "tshark",
                ProcessId = context.Session?.RootProcessId ?? 0,
                ProcessName = SafeFileName(context.TargetPath),
                Attribution = AttributionQuality.Unattributed,
            });
            merged++;
        }

        var summary = new StringBuilder();
        summary.Append($"PCAP {size / 1024.0:F0} KB；");
        summary.Append($"DNS 查询 {dnsHosts.Count} 个域名，TLS SNI {sniHosts.Count} 个域名");

        evidence.Add(ToolEvidence(context, "wireshark", "链路层抓包结果（tshark）",
            summary.ToString(),
            new
            {
                pcapFile = pcap,
                pcapSizeBytes = size,
                interfaceIndex = iface.Index,
                interfaceDescription = iface.Description,
                dnsQueryCount = dnsQueries.Count,
                dnsHosts = dnsHosts.Take(60).ToList(),
                tlsSniHosts = sniHosts.Take(60).ToList(),
                enginePath = location.ExecutablePath,
                engineVersion = location.Version,
            },
            "tshark", "pcap", "network"));

        if (dnsQueries.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "wireshark", "DNS 查询明细（来自报文）",
                string.Join("；", dnsHosts.Take(12)),
                dnsQueries.Take(2000).Select(r => new { source = r.ElementAtOrDefault(0), host = r.ElementAtOrDefault(1) }).ToList(),
                "tshark", "dns"));
        }

        if (sniRows.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "wireshark", "TLS SNI（HTTPS 实际访问域名）",
                string.Join("；", sniHosts.Take(12)),
                sniRows.Take(2000).Select(r => new { destIp = r.ElementAtOrDefault(0), sni = r.ElementAtOrDefault(1) }).ToList(),
                "tshark", "tls", "sni"));
        }

        if (hierRun.StdOut.Length > 0)
        {
            var hierFile = ToolArtifact.WriteText(dir, "protocol-hierarchy.txt", hierRun.Combined);
            if (hierFile is not null) artifacts.Add(hierFile);

            var protocolLines = hierRun.StdOut.Split('\n')
                .Select(l => l.TrimEnd()).Where(l => l.Trim().StartsWith("eth") || l.Contains("Protocols in frame"))
                .Take(40).ToList();
            if (protocolLines.Count > 0)
            {
                evidence.Add(ToolEvidence(context, "wireshark", "协议分层统计", Truncate(hierRun.StdOut, 400),
                    protocolLines, "tshark", "protocol-stats"));
            }
        }

        // tshark 原始输出也留档，便于和内置连接表结论交叉核对
        var rawFile = ToolArtifact.WriteText(dir, "tshark-raw.txt",
            $"# tshark -D\n{string.Join("\n", allInterfaces.Select(i => $"{i.Index}. {i.Description}"))}" +
            $"\n\n# DNS\n{dnsRun.StdOut}\n\n# TLS SNI\n{tlsRun.StdOut}");
        if (rawFile is not null) artifacts.Add(rawFile);

        var okRun = PluginRunResult.Ok(
            $"tshark 分析完成：{dnsHosts.Count} 个 DNS 域名、{sniHosts.Count} 个 TLS SNI 域名，PCAP {size / 1024.0:F0} KB",
            evidence, null, artifacts);
        foreach (var l in log) okRun.Log.Add(l);
        return okRun;
    }

    private static Task<ToolRunResult> RunTshark(string tshark, string pcap, string displayFilter,
        string[] fields, PluginContext context, List<string> log)
    {
        var args = new StringBuilder();
        args.Append("-r ").Append(ProcessRunner.Quote(pcap));
        args.Append(" -Y ").Append(ProcessRunner.Quote(displayFilter));
        args.Append(" -T fields");
        foreach (var f in fields) args.Append(" -e ").Append(f);
        args.Append(" -E separator=/t");   // 用制表符，域名里可能有逗号
        args.Append(" -2");                // 两遍解析，保证字段完整

        return ProcessRunner.RunAsync(tshark, args.ToString(), null,
            timeoutMs: 180_000, cancellationToken: context.CancellationToken, log: log.Add);
    }

    internal sealed record TsharkInterface(int Index, string Description);

    internal static List<TsharkInterface> ParseInterfaces(string output)
    {
        var list = new List<TsharkInterface>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            var dot = line.IndexOf('.');
            if (dot <= 0) continue;
            if (!int.TryParse(line[..dot].Trim(), out var index)) continue;
            var desc = line[(dot + 1)..].Trim();
            if (desc.Length == 0) continue;
            list.Add(new TsharkInterface(index, desc));
        }
        return list;
    }

    /// <summary>优先选有描述性名称的物理网卡，跳过回环与 Npcap Loopback。</summary>
    internal static TsharkInterface PickInterface(List<TsharkInterface> interfaces, int? preferred)
    {
        if (preferred is int p)
        {
            var hit = interfaces.FirstOrDefault(i => i.Index == p);
            if (hit is not null) return hit;
        }

        string[] bad = { "loopback", "Loopback", "Adapter for loopback", "Npcap Loopback", "Bluetooth" };
        var candidates = interfaces
            .Where(i => !bad.Any(b => i.Description.Contains(b, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (candidates.Count == 0) return interfaces[0];
        // 描述里带 Ethernet / Wi-Fi / WLAN 的优先
        var preferredNames = new[] { "Ethernet", "以太网", "Wi-Fi", "WLAN", "无线" };
        return candidates.FirstOrDefault(i => preferredNames.Any(n => i.Description.Contains(n, StringComparison.OrdinalIgnoreCase)))
               ?? candidates[0];
    }

    /// <summary>tshark -T fields 输出：每行制表符分隔，缺字段会是空串。</summary>
    internal static List<List<string>> ParseRows(string output)
    {
        var rows = new List<List<string>>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r', '\n');
            if (line.Length == 0) continue;
            rows.Add(line.Split('\t').Select(s => s.Trim()).ToList());
        }
        return rows;
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path) ?? ""; } catch { return ""; }
    }

    private static string FirstLines(string text, int count) =>
        string.Join(" / ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim()).Where(l => l.Length > 0).Take(count));

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

// ═══════════════════════════════════════════════════════════════════════════
//  Dependencies (lucasg) —— 依赖链交叉验证
// ═══════════════════════════════════════════════════════════════════════════

public sealed class DependenciesToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "dependencies";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var dir = ToolDirectory(context, "dependencies");
        var log = new List<string>();
        var exe = location.ExecutablePath!;

        // 用 -imports（而非 -chain -modules）：后者会递归解析整棵依赖树，实测跑不完，
        // 且"批量枚举系统二进制"的行为会被安全软件直接掐掉。
        // 加 -json 拿结构化输出 —— 文本模式在中文路径下会出现编码错乱。
        var result = await ProcessRunner.RunAsync(exe, $"-imports -json {ProcessRunner.Quote(context.TargetPath)}",
            dir, 60_000, context.CancellationToken, log.Add).ConfigureAwait(false);

        var artifacts = new List<string>();
        var rawFile = ToolArtifact.WriteText(dir, "dependencies-output.txt", result.Combined);
        if (rawFile is not null) artifacts.Add(rawFile);

        if (!result.Started)
            return PluginRunResult.Fail($"Dependencies 启动失败：{result.StdErr}");

        if (result.TimedOut)
            return PluginRunResult.Fail("Dependencies 执行超时（60s），未取得结果。");

        var toolModules = ParseImportsOutput(result.StdOut);

        // 与内置解析结果对照：内置漏掉而工具找到的，往往是隐式加载（DelayLoad / 动态 LoadLibrary）
        var ours = context.Result.Dependencies
            .Select(d => d.Name)
            .Where(n => n.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var toolOnly = toolModules.Where(m => !ours.Contains(m)).ToList();
        var oursOnly = ours.Where(o => !toolModules.Contains(o, StringComparer.OrdinalIgnoreCase)).ToList();

        var evidence = new List<Evidence>
        {
            ToolEvidence(context, "dependencies", "导入表交叉验证（Dependencies.exe）",
                $"工具识别 {toolModules.Count} 个模块，内置解析 {ours.Count} 个模块；"
                + $"工具独有 {toolOnly.Count} 个，内置独有 {oursOnly.Count} 个",
                new
                {
                    toolModuleCount = toolModules.Count,
                    builtinModuleCount = ours.Count,
                    toolOnly = toolOnly.Take(80).ToList(),
                    builtinOnly = oursOnly.Take(80).ToList(),
                    exitCode = result.ExitCode,
                    enginePath = location.ExecutablePath,
                    durationSeconds = Math.Round(result.Duration.TotalSeconds, 2),
                },
                "dependencies", "cross-validation"),
        };

        if (toolOnly.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "dependencies", "内置解析未覆盖的模块",
                $"{toolOnly.Count} 个模块只被外部工具识别 —— 通常意味着隐式加载（LoadLibrary / DelayLoad / COM）",
                toolOnly.Take(200).ToList(), "dependencies", "implicit-load"));
        }

        var run = PluginRunResult.Ok(
            $"Dependencies 交叉验证完成：工具 {toolModules.Count} 模块 / 内置 {ours.Count} 模块，差异 {toolOnly.Count + oursOnly.Count} 项",
            evidence, null, artifacts);
        foreach (var l in log) run.Log.Add(l);
        return run;
    }

    /// <summary>
    /// 解析 Dependencies 的 <c>-imports</c> 输出。优先走 JSON（结构化、无编码问题），
    /// JSON 解析失败则回退到文本格式 —— 别人的工具升级会改格式，两级兜底更扛造。
    /// </summary>
    internal static List<string> ParseImportsOutput(string output)
    {
        var fromJson = TryParseImportsJson(output);
        return fromJson.Count > 0 ? fromJson : ParseModuleLines(output);
    }

    /// <summary>解析 `-imports -json` 的 {"Imports":[{"Name":"GDI32.dll",...}]} 结构。</summary>
    private static List<string> TryParseImportsJson(string output)
    {
        try
        {
            var start = output.IndexOf('{');
            if (start < 0) return new List<string>();
            var end = output.LastIndexOf('}');
            if (end <= start) return new List<string>();

            using var doc = System.Text.Json.JsonDocument.Parse(output[start..(end + 1)]);
            if (!doc.RootElement.TryGetProperty("Imports", out var imports)
                || imports.ValueKind != System.Text.Json.JsonValueKind.Array)
                return new List<string>();

            var names = new List<string>();
            foreach (var item in imports.EnumerateArray())
            {
                if (item.TryGetProperty("Name", out var name)
                    && name.GetString() is { Length: > 0 } s)
                    names.Add(s);
            }
            return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// 解析 Dependencies 的**文本**模块列表（JSON 不可用时的回退路径），兼容两种格式：
    ///  · <c>-imports</c>：<c>Import from module GDI32.dll :</c>
    ///  · <c>-chain -modules</c>：形如 <c>    C:\path\to\foo.dll</c> 的路径行
    /// </summary>
    internal static List<string> ParseModuleLines(string output)
    {
        var modules = new List<string>();
        const string importMarker = "Import from module";

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length < 4) continue;

            // 格式一：Import from module <名字> :
            if (line.StartsWith(importMarker, StringComparison.OrdinalIgnoreCase))
            {
                var name = line[importMarker.Length..].Trim().TrimEnd(':').Trim();
                if (name.Length > 0) modules.Add(name);
                continue;
            }

            // 格式二：模块路径行。要求形如 "X:\..." 或 "\\server\..." 的绝对路径 ——
            // 否则 "[-] Import listing for file : C:/tmp/target.exe" 这类标题行会被误收。
            if (!(line.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                  || line.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                  || line.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)
                  || line.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase))) continue;
            var looksLikePath = (line.Length > 2 && line[1] == ':' && (line[2] == '\\' || line[2] == '/'))
                                || line.StartsWith(@"\\", StringComparison.Ordinal);
            if (!looksLikePath) continue;
            if (line.Contains("://", StringComparison.Ordinal)) continue;
            modules.Add(line);
        }
        return modules.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Sigcheck —— 签名结果交叉验证
// ═══════════════════════════════════════════════════════════════════════════

public sealed class SigcheckToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "sigcheck";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var dir = ToolDirectory(context, "sigcheck");
        var log = new List<string>();
        var exe = location.ExecutablePath!;
        var csv = Path.Combine(dir, "sigcheck.csv");
        ToolArtifact.TryDelete(csv);

        // -accepteula 必须带：Sysinternals 工具首次运行会先打印 EULA 授权页，
        // 不仅污染输出，还会让 CSV 头的 Verified 列解析不到（实测踩过）。
        // outputEncoding=Unicode：sigcheck 的输出是 UTF-16LE（实测 CSV 头是 "P\0a\0t\0h\0"），
        // 按 UTF-8 读会得到字符间夹 NUL 的乱码，导致 ParseSigcheckCsv 完全失效。
        var result = await ProcessRunner.RunAsync(exe,
            $"-accepteula -a -h -nobanner -c {ProcessRunner.Quote(context.TargetPath)}",
            dir, 120_000, context.CancellationToken, log.Add,
            outputEncoding: Encoding.Unicode).ConfigureAwait(false);

        var artifacts = new List<string>();
        if (File.Exists(csv)) artifacts.Add(csv);

        var rawFile = ToolArtifact.WriteText(dir, "sigcheck-output.txt", result.Combined);
        if (rawFile is not null) artifacts.Add(rawFile);

        if (!result.Started)
            return PluginRunResult.Fail($"Sigcheck 启动失败：{result.StdErr}");

        // Sigcheck 会把 CSV 同时打印到 stdout 和文件，优先用 stdout（避免文件写入被拦）
        var csvText = result.StdOut.Contains("Verified", StringComparison.OrdinalIgnoreCase)
            ? result.StdOut
            : File.Exists(csv) ? ReadSigcheckCsvFile(csv) : "";

        if (csvText.Length == 0)
            return PluginRunResult.Fail($"Sigcheck 未返回可解析输出（退出码 {result.ExitCode}）：{FirstLines(result.StdErr, 3)}");

        var parsed = ParseSigcheckCsv(csvText);
        var builtin = context.Result.Pe?.Signature;

        var agreement = "无法比较";
        if (parsed is not null && builtin is not null)
        {
            var toolSigned = parsed.Verified is not null
                && (parsed.Verified.Equals("Signed", StringComparison.OrdinalIgnoreCase)
                    || parsed.Verified.StartsWith("Signed", StringComparison.OrdinalIgnoreCase));
            var builtinSigned = builtin.IsSignatureValid;
            agreement = toolSigned == builtinSigned
                ? $"一致（均判定为{(toolSigned ? "已签名有效" : "未签名 / 无效")}）"
                : $"不一致 —— 内置 WinVerifyTrust 判定「{builtin.StatusText}」，Sigcheck 判定「{parsed.Verified}」（需人工复核，可能是信任链存储差异）";
        }

        var evidence = new List<Evidence>
        {
            ToolEvidence(context, "sigcheck", "签名交叉验证（Sigcheck）",
                parsed is null
                    ? "Sigcheck 输出格式未识别，原始输出已留档。"
                    : $"签名状态：{parsed.Verified ?? "未知"}；签名者：{parsed.Signer ?? "无"}；比较结论：{agreement}",
                new
                {
                    sigcheckVerified = parsed?.Verified,
                    sigcheckSigner = parsed?.Signer,
                    sigcheckCompany = parsed?.Company,
                    sigcheckDescription = parsed?.Description,
                    sigcheckProductVersion = parsed?.ProductVersion,
                    sigcheckFileVersion = parsed?.FileVersion,
                    builtinStatus = builtin?.StatusText,
                    builtinSigner = builtin?.SignerSubject,
                    agreement,
                    enginePath = location.ExecutablePath,
                },
                "sigcheck", "signature", "cross-validation"),
        };

        var run = PluginRunResult.Ok($"Sigcheck 完成：{agreement}", evidence, null, artifacts);
        foreach (var l in log) run.Log.Add(l);
        return run;
    }

    internal sealed class SigcheckRow
    {
        public string? Path { get; set; }
        public string? Verified { get; set; }
        public string? Signer { get; set; }
        public string? Company { get; set; }
        public string? Description { get; set; }
        public string? ProductVersion { get; set; }
        public string? FileVersion { get; set; }
    }

    /// <summary>
    /// 读 sigcheck 写出的 CSV 文件，自动识别编码。
    /// sigcheck 在中文 Windows 上默认吐 UTF-16LE（无 BOM），按 UTF-8 读会是乱码，
    /// 所以先看 BOM，没有 BOM 则靠"NUL 字节占比"判断是不是 UTF-16。
    /// </summary>
    private static string ReadSigcheckCsvFile(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length == 0) return "";

            // BOM 优先
            if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
                return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);

            // 无 BOM：偶数字节大量为 0 → 几乎可以断定是 UTF-16LE
            var sample = Math.Min(bytes.Length, 512);
            var zeros = 0;
            for (var i = 1; i < sample; i += 2) if (bytes[i] == 0) zeros++;
            if (sample >= 2 && zeros > sample / 4)
                return Encoding.Unicode.GetString(bytes);

            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return "";
        }
    }

    internal static SigcheckRow? ParseSigcheckCsv(string csvText)
    {
        // 注意：只去掉换行，绝不能把 '"' 也剥掉 —— 引号是 CSV 语法的一部分，
        // 先剥引号会让 SplitCsvLine 的引号状态机错乱，整行被当成一个字段（实测踩过）。
        var lines = csvText.Split('\n')
            .Select(l => l.Trim('\r', '\n'))
            .Where(l => l.Trim().Length > 0)
            .ToList();
        if (lines.Count < 2) return null;

        var header = ProcmonCsvParser.SplitCsvLine(lines[0]).Select(h => h.Trim().Trim('"')).ToList();
        var row = ProcmonCsvParser.SplitCsvLine(lines[1]).Select(v => v.Trim().Trim('"')).ToList();

        string? Get(params string[] names)
        {
            foreach (var n in names)
            {
                var i = header.FindIndex(h => string.Equals(h, n, StringComparison.OrdinalIgnoreCase));
                if (i >= 0 && i < row.Count && row[i].Length > 0) return row[i];
            }
            return null;
        }

        return new SigcheckRow
        {
            Path = Get("Path"),
            Verified = Get("Verified"),
            // 不同版本 Sigcheck 的列名在 Signer / Publisher 之间摇摆过，两个都认
            Signer = Get("Signer", "Publisher"),
            Company = Get("Company"),
            Description = Get("Description"),
            ProductVersion = Get("Product Version", "ProductVersion"),
            FileVersion = Get("File Version", "FileVersion"),
        };
    }

    /// <summary>测试入口：验证编码自识别的文件读取。</summary>
    internal static string ReadSigcheckCsvForTest(string path) => ReadSigcheckCsvFile(path);

    private static string FirstLines(string text, int count) =>
        string.Join(" / ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim()).Where(l => l.Length > 0).Take(count));
}

// ═══════════════════════════════════════════════════════════════════════════
//  Sysinternals Strings —— 字符串召回率校验
// ═══════════════════════════════════════════════════════════════════════════

public sealed class StringsToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "strings";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var dir = ToolDirectory(context, "strings");
        var log = new List<string>();
        var minLen = Math.Max(4, context.Options.StringMinLength);

        // -accepteula：跳过首次运行的 EULA 页；-nobanner：去掉 "Strings v2.54 ..." 横幅。
        // 少这两个开关，横幅会被当成一条提取到的字符串混进结果，污染召回率统计。
        var result = await ProcessRunner.RunAsync(location.ExecutablePath!,
            $"-accepteula -nobanner -n {minLen} -q {ProcessRunner.Quote(context.TargetPath)}",
            dir, 180_000, context.CancellationToken, log.Add).ConfigureAwait(false);

        if (!result.Started)
            return PluginRunResult.Fail($"strings 启动失败：{result.StdErr}");

        var toolStrings = result.StdOut
            .Split('\n')
            .Select(l => l.TrimEnd('\r'))
            .Where(l => l.Length >= minLen)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var ours = context.Result.Strings.Select(s => s.Value).ToHashSet(StringComparer.Ordinal);
        var toolOnly = toolStrings.Where(s => !ours.Contains(s)).ToList();

        var artifacts = new List<string>();
        var rawFile = ToolArtifact.WriteText(dir, "strings-output.txt", result.Combined);
        if (rawFile is not null) artifacts.Add(rawFile);

        var recallText = ours.Count == 0
            ? "内置提取器未运行或结果为空，无法计算召回率。"
            : $"内置提取 {ours.Count} 条，Sysinternals 提取 {toolStrings.Count} 条，"
              + $"仅工具发现 {toolOnly.Count} 条（召回率参考 {100.0 * (toolStrings.Count - toolOnly.Count) / Math.Max(1, toolStrings.Count):F1}%）";

        var evidence = new List<Evidence>
        {
            ToolEvidence(context, "strings", "字符串提取召回率对照",
                recallText,
                new
                {
                    minLength = minLen,
                    toolCount = toolStrings.Count,
                    builtinCount = ours.Count,
                    toolOnlyCount = toolOnly.Count,
                    toolOnlySample = toolOnly.Take(120).ToList(),
                    enginePath = location.ExecutablePath,
                    exitCode = result.ExitCode,
                },
                "strings", "cross-validation"),
        };

        // 只工具发现的字符串里挑"看起来敏感"的，避免把整个列表塞给用户
        var sensitive = toolOnly.Where(IsInteresting).Take(200).ToList();
        if (sensitive.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "strings", "内置提取器遗漏的关注字符串",
                $"共 {sensitive.Count} 条值得人工确认（含 URL / 路径 / 凭据 / 命令特征）",
                sensitive, "strings", "gap"));
        }

        var run = PluginRunResult.Ok(
            $"strings 完成：工具 {toolStrings.Count} 条 / 内置 {ours.Count} 条，差异 {toolOnly.Count} 条", evidence, null, artifacts);
        foreach (var l in log) run.Log.Add(l);
        return run;
    }

    private static bool IsInteresting(string s)
    {
        if (s.Contains("://", StringComparison.Ordinal)) return true;
        if (s.Contains("password", StringComparison.OrdinalIgnoreCase)) return true;
        if (s.Contains("token", StringComparison.OrdinalIgnoreCase)) return true;
        if (s.Contains("apikey", StringComparison.OrdinalIgnoreCase)) return true;
        if (s.StartsWith('\\') || (s.Length > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))) return true;
        if (s.Contains(".dll", StringComparison.OrdinalIgnoreCase)) return true;
        return s.Contains('\\') && s.Length > 12;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  ILSpy (ilspycmd) —— 托管代码结构 / 反编译导出
// ═══════════════════════════════════════════════════════════════════════════

public sealed class IlSpyToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "ilspy";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        // 只有托管程序集才有意义，先确认目标确实是 .NET
        var isDotNet = context.Result.DotNet is not null
                       || (context.Result.Pe?.IsDotNet ?? false);
        if (!isDotNet)
        {
            return PluginRunResult.Skipped(
                "目标不是 .NET 程序集（未检测到 CLR 头 / 无托管元数据），ILSpy 不适用。");
        }

        var dir = ToolDirectory(context, "ilspy");
        var log = new List<string>();
        var exe = location.ExecutablePath!;
        var evidence = new List<Evidence>();
        var artifacts = new List<string>();

        // 1) 列类型：轻量、快、几乎不会失败，作为默认动作
        var listRun = await ProcessRunner.RunAsync(exe,
            $"-l c {ProcessRunner.Quote(context.TargetPath)}",
            dir, 120_000, context.CancellationToken, log.Add).ConfigureAwait(false);

        if (!listRun.Started)
            return PluginRunResult.Fail($"ilspycmd 启动失败：{listRun.StdErr}");

        var types = listRun.StdOut.Split('\n')
            .Select(l => l.Trim()).Where(l => l.Length > 0)
            .Distinct(StringComparer.Ordinal).ToList();

        var listFile = ToolArtifact.WriteText(dir, "types.txt", listRun.StdOut);
        if (listFile is not null) artifacts.Add(listFile);

        var builtinTypeCount = context.Result.DotNet?.TypeCount ?? 0;
        evidence.Add(ToolEvidence(context, "ilspy", "ILSpy 类型清单",
            listRun.ExitCode == 0
                ? $"ilspycmd 列出 {types.Count} 个类型；内置元数据解析得到 {builtinTypeCount} 个类型"
                : $"ilspycmd 退出码 {listRun.ExitCode}，输出可能不完整：{FirstLines(listRun.StdErr, 2)}",
            new
            {
                toolTypeCount = types.Count,
                builtinTypeCount,
                sample = types.Take(80).ToList(),
                exitCode = listRun.ExitCode,
                enginePath = location.ExecutablePath,
                engineVersion = location.Version,
            },
            "ilspy", "dotnet", "cross-validation"));

        // 2) 反编译导出：产物多、耗时长，必须显式开启
        if (!context.Options.EnableIlSpyDecompile)
        {
            var skipRun = PluginRunResult.Ok(
                $"ILSpy 类型清单完成（{types.Count} 个类型）；反编译导出未开启（可在设置中启用）", evidence, null, artifacts);
            foreach (var l in log) skipRun.Log.Add(l);
            return skipRun;
        }

        var outDir = Path.Combine(dir, "decompiled");
        Directory.CreateDirectory(outDir);
        context.Progress(0.5, "ilspycmd 反编译导出");

        var decompile = await ProcessRunner.RunAsync(exe,
            $"-o {ProcessRunner.Quote(outDir)} -p {ProcessRunner.Quote(context.TargetPath)}",
            dir, timeoutMs: 600_000, cancellationToken: context.CancellationToken, log: log.Add).ConfigureAwait(false);

        var files = new List<string>();
        try { files = Directory.EnumerateFiles(outDir, "*.cs", SearchOption.AllDirectories).Take(20_000).ToList(); }
        catch { }

        evidence.Add(ToolEvidence(context, "ilspy", "ILSpy 反编译导出",
            decompile.TimedOut
                ? $"反编译超过 600s 被终止，已导出 {files.Count} 个源文件（不完整）。"
                : $"反编译完成，导出 {files.Count} 个 .cs 文件到 {outDir}",
            new
            {
                outputDirectory = outDir,
                fileCount = files.Count,
                timedOut = decompile.TimedOut,
                exitCode = decompile.ExitCode,
                durationSeconds = Math.Round(decompile.Duration.TotalSeconds, 1),
            },
            "ilspy", "decompiled"));

        var run = PluginRunResult.Ok(
            $"ILSpy 完成：{types.Count} 个类型，反编译导出 {files.Count} 个文件", evidence, null, artifacts);
        foreach (var l in log) run.Log.Add(l);
        return run;
    }

    private static string FirstLines(string text, int count) =>
        string.Join(" / ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim()).Where(l => l.Length > 0).Take(count));
}
