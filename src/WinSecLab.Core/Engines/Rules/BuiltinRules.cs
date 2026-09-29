using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Rules;

/// <summary>
/// 内置规则目录。分三大类：
///  1. 二进制静态特征（可验证的客观事实，如未签名、RWX 节区、危险 API）；
///  2. 运行期行为（来自本次会话实际观测到的进程 / 文件 / 注册表 / 网络事件）；
///  3. 工具与规则库命中（YARA、第三方工具输出）。
/// 每条规则都给出 CWE 归类与可执行的整改建议，避免只报问题不给方向。
/// </summary>
public static class BuiltinRules
{
    public static readonly IReadOnlyList<RuleDefinition> All = BuildRules();

    private static List<RuleDefinition> BuildRules()
    {
        var rules = new List<RuleDefinition>();
        AddBinaryRules(rules);
        AddRuntimeRules(rules);
        AddNetworkRules(rules);
        AddToolRules(rules);
        return rules;
    }

    // =====================================================================
    // 一、二进制静态特征
    // =====================================================================

    private static void AddBinaryRules(List<RuleDefinition> rules)
    {
        rules.Add(new RuleDefinition(
            "WS-001", "代码完整性与签名", Severity.Medium, Confidence.High,
            "可执行文件缺少有效的数字签名",
            "被测主程序未通过 WinVerifyTrust 校验。缺失或无效的签名意味着二进制内容无法与发布者身份绑定，"
            + "同时也会让终端防护软件降低对它的信任评级。",
            "无法验证发布者与完整性：分发链被替换、被第三方二次打包时不会有任何提示。",
            "为发布版本配置代码签名证书（EV 证书可获得 SmartScreen 立即信誉），在 CI 中对每个产物签名并校验。",
            "CWE-345", "A08:2021 Software and Data Integrity Failures",
            ctx =>
            {
                if (ctx.Pe is null || ctx.Pe.IsSigned) return Enumerable.Empty<RuleHit>();

                var pe = ctx.Pe;
                var facts = new List<string>
                {
                    $"签名状态：{pe.Signature.StatusText}",
                    $"WinVerifyTrust 返回：0x{pe.Signature.WinVerifyTrustResult:X8}",
                };

                // Windows 系统目录下的文件通常是目录签名（catalog），不内嵌签名，不应按缺陷计
                var inWindowsDir = PathSemantics.IsWindowsDirectory(pe.FilePath);
                if (inWindowsDir)
                {
                    facts.Add("文件位于 Windows 系统目录，可能采用了目录签名（catalog）而非内嵌签名");
                    return new[]
                    {
                        new RuleHit
                        {
                            Target = pe.FilePath,
                            EvidenceIds = ctx.IdsWithTag("signature"),
                            Facts = facts,
                            RelatedFiles = { pe.FilePath },
                            SeverityOverride = Severity.Info,
                            ConfidenceOverride = Confidence.Low,
                        },
                    };
                }

                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("signature"),
                        Facts = facts,
                        RelatedFiles = { pe.FilePath },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-002", "代码完整性与签名", Severity.Critical, Confidence.High,
            "数字签名无效：文件在签名之后被修改",
            "WinVerifyTrust 报告摘要不匹配（TRUST_E_BAD_DIGEST）。这说明二进制在签名完成之后被改动过，"
            + "是「二进制被篡改 / 被二次打包」的直接证据。",
            "文件内容与发布者签署的版本不一致，无法排除恶意代码注入，不能在生产环境使用。",
            "立即停止分发该产物；从官方渠道重新取得原始安装包并比对 SHA-256；排查构建与发布环节是否被植入后门。",
            "CWE-494", "A08:2021 Software and Data Integrity Failures",
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null || pe.Signature.Status != SignatureStatus.Invalid) return Enumerable.Empty<RuleHit>();
                if (pe.Signature.WinVerifyTrustResult != unchecked((long)0x80096010L)) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("signature"),
                        Facts =
                        {
                            $"WinVerifyTrust = 0x{pe.Signature.WinVerifyTrustResult:X8}（TRUST_E_BAD_DIGEST）",
                            $"签名者：{pe.Signature.SignerSubject ?? "未知"}",
                            $"SHA-256：{pe.Sha256}",
                        },
                        RelatedFiles = { pe.FilePath },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-003", "代码完整性与签名", Severity.Low, Confidence.Medium,
            "签名有效但证书链不受信任",
            "签名本身校验通过，但签名者证书的信任链存在问题（根证书不在受信任存储、链不完整或证书用途不匹配）。",
            "用户环境可能仍会弹出安全警告；企业环境中可能被策略拦截。",
            "使用来自受信任 CA 的证书重新签名；确保签名时附带完整证书链并配置时间戳服务（RFC 3161）。",
            "CWE-295", "A02:2021 Cryptographic Failures",
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null) return Enumerable.Empty<RuleHit>();
                if (pe.Signature.Status != SignatureStatus.ValidButUntrusted) return Enumerable.Empty<RuleHit>();

                var facts = new List<string>
                {
                    $"签名者：{pe.Signature.SignerSubject ?? "未知"}",
                    $"签发者：{pe.Signature.SignerIssuer ?? "未知"}",
                };
                facts.AddRange(pe.Signature.ChainIssues.Select(i => "链问题：" + i));
                if (!pe.Signature.IsTimestamped) facts.Add("未检测到时间戳签名，证书过期后所有旧版本签名将失效");

                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("signature"),
                        Facts = facts,
                        RelatedFiles = { pe.FilePath },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-004", "内存保护与缓解措施", Severity.High, Confidence.High,
            "PE 节区同时具有可写与可执行权限（RWX）",
            "存在 Characteristics 同时置位 MEM_WRITE 与 MEM_EXECUTE 的节区。正常编译器不会生成 RWX 节区，"
            + "它通常来自加壳器、自修改代码或手工构造的加载器，是代码注入的常见前置条件。",
            "为攻击者提供了无需额外触发即可写入并执行代码的内存区域，绕过 DEP 的意义。",
            "若为自研代码，检查是否有运行时改写代码段的设计；若为第三方加壳产物，考虑改用不产生 RWX 节区的保护方案。",
            "CWE-732", "A04:2021 Insecure Design",
            ctx =>
            {
                if (ctx.Pe is null) return Enumerable.Empty<RuleHit>();
                return ctx.Pe.Sections.Where(s => s.IsWritableAndExecutable)
                    .Select(s => new RuleHit
                    {
                        GroupKey = s.Name,
                        Target = $"{Path.GetFileName(ctx.Pe.FileName)} 节区 {s.Name}",
                        EvidenceIds = ctx.IdsWithTag("entropy").Concat(ctx.IdsWithTag("pe")).Distinct().Take(4).ToList(),
                        Facts =
                        {
                            $"节区 {s.Name}：权限 {s.Permissions}，虚拟大小 {s.VirtualSize} 字节，熵值 {s.Entropy}",
                            $"原始数据偏移 0x{s.RawOffset:X}，大小 {s.RawSize} 字节",
                        },
                        RelatedFiles = { ctx.Pe.FilePath },
                    });
            }));

        rules.Add(new RuleDefinition(
            "WS-005", "内存保护与缓解措施", Severity.Medium, Confidence.Medium,
            "存在高熵节区，疑似加壳或加密载荷",
            "有节区的 Shannon 熵值达到 7.2 bit/byte 以上且体积超过 4 KB。压缩或加密后的数据才会呈现这种分布，"
            + "正常编译产物的代码段熵值一般在 6.0–6.8 之间。",
            "静态分析（字符串、导入表、YARA）对加壳后的外层几乎无效，需要先脱壳才能看到真实行为；"
            + "同时也意味着该程序有意隐藏内部结构。",
            "确认是否为已知商用保护壳；若为自研，评估是否必须加壳（可能触发杀软误报）；分析时先脱壳或转为动态行为监控。",
            "CWE-506", null,
            ctx =>
            {
                if (ctx.Pe is null) return Enumerable.Empty<RuleHit>();
                var threshold = ctx.Options.HighEntropyThreshold;
                var packed = ctx.Pe.Sections
                    .Where(s => s.Entropy >= threshold && s.RawSize >= 4096)
                    .ToList();
                if (packed.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("entropy"),
                        Facts = packed.Select(s =>
                            $"节区 {s.Name}：熵 {s.Entropy}（{Util.Entropy.Describe(s.Entropy)}），大小 {s.RawSize} 字节").ToList(),
                        RelatedFiles = { ctx.Pe.FilePath },
                        ConfidenceOverride = packed.Count >= 2 ? Confidence.High : Confidence.Medium,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-006", "防篡改与构建可信性", Severity.Low, Confidence.Low,
            "缺少 Rich Header，二进制可能被重写工具处理过",
            "MSVC 工具链默认会在 DOS Stub 与 PE 头之间写入 Rich Header。它缺失通常意味着文件被 "
            + "二进制重写工具（LordPE、CFF Explorer、PE-Bear 等）修改过，或使用了非 MSVC 工具链。",
            "可能说明产物经过了工具链之外的修改，构建产物与源码的对应关系被破坏。",
            "确认发布流程中是否存在人工修改二进制的步骤；如需保持可信，应保证产物完全由 CI 从源码构建。",
            "CWE-345", null,
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null || pe.IsValidPe == false) return Enumerable.Empty<RuleHit>();
                if (!pe.RichHeader.Stripped) return Enumerable.Empty<RuleHit>();
                // Go / Rust / MinGW 等本来就不会写 Rich Header，单独排除
                if (pe.Compiler.Contains("Go", StringComparison.OrdinalIgnoreCase) ||
                    pe.Compiler.Contains("Rust", StringComparison.OrdinalIgnoreCase) ||
                    pe.Compiler.Contains("Delphi", StringComparison.OrdinalIgnoreCase) ||
                    pe.Compiler == "unknown") return Enumerable.Empty<RuleHit>();
                if (!pe.Compiler.StartsWith("MSVC", StringComparison.OrdinalIgnoreCase)) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("pe"),
                        Facts =
                        {
                            $"推断编译器为 {pe.Compiler}，但未找到 Rich Header",
                            $"链接器版本 {pe.LinkerMajor}.{pe.LinkerMinor}",
                        },
                        RelatedFiles = { pe.FilePath },
                        ConfidenceOverride = Confidence.Low,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-007", "防篡改与构建可信性", Severity.High, Confidence.Medium,
            "链接了常见的进程注入 API 组合",
            "导入表中出现了「申请可执行内存 + 写入远程进程 + 创建远程线程」这一注入三件套，"
            + "或其它典型的跨进程操控接口。合法软件（调试器、游戏反作弊、安全产品、辅助工具）也会用到，"
            + "因此必须结合行为证据判断，不能仅凭导入表定性。",
            "具备向其它进程注入并执行任意代码的能力，是权限提升与持久化常用的技术手段。",
            "确认该能力是否为产品功能所必需；若必需，应说明用途并保证只对本进程或已授权目标生效，"
            + "同时在文档中明示，避免被终端防护判定为恶意行为。",
            "CWE-1125", null,
            ctx =>
            {
                if (ctx.Pe is null) return Enumerable.Empty<RuleHit>();

                var required = new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" };
                var matched = required.Where(name => ctx.HasImportFunction(name)).ToList();
                var hookApis = new[] { "SetWindowsHookExA", "SetWindowsHookExW", "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection" };
                var matchedHooks = hookApis.Where(name => ctx.HasImportFunction(name)).ToList();

                if (matched.Count < 2 && matchedHooks.Count == 0) return Enumerable.Empty<RuleHit>();

                var facts = new List<string>();
                if (matched.Count > 0)
                    facts.Add($"注入三件套命中 {matched.Count}/3：{string.Join(", ", ctx.MatchedImportFunctions(required.ToArray()))}");
                if (matchedHooks.Count > 0)
                    facts.Add($"钩子 / 线程上下文类 API：{string.Join(", ", ctx.MatchedImportFunctions(hookApis))}");

                var severity = matched.Count == 3 ? Severity.High : Severity.Medium;

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("pe"),
                        Facts = facts,
                        RelatedFiles = { ctx.Pe.FilePath },
                        SeverityOverride = severity,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-008", "内存保护与缓解措施", Severity.Medium, Confidence.High,
            "PE 未启用关键的漏洞缓解措施",
            "可选头的 DllCharacteristics 中缺少 ASLR（DYNAMIC_BASE）、DEP（NX_COMPAT）或 CFG。"
            + "这些是编译期就能开启的编译缓解，缺失会显著降低利用内存破坏漏洞的成本。",
            "内存破坏类漏洞更容易被稳定利用，攻击者可直接跳转到固定地址执行载荷。",
            "在项目属性中开启 /DYNAMICBASE、/NXCOMPAT、/guard:cf（并配合 /GS、/sdl），重新构建发布版本。",
            "CWE-693", "A06:2021 Vulnerable and Outdated Components",
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null || !pe.IsValidPe || string.IsNullOrEmpty(pe.DllCharacteristics)) return Enumerable.Empty<RuleHit>();
                // 驱动与 .NET 引用程序集不适用这套判定
                if (pe.IsDriver) return Enumerable.Empty<RuleHit>();

                var missing = new List<string>();
                if (!pe.DllCharacteristics.Contains("ASLR")) missing.Add("ASLR (/DYNAMICBASE)");
                if (!pe.DllCharacteristics.Contains("DEP")) missing.Add("DEP (/NXCOMPAT)");
                if (!pe.DllCharacteristics.Contains("CFG") && pe.Is64Bit) missing.Add("CFG (/guard:cf)");
                if (missing.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("pe"),
                        Facts =
                        {
                            $"当前 DllCharacteristics：{pe.DllCharacteristics}",
                            $"缺失：{string.Join("、", missing)}",
                            $"子系统 {pe.Subsystem}，位数 {(pe.Is64Bit ? "64" : "32")}",
                        },
                        RelatedFiles = { pe.FilePath },
                        SeverityOverride = missing.Count >= 2 ? Severity.Medium : Severity.Low,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-009", "依赖与加载安全", Severity.High, Confidence.High,
            "存在从用户可写目录解析的依赖 DLL",
            "导入表中有 DLL 实际解析到普通用户可写的位置（AppData、Temp、ProgramData、程序自身目录等）。"
            + "若该程序以更高权限运行，攻击者可以在这些位置放置同名 DLL 实现加载劫持（DLL 劫持 / 种马）。",
            "在提权场景下可导致任意代码以高权限执行；即使不提权，也能实现对被测程序的功能劫持。",
            "把依赖 DLL 收敛到 Program Files 下的安装目录并设为管理员可写；对关键模块使用 SetDefaultDllDirectories "
            + "与 LoadLibraryEx(LOAD_LIBRARY_SEARCH_SYSTEM32) 限定搜索顺序；为安装目录设置正确的 ACL。",
            "CWE-427", "A03:2021 Injection",
            ctx =>
            {
                var risky = ctx.Dependencies
                    .Where(d => d.IsPresent && d.IsUserWritableLocation && !d.IsSystemLibrary)
                    .ToList();
                if (risky.Count == 0) return Enumerable.Empty<RuleHit>();

                return risky.Select(d => new RuleHit
                {
                    GroupKey = d.Name,
                    Target = d.ResolvedPath ?? d.Name,
                    EvidenceIds = ctx.IdsWithTag("deps"),
                    Facts =
                    {
                        $"依赖 {d.Name} 解析到 {d.ResolvedPath}",
                        $"搜索来源：{d.SearchSource}；签名：{(d.IsSigned == true ? "有" : d.IsSigned == false ? "无" : "未知")}",
                    },
                    RelatedFiles = { d.ResolvedPath ?? d.Name },
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-010", "依赖与加载安全", Severity.Medium, Confidence.Medium,
            "安装目录中存在与系统 DLL 同名的本地副本",
            "被测程序所在目录里有文件名与 Windows 系统 DLL 相同的模块。这类「本地副本」是 DLL 劫持的经典手法："
            + "应用目录在搜索顺序中优先级高于 System32，同名文件会先被加载。",
            "可能劫持系统 API 行为，或在被替换后导致任意代码执行。",
            "确认这些同名副本是否为产品有意携带（如自带的 CRT 分发）；如需携带，应放在子目录并用清单文件"
            + "（manifest）指向正确版本，避免与系统模块同名。",
            "CWE-427", null,
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null) return Enumerable.Empty<RuleHit>();

                var directory = Path.GetDirectoryName(pe.FilePath);
                if (string.IsNullOrEmpty(directory)) return Enumerable.Empty<RuleHit>();

                var props = ctx.Dependencies
                    .Where(d => d.ResolvedPath is not null &&
                                string.Equals(Path.GetDirectoryName(d.ResolvedPath), directory,
                                    StringComparison.OrdinalIgnoreCase) &&
                                PathSemantics.IsKnownSystemLibrary(d.Name))
                    .ToList();
                if (props.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = directory,
                        EvidenceIds = ctx.IdsWithTag("deps"),
                        Facts = props.Select(p => $"{p.Name} → {p.ResolvedPath}（与系统模块同名）").ToList(),
                        RelatedFiles = props.Select(p => p.ResolvedPath!).ToList(),
                        ConfidenceOverride = Confidence.Medium,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-011", "敏感信息暴露", Severity.Medium, Confidence.Medium,
            "二进制中疑似包含硬编码凭据",
            "字符串提取结果里出现了 password / secret / token / api_key 等凭据语义的关键字。"
            + "硬编码在二进制里的凭据可以被任何拿到文件的人提取出来，且无法在不发版的情况下轮换。",
            "凭据泄露后可被用于访问后端服务、第三方 API，横向影响范围通常超出单个客户端。",
            "把所有密钥迁移到服务端下发或使用短期令牌；客户端只保留不可逆的公钥类材料；"
            + "轮换已泄露的凭据，并在代码评审中加入对硬编码凭据的静态检查。",
            "CWE-798", "A07:2021 Identification and Authentication Failures",
            ctx =>
            {
                var hits = ctx.StringsInCategory("Credential")
                    .Where(s => s.Value.Length is >= 6 and <= 160)
                    .Take(200)
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                // 纯函数名/常量名（不含值）不算泄露证据，过滤掉只含关键字的短串
                var meaningful = hits.Where(s =>
                {
                    var v = s.Value.Trim();
                    var lower = v.ToLowerInvariant();
                    if (lower is "password" or "passwd" or "pwd" or "secret" or "token" or "apikey" or "api_key"
                        or "access_key" or "private_key" or "credential" or "bearer") return false;
                    return v.Length >= 8;
                }).ToList();

                if (meaningful.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe?.FilePath ?? "(二进制)",
                        EvidenceIds = ctx.IdsWithTag("strings"),
                        Facts = meaningful.Take(8)
                            .Select(s => $"[{s.Section}@0x{s.Offset:X}] {Truncate(s.Value, 110)}").ToList(),
                        RelatedFiles = ctx.Pe is null ? new List<string>() : new List<string> { ctx.Pe.FilePath },
                        ConfidenceOverride = meaningful.Count >= 3 ? Confidence.High : Confidence.Medium,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-012", "网络与会话安全", Severity.Low, Confidence.High,
            "二进制中包含明文 HTTP 地址",
            "字符串里出现 http:// 开头的地址。明文 HTTP 无法保证传输内容的机密性与完整性，"
            + "在公共网络下可被中间人读取或篡改。",
            "客户端与服务器之间的数据（包括认证信息）可能被窃听或篡改。",
            "所有对外通信切换到 HTTPS 并启用证书校验（禁止跳过证书错误）；如必须兼容旧协议，"
            + "至少对敏感字段做应用层加密并加入完整性校验。",
            "CWE-319", "A02:2021 Cryptographic Failures",
            ctx =>
            {
                var urls = ctx.StringsInCategory("URL")
                    .Where(s => s.Value.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (urls.Count == 0) return Enumerable.Empty<RuleHit>();

                var hosts = urls.Select(u => ExtractHost(u.Value)).Where(h => h.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe?.FilePath ?? "(二进制)",
                        EvidenceIds = ctx.IdsWithTag("strings"),
                        Facts = hosts.Take(10).Select(h => $"明文端点：{h}").ToList(),
                        RelatedNetwork = hosts.Take(10).ToList(),
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-013", "命令与代码执行", Severity.Medium, Confidence.Low,
            "二进制中包含命令行解释器 / 系统工具调用特征",
            "字符串里出现 cmd.exe、powershell、rundll32、regsvr32、mshta、certutil、bitsadmin 等宿主程序名。"
            + "这些是 LOLBin（Living-off-the-Land Binary）的典型载体，常用于绕过应用白名单执行代码。",
            "若相关路径可由外部输入影响，可能形成命令注入；若为设计内的更新机制，也存在被劫持滥用的空间。",
            "核对每一处调用的实际用途；避免用字符串拼接构造命令行（使用参数数组形式）；"
            + "对可执行路径做白名单校验，禁止从可写目录或用户输入决定要执行的宿主程序。",
            "CWE-78", "A03:2021 Injection",
            ctx =>
            {
                var hits = ctx.StringsInCategory("Command").ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();
                if (hits.Count < 2) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe?.FilePath ?? "(二进制)",
                        EvidenceIds = ctx.IdsWithTag("strings"),
                        Facts = hits.Take(10).Select(h => $"[{h.Section}] {Truncate(h.Value, 100)}").ToList(),
                        ConfidenceOverride = hits.Count >= 5 ? Confidence.Medium : Confidence.Low,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-014", "防篡改与构建可信性", Severity.Info, Confidence.High,
            "二进制保留了调试信息（PDB 路径）",
            "PE 的调试目录中保留了 CodeView 记录，包含编译机上的 PDB 路径。"
            + "这属于信息泄露：可能暴露项目结构和开发者账号名；同时也说明这是未做符号剥离的调试或内部版本。",
            "泄露内部目录结构与可能的开发者身份信息，便于攻击者构造针对性攻击。",
            "发布构建中使用 /DEBUG:NONE，或构建后剥离调试目录与 PDB 引用。",
            "CWE-200", "A05:2021 Security Misconfiguration",
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null || pe.DebugPaths.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("pe"),
                        Facts = pe.DebugPaths.Select(p => $"调试路径：{p}").ToList(),
                        RelatedFiles = { pe.FilePath },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-015", "依赖与加载安全", Severity.Low, Confidence.Medium,
            "存在无法解析的依赖 DLL",
            "导入表中有模块在「应用目录 / 系统目录 / 附加搜索目录」中均未找到。"
            + "这类模块可能在运行时才由安装程序补齐，也可能是被削掉的运行库，或加载顺序依赖了当前工作目录。",
            "部署到干净环境时可能出现加载失败；若依赖「当前目录」搜索，则存在被同名文件劫持的空间。",
            "确认缺失模块的分发方式（随包携带 / 运行库安装）；不要把安全关键模块交给默认搜索顺序解析。",
            "CWE-427", null,
            ctx =>
            {
                var missing = ctx.Dependencies
                    .Where(d => !d.IsPresent && !d.IsSystemLibrary)
                    .Take(40)
                    .ToList();
                if (missing.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe?.FilePath ?? "(二进制)",
                        EvidenceIds = ctx.IdsWithTag("deps"),
                        Facts = missing.Select(m => $"未解析：{m.Name}（{m.SearchSource}）").ToList(),
                        RelatedFiles = ctx.Pe is null ? new List<string>() : new List<string> { ctx.Pe.FilePath },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-016", "代码完整性与签名", Severity.High, Confidence.High,
            "内核驱动（System 子系统）文件，需要单独的安全审查",
            "被测文件是 Windows 内核驱动。驱动运行在 Ring 0，一旦存在缺陷或恶意逻辑，影响面覆盖整个系统，"
            + "且不受用户态安全机制的约束。",
            "驱动中的任意内存写入或输入校验缺失都可能直接导致系统提权或蓝屏。",
            "仅在具备驱动签名（WHQL / EV）的前提下分发；对 IOCTL 接口做完整的输入校验与访问控制；"
            + "启用内核池隔离与 CFG；在 Hyper-V 虚拟机中做模糊测试。",
            "CWE-1284", null,
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null || !pe.IsDriver) return Enumerable.Empty<RuleHit>();
                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("pe"),
                        Facts =
                        {
                            $"子系统：{pe.Subsystem}",
                            $"位数：{(pe.Is64Bit ? "64" : "32")}",
                            $"签名状态：{pe.Signature.StatusText}",
                        },
                        RelatedFiles = { pe.FilePath },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-017", "防篡改与构建可信性", Severity.Medium, Confidence.Low,
            "文件存在大体积的附加数据（overlay），可能是投放的载荷",
            "PE 节区数据结束之后仍有大量附加数据。安装包（自解压）、游戏资源包都会正常使用 overlay，"
            + "但当 overlay 体积大且熵值高时，通常意味着里面封装了压缩或加密的可执行载荷。",
            "附加数据在常规签名校验与部分扫描工具中容易被忽略，可能承载未声明的组件。",
            "确认 overlay 的来源与内容（解包查看）；若为打包器产生，考虑改为标准的安装包格式并保留可校验清单。",
            "CWE-506", null,
            ctx =>
            {
                var pe = ctx.Pe;
                if (pe is null || !pe.HasOverlay) return Enumerable.Empty<RuleHit>();
                if (pe.OverlaySize < 256 * 1024) return Enumerable.Empty<RuleHit>();
                if (pe.IsInstallerPackage) return Enumerable.Empty<RuleHit>();

                var highEntropy = pe.OverlayEntropy >= 7.2;
                return new[]
                {
                    new RuleHit
                    {
                        Target = pe.FilePath,
                        EvidenceIds = ctx.IdsWithTag("entropy"),
                        Facts =
                        {
                            $"overlay 大小 {pe.OverlaySize / 1024} KB（占文件的 {pe.OverlaySize * 100.0 / Math.Max(1, pe.FileSize):F1}%）",
                            $"overlay 熵值 {pe.OverlayEntropy}（{Util.Entropy.Describe(pe.OverlayEntropy)}）",
                        },
                        RelatedFiles = { pe.FilePath },
                        SeverityOverride = highEntropy ? Severity.Medium : Severity.Low,
                        ConfidenceOverride = highEntropy ? Confidence.Medium : Confidence.Low,
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-018", "代码完整性与签名", Severity.Medium, Confidence.Medium,
            ".NET 程序集经过混淆，无法直接审计源码逻辑",
            "托管元数据中出现了混淆器特征（属性标记、超短符号名、非打印字符类型名等）。"
            + "混淆本身不是漏洞，但它会阻断代码审计，并常被用于隐藏不希望被审计的逻辑。",
            "无法通过反编译确认是否存在后门、绕过或凭据硬编码；后续安全评估只能依赖动态行为。",
            "确认混淆是否为许可保护所必需；若必须混淆，应在内部保留未混淆的对应版本供安全评审使用，"
            + "并确保混淆不会破坏 .NET 的强名称与反射调用。",
            "CWE-656", null,
            ctx =>
            {
                var dotnet = ctx.DotNet;
                if (dotnet is null || !dotnet.IsDotNet || !dotnet.UsesObfuscation) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Pe?.FilePath ?? dotnet.AssemblyName ?? "(托管程序集)",
                        EvidenceIds = ctx.IdsWithTag("dotnet"),
                        Facts = dotnet.ObfuscationHints.Take(8).ToList(),
                        RelatedFiles = ctx.Pe is null ? new List<string>() : new List<string> { ctx.Pe.FilePath },
                    },
                };
            }));
    }

    // =====================================================================
    // 二、运行期行为
    // =====================================================================

    private static void AddRuntimeRules(List<RuleDefinition> rules)
    {
        rules.Add(new RuleDefinition(
            "WS-101", "持久化", Severity.High, Confidence.High,
            "运行期在自启动位置创建或修改了注册表项",
            "本次会话观测到被测进程相关活动期间，Run / RunOnce / Winlogon / IFEO / AppInit_DLLs 等"
            + "持久化相关的注册表键被创建或修改。这类位置决定系统下次启动时自动执行什么。",
            "攻击者可借此在重启后继续控制系统；也可能是产品自身的自动启动功能，需要与实际设计对照。",
            "确认该自启动是否为产品预期行为；若为预期，需要在安装界面明确告知用户并提供开关；"
            + "若为非预期，按恶意持久化处理并排查写入来源。",
            "CWE-15", "A05:2021 Security Misconfiguration",
            ctx =>
            {
                var hits = ctx.EventsMatching(e =>
                        e.Type is MonitorEventType.RegistryCreate or MonitorEventType.RegistrySet
                        && Engines.Dynamic.RegistryMonitor.IsPersistencePath(e.Target))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return hits.GroupBy(e => e.Target).Select(g =>
                {
                    var first = g.First();
                    return new RuleHit
                    {
                        GroupKey = first.Target,
                        Target = first.Target,
                        EvidenceIds = ctx.IdsWithTag("registry"),
                        Facts = new List<string>
                        {
                            $"{first.Timestamp:HH:mm:ss.fff} {first.Operation} → {first.Target}",
                            first.Detail is null ? "" : $"值变化：{Truncate(first.Detail, 160)}",
                        }.Where(f => f.Length > 0).ToList(),
                        RelatedRegistry = { first.Target },
                        Reproduction =
                            "1. 在干净快照的测试虚拟机中导出注册表 Run / RunOnce / Winlogon 分支作为基线。\n"
                            + "2. 运行被测程序并正常操作一次（含首次启动向导）。\n"
                            + "3. 再次导出同一分支并 diff，确认新增项与本次观测一致。\n"
                            + $"4. 关注项：{first.Target}",
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-102", "持久化", Severity.High, Confidence.Medium,
            "运行期创建了 Windows 服务",
            "观测到 HKLM\\SYSTEM\\CurrentControlSet\\Services 下出现了新的服务键。"
            + "服务以 SYSTEM 权限运行，是提权与持久化的高价值载体。",
            "新建服务可能带来 SYSTEM 权限的常驻进程；若服务的可执行路径位于可写目录，则等于给攻击者预置了提权入口。",
            "确认新增服务是否为产品正常安装的一部分；服务的 ImagePath 必须指向 Program Files 下受保护目录；"
            + "服务应使用最小必要权限账户（避免 LocalSystem），并对命名管道 / IPC 接口做访问控制。",
            "CWE-15", null,
            ctx =>
            {
                var hits = ctx.EventsMatching(e =>
                        e.Type is MonitorEventType.RegistryCreate or MonitorEventType.RegistrySet &&
                        e.Target.Contains(@"SYSTEM\CurrentControlSet\Services", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                        EvidenceIds = ctx.IdsWithTag("registry"),
                        Facts = hits.Take(10).Select(e => $"{e.Timestamp:HH:mm:ss.fff} {e.Target}").ToList(),
                        RelatedRegistry = hits.Take(10).Select(e => e.Target).ToList(),
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-103", "持久化", Severity.Critical, Confidence.High,
            "运行期修改了 IFEO / AppInit_DLLs / Winlogon 等劫持点",
            "这些注册表位置可以改变其它程序的加载与登录流程：IFEO 的 Debugger 值能把任意程序变成调试目标，"
            + "AppInit_DLLs 会向所有加载 user32.dll 的进程注入 DLL，Winlogon 相关值可劫持登录过程。"
            + "正常情况下应用软件不应改动这些位置。",
            "可直接实现全局代码注入与登录流程劫持，属于典型的系统级后门手法。",
            "按高危事件处置：还原被修改的键值，定位写入来源，确认是否为第三方组件（如某些国产安全软件的"
            + "「开机加速」功能）遗留；产品自身绝不应触碰这些位置。",
            "CWE-15", "A05:2021 Security Misconfiguration",
            ctx =>
            {
                var keywords = new[]
                {
                    "Image File Execution Options", "AppInit_DLLs", "Winlogon",
                    "ShellServiceObjectDelayLoad", "Browser Helper Objects",
                };
                var hits = ctx.EventsMatching(e =>
                        e.Type is MonitorEventType.RegistryCreate or MonitorEventType.RegistrySet &&
                        keywords.Any(k => e.Target.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return hits.GroupBy(e => e.Target).Select(g =>
                {
                    var first = g.First();
                    return new RuleHit
                    {
                        GroupKey = first.Target,
                        Target = first.Target,
                        EvidenceIds = ctx.IdsWithTag("registry"),
                        Facts = new List<string> { $"{first.Timestamp:HH:mm:ss.fff} {first.Operation} → {first.Target}" }
                            .Concat(first.Detail is null ? Array.Empty<string>() : new[] { $"值变化：{Truncate(first.Detail, 160)}" })
                            .ToList(),
                        RelatedRegistry = { first.Target },
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-104", "文件系统与落地", Severity.Medium, Confidence.Medium,
            "运行期向用户可写目录写入可执行文件",
            "会话期间在 AppData、Temp、ProgramData 等普通用户可写的位置出现了可执行文件（exe/dll/脚本）。"
            + "写入本身可能是正常的更新缓存或安装解包，但结合「从这些位置加载」就是完整的劫持链路。",
            "落地到可写目录的可执行文件可被同机低权限用户替换，配合提权运行即形成本地提权路径。",
            "把可执行组件的落地位置改到受保护的安装目录（Program Files）；确需缓存的，只缓存数据不缓存代码，"
            + "并在加载前校验哈希与签名。",
            "CWE-732", "A04:2021 Insecure Design",
            ctx =>
            {
                var hits = ctx.SuspiciousFileWrites()
                    .Where(e => PathSemantics.IsUserWritable(e.Target))
                    .Where(e => !e.Target.Contains(@"\WinSecLab", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return hits.GroupBy(e => Path.GetDirectoryName(e.Target) ?? e.Target).Select(g =>
                {
                    var first = g.First();
                    var directory = Path.GetDirectoryName(first.Target) ?? first.Target;
                    return new RuleHit
                    {
                        GroupKey = directory,
                        Target = directory,
                        EvidenceIds = ctx.IdsWithTag("filesystem"),
                        Facts = g.Take(6).Select(e => $"{e.Timestamp:HH:mm:ss.fff} {e.Type} → {e.Target}").ToList(),
                        RelatedFiles = g.Take(10).Select(e => e.Target).ToList(),
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-105", "依赖与加载安全", Severity.High, Confidence.Medium,
            "运行期从用户可写目录加载了模块",
            "进程树中的进程加载了位于可写目录（AppData / Temp / ProgramData）的 DLL。"
            + "与静态导入不同，运行期加载通常由 LoadLibrary 动态决定路径，攻击者可通过替换该文件实现代码劫持。",
            "动态加载路径若可控（或依赖当前工作目录），可被替换为恶意模块并在被测进程上下文执行。",
            "动态加载时使用绝对路径 + 签名校验；使用 LoadLibraryEx 的 LOAD_LIBRARY_SEARCH_SYSTEM32 等受限标志；"
            + "对模块目录设置仅管理员可写的 ACL。",
            "CWE-427", null,
            ctx =>
            {
                var hits = ctx.EventsMatching(e =>
                        e.Type == MonitorEventType.DllLoad &&
                        PathSemantics.IsUserWritable(e.Target) &&
                        !PathSemantics.IsWindowsDirectory(e.Target))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return hits.GroupBy(e => e.Target).Select(g =>
                {
                    var first = g.First();
                    return new RuleHit
                    {
                        GroupKey = first.Target,
                        Target = first.Target,
                        EvidenceIds = ctx.IdsWithTag("process"),
                        Facts = { $"{first.Timestamp:HH:mm:ss.fff} {first.ProcessName} 加载 {first.Target}" },
                        RelatedFiles = { first.Target },
                        RelatedProcesses = g.Select(e => e.ProcessName).Distinct().Take(5).ToList(),
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-106", "命令与代码执行", Severity.Medium, Confidence.Medium,
            "运行期创建了命令行 / 脚本宿主类子进程",
            "被测进程树里出现了 cmd.exe、powershell、wscript、mshta、rundll32 等宿主程序。"
            + "正常桌面应用很少在运行时唤起这些进程，出现即需要确认调用意图与参数来源。",
            "若参数受外部影响，可演变为命令注入；即便参数固定，也可能被中间人替换目标脚本实现代码执行。",
            "确认每个子进程调用的业务必要性；改用 Win32 API 或原生库替代命令行调用；"
            + "必须调用时使用完整路径、参数数组形式，校验目标脚本的签名与哈希。",
            "CWE-78", "A03:2021 Injection",
            ctx =>
            {
                var hosts = new[] { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "curl.exe" };
                var hits = ctx.EventsMatching(e =>
                        e.Type is MonitorEventType.ProcessStart or MonitorEventType.ChildProcess &&
                        hosts.Contains(e.ProcessName, StringComparer.OrdinalIgnoreCase))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return hits.GroupBy(e => e.ProcessName, StringComparer.OrdinalIgnoreCase).Select(g =>
                {
                    var first = g.First();
                    return new RuleHit
                    {
                        GroupKey = first.ProcessName,
                        Target = first.ProcessName,
                        EvidenceIds = ctx.IdsWithTag("process"),
                        Facts = g.Take(5).Select(e =>
                            $"{e.Timestamp:HH:mm:ss.fff} 由 {e.ParentProcessId} 创建 {e.ProcessName}"
                            + (e.ProcessPath is null ? "" : $"（{e.ProcessPath}）")).ToList(),
                        RelatedProcesses = { first.ProcessName },
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-107", "文件系统与落地", Severity.Critical, Confidence.Medium,
            "运行期向系统目录或驱动目录写入文件",
            "观测到在 System32、drivers、WinSxS 等系统保护目录中出现了文件变更。"
            + "正常应用不具备也不应触碰这些位置；能写入说明进程以管理员 / SYSTEM 权限运行，或被系统机制代理写入。",
            "系统目录被写入意味着可以直接替换系统组件或加载内核驱动，属于最严重的落地行为。",
            "立即确认写入内容与来源进程；检查是否有合法的安装流程代理；对产品而言应彻底移除写入系统目录的逻辑。",
            "CWE-732", null,
            ctx =>
            {
                var hits = ctx.EventsMatching(e =>
                        e.Type is MonitorEventType.FileCreate or MonitorEventType.FileWrite or MonitorEventType.FileRename &&
                        (e.Target.Contains(@"\Windows\System32", StringComparison.OrdinalIgnoreCase) ||
                         e.Target.Contains(@"\Windows\SysWOW64", StringComparison.OrdinalIgnoreCase) ||
                         e.Target.Contains(@"\System32\drivers", StringComparison.OrdinalIgnoreCase) ||
                         e.Target.Contains(@"\Windows\WinSxS", StringComparison.OrdinalIgnoreCase)))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = "C:\\Windows\\System32",
                        EvidenceIds = ctx.IdsWithTag("filesystem"),
                        Facts = hits.Take(10).Select(e => $"{e.Timestamp:HH:mm:ss.fff} {e.Type} → {e.Target}").ToList(),
                        RelatedFiles = hits.Take(10).Select(e => e.Target).ToList(),
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-108", "命令与代码执行", Severity.High, Confidence.High,
            "运行期修改了 hosts 文件",
            "hosts 文件（C:\\Windows\\System32\\drivers\\etc\\hosts）可以把域名强制指向任意 IP，"
            + "常用于劫持更新服务器、绕过授权校验或屏蔽安全软件域名。",
            "可实现流量重定向与中间人，篡改后用户很难察觉。",
            "产品不应修改 hosts；若确为网络代理类功能，需在用户界面明确提示并提供完整还原路径。"
            + "同时应把 hosts 纳入文件完整性监控。",
            "CWE-346", "A08:2021 Software and Data Integrity Failures",
            ctx =>
            {
                var hits = ctx.EventsMatching(e =>
                        e.Target.Contains("hosts", StringComparison.OrdinalIgnoreCase) &&
                        e.Target.Contains(@"\drivers\etc", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = @"C:\Windows\System32\drivers\etc\hosts",
                        EvidenceIds = ctx.IdsWithTag("filesystem"),
                        Facts = hits.Take(6).Select(e => $"{e.Timestamp:HH:mm:ss.fff} {e.Type} → {e.Target}").ToList(),
                        RelatedFiles = { @"C:\Windows\System32\drivers\etc\hosts" },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-109", "持久化", Severity.High, Confidence.Medium,
            "运行期修改了 PATH 环境变量",
            "观测到 HKCU\\Environment\\Path 发生了变化。PATH 决定系统按什么顺序查找可执行文件，"
            + "向其中插入目录是最隐蔽的劫持手法之一 —— 之后任何按名字调用程序的行为都可能落到攻击者目录。",
            "可实现长期、跨进程的命令劫持，且不产生明显的文件落地痕迹。",
            "确认修改是否为正常的安装行为（多数安装程序会追加自己的 bin 目录）；应追加而不要前置，"
            + "并确保追加的目录有正确的 ACL；向用户展示变更内容。",
            "CWE-426", null,
            ctx =>
            {
                var hits = ctx.EventsMatching(e =>
                        e.Type is MonitorEventType.RegistryCreate or MonitorEventType.RegistrySet &&
                        e.Target.Contains(@"\Environment\Path", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = "HKCU\\Environment\\Path",
                        EvidenceIds = ctx.IdsWithTag("registry"),
                        Facts = hits.Take(4).Select(e => $"{e.Timestamp:HH:mm:ss.fff} {Truncate(e.Detail, 200)}").ToList(),
                        RelatedRegistry = { "HKCU\\Environment\\Path" },
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-110", "行为画像", Severity.Info, Confidence.High,
            "运行期行为画像汇总",
            "汇总本次会话观测到的进程树、文件、注册表与网络活动，作为整体行为画像供人工复核。",
            "行为画像是判断程序是否「说了不做、做了不说」的基础：声称为本地工具的程序若频繁联网，"
            + "或安装包落地可执行文件后又自我删除，都会在这里先露出痕迹。",
            "逐项核对画像中的每类活动是否都有对应的业务解释；解释不通的条目回到「证据库」"
            + "定位原始记录，必要时用 Process Monitor 补一次 PID 级归因。",
            "CWE-1059", null,
            ctx =>
            {
                var events = ctx.Events.Where(e => e.Type != MonitorEventType.SessionStart
                                                   && e.Type != MonitorEventType.SessionStop
                                                   && e.Type != MonitorEventType.Note).ToList();
                if (events.Count == 0) return Enumerable.Empty<RuleHit>();

                var counts = events.GroupBy(e => e.Type)
                    .OrderByDescending(g => g.Count())
                    .Select(g => $"{g.Key}：{g.Count()} 条")
                    .ToList();

                var tree = events.Where(e => e.Type is MonitorEventType.ProcessStart or MonitorEventType.ChildProcess)
                    .Select(e => e.ProcessName).Distinct().Take(20).ToList();

                var facts = new List<string> { "事件构成：" + string.Join("；", counts) };
                if (tree.Count > 0) facts.Add("涉及进程：" + string.Join(", ", tree));

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Project.Target.FileName,
                        EvidenceIds = ctx.IdsWithTag("process", 4).Concat(ctx.IdsWithTag("filesystem", 2))
                            .Concat(ctx.IdsWithTag("registry", 2)).Concat(ctx.IdsWithTag("network", 2))
                            .Distinct().Take(10).ToList(),
                        Facts = facts,
                        RelatedProcesses = tree,
                    },
                };
            }));
    }

    // =====================================================================
    // 三、网络与会话安全
    // =====================================================================

    private static void AddNetworkRules(List<RuleDefinition> rules)
    {
        rules.Add(new RuleDefinition(
            "WS-201", "网络与会话安全", Severity.Low, Confidence.High,
            "捕获到明文 HTTP 请求",
            "本地代理记录到明文 HTTP 会话。请求头（含 Cookie / Authorization）与请求体在链路上完全可见。",
            "同网络下的第三方可读取或篡改请求内容，包括会话凭据。",
            "把接口全部迁移到 HTTPS，并在客户端启用证书校验（禁止信任所有证书的回调）；"
            + "对确实无法加密的场景，不要在其中传输凭据。",
            "CWE-319", "A02:2021 Cryptographic Failures",
            ctx =>
            {
                var hits = ctx.Http.Where(x => x.Scheme == "http" && x.Host.Length > 0).ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Project.Target.FileName,
                        EvidenceIds = ctx.IdsWithTag("http"),
                        Facts = hits.Take(10).Select(x => $"{x.Method} {x.Url} → {x.StatusTextCombined}").ToList(),
                        RelatedNetwork = hits.Select(x => x.Host).Distinct().Take(10).ToList(),
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-202", "敏感信息暴露", Severity.Medium, Confidence.High,
            "HTTP 请求在 URL 查询串中携带凭据类参数",
            "请求把 token / key / password 之类的敏感参数放在 URL 里。URL 会被写入服务端访问日志、"
            + "浏览器历史、代理日志以及 Referer 头，泄露面比请求体大得多。",
            "凭据可能通过日志与第三方脚本泄露，且往往长期有效（静态 token）。",
            "敏感参数改到请求体或 Authorization 头传递；同时缩短令牌有效期并支持主动撤销。",
            "CWE-598", "A04:2021 Insecure Design",
            ctx =>
            {
                var hits = ctx.Http.Where(x =>
                    x.QueryString.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                    x.QueryString.Contains("key=", StringComparison.OrdinalIgnoreCase) ||
                    x.QueryString.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                    x.QueryString.Contains("secret", StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Project.Target.FileName,
                        EvidenceIds = ctx.IdsWithTag("http"),
                        Facts = hits.Take(8).Select(x => $"{x.Method} {x.Host}{x.Path}{x.QueryString}").ToList(),
                        RelatedNetwork = hits.Select(x => x.Host).Distinct().Take(6).ToList(),
                    },
                };
            }));

        rules.Add(new RuleDefinition(
            "WS-203", "网络与会话安全", Severity.Medium, Confidence.Medium,
            "运行期连接到未观测到域名解析记录的直连 IP",
            "被测进程建立了到公网 IP 的 TCP 连接，但在 DNS 缓存中没有对应的域名解析记录，"
            + "且端口不是 80/443/53 等常见服务端口。硬编码 IP 直连通常用于规避 DNS 层面的可见性与拦截。",
            "绕过 DNS 层监控与内容过滤，通信目标难以审计；也常见于恶意程序的上报与被控通道。",
            "确认该 IP 的归属与业务用途；正常的服务端通信应使用域名并支持配置化，便于切换与审计。",
            "CWE-506", null,
            ctx =>
            {
                var hits = ctx.Connections.Where(c =>
                        c.State == ConnectionState.Established &&
                        !c.IsLoopback && !c.IsPrivateAddress &&
                        c.Domain is null &&
                        c.RemotePort is not (80 or 443 or 53) &&
                        c.IsFromTargetTree)
                    .ToList();
                if (hits.Count == 0) return Enumerable.Empty<RuleHit>();

                return hits.GroupBy(c => c.RemoteAddress).Select(g =>
                {
                    var first = g.First();
                    return new RuleHit
                    {
                        GroupKey = first.RemoteAddress,
                        Target = first.RemoteEndpoint,
                        EvidenceIds = ctx.IdsWithTag("network"),
                        Facts =
                        {
                            $"{first.ProcessName} (pid={first.ProcessId}) → {first.RemoteEndpoint}，端口 {first.RemotePort}（{first.ServiceHint}）",
                            $"首次观测 {first.FirstSeen:HH:mm:ss.fff}，持续观测 {first.ObservationCount} 次",
                            $"归因精确度：{first.Attribution}",
                        },
                        RelatedNetwork = { first.RemoteEndpoint },
                        RelatedProcesses = { first.ProcessName },
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-204", "网络与会话安全", Severity.Info, Confidence.High,
            "被测程序建立了对外网络通信（清单）",
            "列出本次会话中被测进程树建立的所有对外连接与解析到的域名，供人工核对是否符合产品设计。",
            "外联是数据外泄与远程控制的必经通道；域名比 IP 更能说明意图，"
            + "而「清单里出现的域名用户毫不知情」是最值得警惕的信号。",
            "逐条确认通信目的；对未在文档中声明的外联应重点核查，必要时抓包确认内容。",
            "CWE-1059", null,
            ctx =>
            {
                var external = ctx.Connections
                    .Where(c => !c.IsLoopback && c.IsFromTargetTree && c.RemoteAddress != "0.0.0.0" && c.RemoteAddress != "::")
                    .ToList();
                if (external.Count == 0) return Enumerable.Empty<RuleHit>();

                var domains = external.Where(c => c.Domain is not null).Select(c => c.Domain!)
                    .Distinct().Take(20).ToList();

                var facts = new List<string>();
                if (domains.Count > 0) facts.Add("解析到的域名：" + string.Join(", ", domains));
                facts.AddRange(external.GroupBy(c => c.DisplayHost)
                    .OrderByDescending(g => g.Count()).Take(10)
                    .Select(g => $"{g.Key}：{g.Count()} 条连接，端口 {string.Join("/", g.Select(c => c.RemotePort).Distinct().Take(4))}"));

                return new[]
                {
                    new RuleHit
                    {
                        Target = ctx.Project.Target.FileName,
                        EvidenceIds = ctx.IdsWithTag("network"),
                        Facts = facts,
                        RelatedNetwork = external.Select(c => c.RemoteEndpoint).Distinct().Take(20).ToList(),
                        RelatedProcesses = external.Select(c => c.ProcessName).Distinct().Take(10).ToList(),
                    },
                };
            }));
    }

    // =====================================================================
    // 四、工具与规则库
    // =====================================================================

    private static void AddToolRules(List<RuleDefinition> rules)
    {
        rules.Add(new RuleDefinition(
            "WS-301", "威胁情报匹配", Severity.High, Confidence.Medium,
            "YARA 规则命中",
            "内置或外部 YARA 规则在目标文件上命中。命中结果反映的是「与已知特征相似」，"
            + "必须结合规则语义与上下文判断，不能单凭命中定性。",
            "命中的规则可能指向加壳、凭据窃取、远控通信等已知家族特征。",
            "逐条核对命中的规则逻辑与匹配到的字符串位置；确认是已知库的误报后，把例外加入白名单并记录理由。",
            "CWE-506", null,
            ctx =>
            {
                if (ctx.Yara.Count == 0) return Enumerable.Empty<RuleHit>();

                return ctx.Yara.GroupBy(m => m.RuleName).Select(g =>
                {
                    var first = g.First();
                    var severity = first.Severity.ToLowerInvariant() switch
                    {
                        "critical" => Severity.Critical,
                        "high" => Severity.High,
                        "medium" => Severity.Medium,
                        "low" => Severity.Low,
                        _ => Severity.Medium,
                    };

                    var facts = new List<string>
                    {
                        $"规则：{first.RuleName}" + (first.RuleSet is null ? "" : $"（{first.RuleSet}）"),
                        $"来源引擎：{(first.IsBuiltinLightweight ? "WinSecLab 内置轻量匹配器" : "外部 YARA 引擎")}",
                    };
                    if (first.Description is not null) facts.Add($"规则说明：{first.Description}");
                    if (first.MatchedStrings.Count > 0)
                        facts.Add("匹配内容：" + string.Join("；", first.MatchedStrings.Take(5)));

                    return new RuleHit
                    {
                        GroupKey = first.RuleName,
                        Target = first.FilePath,
                        EvidenceIds = ctx.IdsWithTag("yara"),
                        Facts = facts,
                        RelatedFiles = { first.FilePath },
                        SeverityOverride = severity,
                    };
                });
            }));

        rules.Add(new RuleDefinition(
            "WS-302", "工具链与环境", Severity.Info, Confidence.High,
            "测试环境权限不足，部分证据的完整性受限",
            "本次分析未能以管理员权限运行，或所需的第三方工具未安装。进程事件退化为轮询、"
            + "注册表事件精度受扫描间隔限制、TLS 证书字段无法解析等，都会让证据出现空白。",
            "证据缺失可能掩盖真实存在的问题，结论只能作为「已知范围内」的判断。",
            "以管理员身份重新运行一次完整测试；按「插件与工具」页面的提示安装 Process Monitor、"
            + "Wireshark（含 tshark）、YARA、Ghidra 等工具后复测，获得内核级精确归因。",
            "CWE-1059", null,
            ctx =>
            {
                // 没有采集动作就没有"证据完整性"可言 —— 空上下文不该凭空生成提示。
                var hasCollection = ctx.Evidence.Count > 0
                                    || ctx.Events.Any(e => e.Type is MonitorEventType.SessionStart
                                        or MonitorEventType.SessionStop);
                if (!hasCollection)
                    return Enumerable.Empty<RuleHit>();

                var unavailable = ctx.Result.Plugins.Where(p => !p.Available).ToList();
                var warnings = new List<string>();
                if (!ctx.Project.Environment.IsElevated)
                    warnings.Add("当前未以管理员权限运行");
                warnings.AddRange(unavailable.Select(p => $"{p.Name} 不可用：{p.AvailabilityText}"));

                if (warnings.Count == 0) return Enumerable.Empty<RuleHit>();

                return new[]
                {
                    new RuleHit
                    {
                        Target = "本机测试环境",
                        EvidenceIds = ctx.IdsWithTag("environment", 2),
                        Facts = warnings.Take(10).ToList(),
                    },
                };
            }));
    }

    private static string ExtractHost(string url)
    {
        try
        {
            return Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : url;
        }
        catch
        {
            return url;
        }
    }

    private static string Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) ? "" : value.Length <= max ? value : value[..max] + "…";
}
