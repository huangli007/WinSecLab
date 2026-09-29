using System.Text;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Static;

/// <summary>模式匹配方式。</summary>
public enum YaraPatternEncoding
{
    /// <summary>ASCII 单字节。</summary>
    Ascii,
    /// <summary>UTF-16LE（YARA 的 wide）。</summary>
    Wide,
    /// <summary>两种都要命中（YARA 的 ascii wide）。</summary>
    AsciiAndWide,
}

public sealed class YaraPattern
{
    /// <summary>字面量文本，或十六进制字节（Hex=true 时形如 "4D 5A 90 00"）。</summary>
    public required string Value { get; init; }
    public bool Hex { get; init; }
    public YaraPatternEncoding Encoding { get; init; } = YaraPatternEncoding.Ascii;
    /// <summary>ASCII 大小写不敏感（仅对 Ascii 编码有效）。</summary>
    public bool NoCase { get; init; } = true;
    public string? Identifier { get; init; }
}

public enum YaraCondition
{
    AnyOfThem,
    AllOfThem,
    /// <summary>至少 N 个模式命中（YARA 的 "N of them"）。</summary>
    AtLeastN,
    /// <summary>全部模式都不命中（用于"干净"类规则，少见）。</summary>
    NoneOfThem,
}

public sealed class YaraRule
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public string Severity { get; init; } = "info";
    public string? Author { get; init; }
    public string RuleSet { get; init; } = "builtin";
    public List<string> Tags { get; init; } = new();
    public List<YaraPattern> Patterns { get; init; } = new();
    public YaraCondition Condition { get; init; } = YaraCondition.AnyOfThem;
    public int Threshold { get; init; } = 1;
    /// <summary>命中后给出的分析建议（写进 Finding 的 Remediation）。</summary>
    public string? Remediation { get; init; }
    public string? Cwe { get; init; }
    /// <summary>解析外部 .yar 时无法识别的条件片段，保留给用户参考（内置规则为空）。</summary>
    public string? RawCondition { get; init; }
}

/// <summary>
/// 内置轻量 YARA 引擎（§19 ⑦）。
/// 定位：在没有安装 yara.exe 的机器上也能给出有意义的规则匹配结果；
/// 装了 yara.exe 时，同一套规则会被导出成真正的 .yar 文件交给完整引擎执行（见 <see cref="EmitYaraText"/>）。
/// </summary>
public static class YaraAnalyzer
{
    /// <summary>参与模式扫描的文件上限（超过则只扫可执行区段 + 头部，避免大文件拖垮 UI）。</summary>
    public const long MaxScanBytes = 192L * 1024 * 1024;

    // ─────────────────────────────── 内置规则集 ───────────────────────────────
    // 全部为自研通用启发式规则，不含任何商业规则库内容。
    public static IReadOnlyList<YaraRule> BuiltinRules { get; } = new List<YaraRule>
    {
        new()
        {
            Name = "WS_YR_Download_Execute_PowerShell",
            Description = "出现下载即执行的 PowerShell 命令特征（DownloadString / IEX / -EncodedCommand 组合）。",
            Severity = "high", Cwe = "CWE-494", RuleSet = "builtin",
            Tags = { "execution", "powershell", "download" },
            Patterns =
            {
                new() { Value = "DownloadString", Identifier = "$ds" },
                new() { Value = "DownloadFile", Identifier = "$df" },
                new() { Value = "Invoke-Expression", Identifier = "$iex" },
                new() { Value = "IEX(", Identifier = "$iex2" },
                new() { Value = "-EncodedCommand", Identifier = "$enc" },
                new() { Value = "-w hidden", Identifier = "$hide" },
                new() { Value = "FromBase64String", Identifier = "$b64" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "确认该行为是否为产品自身的更新/诊断机制；若为第三方注入，应移除动态代码执行路径。",
        },
        new()
        {
            Name = "WS_YR_Process_Injection_Api_Cluster",
            Description = "进程注入 API 组合：跨进程内存分配 + 写入 + 远程线程。",
            Severity = "high", Cwe = "CWE-691", RuleSet = "builtin",
            Tags = { "injection", "evasion" },
            Patterns =
            {
                new() { Value = "VirtualAllocEx", Identifier = "$a" },
                new() { Value = "WriteProcessMemory", Identifier = "$b" },
                new() { Value = "CreateRemoteThread", Identifier = "$c" },
                new() { Value = "NtCreateThreadEx", Identifier = "$d" },
                new() { Value = "QueueUserAPC", Identifier = "$e" },
                new() { Value = "SetThreadContext", Identifier = "$f" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 3,
            Remediation = "进程注入能力若不属于调试/插件框架的正常实现，应视为高危并做人工逆向确认。",
        },
        new()
        {
            Name = "WS_YR_Anti_Debug_Cluster",
            Description = "反调试 API 密集：判断是否被调试、检查父进程、时间差检测。",
            Severity = "medium", Cwe = "CWE-693", RuleSet = "builtin",
            Tags = { "anti-analysis", "evasion" },
            Patterns =
            {
                new() { Value = "IsDebuggerPresent", Identifier = "$a" },
                new() { Value = "CheckRemoteDebuggerPresent", Identifier = "$b" },
                new() { Value = "NtQueryInformationProcess", Identifier = "$c" },
                new() { Value = "OutputDebugString", Identifier = "$d" },
                new() { Value = "QueryPerformanceCounter", Identifier = "$e" },
                new() { Value = "GetTickCount", Identifier = "$f" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 3,
            Remediation = "反调试常见于加壳与保护方案；若产品未声明保护机制，需核实其来源与必要性。",
        },
        new()
        {
            Name = "WS_YR_Credential_Access_Paths",
            Description = "凭据相关路径或工具名（LSASS 内存、浏览器凭据库、凭据管理器）。",
            Severity = "high", Cwe = "CWE-522", RuleSet = "builtin",
            Tags = { "credential-access", "collection" },
            Patterns =
            {
                new() { Value = "sekurlsa", Identifier = "$a" },
                new() { Value = "lsass.exe", Identifier = "$b" },
                new() { Value = @"Login Data", Identifier = "$c" },
                new() { Value = @"Local State", Identifier = "$d" },              // Chromium cookie 加密密钥
                new() { Value = @"Microsoft\Vault", Identifier = "$e" },
                new() { Value = @"SAM\Domains", Identifier = "$f" },
                new() { Value = "vaultcmd", Identifier = "$g" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "任何对凭据存储的直接读取都应被调查；正常应用不应访问 LSASS 或浏览器凭据库。",
        },
        new()
        {
            Name = "WS_YR_Ransomware_Language",
            Description = "勒索信模板语言特征。",
            Severity = "critical", Cwe = "CWE-311", RuleSet = "builtin",
            Tags = { "ransomware", "impact" },
            Patterns =
            {
                new() { Value = "your files have been encrypted" },
                new() { Value = "all your files are encrypted" },
                new() { Value = "to decrypt your files" },
                new() { Value = ".onion" },
                new() { Value = "bitcoin", NoCase = true },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "立即隔离样本，不要运行；按事件响应流程上报。",
        },
        new()
        {
            Name = "WS_YR_Crypto_Miner",
            Description = "挖矿程序特征：矿池协议、常见矿工标识。",
            Severity = "high", Cwe = "CWE-400", RuleSet = "builtin",
            Tags = { "miner", "resource-hijack" },
            Patterns =
            {
                new() { Value = "stratum+tcp://" },
                new() { Value = "stratum+ssl://" },
                new() { Value = "xmrig" },
                new() { Value = "randomx" },
                new() { Value = "nicehash" },
                new() { Value = "minergate" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "确认是否存在隐蔽挖矿；产品不应内置算力出租能力。",
        },
        new()
        {
            Name = "WS_YR_Keylogger_Cluster",
            Description = "键盘记录 API 组合：全局钩子 + 按键状态轮询。",
            Severity = "high", Cwe = "CWE-359", RuleSet = "builtin",
            Tags = { "collection", "input-capture" },
            Patterns =
            {
                new() { Value = "SetWindowsHookEx", Identifier = "$a" },
                new() { Value = "GetAsyncKeyState", Identifier = "$b" },
                new() { Value = "GetKeyState", Identifier = "$c" },
                new() { Value = "WH_KEYBOARD", Identifier = "$d" },
                new() { Value = "GetKeyboardState", Identifier = "$e" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 3,
            Remediation = "全局键盘钩子会影响整机输入，必须确认其用途并获得用户明确授权。",
        },
        new()
        {
            Name = "WS_YR_Screen_Capture_Cluster",
            Description = "屏幕 / 窗口内容捕获 API 组合。",
            Severity = "medium", Cwe = "CWE-359", RuleSet = "builtin",
            Tags = { "collection", "screen-capture" },
            Patterns =
            {
                new() { Value = "BitBlt", Identifier = "$a" },
                new() { Value = "GetDC", Identifier = "$b" },
                new() { Value = "PrintWindow", Identifier = "$c" },
                new() { Value = "GetForegroundWindow", Identifier = "$d" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 3,
            Remediation = "若无截屏类功能，应排查该能力的引入来源。",
        },
        new()
        {
            Name = "WS_YR_Webhook_Exfiltration",
            Description = "常见即时消息 / Webhook 外发通道（合规用途也存在，但需核实）。",
            Severity = "medium", Cwe = "CWE-200", RuleSet = "builtin",
            Tags = { "exfiltration", "c2" },
            Patterns =
            {
                new() { Value = "discord.com/api/webhooks" },
                new() { Value = "discordapp.com/api/webhooks" },
                new() { Value = "api.telegram.org/bot" },
                new() { Value = "hooks.slack.com/services" },
                new() { Value = "oapi.dingtalk.com/robot/send" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "确认外发通道的业务必要性；凭据类信息不应经第三方 Webhook 传输。",
        },
        new()
        {
            Name = "WS_YR_Upx_Packer_Stub",
            Description = "UPX 加壳存根特征。",
            Severity = "medium", Cwe = "CWE-506", RuleSet = "builtin",
            Tags = { "packer" },
            Patterns =
            {
                new() { Value = "UPX0" }, new() { Value = "UPX1" }, new() { Value = "UPX!" },
                new() { Value = "$Info: This file is packed" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "加壳会隐藏真实代码；建议脱壳后重新做静态检查，或改用未加壳构建。",
        },
        new()
        {
            Name = "WS_YR_Persistence_Run_Key",
            Description = "自启动相关注册表路径字符串。",
            Severity = "medium", Cwe = "CWE-284", RuleSet = "builtin",
            Tags = { "persistence" },
            Patterns =
            {
                new() { Value = @"CurrentVersion\Run" },
                new() { Value = @"CurrentVersion\RunOnce" },
                new() { Value = @"Winlogon\Shell" },
                new() { Value = @"Explorer\Shell Folders" },
                new() { Value = @"Services\CurrentControlSet" },
                new() { Value = @"ShellServiceObjectDelayLoad" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "确认是否真的需要开机自启；若需要，应在安装包中显式声明并让用户可见。",
        },
        new()
        {
            Name = "WS_YR_Wmi_Persistence",
            Description = "WMI 事件订阅持久化特征。",
            Severity = "high", Cwe = "CWE-284", RuleSet = "builtin",
            Tags = { "persistence", "wmi" },
            Patterns =
            {
                new() { Value = "__EventFilter" },
                new() { Value = "CommandLineEventConsumer" },
                new() { Value = "ActiveScriptEventConsumer" },
                new() { Value = @"root\subscription" },
                new() { Value = @"root\cimv2" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "WMI 订阅是常见无文件持久化手法，需要人工核对订阅内容。",
        },
        new()
        {
            Name = "WS_YR_Tls_Validation_Bypass",
            Description = "疑似绕过 TLS 证书校验的代码模式。",
            Severity = "high", Cwe = "CWE-295", RuleSet = "builtin",
            Tags = { "crypto", "mitm-surface" },
            Patterns =
            {
                new() { Value = "ServerCertificateValidationCallback" },
                new() { Value = "RemoteCertificateValidationCallback" },
                new() { Value = "CertificateValidationCallback" },
                new() { Value = "ServerCertificateCustomValidationCallback" },
                new() { Value = "verify=False" },
                new() { Value = "AcceptAllCerts" },
                new() { Value = "checkServerTrusted" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "禁止无条件放行证书校验；如确需自签证书，应做证书指纹固定（pin）而非整体关闭校验。",
        },
        new()
        {
            Name = "WS_YR_Hardcoded_Credential_Hint",
            Description = "硬编码凭据关键字附近的赋值模式。",
            Severity = "medium", Cwe = "CWE-798", RuleSet = "builtin",
            Tags = { "hardcoded-credential", "secrets" },
            Patterns =
            {
                new() { Value = "password=" },
                new() { Value = "passwd=" },
                new() { Value = "pwd=" },
                new() { Value = "api_key=" },
                new() { Value = "apikey=" },
                new() { Value = "access_key=" },
                new() { Value = "secret_key=" },
                new() { Value = "Authorization: Bearer " },
                new() { Value = "-----BEGIN RSA PRIVATE KEY-----" },
                new() { Value = "-----BEGIN PRIVATE KEY-----" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "凭据不应随二进制分发；改为运行期获取 + 安全存储（Credential Manager / DPAPI）。",
        },
        new()
        {
            Name = "WS_YR_Build_Path_Leak",
            Description = "编译期绝对路径泄漏（可能暴露开发机用户名与内部目录结构）。",
            Severity = "low", Cwe = "CWE-538", RuleSet = "builtin",
            Tags = { "information-disclosure", "build-hygiene" },
            Patterns =
            {
                new() { Value = @"\source\repos\" },
                new() { Value = @"\BuildAgent\" },
                new() { Value = @"\agent\_work\" },
                new() { Value = @"\jenkins\workspace\" },
                new() { Value = @"C:\Users\" }, new() { Value = @"D:\work\" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "启用 /pathmap 或确定性构建（Deterministic / ContinuousIntegrationBuild）以消除绝对路径。",
        },
        new()
        {
            Name = "WS_YR_Tor_Endpoint",
            Description = "Tor 隐藏服务地址（.onion）。",
            Severity = "high", Cwe = "CWE-200", RuleSet = "builtin",
            Tags = { "c2", "tor" },
            Patterns = { new() { Value = ".onion" }, new() { Value = "torproject.org/download" } },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "业务应用不应内置匿名网络通道，需核实并移除。",
        },
        new()
        {
            Name = "WS_YR_Archive_Exfil_Cli",
            Description = "命令行压缩 / 外传组合（curl -T、ftp -s、7z + 上传）。",
            Severity = "medium", Cwe = "CWE-200", RuleSet = "builtin",
            Tags = { "exfiltration" },
            Patterns =
            {
                new() { Value = "curl -T" }, new() { Value = "curl --upload-file" },
                new() { Value = "ftp -s:" }, new() { Value = "7z a -p" },
                new() { Value = "tar -czf" }, new() { Value = "rclone copy" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "确认是否存在未声明的数据外发行为。",
        },
        new()
        {
            Name = "WS_YR_Telemetry_Endpoint_Cluster",
            Description = "遥测 / 崩溃上报端点（属合规关注项，未必是缺陷）。",
            Severity = "info", Cwe = "CWE-200", RuleSet = "builtin",
            Tags = { "telemetry", "privacy" },
            Patterns =
            {
                new() { Value = "telemetry" }, new() { Value = "/v2/track" },
                new() { Value = "sentry.io" }, new() { Value = "bugsnag" },
                new() { Value = "appcenter.ms" }, new() { Value = "google-analytics.com" },
                new() { Value = "umeng.com" }, new() { Value = "talkingdata" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 1,
            Remediation = "遥测需在隐私政策中披露并提供关闭开关。",
        },
        new()
        {
            Name = "WS_YR_Self_Update_Script_Drop",
            Description = "落地可执行文件并启动的特征（写 .exe/.dll 后 CreateProcess）。",
            Severity = "medium", Cwe = "CWE-494", RuleSet = "builtin",
            Tags = { "update", "dropper" },
            Patterns =
            {
                new() { Value = ".exe\"" }, new() { Value = ".dll\"" },
                new() { Value = "CreateProcess" }, new() { Value = "ShellExecute" },
                new() { Value = "%TEMP%\\" }, new() { Value = "%AppData%\\" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 3,
            Remediation = "更新流程应校验签名与哈希，且不应把可执行文件落在用户可写临时目录。",
        },
        new()
        {
            Name = "WS_YR_Debug_Symbol_Residual",
            Description = "发布包中残留的调试符号 / PDB 与断言信息。",
            Severity = "low", Cwe = "CWE-215", RuleSet = "builtin",
            Tags = { "debug-artifact", "build-hygiene" },
            Patterns =
            {
                new() { Value = "Assertion failed" }, new() { Value = "debugbreak" },
                new() { Value = "__debugbreak" }, new() { Value = "Internal error at" },
            },
            Condition = YaraCondition.AtLeastN, Threshold = 2,
            Remediation = "发布构建应关闭 DEBUG 宏并剥离符号，避免向外暴露内部实现细节。",
        },
    };

    // ─────────────────────────────── 扫描实现 ───────────────────────────────

    public static List<YaraMatch> Scan(string filePath, IEnumerable<YaraRule> rules)
    {
        var results = new List<YaraMatch>();
        byte[] raw;
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists) return results;
            if (info.Length > MaxScanBytes)
            {
                // 超大文件只取前 64MB —— 规则包本身都是小样本匹配，性价比最高
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var take = (int)Math.Min(64L * 1024 * 1024, info.Length);
                raw = new byte[take];
                var read = fs.Read(raw, 0, take);
                if (read < take) Array.Resize(ref raw, read);
            }
            else
            {
                raw = File.ReadAllBytes(filePath);
            }
        }
        catch
        {
            return results;
        }

        return Scan(raw, filePath, rules);
    }

    /// <summary>对已在内存中的字节做规则扫描（PE 插件里可复用已读入的 buffer）。</summary>
    public static List<YaraMatch> Scan(byte[] raw, string filePath, IEnumerable<YaraRule> rules)
    {
        var results = new List<YaraMatch>();
        if (raw.Length == 0) return results;

        var lower = BuildAsciiLower(raw);

        foreach (var rule in rules)
        {
            if (rule.Patterns.Count == 0) continue;

            var matched = new List<string>();
            foreach (var pattern in rule.Patterns)
            {
                if (MatchesPattern(raw, lower, pattern, out var detail))
                    matched.Add(detail);
            }

            var hit = rule.Condition switch
            {
                YaraCondition.AllOfThem => matched.Count == rule.Patterns.Count,
                YaraCondition.AtLeastN => matched.Count >= Math.Max(1, rule.Threshold),
                YaraCondition.NoneOfThem => matched.Count == 0,
                _ => matched.Count > 0,
            };
            if (!hit) continue;

            results.Add(new YaraMatch
            {
                RuleName = rule.Name,
                RuleSet = rule.RuleSet,
                FilePath = filePath,
                Severity = rule.Severity,
                Description = rule.Description,
                Author = rule.Author ?? "WinSecLab 内置规则集",
                MatchedStrings = matched.Take(40).ToList(),
                Tags = rule.Tags.ToList(),
                Meta = rule.Cwe,
                Source = "builtin",
                Timestamp = DateTime.Now,
            });
        }

        return results;
    }

    /// <summary>找规则的补救建议（供 Findings 引擎复用）。</summary>
    public static YaraRule? FindRule(string ruleName, IEnumerable<YaraRule>? extra = null) =>
        BuiltinRules.FirstOrDefault(r => r.Name == ruleName)
        ?? extra?.FirstOrDefault(r => r.Name == ruleName);

    private static bool MatchesPattern(byte[] raw, byte[] lower, YaraPattern pattern, out string detail)
    {
        detail = "";
        List<byte[]> needles = new();
        var label = pattern.Identifier is null ? pattern.Value : $"{pattern.Identifier} = {pattern.Value}";

        if (pattern.Hex)
        {
            var bytes = ParseHexBytes(pattern.Value);
            if (bytes.Length == 0) return false;
            needles.Add(bytes);
        }
        else
        {
            switch (pattern.Encoding)
            {
                case YaraPatternEncoding.Ascii:
                    needles.Add(EncodeAscii(pattern.Value, pattern.NoCase));
                    break;
                case YaraPatternEncoding.Wide:
                    needles.Add(EncodeWide(pattern.Value, pattern.NoCase));
                    break;
                default:
                    needles.Add(EncodeAscii(pattern.Value, pattern.NoCase));
                    needles.Add(EncodeWide(pattern.Value, pattern.NoCase));
                    break;
            }
        }

        var haystack = pattern.Hex ? raw : (pattern.NoCase && !pattern.Hex ? lower : raw);

        foreach (var needle in needles)
        {
            if (needle.Length == 0) continue;
            if (haystack.AsSpan().IndexOf(needle) >= 0)
            {
                detail = label;
                return true;
            }
        }
        return false;
    }

    /// <summary>ASCII 小写副本：只改 A-Z，保证字节位置与原文一一对应（不能用字符串解码）。</summary>
    private static byte[] BuildAsciiLower(byte[] raw)
    {
        var lower = new byte[raw.Length];
        for (var i = 0; i < raw.Length; i++)
        {
            var b = raw[i];
            lower[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
        }
        return lower;
    }

    private static byte[] EncodeAscii(string text, bool noCase)
    {
        var bytes = new byte[text.Length];
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c > 0x7F) c = '?';
            if (noCase && c is >= 'A' and <= 'Z') c = (char)(c + 32);
            bytes[i] = (byte)c;
        }
        return bytes;
    }

    private static byte[] EncodeWide(string text, bool noCase)
    {
        var bytes = new byte[text.Length * 2];
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (noCase && c is >= 'A' and <= 'Z') c = (char)(c + 32);
            bytes[i * 2] = (byte)(c & 0xFF);
            bytes[i * 2 + 1] = (byte)((c >> 8) & 0xFF);
        }
        return bytes;
    }

    private static byte[] ParseHexBytes(string hex)
    {
        var parts = hex.Replace("{", "").Replace("}", "")
            .Split(new[] { ' ', '\t', '\r', '\n', '?' }, StringSplitOptions.RemoveEmptyEntries);
        var list = new List<byte>(parts.Length);
        foreach (var p in parts)
        {
            if (p.Length != 2) continue;
            if (byte.TryParse(p, System.Globalization.NumberStyles.HexNumber, null, out var b))
                list.Add(b);
        }
        return list.ToArray();
    }

    // ─────────────────────────────── 规则导出 ───────────────────────────────

    /// <summary>
    /// 把内置规则序列化成标准 YARA 语法，写入目录。
    /// 这样"内置引擎"与"外部 yara.exe"用的是同一套规则，结论具备可比性（§25 可重复测试）。
    /// </summary>
    public static List<string> EmitYaraText(IEnumerable<YaraRule> rules, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        var written = new List<string>();

        foreach (var group in rules.GroupBy(r => r.RuleSet))
        {
            var sb = new StringBuilder();
            sb.AppendLine("/*");
            sb.AppendLine(" * WinSecLab 内置规则集 —— 自动导出，请勿手工编辑。");
            sb.AppendLine($" * 规则集：{group.Key}，规则数：{group.Count()}，导出时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(" * 这些规则同时被内置轻量引擎与 yara.exe 使用，结论可直接互相校验。");
            sb.AppendLine(" */");
            sb.AppendLine();

            foreach (var rule in group)
            {
                sb.Append("rule ").Append(rule.Name);
                if (rule.Tags.Count > 0)
                    sb.Append(" : ").Append(string.Join(" ", rule.Tags));
                sb.AppendLine();
                sb.AppendLine("{");
                sb.AppendLine("    meta:");
                sb.AppendLine("        description = \"" + Escape(rule.Description) + "\"");
                sb.AppendLine("        severity = \"" + rule.Severity + "\"");
                if (!string.IsNullOrEmpty(rule.Author))
                    sb.AppendLine("        author = \"" + Escape(rule.Author!) + "\"");
                if (!string.IsNullOrEmpty(rule.Cwe))
                    sb.AppendLine("        cwe = \"" + rule.Cwe + "\"");
                sb.AppendLine("        generator = \"WinSecLab\"");
                sb.AppendLine("    strings:");

                var index = 0;
                foreach (var pattern in rule.Patterns)
                {
                    var varName = "$" + (pattern.Identifier?.TrimStart('$') ?? "s" + index);
                    sb.Append("        ").Append(varName).Append(" = ");
                    if (pattern.Hex)
                        sb.Append("{ ").Append(pattern.Value).Append(" }");
                    else
                        sb.Append('"').Append(Escape(pattern.Value)).Append('"');
                    if (!pattern.Hex)
                    {
                        if (pattern.Encoding is YaraPatternEncoding.Wide or YaraPatternEncoding.AsciiAndWide) sb.Append(" wide");
                        if (pattern.Encoding is YaraPatternEncoding.Ascii or YaraPatternEncoding.AsciiAndWide) sb.Append(" ascii");
                        if (pattern.NoCase) sb.Append(" nocase");
                    }
                    sb.AppendLine();
                    index++;
                }

                sb.AppendLine("    condition:");
                var condition = rule.Condition switch
                {
                    YaraCondition.AllOfThem => "all of them",
                    YaraCondition.AtLeastN => Math.Max(1, rule.Threshold) >= rule.Patterns.Count
                        ? "all of them"
                        : $"{Math.Max(1, rule.Threshold)} of them",
                    YaraCondition.NoneOfThem => "none of them",
                    _ => "any of them",
                };
                sb.Append("        ").AppendLine(condition);
                sb.AppendLine("}");
                sb.AppendLine();
            }

            var file = Path.Combine(outputDirectory, $"winseclab_{Sanitize(group.Key)}.yar");
            File.WriteAllText(file, sb.ToString(), new UTF8Encoding(false));
            written.Add(file);
        }

        return written;
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    private static string Sanitize(string s)
    {
        var chars = s.Select(c => char.IsLetterOrDigit(c) || c == '_' ? c : '_').ToArray();
        return new string(chars);
    }
}
