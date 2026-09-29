using System.Text;
using System.Text.RegularExpressions;

namespace WinSecLab.Core.Engines.Static;

public sealed class YaraParseOutcome
{
    public List<YaraRule> Rules { get; } = new();
    public List<string> Warnings { get; } = new();
    public List<string> Files { get; } = new();
}

/// <summary>
/// 用户自备 .yar 文件的「够用子集」解析器。
///
/// 为什么不用完整 YARA：外部 yara.exe 未安装时平台仍需消费用户规则；
/// 完整 YARA 语法（module、正则、for..of、外部变量）不可能也不应该在托管层重写。
/// 因此这里只支持真正常见的那一档，遇到不认识的片段就记 warning 并降级为 any of them，
/// 绝不静默曲解规则语义 —— 安全工具的结论错了比没有结论更糟。
///
/// 支持：
///   rule 名称 [: tag1 tag2] { meta: ... strings: $x = "文本" [ascii|wide|nocase] / { 4D 5A }  condition: any/all/N of them }
/// 不支持（会记警告）：modules、正则、$a* 通配、for 循环、外部变量、filesize 等算术条件。
/// </summary>
public static class YaraRuleParser
{
    private static readonly Regex RuleStart = new(
        @"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex MetaLine = new(
        @"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*""(?<v>.*?)""\s*$",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex StringLiteral = new(
        @"^\s*(?<id>\$[A-Za-z0-9_]*)\s*=\s*""(?<v>(?:\\.|[^""\\])*)""(?<mods>[^\r\n]*)$",
        RegexOptions.Compiled);

    private static readonly Regex StringHex = new(
        @"^\s*(?<id>\$[A-Za-z0-9_]*)\s*=\s*\{(?<v>[^}]*)\}\s*(?<mods>.*)$",
        RegexOptions.Compiled);

    private static readonly Regex AtLeastN = new(
        @"^\s*(?<n>\d+)\s+of\s+them\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>扫描目录与单个文件，合并解析结果。</summary>
    public static YaraParseOutcome Load(IEnumerable<string> paths)
    {
        var outcome = new YaraParseOutcome();
        foreach (var path in paths)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    foreach (var f in Directory.EnumerateFiles(path, "*.yar", SearchOption.AllDirectories)
                                 .Concat(Directory.EnumerateFiles(path, "*.yara", SearchOption.AllDirectories)))
                    {
                        ParseFile(f, outcome);
                    }
                }
                else if (File.Exists(path))
                {
                    ParseFile(path, outcome);
                }
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add($"{path}: 读取失败 —— {ex.Message}");
            }
        }

        // 规则名去重（后者覆盖前者，用户可借此覆盖内置规则）
        var dedup = new Dictionary<string, YaraRule>(StringComparer.Ordinal);
        foreach (var r in outcome.Rules) dedup[r.Name] = r;
        outcome.Rules.Clear();
        outcome.Rules.AddRange(dedup.Values);
        return outcome;
    }

    private static void ParseFile(string file, YaraParseOutcome outcome)
    {
        string text;
        try { text = File.ReadAllText(file, Encoding.UTF8); }
        catch (Exception ex) { outcome.Warnings.Add($"{file}: 读取失败 —— {ex.Message}"); return; }

        // 去注释，避免注释里的 rule 关键字被误识别
        var cleaned = StripComments(text, file, outcome);

        var matches = RuleStart.Matches(cleaned);
        if (matches.Count == 0)
        {
            if (cleaned.Contains("import ", StringComparison.Ordinal))
                outcome.Warnings.Add($"{file}: 只包含 import 语句，本子集解析器不支持 YARA module（需要安装 yara.exe）。");
            return;
        }

        var ruleSet = Path.GetFileNameWithoutExtension(file);
        var parsedAny = false;

        for (var i = 0; i < matches.Count; i++)
        {
            var start = matches[i].Index;
            var end = i + 1 < matches.Count ? matches[i + 1].Index : cleaned.Length;
            var block = cleaned.Substring(start, end - start);

            var rule = ParseRule(block, matches[i].Groups[1].Value, ruleSet, file, outcome);
            if (rule is not null)
            {
                outcome.Rules.Add(rule);
                parsedAny = true;
            }
        }

        if (parsedAny) outcome.Files.Add(file);
    }

    private static YaraRule? ParseRule(string block, string name, string ruleSet, string file, YaraParseOutcome outcome)
    {
        var tags = new List<string>();
        var headerEnd = block.IndexOf('{');
        if (headerEnd < 0)
        {
            outcome.Warnings.Add($"{file}: 规则 {name} 缺少 '{{' 主体，已跳过。");
            return null;
        }

        var colon = block.IndexOf(':', block.IndexOf(name, StringComparison.Ordinal) + name.Length);
        if (colon > 0 && colon < headerEnd)
        {
            tags.AddRange(block[(colon + 1)..headerEnd]
                .Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries));
        }

        var bodyEnd = block.LastIndexOf('}');
        if (bodyEnd <= headerEnd)
        {
            outcome.Warnings.Add($"{file}: 规则 {name} 主体未闭合，已跳过。");
            return null;
        }
        var body = block[(headerEnd + 1)..bodyEnd];

        var stringsIdx = IndexOfSection(body, "strings:");
        var conditionIdx = IndexOfSection(body, "condition:");
        if (conditionIdx < 0)
        {
            outcome.Warnings.Add($"{file}: 规则 {name} 没有 condition 段，已跳过。");
            return null;
        }

        var metaText = stringsIdx > 0 ? body[..stringsIdx] : conditionIdx > 0 ? body[..conditionIdx] : "";
        var stringsText = stringsIdx >= 0 && conditionIdx > stringsIdx
            ? body[(stringsIdx + "strings:".Length)..conditionIdx]
            : "";
        var conditionText = body[(conditionIdx + "condition:".Length)..];

        // ── meta ──
        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in MetaLine.Matches(metaText))
            meta[m.Groups[1].Value] = Unescape(m.Groups["v"].Value);

        // ── strings ──
        var patterns = new List<YaraPattern>();
        foreach (var rawLine in stringsText.Split('\n'))
        {
            var line = rawLine.Trim('\r', ' ', '\t');
            if (line.Length == 0 || !line.StartsWith('$')) continue;

            var match = StringLiteral.Match(line);
            if (match.Success)
            {
                var mods = match.Groups["mods"].Value;
                var wide = mods.Contains("wide", StringComparison.OrdinalIgnoreCase);
                var ascii = mods.Contains("ascii", StringComparison.OrdinalIgnoreCase);
                var nocase = mods.Contains("nocase", StringComparison.OrdinalIgnoreCase);
                var fullword = mods.Contains("fullword", StringComparison.OrdinalIgnoreCase);
                var xor = mods.Contains("xor", StringComparison.OrdinalIgnoreCase);
                if (fullword) outcome.Warnings.Add($"{file}: 规则 {name} 的 fullword 修饰符在本子集引擎中退化为普通匹配（yara.exe 可用时不受影响）。");
                if (xor) outcome.Warnings.Add($"{file}: 规则 {name} 的 xor 修饰符本子集引擎不支持，该模式已忽略。");

                patterns.Add(new YaraPattern
                {
                    Value = Unescape(match.Groups["v"].Value),
                    Identifier = match.Groups["id"].Value,
                    Encoding = wide && ascii ? YaraPatternEncoding.AsciiAndWide
                             : wide ? YaraPatternEncoding.Wide
                             : YaraPatternEncoding.Ascii,
                    NoCase = nocase,
                });
                continue;
            }

            var hexMatch = StringHex.Match(line);
            if (hexMatch.Success)
            {
                var hex = hexMatch.Groups["v"].Value;
                if (hex.Contains('[') || hex.Contains('(') || hex.Contains('-'))
                    outcome.Warnings.Add($"{file}: 规则 {name} 的十六进制跳转/选择语法本子集引擎不支持，已按固定字节序列处理。");
                patterns.Add(new YaraPattern
                {
                    Value = hex,
                    Hex = true,
                    Identifier = hexMatch.Groups["id"].Value,
                });
                continue;
            }

            // 正则模式（$x = /.../）：既不支持也不该静默丢弃 —— 静默丢弃等于
            // 让用户以为这条规则在生效，实际却漏检，这对安全工具是最危险的失败模式。
            if (line.StartsWith("$") && Regex.IsMatch(line, @"^\$[A-Za-z0-9_]+\s*=\s*/"))
            {
                outcome.Warnings.Add($"{file}: 规则 {name} 使用了正则字符串（{Truncate(line.Trim(), 50)}），"
                                      + "本子集引擎不支持，该模式已忽略；请安装 yara.exe 使用完整引擎。");
                continue;
            }

            if (line.Contains("regex", StringComparison.OrdinalIgnoreCase))
                outcome.Warnings.Add($"{file}: 规则 {name} 使用了正则字符串，本子集引擎不支持，该模式已忽略。");
        }

        if (patterns.Count == 0)
        {
            outcome.Warnings.Add($"{file}: 规则 {name} 没有可用的字符串模式，已跳过。");
            return null;
        }

        // ── condition ──
        var condition = YaraCondition.AnyOfThem;
        var threshold = 1;
        var normalized = conditionText.Replace("\n", " ").Replace("\r", " ").Trim();
        normalized = Regex.Replace(normalized, @"\s+", " ");

        if (normalized.Contains("all of them", StringComparison.OrdinalIgnoreCase))
        {
            condition = YaraCondition.AllOfThem;
        }
        else if (normalized.Contains("none of them", StringComparison.OrdinalIgnoreCase))
        {
            condition = YaraCondition.NoneOfThem;
        }
        else
        {
            var n = AtLeastN.Match(normalized);
            if (n.Success)
            {
                condition = YaraCondition.AtLeastN;
                threshold = int.Parse(n.Groups["n"].Value);
            }
            else if (!normalized.Contains("any of them", StringComparison.OrdinalIgnoreCase))
            {
                outcome.Warnings.Add($"{file}: 规则 {name} 的 condition「{Truncate(normalized, 60)}」不受支持，已降级为 any of them（结论为「至少命中一个模式」，请人工复核）。");
            }
        }

        var severity = meta.TryGetValue("severity", out var sev) ? NormalizeSeverity(sev) : "info";

        return new YaraRule
        {
            Name = name,
            Description = meta.TryGetValue("description", out var d) ? d
                        : meta.TryGetValue("desc", out var d2) ? d2
                        : $"{ruleSet} 中的规则（未提供 description）",
            Severity = severity,
            Author = meta.TryGetValue("author", out var a) ? a : null,
            RuleSet = ruleSet,
            Tags = tags,
            Patterns = patterns,
            Condition = condition,
            Threshold = threshold,
            Cwe = meta.TryGetValue("cwe", out var cwe) ? cwe : null,
            Remediation = meta.TryGetValue("remediation", out var rem) ? rem : null,
            RawCondition = normalized,
        };
    }

    private static int IndexOfSection(string body, string keyword) => body.IndexOf(keyword, StringComparison.Ordinal);

    private static string NormalizeSeverity(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "critical" or "严重" => "critical",
        "high" or "高" => "high",
        "medium" or "中" => "medium",
        "low" or "低" => "low",
        _ => "info",
    };

    /// <summary>去掉 // 与 /* */ 注释，但保留字符串字面量里的 // 与 /*。</summary>
    private static string StripComments(string text, string file, YaraParseOutcome outcome)
    {
        var sb = new StringBuilder(text.Length);
        var inString = false;
        var inLineComment = false;
        var inBlockComment = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            var next = i + 1 < text.Length ? text[i + 1] : '\0';

            if (inLineComment)
            {
                if (c == '\n') { inLineComment = false; sb.Append(c); }
                else sb.Append(' ');
                continue;
            }
            if (inBlockComment)
            {
                if (c == '*' && next == '/') { inBlockComment = false; sb.Append("  "); i++; }
                else sb.Append(c == '\n' ? '\n' : ' ');
                continue;
            }
            if (inString)
            {
                sb.Append(c);
                if (c == '\\' && next != '\0') { sb.Append(next); i++; }
                else if (c == '"') inString = false;
                continue;
            }

            if (c == '"') { inString = true; sb.Append(c); continue; }
            if (c == '/' && next == '/') { inLineComment = true; sb.Append("  "); i++; continue; }
            if (c == '/' && next == '*') { inBlockComment = true; sb.Append("  "); i++; continue; }

            sb.Append(c);
        }

        if (inBlockComment) outcome.Warnings.Add($"{file}: 块注释未闭合。");
        return sb.ToString();
    }

    private static string Unescape(string s)
    {
        if (!s.Contains('\\')) return s;
        var sb = new StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] != '\\' || i + 1 >= s.Length) { sb.Append(s[i]); continue; }
            var n = s[++i];
            sb.Append(n switch
            {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                '0' => '\0',
                'x' when i + 2 < s.Length => ParseHexEscape(s, ref i),
                _ => n,
            });
        }
        return sb.ToString();
    }

    private static char ParseHexEscape(string s, ref int i)
    {
        var hex = s.Substring(i + 1, 2);
        i += 2;
        return byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var b) ? (char)b : '?';
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
