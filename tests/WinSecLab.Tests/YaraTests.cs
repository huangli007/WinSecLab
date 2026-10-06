using System.Text;
using WinSecLab.Core.Engines.Static;
using WinSecLab.Core.Plugins.Builtin;

namespace WinSecLab.Tests;

/// <summary>
/// YARA 引擎与规则解析。规则引擎是安全工具的"结论来源"，
/// 这里的每个用例都在防一类真实事故：误报、漏报、以及把用户的规则解析错。
/// </summary>
[Collection(ExternalProcess.Name)]
public class YaraTests
{
    private static byte[] Bytes(string text) => Encoding.ASCII.GetBytes(text);

    private static byte[] WideBytes(string text)
    {
        // UTF-16LE：每个 ASCII 字符后跟一个 0x00
        var result = new byte[text.Length * 2];
        for (var i = 0; i < text.Length; i++)
        {
            result[i * 2] = (byte)text[i];
            result[i * 2 + 1] = 0;
        }
        return result;
    }

    private static YaraRule Rule(string name, string[] patterns,
        YaraCondition condition = YaraCondition.AnyOfThem, int threshold = 1)
    {
        return new YaraRule
        {
            Name = name,
            Description = $"测试规则 {name}",
            Severity = "medium",
            RuleSet = "test",
            Patterns = patterns.Select(p => new YaraPattern { Value = p }).ToList(),
            Condition = condition,
            Threshold = threshold,
        };
    }

    // ─────────────────────────────── 匹配语义 ───────────────────────────────

    [Fact]
    public void Scan_MatchesAsciiNoCase()
    {
        var rules = new[] { Rule("r1", new[] { "CreateRemoteThread" }) };
        var matches = YaraAnalyzer.Scan(Bytes("call CreateRemoteThreadEx to inject"), "t.exe", rules);

        // nocase 默认开启：大小写不同也要命中
        Assert.Single(matches);
        Assert.Equal("r1", matches[0].RuleName);
    }

    [Fact]
    public void Scan_MatchesWideEncoding()
    {
        var rules = new[]
        {
            new YaraRule
            {
                Name = "wide_rule",
                Description = "wide 匹配",
                Patterns = new List<YaraPattern>
                {
                    new() { Value = "powershell", Encoding = YaraPatternEncoding.AsciiAndWide },
                },
            },
        };

        Assert.NotEmpty(YaraAnalyzer.Scan(WideBytes("powershell -enc AA=="), "t.exe", rules));
        Assert.NotEmpty(YaraAnalyzer.Scan(Bytes("powershell -enc AA=="), "t.exe", rules));
    }

    [Fact]
    public void Scan_NoMatch_ReturnsEmpty()
    {
        var rules = new[] { Rule("r1", new[] { "CreateRemoteThread" }) };
        Assert.Empty(YaraAnalyzer.Scan(Bytes("hello world"), "t.exe", rules));
    }

    [Fact]
    public void Scan_EmptyInput_ReturnsEmpty()
    {
        var rules = new[] { Rule("r1", new[] { "CreateRemoteThread" }) };
        Assert.Empty(YaraAnalyzer.Scan(Array.Empty<byte>(), "t.exe", rules));
    }

    /// <summary>"至少 N 个命中"是多特征规则的语义核心，判错会把单特征样本误报成组合行为。</summary>
    [Fact]
    public void Scan_AtLeastN_RespectsThreshold()
    {
        var patterns = new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" };
        var rule = Rule("cluster", patterns, YaraCondition.AtLeastN, threshold: 3);

        // 只命中 1 个 → 不报
        Assert.Empty(YaraAnalyzer.Scan(Bytes("calls VirtualAllocEx"), "t.exe", new[] { rule }));

        // 命中 3 个 → 报
        var hit = YaraAnalyzer.Scan(
            Bytes("VirtualAllocEx WriteProcessMemory CreateRemoteThread"), "t.exe", new[] { rule });
        Assert.Single(hit);
    }

    [Fact]
    public void Scan_AllOfThem_RequiresEveryPattern()
    {
        var rule = Rule("all_rule", new[] { "alpha", "beta" }, YaraCondition.AllOfThem);

        Assert.Empty(YaraAnalyzer.Scan(Bytes("only alpha here"), "t.exe", new[] { rule }));
        Assert.NotEmpty(YaraAnalyzer.Scan(Bytes("alpha and beta together"), "t.exe", new[] { rule }));
    }

    // ─────────────────────────────── 内置规则集质量门禁 ───────────────────────────────

    /// <summary>规则集质量门禁：同名规则会互相覆盖，缺元数据的规则在报告里没法解释。</summary>
    [Fact]
    public void BuiltinRules_HaveUniqueNames_AndRequiredMetadata()
    {
        var rules = YaraAnalyzer.BuiltinRules;

        Assert.True(rules.Count >= 15, $"内置规则过少：{rules.Count}");
        Assert.Equal(rules.Count, rules.Select(r => r.Name).Distinct().Count());

        foreach (var rule in rules)
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Description), $"{rule.Name} 缺 description");
            Assert.False(string.IsNullOrWhiteSpace(rule.Severity), $"{rule.Name} 缺 severity");
            Assert.True(rule.Patterns.Count > 0, $"{rule.Name} 没有任何模式");
            Assert.True(rule.Remediation is null || rule.Remediation.Length > 0);
        }
    }

    [Fact]
    public void BuiltinRules_CoverCoreThreatCategories()
    {
        var names = string.Join(" ", YaraAnalyzer.BuiltinRules.Select(r => r.Name));

        foreach (var expected in new[] { "Injection", "Credential", "Persistence", "Packer", "Exfil" })
            Assert.True(names.Contains(expected, StringComparison.OrdinalIgnoreCase),
                $"内置规则缺少 {expected} 类别的覆盖");
    }

    // ─────────────────────────────── 规则导出 ───────────────────────────────

    [Fact]
    public void EmitYaraText_WritesOneFilePerRuleSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsl-yara-{Guid.NewGuid():N}");
        try
        {
            var files = YaraAnalyzer.EmitYaraText(YaraAnalyzer.BuiltinRules, dir);

            Assert.NotEmpty(files);
            Assert.All(files, f => Assert.True(File.Exists(f)));

            var content = File.ReadAllText(files[0]);
            Assert.Contains("rule ", content);
            Assert.Contains("condition:", content);
            Assert.Contains("generator = \"WinSecLab\"", content);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ─────────────────────────────── 用户规则解析 ───────────────────────────────

    private static string WriteRuleFile(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsl-rule-{Guid.NewGuid():N}.yar");
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    [Fact]
    public void Parser_ParsesTagsMetaAndAnyCondition()
    {
        var file = WriteRuleFile("""
            rule Test_Rule : t1 t2 {
                meta:
                    description = "测试规则"
                    severity = "high"
                    author = "unit-test"
                strings:
                    $a = "CreateRemoteThread" ascii nocase
                    $b = "VirtualAllocEx"
                condition:
                    any of them
            }
            """);
        try
        {
            var outcome = YaraRuleParser.Load(new[] { file });

            Assert.Empty(outcome.Warnings);
            var rule = Assert.Single(outcome.Rules);
            Assert.Equal("Test_Rule", rule.Name);
            Assert.Equal("high", rule.Severity);
            Assert.Equal("unit-test", rule.Author);
            Assert.Equal(new[] { "t1", "t2" }, rule.Tags);
            Assert.Equal(2, rule.Patterns.Count);
            Assert.Equal(YaraCondition.AnyOfThem, rule.Condition);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Parser_ParsesAtLeastNCondition()
    {
        var file = WriteRuleFile("""
            rule N_Of {
                strings:
                    $a = "one"
                    $b = "two"
                    $c = "three"
                condition:
                    2 of them
            }
            """);
        try
        {
            var rule = Assert.Single(YaraRuleParser.Load(new[] { file }).Rules);
            Assert.Equal(YaraCondition.AtLeastN, rule.Condition);
            Assert.Equal(2, rule.Threshold);
        }
        finally
        {
            File.Delete(file);
        }
    }

    /// <summary>不支持的语法必须留痕：静默曲解规则语义比解析失败更危险。</summary>
    [Fact]
    public void Parser_UnsupportedRegex_RecordsWarning_AndSkipsPattern()
    {
        var file = WriteRuleFile("""
            rule With_Regex {
                strings:
                    $re = /foo\d+bar/
                    $lit = "literal-ok"
                condition:
                    any of them
            }
            """);
        try
        {
            var outcome = YaraRuleParser.Load(new[] { file });

            Assert.NotEmpty(outcome.Warnings);
            var rule = Assert.Single(outcome.Rules);
            // 正则被跳过，但可用的字面量模式要保留
            Assert.Single(rule.Patterns);
            Assert.Equal("literal-ok", rule.Patterns[0].Value);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Parser_StripsCommentsWithoutBreakingStrings()
    {
        var file = WriteRuleFile("""
            // 行注释里的 rule 关键字不应被误识别
            rule Commented {
                strings:
                    /* 块注释 $x = "fake" */
                    $a = "real-value"   // 行内注释
                condition:
                    any of them
            }
            """);
        try
        {
            var outcome = YaraRuleParser.Load(new[] { file });

            var rule = Assert.Single(outcome.Rules);
            Assert.Equal("Commented", rule.Name);
            Assert.Equal("real-value", Assert.Single(rule.Patterns).Value);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Parser_RuleWithoutCondition_IsRejected()
    {
        var file = WriteRuleFile("""
            rule No_Condition {
                strings:
                    $a = "x"
            }
            """);
        try
        {
            var outcome = YaraRuleParser.Load(new[] { file });
            Assert.Empty(outcome.Rules);
            Assert.NotEmpty(outcome.Warnings);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Parser_MissingFile_DoesNotThrow()
    {
        var outcome = YaraRuleParser.Load(new[] { Path.Combine(Path.GetTempPath(), "definitely-not-exist.yar") });
        Assert.Empty(outcome.Rules);
    }

    // ─────────────────────────────── 外部 yara.exe 输出解析 ───────────────────────────────

    [Fact]
    public void ParseYaraOutput_ParsesTagsAndDetailLines()
    {
        // yara -s 的输出格式：命中行顶格、字符串明细行有缩进 —— 这正是解析器区分两者的依据
        const string output = """
            Some_Rule [a,b] C:\sample.exe
                0x1a2b:$a: CreateRemoteThread
                0x1c3d:$b: WriteProcessMemory
            Another_Rule C:\sample.exe
            """;

        var matches = YaraToolAdapter.ParseYaraOutput(output, @"C:\sample.exe");

        Assert.Equal(2, matches.Count);
        Assert.Equal("Some_Rule", matches[0].RuleName);
        Assert.Equal(new[] { "a", "b" }, matches[0].Tags);
        Assert.Equal(2, matches[0].MatchedStrings.Count);
        Assert.Contains("CreateRemoteThread", matches[0].MatchedStrings[0]);
        Assert.Equal("Another_Rule", matches[1].RuleName);
        Assert.Empty(matches[1].Tags);
        Assert.Equal("yara", matches[1].Source);
    }

    [Fact]
    public void ParseYaraOutput_EmptyInput_ReturnsEmpty()
    {
        Assert.Empty(YaraToolAdapter.ParseYaraOutput("", "x"));
        Assert.Empty(YaraToolAdapter.ParseYaraOutput("\n\n", "x"));
    }
}
