using WinSecLab.Core.Engines.Static;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Plugins.Builtin;

/// <summary>
/// §19 ⑦ YARA —— 内置轻量引擎版本。
/// 同一套规则既能被这里的托管匹配器执行，也能由 <see cref="YaraToolAdapter"/> 交给真正的 yara.exe 执行，
/// 两者结论可直接对照（§25 结果统一 / 可重复测试）。
/// </summary>
public sealed class BuiltinYaraPlugin : IWinSecLabPlugin
{
    /// <summary>除目标文件外，额外扫描同目录二进制的上限。</summary>
    public const int DefaultSiblingScanLimit = 12;

    public string Id => "builtin.yara";
    public string Name => "YARA (内置引擎)";
    public string Version => "1.0";
    public string? Description => "内置 20 条启发式规则（下载执行、注入、凭据访问、持久化、加壳、密钥泄漏等），同时加载用户自定义 .yar 规则目录。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.YaraScan };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() =>
        PluginProbeResult.Builtin($"内置轻量匹配器 + {YaraAnalyzer.BuiltinRules.Count} 条自研规则；安装 yara.exe 后可通过 yara 适配器切换到完整引擎");

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        context.Progress(-1, "加载 YARA 规则");
        var rules = LoadRules(context, out var ruleWarnings, out var userRuleCount);

        if (rules.Count == 0)
            return PluginRunResult.Fail("规则集为空：既没有内置规则也没有可用的用户规则。");

        // 把内置规则导出成标准 .yar，用户可以拿去喂给真正的 yara.exe，也方便 review 规则内容
        var exportedDir = Path.Combine(context.Layout.Artifacts, "yara", "builtin");
        List<string> exported;
        try { exported = YaraAnalyzer.EmitYaraText(YaraAnalyzer.BuiltinRules, exportedDir); }
        catch (Exception ex)
        {
            exported = new List<string>();
            context.Log($"规则导出失败（不影响本次扫描）：{ex.Message}");
        }

        var targets = CollectTargets(context);
        context.Log($"规则 {rules.Count} 条（内置 {YaraAnalyzer.BuiltinRules.Count} + 用户 {userRuleCount}），待扫描文件 {targets.Count} 个");

        var allMatches = new List<YaraMatch>();
        var perFile = new List<(string File, int Count, long Size)>();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        for (var i = 0; i < targets.Count; i++)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var file = targets[i];
            var pct = targets.Count == 0 ? 1d : (double)i / targets.Count;
            context.Progress(pct, $"扫描 {Path.GetFileName(file)}（{i + 1}/{targets.Count}）");

            var matches = await Task.Run(() => YaraAnalyzer.Scan(file, rules), context.CancellationToken)
                .ConfigureAwait(false);

            long size = 0;
            try { size = new FileInfo(file).Length; } catch { }

            allMatches.AddRange(matches);
            perFile.Add((file, matches.Count, size));
            foreach (var m in matches)
                context.Log($"  命中 {m.RuleName} [{m.Severity}] → {Path.GetFileName(m.FilePath)}");
        }

        sw.Stop();
        context.Progress(1, "整理 YARA 结果");

        context.Result.YaraMatches.AddRange(allMatches);
        if (allMatches.Count > 0) context.Database.SaveYaraMatches(allMatches);

        // ── 证据 ──
        var evidence = new List<Evidence>();
        var severityCounts = allMatches
            .GroupBy(m => m.Severity.ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.Count());

        evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Yara, "YARA 扫描汇总", "builtin.yara",
            context.TargetPath,
            allMatches.Count == 0
                ? $"扫描 {targets.Count} 个文件，规则 {rules.Count} 条，未发生命中。"
                : $"扫描 {targets.Count} 个文件，规则 {rules.Count} 条，命中 {allMatches.Count} 次"
                  + $"（{string.Join("、", severityCounts.Select(kv => $"{Describe(kv.Key)} {kv.Value}"))}），"
                  + $"耗时 {sw.Elapsed.TotalSeconds:F1}s",
            new
            {
                ruleCount = rules.Count,
                builtinRuleCount = YaraAnalyzer.BuiltinRules.Count,
                userRuleCount,
                scannedFiles = perFile.Select(p => new { p.File, p.Size, p.Count }).ToList(),
                severityCounts,
                exportedRuleFiles = exported,
                durationSeconds = Math.Round(sw.Elapsed.TotalSeconds, 2),
            },
            "yara", "static"));

        if (allMatches.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Yara, "YARA 命中明细", "builtin.yara",
                context.TargetPath,
                string.Join("；", allMatches.Take(12).Select(m => $"{m.RuleName}@{Path.GetFileName(m.FilePath)}")),
                allMatches, "yara", "static", "signature-match"));

            // 按规则聚合出「受影响文件清单」，方便按样本而不是按规则推进人工分析
            var byRule = allMatches
                .GroupBy(m => m.RuleName)
                .Select(g => new
                {
                    rule = g.Key,
                    severity = g.First().Severity,
                    description = g.First().Description,
                    matchedStringSample = g.SelectMany(x => x.MatchedStrings).Distinct().Take(8).ToList(),
                    files = g.Select(x => x.FilePath).Distinct().ToList(),
                })
                .OrderByDescending(x => SeverityRank(x.severity))
                .ToList();

            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Yara, "YARA 规则视角聚合", "builtin.yara",
                context.TargetPath,
                $"{byRule.Count} 条规则命中，涉及 {allMatches.Select(m => m.FilePath).Distinct().Count()} 个文件",
                byRule, "yara", "static"));
        }

        if (userRuleCount > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Yara, "已加载的用户规则", "builtin.yara",
                context.Layout.Rules,
                $"从规则目录加载 {userRuleCount} 条用户规则",
                rules.Where(r => r.RuleSet != "builtin").Select(r => new { r.Name, r.RuleSet, r.Severity, r.Description }).ToList(),
                "yara", "rules"));
        }

        var run = PluginRunResult.Ok(
            allMatches.Count == 0
                ? $"YARA 扫描完成：{targets.Count} 个文件未命中任何规则"
                : $"YARA 扫描完成：{allMatches.Count} 次命中，覆盖 {allMatches.Select(m => m.RuleName).Distinct().Count()} 条规则",
            evidence);

        foreach (var w in ruleWarnings) run.Warnings.Add(w);
        if (exported.Count > 0) run.Artifacts.AddRange(exported);
        return run;
    }

    public void Stop() { }

    public IReadOnlyList<string> Export(PluginContext context)
    {
        var matches = context.Result.YaraMatches;
        if (matches.Count == 0) return Array.Empty<string>();

        var dir = Path.Combine(context.Layout.Artifacts, "yara");
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "yara-matches.json");
        File.WriteAllText(file, Serialization.WslJson.Serialize(matches, indented: true), System.Text.Encoding.UTF8);
        return new[] { file };
    }

    // ─────────────────────────────── 内部实现 ───────────────────────────────

    /// <summary>规则优先级：内置在前，用户规则在后（同名覆盖），符合"用户规则更贴近当前项目"的直觉。</summary>
    internal static List<YaraRule> LoadRules(PluginContext context, out List<string> warnings, out int userRuleCount)
    {
        warnings = new List<string>();
        var merged = new Dictionary<string, YaraRule>(StringComparer.Ordinal);
        foreach (var r in YaraAnalyzer.BuiltinRules) merged[r.Name] = r;

        var userDirs = new List<string>();
        if (!string.IsNullOrWhiteSpace(context.Options.YaraRulesDirectory))
            userDirs.Add(context.Options.YaraRulesDirectory!);
        if (Directory.Exists(context.Layout.Rules))
            userDirs.Add(context.Layout.Rules);

        var loadedNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var dir in userDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var outcome = YaraRuleParser.Load(new[] { dir });
            warnings.AddRange(outcome.Warnings);
            foreach (var r in outcome.Rules)
            {
                var overridesBuiltin = merged.ContainsKey(r.Name);
                merged[r.Name] = r;
                loadedNames.Add(r.Name);
                if (overridesBuiltin)
                    warnings.Add($"用户规则 {r.Name} 与内置规则同名，已按用户版本执行（{Path.GetFileName(dir)}）。");
            }
        }

        userRuleCount = loadedNames.Count;
        return merged.Values.ToList();
    }

    /// <summary>目标文件 + 同目录其它 PE 文件（DLL 劫持、捆绑组件常藏在这里）。</summary>
    internal static List<string> CollectTargets(PluginContext context)
    {
        var targets = new List<string>();

        void AddFile(string path)
        {
            if (!File.Exists(path)) return;
            if (targets.Any(t => string.Equals(t, path, StringComparison.OrdinalIgnoreCase))) return;
            targets.Add(path);
        }

        AddFile(context.TargetPath);

        var limit = context.Options.YaraMaxFiles <= 0 ? DefaultSiblingScanLimit : context.Options.YaraMaxFiles;
        if (limit <= 1) return targets;

        var dir = Path.GetDirectoryName(context.TargetPath);
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return targets;

        var siblings = new List<(string Path, long Size)>();
        try
        {
            var exts = new[] { ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".node" };
            foreach (var f in Directory.EnumerateFiles(dir))
            {
                var ext = Path.GetExtension(f);
                if (!exts.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                if (string.Equals(f, context.TargetPath, StringComparison.OrdinalIgnoreCase)) continue;
                long size;
                try { size = new FileInfo(f).Length; } catch { continue; }
                siblings.Add((f, size));
            }
        }
        catch { return targets; }

        // 大文件更可能是有实际逻辑的组件，优先扫；同尺寸按路径稳定排序保证可复现
        foreach (var s in siblings.OrderByDescending(x => x.Size).ThenBy(x => x.Path, StringComparer.Ordinal))
        {
            if (targets.Count >= limit) break;
            AddFile(s.Path);
        }

        return targets;
    }

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };

    private static string Describe(string severity) => severity switch
    {
        "critical" => "严重",
        "high" => "高",
        "medium" => "中",
        "low" => "低",
        _ => "提示",
    };
}

/// <summary>
/// YARA 适配器（§17 ExternalToolAdapter）。检测到 yara.exe 时用完整引擎重跑一遍内置规则 + 用户规则，
/// 让"自研规则集"在真正的 YARA 语义下再验证一次；未安装时明确跳过（而不是假装做过）。
///
/// 注意它必须继承 <see cref="ExternalToolAdapterBase"/>：编排层靠
/// <c>p is ExternalToolAdapterBase a &amp;&amp; a.Descriptor.Role == Substitutive</c> 判断
/// "该不该让外部工具接管内置引擎"。早先这里是裸实现 IWinSecLabPlugin，
/// 结果 YARA 装上了也不会被当成替代型 —— 白装。
/// </summary>
public sealed class YaraToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "yara";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation loc)
    {
        var exe = loc.ExecutablePath!;

        // 规则目录：内置规则导出到 artifacts 下，用户规则目录若存在则一并纳入
        var rulesDir = Path.Combine(context.Layout.Artifacts, "yara", "external");
        List<string> ruleFiles;
        try
        {
            ruleFiles = YaraAnalyzer.EmitYaraText(YaraAnalyzer.BuiltinRules, rulesDir);
        }
        catch (Exception ex)
        {
            return PluginRunResult.Fail($"导出内置规则失败，无法调用外部 YARA：{ex.Message}");
        }

        if (Directory.Exists(context.Layout.Rules))
        {
            try
            {
                ruleFiles.AddRange(Directory.EnumerateFiles(context.Layout.Rules, "*.yar", SearchOption.AllDirectories));
                ruleFiles.AddRange(Directory.EnumerateFiles(context.Layout.Rules, "*.yara", SearchOption.AllDirectories));
            }
            catch { }
        }
        if (!string.IsNullOrWhiteSpace(context.Options.YaraRulesDirectory) && Directory.Exists(context.Options.YaraRulesDirectory))
        {
            try
            {
                ruleFiles.AddRange(Directory.EnumerateFiles(context.Options.YaraRulesDirectory!, "*.yar", SearchOption.AllDirectories));
            }
            catch { }
        }

        ruleFiles = ruleFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var log = new List<string>();
        log.Add($"外部 YARA：{exe}（{loc.Source}）");
        log.Add($"规则文件 {ruleFiles.Count} 个");

        var matches = new List<YaraMatch>();
        var artifacts = new List<string>();
        var warnings = new List<string>();

        // 逐个文件调用：yara 命令行本身支持多目标，但逐个调用可以拿到清晰的单文件归因与耗时
        var targets = BuiltinYaraPlugin.CollectTargets(context);
        for (var i = 0; i < targets.Count; i++)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var target = targets[i];
            context.Progress((double)i / Math.Max(1, targets.Count), $"外部 YARA：{Path.GetFileName(target)}");

            var args = BuildArguments(ruleFiles, target);
            var result = await ProcessRunner.RunAsync(
                exe, args, Path.GetDirectoryName(target),
                timeoutMs: 90_000, cancellationToken: context.CancellationToken, log: log.Add)
                .ConfigureAwait(false);

            if (!result.Started)
            {
                warnings.Add($"{Path.GetFileName(target)}：{result.StdErr}");
                continue;
            }
            if (result.TimedOut)
            {
                warnings.Add($"{Path.GetFileName(target)}：外部 YARA 超时（90s）已被终止，该文件结果缺失。");
                continue;
            }
            if (result.ExitCode != 0 && string.IsNullOrWhiteSpace(result.StdOut))
            {
                // yara 用非 0 退出码表达"编译错误"或"无命中"，需要看 stderr 才能区分
                var err = result.StdErr.Trim();
                if (err.Length > 0)
                {
                    warnings.Add($"{Path.GetFileName(target)}：yara 退出码 {result.ExitCode} —— {FirstLines(err, 3)}");
                }
                continue;
            }

            var parsed = ParseYaraOutput(result.StdOut, target);
            matches.AddRange(parsed);
            context.Log($"  外部 YARA：{Path.GetFileName(target)} 命中 {parsed.Count} 条");

            // 原始输出留档，方便和内置引擎结论做 diff
            try
            {
                var dir = Path.Combine(context.Layout.Artifacts, "yara", "external");
                Directory.CreateDirectory(dir);
                var outFile = Path.Combine(dir, Path.GetFileName(target) + ".yara-output.txt");
                File.WriteAllText(outFile, result.Combined, System.Text.Encoding.UTF8);
                artifacts.Add(outFile);
            }
            catch { }
        }

        context.Result.YaraMatches.AddRange(matches);
        if (matches.Count > 0) context.Database.SaveYaraMatches(matches);

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.ToolOutput, "外部 YARA 引擎结果", "yara",
                context.TargetPath,
                matches.Count == 0
                    ? $"yara.exe 已执行，扫描 {targets.Count} 个文件，未命中规则。"
                    : $"yara.exe 命中 {matches.Count} 次，覆盖 {matches.Select(m => m.RuleName).Distinct().Count()} 条规则。",
                new
                {
                    enginePath = exe,
                    engineSource = loc.Source,
                    engineVersion = loc.Version,
                    ruleFileCount = ruleFiles.Count,
                    ruleFiles = ruleFiles.Take(40).ToList(),
                    scannedCount = targets.Count,
                    matchCount = matches.Count,
                },
                "yara", "external-tool"),
        };

        if (matches.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Yara, "外部 YARA 命中明细", "yara",
                context.TargetPath,
                string.Join("；", matches.Take(12).Select(m => $"{m.RuleName}@{Path.GetFileName(m.FilePath)}")),
                matches, "yara", "external-tool"));
        }

        var run = PluginRunResult.Ok(
            $"外部 YARA 执行完成：{targets.Count} 个文件，{matches.Count} 次命中", evidence, null, artifacts);
        foreach (var w in warnings) run.Warnings.Add(w);
        foreach (var l in log) run.Log.Add(l);
        return run;
    }

    private static string BuildArguments(List<string> ruleFiles, string target)
    {
        // -s 打印命中字符串，-m 打印 meta，-w 抑制警告，-r 递归规则目录（这里显式列文件，故不用 -r）
        var sb = new System.Text.StringBuilder();
        sb.Append("-s -m -w ");
        foreach (var f in ruleFiles)
            sb.Append(ProcessRunner.Quote(f)).Append(' ');
        sb.Append(ProcessRunner.Quote(target));
        return sb.ToString();
    }

    /// <summary>
    /// 解析 `yara -s -m` 输出。格式：
    ///   RuleName [tag1,tag2] /path/to/target
    ///   0x1234:$a: matched text
    /// 命中行以非空白开头，明细行以空白开头。
    /// </summary>
    internal static List<YaraMatch> ParseYaraOutput(string output, string targetPath)
    {
        var results = new List<YaraMatch>();
        YaraMatch? current = null;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;

            var isDetail = char.IsWhiteSpace(line[0]);
            if (!isDetail)
            {
                // 形如：RuleName [tag1,tag2] C:\path\file
                var tags = new List<string>();
                var name = line;
                var bracketStart = line.IndexOf('[');
                var bracketEnd = line.IndexOf(']');
                if (bracketStart > 0 && bracketEnd > bracketStart)
                {
                    name = line[..bracketStart].Trim();
                    tags = line[(bracketStart + 1)..bracketEnd]
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                }
                else
                {
                    // 无 tag 时，规则名与路径以空白分隔
                    var space = line.IndexOf(' ');
                    if (space > 0)
                    {
                        // 路径可能含空格，因此只有在空格后看起来像路径时才切
                        var rest = line[(space + 1)..].Trim();
                        if (rest.Length > 1 && (rest.Contains(':') || rest.Contains('\\') || rest.Contains('/')))
                            name = line[..space].Trim();
                    }
                }
                if (string.IsNullOrWhiteSpace(name)) continue;

                var rule = YaraAnalyzer.FindRule(name);
                current = new YaraMatch
                {
                    RuleName = name,
                    RuleSet = rule?.RuleSet ?? "external",
                    FilePath = targetPath,
                    Severity = rule?.Severity ?? "info",
                    Description = rule?.Description ?? "外部 YARA 规则命中（未在本地规则集中找到同名规则，描述缺失）。",
                    Author = rule?.Author ?? "外部 YARA 规则",
                    Tags = tags.Count > 0 ? tags : rule?.Tags.ToList() ?? new List<string>(),
                    Source = "yara",
                    Timestamp = DateTime.Now,
                };
                results.Add(current);
                continue;
            }

            if (current is null) continue;
            var detail = line.Trim();
            if (detail.Length == 0) continue;
            if (current.MatchedStrings.Count < 40) current.MatchedStrings.Add(detail);
        }

        return results;
    }

    private static string FirstLines(string text, int count) =>
        string.Join(" / ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => l.Length > 0)
            .Take(count));
}
