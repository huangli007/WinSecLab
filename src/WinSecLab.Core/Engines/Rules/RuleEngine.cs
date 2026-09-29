using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins;

namespace WinSecLab.Core.Engines.Rules;

/// <summary>规则命中。一条规则可以命中多次，最终按 GroupKey 汇总成一个 Finding。</summary>
public sealed class RuleHit
{
    /// <summary>同一规则内用于聚合的键。空字符串表示「全部汇总成一条」。</summary>
    public string GroupKey { get; init; } = "";

    /// <summary>命中对象（进程名 / 文件路径 / 注册表键 / 网络端点）。</summary>
    public string Target { get; init; } = "";

    /// <summary>支撑这条命中的证据。</summary>
    public List<string> EvidenceIds { get; init; } = new();

    /// <summary>写进 Finding 描述的具体事实，一行一条。</summary>
    public List<string> Facts { get; init; } = new();

    public List<string> RelatedProcesses { get; init; } = new();
    public List<string> RelatedFiles { get; init; } = new();
    public List<string> RelatedRegistry { get; init; } = new();
    public List<string> RelatedNetwork { get; init; } = new();

    /// <summary>复现步骤，可以由规则自动生成，也可以由分析员补充。</summary>
    public string? Reproduction { get; init; }

    public Severity? SeverityOverride { get; init; }
    public Confidence? ConfidenceOverride { get; init; }
}

/// <summary>规则求值上下文：一次分析的全部证据视图。</summary>
public sealed class RuleContext
{
    public required AnalysisResult Result { get; init; }
    public required TestProject Project { get; init; }
    public required IReadOnlyList<Evidence> Evidence { get; init; }
    public AnalysisOptions Options { get; init; } = new();

    public PeImageInfo? Pe => Result.Pe;
    public DotNetAssemblyInfo? DotNet => Result.DotNet;
    public IReadOnlyList<DependencyInfo> Dependencies => Result.Dependencies;
    public IReadOnlyList<StringHit> Strings => Result.Strings;
    public IReadOnlyList<MonitorEvent> Events => Result.Events;
    public IReadOnlyList<NetworkConnection> Connections => Result.Connections;
    public IReadOnlyList<HttpExchange> Http => Result.Http;
    public IReadOnlyList<YaraMatch> Yara => Result.YaraMatches;

    private Dictionary<EvidenceKind, List<Evidence>>? _index;

    public IReadOnlyList<Evidence> EvidenceOf(EvidenceKind kind)
    {
        _index ??= Evidence.GroupBy(e => e.Kind).ToDictionary(g => g.Key, g => g.ToList());
        return _index.TryGetValue(kind, out var list) ? list : Array.Empty<Evidence>();
    }

    /// <summary>按标题前缀 / 标签找证据 ID，供命中引用。</summary>
    public List<string> Ids(EvidenceKind kind, Func<Evidence, bool>? filter = null, int max = 6)
    {
        var query = EvidenceOf(kind).AsEnumerable();
        if (filter is not null) query = query.Where(filter);
        return query.Take(max).Select(e => e.Id).ToList();
    }

    public List<string> IdsWithTag(string tag, int max = 6) =>
        Evidence.Where(e => e.Tags.Contains(tag, StringComparer.OrdinalIgnoreCase))
            .Take(max).Select(e => e.Id).ToList();

    // ------------------------------------------------------- 常用便捷查询

    public IEnumerable<MonitorEvent> EventsOfType(params MonitorEventType[] types) =>
        Events.Where(e => types.Contains(e.Type));

    public IEnumerable<MonitorEvent> EventsMatching(Func<MonitorEvent, bool> predicate) => Events.Where(predicate);

    public bool HasImportFunction(params string[] names)
    {
        if (Pe is null) return false;
        var set = names.Select(n => n.ToLowerInvariant()).ToHashSet();
        return Pe.Imports.Any(m => m.Functions.Any(f => set.Contains(StripDecoration(f.Name))));
    }

    public IEnumerable<string> MatchedImportFunctions(params string[] names)
    {
        if (Pe is null) yield break;
        var set = names.Select(n => n.ToLowerInvariant()).ToHashSet();
        foreach (var module in Pe.Imports)
        {
            foreach (var function in module.Functions)
            {
                var name = StripDecoration(function.Name);
                if (set.Contains(name)) yield return $"{module.ModuleName}!{name}";
            }
        }
    }

    /// <summary>去掉 MSVC 导入表里的 __imp_ 前缀与 @n 后缀。</summary>
    private static string StripDecoration(string name)
    {
        var n = name;
        if (n.StartsWith("__imp_", StringComparison.OrdinalIgnoreCase)) n = n[6..];
        var at = n.IndexOf('@');
        if (at > 0) n = n[..at];
        return n.ToLowerInvariant();
    }

    public IEnumerable<StringHit> StringsInCategory(string category) =>
        Strings.Where(s => s.Category.Equals(category, StringComparison.OrdinalIgnoreCase));

    /// <summary>取最可疑的文件写入事件（按路径敏感性排序）。</summary>
    public IEnumerable<MonitorEvent> SuspiciousFileWrites() =>
        EventsOfType(MonitorEventType.FileCreate, MonitorEventType.FileWrite, MonitorEventType.FileRename)
            .Where(e => IsExecutablePath(e.Target));

    public static bool IsExecutablePath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var ext = Path.GetExtension(path);
        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".cpl", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".jse", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".wsf", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".hta", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>一条规则的完整定义。</summary>
public sealed record RuleDefinition(
    string Id,
    string Category,
    Severity Severity,
    Confidence Confidence,
    string Title,
    string Description,
    string? Impact,
    string? Recommendation,
    string? CweId,
    string? OwaspCategory,
    Func<RuleContext, IEnumerable<RuleHit>> Evaluate,
    bool EnabledByDefault = true);

/// <summary>
/// §9 Security Findings Engine + 第 3 阶段的行为关联。
/// 规则只做「基于已采集证据的归纳」，不做猜测 —— 每条 Finding 都能回到原始证据，
/// 与 §25「证据优先 / 人工可验证」一致。
/// </summary>
public sealed class RuleEngine
{
    private readonly List<RuleDefinition> _rules;

    public RuleEngine(IEnumerable<RuleDefinition>? rules = null)
    {
        _rules = (rules ?? BuiltinRules.All).Where(r => r.EnabledByDefault).ToList();
    }

    public IReadOnlyList<RuleDefinition> Rules => _rules;

    public IReadOnlyList<RuleDefinition> DisabledRules =>
        BuiltinRules.All.Where(r => !r.EnabledByDefault).ToList();

    public sealed class RuleEngineReport
    {
        public List<Finding> Findings { get; } = new();
        public List<string> RuleErrors { get; } = new();
        public Dictionary<string, int> FiredRuleCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public RuleEngineReport Run(RuleContext context, string projectId, int startingSerial = 101)
    {
        var report = new RuleEngineReport();
        var serial = startingSerial;

        foreach (var rule in _rules)
        {
            List<RuleHit> hits;
            try
            {
                hits = rule.Evaluate(context).ToList();
            }
            catch (Exception ex)
            {
                report.RuleErrors.Add($"{rule.Id} 求值异常：{ex.GetType().Name}: {ex.Message}");
                continue;
            }

            if (hits.Count == 0) continue;
            report.FiredRuleCounts[rule.Id] = hits.Count;

            foreach (var group in hits.GroupBy(h => h.GroupKey, StringComparer.OrdinalIgnoreCase))
            {
                var groupHits = group.ToList();
                var finding = BuildFinding(rule, groupHits, projectId, ref serial);
                report.Findings.Add(finding);
            }
        }

        // 严重级降序，同级按规则编号升序，保证报告稳定可复现
        report.Findings.Sort((a, b) =>
        {
            var bySeverity = b.Severity.CompareTo(a.Severity);
            return bySeverity != 0 ? bySeverity : string.CompareOrdinal(a.RuleId, b.RuleId);
        });

        return report;
    }

    private static Finding BuildFinding(RuleDefinition rule, List<RuleHit> hits, string projectId, ref int serial)
    {
        var primary = hits[0];
        var severity = primary.SeverityOverride ?? rule.Severity;
        var confidence = primary.ConfidenceOverride ?? rule.Confidence;

        // 证据越多、命中越多，置信度适当上调（置信度只升不降，避免越过规则本意）
        if (hits.Count >= 3 && confidence == Confidence.Medium) confidence = Confidence.High;

        var description = rule.Description;
        var extraFacts = new List<string>();
        foreach (var hit in hits.Take(12))
        {
            foreach (var fact in hit.Facts)
            {
                if (!extraFacts.Contains(fact)) extraFacts.Add(fact);
            }
        }

        if (extraFacts.Count > 0)
        {
            description += Environment.NewLine + Environment.NewLine + "命中事实：" + Environment.NewLine +
                           string.Join(Environment.NewLine, extraFacts.Select(f => "• " + f));
        }

        if (hits.Count > 12)
            description += Environment.NewLine + $"（同类命中共 {hits.Count} 处，此处列出前 12 处）";

        var finding = new Finding
        {
            Id = $"WS-{serial++}",
            ProjectId = projectId,
            RuleId = rule.Id,
            Title = rule.Title,
            Description = description,
            Severity = severity,
            Confidence = confidence,
            Category = rule.Category,
            Source = "WinSecLab 规则引擎",
            Target = primary.Target,
            Timestamp = DateTime.Now,
            Impact = rule.Impact,
            Recommendation = rule.Recommendation,
            CweId = rule.CweId,
            OwaspCategory = rule.OwaspCategory,
            Reproduction = primary.Reproduction ?? BuildDefaultReproduction(rule, primary),
            EvidenceIds = hits.SelectMany(h => h.EvidenceIds).Distinct().Take(40).ToList(),
            RelatedProcesses = hits.SelectMany(h => h.RelatedProcesses).Distinct().Take(20).ToList(),
            RelatedFiles = hits.SelectMany(h => h.RelatedFiles).Distinct().Take(20).ToList(),
            RelatedRegistry = hits.SelectMany(h => h.RelatedRegistry).Distinct().Take(20).ToList(),
            RelatedNetwork = hits.SelectMany(h => h.RelatedNetwork).Distinct().Take(20).ToList(),
        };

        return finding;
    }

    private static string BuildDefaultReproduction(RuleDefinition rule, RuleHit hit)
    {
        var steps = new List<string>
        {
            $"1. 在隔离的 Windows 测试环境中以测试账号运行被测程序（本次会话已记录证据）。",
        };
        if (!string.IsNullOrEmpty(hit.Target))
            steps.Add($"2. 关注对象：{hit.Target}");
        steps.Add($"3. 在 {rule.Id} 关联的证据条目中查看原始记录（进程 / 文件 / 注册表 / 网络时间线）。");
        steps.Add("4. 若需精确归因（谁写的、哪个线程调的），按建议启用 Process Monitor 适配器复现一次。");
        return string.Join(Environment.NewLine, steps);
    }
}
