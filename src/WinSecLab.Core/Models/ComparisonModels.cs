namespace WinSecLab.Core.Models;

/// <summary>
/// 一次分析的「结论快照」—— 只保留跨轮次对比需要的最小信息。
///
/// 为什么需要它：<see cref="Finding"/> 是按 ID 覆盖写入的（ON CONFLICT DO UPDATE），
/// 同一目标跑第二遍时，规则命中的 ID 往往完全一致，数据库里根本看不出"这次多了什么、
/// 上次那条怎么没了"。没跑过的目标重新分析也只会盖掉旧数据。
/// 所以每轮结束存一份快照，下一轮就能 diff 出「新增 / 消失 / 持续 / 状态变化」。
/// </summary>
public sealed class AnalysisSnapshot
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    /// <summary>关联的动态会话（纯静态分析时可能为空）。</summary>
    public string? SessionId { get; set; }
    public DateTime CapturedAt { get; set; } = DateTime.Now;
    /// <summary>触发这轮分析使用的 Profile，便于判断两轮是否可比。</summary>
    public TestProfileKind Profile { get; set; } = TestProfileKind.Basic;
    /// <summary>被测样本哈希。两轮哈希不同说明换了版本，对比会给出提示。</summary>
    public string? TargetSha256 { get; set; }
    public string? TargetVersion { get; set; }

    /// <summary>本轮每条发现的精简指纹。</summary>
    public List<SnapshotFinding> Findings { get; set; } = new();

    // ── 关键指标（量级变化本身就是信号：事件从 0 涨到 400 值得看一眼） ──
    public int EventCount { get; set; }
    public int EvidenceCount { get; set; }
    public int ConnectionCount { get; set; }
    public int SuspiciousEventCount { get; set; }
    public int YaraMatchCount { get; set; }

    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);
    public int HighCount => Findings.Count(f => f.Severity == Severity.High);
    public int MediumCount => Findings.Count(f => f.Severity == Severity.Medium);
    public int LowCount => Findings.Count(f => f.Severity == Severity.Low);
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);
    public int TotalFindings => Findings.Count;

    /// <summary>比上次更严重的项数（新增 + 状态回归），用于一句话结论。</summary>
    public int RiskyCount => CriticalCount + HighCount;
}

/// <summary>快照里的单条发现。故意只留对比必需的字段，不存整份 Finding。</summary>
public sealed class SnapshotFinding
{
    public string Id { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public FindingStatus Status { get; set; } = FindingStatus.Open;
    public string Category { get; set; } = "";

    [System.Text.Json.Serialization.JsonIgnore]
    public string SeverityText => Severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高",
        Severity.Medium => "中",
        Severity.Low => "低",
        _ => "提示",
    };

    [System.Text.Json.Serialization.JsonIgnore]
    public string StatusText => Status switch
    {
        FindingStatus.Open => "待处理",
        FindingStatus.Confirmed => "已确认",
        FindingStatus.FalsePositive => "误报",
        FindingStatus.Accepted => "接受风险",
        FindingStatus.Remediated => "已整改",
        _ => Status.ToString(),
    };
}

/// <summary>一次对比的结果：基线快照 → 当前快照 的差异。</summary>
public sealed class ComparisonResult
{
    public AnalysisSnapshot? Baseline { get; set; }
    public AnalysisSnapshot? Current { get; set; }
    public string? Error { get; set; }

    /// <summary>本轮新出现（基线无、当前有）。</summary>
    public List<SnapshotFinding> Added { get; set; } = new();
    /// <summary>本轮消失（基线有、当前无）—— 通常表示修复或规则未再命中。</summary>
    public List<SnapshotFinding> Removed { get; set; } = new();
    /// <summary>两轮都在，但严重级或处理状态变了。</summary>
    public List<FindingChange> Changed { get; set; } = new();
    /// <summary>两轮一致、且未处理的（稳定问题）。</summary>
    public List<SnapshotFinding> Unchanged { get; set; } = new();

    public bool HasBaseline => Baseline is not null && Current is not null;

    /// <summary>两轮样本哈希不同 —— 说明对比的是不同版本，结论需谨慎解读。</summary>
    public bool TargetChanged =>
        Baseline?.TargetSha256 is { Length: > 0 } a &&
        Current?.TargetSha256 is { Length: > 0 } b &&
        !string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    public int DeltaFindings => (Current?.TotalFindings ?? 0) - (Baseline?.TotalFindings ?? 0);
    public int DeltaEvents => (Current?.EventCount ?? 0) - (Baseline?.EventCount ?? 0);
    public int DeltaConnections => (Current?.ConnectionCount ?? 0) - (Baseline?.ConnectionCount ?? 0);

    /// <summary>一句话结论，给报告摘要与 CLI 用。</summary>
    public string Verdict
    {
        get
        {
            if (!HasBaseline) return "无可对比的基线（这是该项目的第一轮分析）。";
            if (Added.Count == 0 && Removed.Count == 0 && Changed.Count == 0)
                return "与上次相比无变化。";

            var parts = new List<string>();
            if (Added.Count > 0) parts.Add($"新增 {Added.Count} 项");
            if (Removed.Count > 0) parts.Add($"消失 {Removed.Count} 项");
            if (Changed.Count > 0) parts.Add($"变化 {Changed.Count} 项");
            return "与上次相比：" + string.Join("，", parts) + "。";
        }
    }
}

/// <summary>单条发现的变化：严重级或处理状态在两次之间发生变化。</summary>
public sealed class FindingChange
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Field { get; set; } = "";   // "严重级" 或 "处理状态"
    public string Before { get; set; } = "";
    public string After { get; set; } = "";

    public string Describe => $"{Id} {Title}：{Field} {Before} → {After}";
}
