using WinSecLab.Core.Models;

namespace WinSecLab.Core.Plugins;

/// <summary>统一构造证据，保证 ID 稳定、格式一致（§25 证据优先）。</summary>
public static class EvidenceFactory
{
    private static long _counter;

    public static Evidence Create(string projectId, EvidenceKind kind, string title, string source,
        string? target, string summary, object? payload = null, params string[] tags)
    {
        var id = $"EV-{kind.ToString()[..Math.Min(4, kind.ToString().Length)].ToUpperInvariant()}-{Interlocked.Increment(ref _counter):D5}";
        return new Evidence
        {
            Id = id,
            ProjectId = projectId,
            Kind = kind,
            Title = title,
            Source = source,
            Target = target,
            Timestamp = DateTime.Now,
            Summary = summary,
            DataJson = payload is null ? "{}" : Serialization.WslJson.Serialize(payload),
            Tags = tags.ToList(),
        };
    }

    /// <summary>重置计数器（每次新的分析任务开始前调用，保证同一项目内 ID 不冲突且可复现）。</summary>
    public static void Reset() => Interlocked.Exchange(ref _counter, 0);
}
