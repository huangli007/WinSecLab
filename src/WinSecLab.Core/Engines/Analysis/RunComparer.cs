using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Analysis;

/// <summary>
/// 会话/轮次对比（回归测试支撑）。
///
/// 解决的问题：同一被测程序改版后重跑，最该被回答的是「这次比上次多了什么、少了什么」。
/// 但发现项是按 ID 覆盖写入的，直接读数据库只能看到"当前状态"，看不到变化。
/// 所以对比走**快照 diff**：每轮结束存一份 <see cref="AnalysisSnapshot"/>，
/// 再拿上一份与本轮做三向对比（新增 / 消失 / 变化），未被规则再命中的上一轮项即为"消失"。
/// </summary>
public static class RunComparer
{
    /// <summary>从一次完整分析结果抽取快照（只取对比必需的字段）。</summary>
    public static AnalysisSnapshot Capture(AnalysisResult result, string? sessionId = null)
    {
        var snapshot = new AnalysisSnapshot
        {
            Id = $"{result.ProjectId}-SN{DateTime.Now:yyyyMMdd-HHmmss}",
            ProjectId = result.ProjectId,
            SessionId = sessionId,
            CapturedAt = DateTime.Now,
            Profile = result.Project?.Profile ?? TestProfileKind.Basic,
            TargetSha256 = result.Project?.Target.Sha256,
            TargetVersion = result.Project?.Target.FileVersion,
            EventCount = result.Events.Count,
            EvidenceCount = result.Evidence.Count,
            ConnectionCount = result.Connections.Count,
            SuspiciousEventCount = result.Events.Count(e => e.IsSuspicious),
            YaraMatchCount = result.YaraMatches.Count,
        };

        snapshot.Findings.AddRange(result.Findings.Select(f => new SnapshotFinding
        {
            Id = f.Id,
            RuleId = f.RuleId,
            Title = f.Title,
            Severity = f.Severity,
            Status = f.Status,
            Category = f.Category,
        }));

        // 稳定排序，保证同一结果每次生成的快照字节一致（便于比对与测试）
        snapshot.Findings.Sort((a, b) =>
        {
            var byId = string.CompareOrdinal(a.Id, b.Id);
            return byId != 0 ? byId : string.CompareOrdinal(a.RuleId, b.RuleId);
        });

        return snapshot;
    }

    /// <summary>
    /// 对比两份快照。<paramref name="baseline"/> 为上一轮，<paramref name="current"/> 为本轮。
    /// 以 (RuleId, Id) 为键匹配 —— 只按 Id 匹配不够：不同规则可能生成同名 ID 前缀，
    /// 而 Id 本身在重新分析时可能被重新编号。
    /// </summary>
    public static ComparisonResult Compare(AnalysisSnapshot? baseline, AnalysisSnapshot? current)
    {
        var result = new ComparisonResult { Baseline = baseline, Current = current };

        if (current is null)
        {
            result.Error = "本轮没有结果可对比。";
            return result;
        }
        if (baseline is null)
        {
            return result;   // 无基线：调用方用 Verdict 说明"第一轮"
        }

        static string Key(SnapshotFinding f) =>
            $"{f.RuleId}\u0001{f.Title}".ToLowerInvariant();

        // 同名项可能多条（同一规则命中多个对象），用队列按顺序消费
        var baselineByKey = new Dictionary<string, Queue<SnapshotFinding>>(StringComparer.Ordinal);
        foreach (var f in baseline.Findings)
        {
            var k = Key(f);
            if (!baselineByKey.TryGetValue(k, out var q))
                baselineByKey[k] = q = new Queue<SnapshotFinding>();
            q.Enqueue(f);
        }

        foreach (var now in current.Findings)
        {
            var k = Key(now);
            if (baselineByKey.TryGetValue(k, out var q) && q.Count > 0)
            {
                var before = q.Dequeue();

                // 严重级变化（规则阈值调整 / 样本特征变化）
                if (before.Severity != now.Severity)
                {
                    result.Changed.Add(new FindingChange
                    {
                        Id = now.Id,
                        Title = now.Title,
                        Field = "严重级",
                        Before = before.SeverityText,
                        After = now.SeverityText,
                    });
                }

                // 处理状态变化（人工复核动作，说明有人在推进）
                if (before.Status != now.Status)
                {
                    result.Changed.Add(new FindingChange
                    {
                        Id = now.Id,
                        Title = now.Title,
                        Field = "处理状态",
                        Before = before.StatusText,
                        After = now.StatusText,
                    });
                }

                if (before.Severity == now.Severity && before.Status == now.Status)
                    result.Unchanged.Add(now);
            }
            else
            {
                result.Added.Add(now);
            }
        }

        // 上一轮剩下没被消费的 = 本轮消失（修复 / 规则未再命中）
        foreach (var q in baselineByKey.Values)
            while (q.Count > 0) result.Removed.Add(q.Dequeue());

        result.Added.Sort(BySeverityThenId);
        result.Removed.Sort(BySeverityThenId);
        result.Unchanged.Sort(BySeverityThenId);
        result.Changed.Sort((a, b) => string.CompareOrdinal(a.Id, b.Id));
        return result;
    }

    private static int BySeverityThenId(SnapshotFinding a, SnapshotFinding b)
    {
        var bySev = b.Severity.CompareTo(a.Severity);   // 严重级降序
        return bySev != 0 ? bySev : string.CompareOrdinal(a.Id, b.Id);
    }
}
