using WinSecLab.Core.Engines.Analysis;
using WinSecLab.Core.Models;
using WinSecLab.Core.Storage;

namespace WinSecLab.Tests;

/// <summary>
/// 会话快照与基线对比（回归测试支撑）。
///
/// 这条链路的价值在于「第二轮能看出跟第一轮的差异」：
/// 快照存不下就退化成"每轮都是第一轮"，对比算法跑错就会把修复报成回归。
/// 所以重点钉两件事：快照持久化往返、diff 四类判定（新增/消失/变化/持续）。
/// </summary>
public class RunComparerTests : IDisposable
{
    private readonly string _dir;

    public RunComparerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"wsl-snap-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        ProjectDatabase.ReleasePools();
        try { Directory.Delete(_dir, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    private ProjectDatabase NewDb() =>
        new(Path.Combine(_dir, $"db-{Guid.NewGuid():N}.db"));

    private static Finding F(string id, string ruleId, string title,
        Severity severity = Severity.Medium, FindingStatus status = FindingStatus.Open) => new()
    {
        Id = id,
        RuleId = ruleId,
        Title = title,
        Severity = severity,
        Status = status,
        ProjectId = "WS-TEST",
        Category = "测试类别",
    };

    private static AnalysisResult Result(params Finding[] findings)
    {
        var r = new AnalysisResult { ProjectId = "WS-TEST" };
        r.Findings.AddRange(findings);
        return r;
    }

    // ───────────────────────── Capture ─────────────────────────

    [Fact]
    public void Capture_SortsFindingsStablyById()
    {
        // 同一结果无论传入顺序如何，快照内部顺序必须一致 —— 否则字节比对与测试都不稳定
        var a = RunComparer.Capture(Result(
            F("WS-103", "R-003", "丙"),
            F("WS-101", "R-001", "甲"),
            F("WS-102", "R-002", "乙")));

        Assert.Equal(new[] { "WS-101", "WS-102", "WS-103" }, a.Findings.Select(f => f.Id));
    }

    [Fact]
    public void Capture_ExtractsCountersAndTargetFingerprint()
    {
        var result = new AnalysisResult
        {
            ProjectId = "WS-TEST",
            Project = new TestProject
            {
                Profile = TestProfileKind.FullSecurityAssessment,
                Target = new TargetSummary { Sha256 = "ABCDEF", FileVersion = "1.2.3" },
            },
        };
        result.Findings.Add(F("WS-101", "R-001", "甲", Severity.High));
        result.Findings.Add(F("WS-102", "R-002", "乙", Severity.High));
        result.Events.Add(new MonitorEvent { IsSuspicious = true });
        result.Events.Add(new MonitorEvent { IsSuspicious = false });
        result.Connections.Add(new NetworkConnection());
        result.Evidence.Add(new Evidence { Id = "EV-1" });

        var snap = RunComparer.Capture(result, "SN-session");

        Assert.Equal("WS-TEST", snap.ProjectId);
        Assert.Equal("SN-session", snap.SessionId);
        Assert.Equal(TestProfileKind.FullSecurityAssessment, snap.Profile);
        Assert.Equal("ABCDEF", snap.TargetSha256);
        Assert.Equal("1.2.3", snap.TargetVersion);
        Assert.Equal(2, snap.EventCount);
        Assert.Equal(1, snap.SuspiciousEventCount);
        Assert.Equal(1, snap.ConnectionCount);
        Assert.Equal(1, snap.EvidenceCount);
        Assert.Equal(2, snap.TotalFindings);
        Assert.Equal(2, snap.HighCount);
    }

    // ───────────────────────── Compare ─────────────────────────

    [Fact]
    public void Compare_NoBaseline_ReportsFirstRound()
    {
        var current = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));

        var cmp = RunComparer.Compare(null, current);

        Assert.False(cmp.HasBaseline);
        Assert.Empty(cmp.Added);
        Assert.Contains("第一轮", cmp.Verdict);
    }

    [Fact]
    public void Compare_DetectsAddedRemovedUnchanged()
    {
        var baseline = RunComparer.Capture(Result(
            F("WS-101", "R-001", "一直存在"),
            F("WS-102", "R-002", "本轮修复")));

        var current = RunComparer.Capture(Result(
            F("WS-101", "R-001", "一直存在"),
            F("WS-103", "R-003", "本轮新增")));

        var cmp = RunComparer.Compare(baseline, current);

        Assert.True(cmp.HasBaseline);
        Assert.Equal("本轮新增", Assert.Single(cmp.Added).Title);
        Assert.Equal("本轮修复", Assert.Single(cmp.Removed).Title);
        Assert.Equal("一直存在", Assert.Single(cmp.Unchanged).Title);
        Assert.Empty(cmp.Changed);
        Assert.Equal(0, cmp.DeltaFindings);
    }

    [Fact]
    public void Compare_MatchesByRuleIdAndTitle_NotById()
    {
        // 重新分析时发现项 ID 可能被重新编号 —— 若按 ID 匹配会把同一条报成"消失+新增"
        var baseline = RunComparer.Capture(Result(F("WS-101", "R-001", "签名缺失")));
        var current = RunComparer.Capture(Result(F("WS-201", "R-001", "签名缺失")));

        var cmp = RunComparer.Compare(baseline, current);

        Assert.Empty(cmp.Added);
        Assert.Empty(cmp.Removed);
        Assert.Single(cmp.Unchanged);
    }

    [Fact]
    public void Compare_DetectsSeverityAndStatusChanges()
    {
        var baseline = RunComparer.Capture(Result(
            F("WS-101", "R-001", "规则A", Severity.Low, FindingStatus.Open),
            F("WS-102", "R-002", "规则B", Severity.Medium, FindingStatus.Open)));

        var current = RunComparer.Capture(Result(
            F("WS-101", "R-001", "规则A", Severity.High, FindingStatus.Open),
            F("WS-102", "R-002", "规则B", Severity.Medium, FindingStatus.Remediated)));

        var cmp = RunComparer.Compare(baseline, current);

        Assert.Empty(cmp.Added);
        Assert.Empty(cmp.Removed);
        Assert.Empty(cmp.Unchanged);
        Assert.Equal(2, cmp.Changed.Count);

        var sev = Assert.Single(cmp.Changed, c => c.Field == "严重级");
        Assert.Equal("低", sev.Before);
        Assert.Equal("高", sev.After);

        var st = Assert.Single(cmp.Changed, c => c.Field == "处理状态");
        Assert.Equal("待处理", st.Before);
        Assert.Equal("已整改", st.After);
    }

    [Fact]
    public void Compare_DuplicateKeyConsumesInOrder_NoFalseAdded()
    {
        // 同一规则命中多个对象时会产生多条同键发现，必须一一配对消费
        var baseline = RunComparer.Capture(Result(
            F("WS-101", "R-001", "重复项"),
            F("WS-102", "R-001", "重复项")));

        var current = RunComparer.Capture(Result(F("WS-101", "R-001", "重复项")));

        var cmp = RunComparer.Compare(baseline, current);

        Assert.Empty(cmp.Added);
        Assert.Single(cmp.Removed);      // 少了一条
        Assert.Single(cmp.Unchanged);    // 配对掉一条
    }

    [Fact]
    public void Compare_TargetChanged_TrueWhenHashesDiffer()
    {
        var baseline = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));
        baseline.TargetSha256 = "AAAA";
        var current = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));
        current.TargetSha256 = "BBBB";

        var cmp = RunComparer.Compare(baseline, current);

        Assert.True(cmp.TargetChanged);
    }

    [Fact]
    public void Compare_VerdictSummarizesCounts()
    {
        var baseline = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));
        var current = RunComparer.Capture(Result(
            F("WS-101", "R-001", "甲"),
            F("WS-102", "R-002", "乙")));

        var cmp = RunComparer.Compare(baseline, current);

        Assert.Contains("新增 1 项", cmp.Verdict);
        Assert.Equal(1, cmp.DeltaFindings);
    }

    [Fact]
    public void Compare_IdenticalSnapshots_ReportsNoChange()
    {
        var a = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));
        var b = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));

        var cmp = RunComparer.Compare(a, b);

        Assert.Equal("与上次相比无变化。", cmp.Verdict);
    }

    // ───────────────────── 快照持久化（数据库） ─────────────────────

    [Fact]
    public void Snapshot_PersistsAndReloads_AcrossReopen()
    {
        var path = Path.Combine(_dir, "snap.db");

        var db = new ProjectDatabase(path);
        var snap = RunComparer.Capture(Result(
            F("WS-101", "R-001", "甲", Severity.High),
            F("WS-102", "R-002", "乙")));
        snap.Id = "WS-TEST-SN20261006-120000";
        db.SaveSnapshot(snap);

        ProjectDatabase.ReleasePools();

        var db2 = new ProjectDatabase(path);
        var loaded = Assert.Single(db2.GetSnapshots());
        Assert.Equal(snap.Id, loaded.Id);
        Assert.Equal(2, loaded.TotalFindings);
        Assert.Equal(1, loaded.HighCount);
        Assert.Equal("WS-101", loaded.Findings[0].Id);
    }

    [Fact]
    public void GetPreviousSnapshot_ExcludesCurrent_ReturnsEarlierRound()
    {
        var db = NewDb();
        var first = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));
        first.Id = "WS-TEST-SN-1";
        first.CapturedAt = new DateTime(2026, 10, 6, 12, 0, 0);
        db.SaveSnapshot(first);

        var second = RunComparer.Capture(Result(F("WS-101", "R-001", "甲"), F("WS-102", "R-002", "乙")));
        second.Id = "WS-TEST-SN-2";
        second.CapturedAt = new DateTime(2026, 10, 6, 13, 0, 0);
        db.SaveSnapshot(second);

        // 最新一份是 second
        Assert.Equal("WS-TEST-SN-2", db.GetLatestSnapshot()!.Id);

        // 排除本轮后应拿到 first（回归对比拿的正是这一份）
        Assert.Equal("WS-TEST-SN-1", db.GetPreviousSnapshot("WS-TEST-SN-2")!.Id);
    }

    [Fact]
    public void SaveSnapshot_IsIdempotentById()
    {
        var db = NewDb();
        var snap = RunComparer.Capture(Result(F("WS-101", "R-001", "甲")));
        snap.Id = "WS-TEST-SN-FIXED";
        db.SaveSnapshot(snap);

        snap.Findings.Add(new SnapshotFinding { Id = "WS-102", RuleId = "R-002", Title = "乙" });
        db.SaveSnapshot(snap);   // 同 ID 覆盖写

        var loaded = Assert.Single(db.GetSnapshots());
        Assert.Equal(2, loaded.TotalFindings);
    }
}
