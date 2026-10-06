using System.Text;
using WinSecLab.Core.Engines.Reports;
using WinSecLab.Core.Models;
using WinSecLab.Core.Storage;

namespace WinSecLab.Tests;

/// <summary>
/// 人工复核闭环（§9 人工深入分析）。
///
/// 这条链路的价值全在"写回去还能读出来"：如果状态只存在内存里，
/// 界面看着改了、报告还是旧的，闭环就是假的。所以这里重点钉持久化往返。
/// </summary>
public class FindingReviewTests : IDisposable
{
    private readonly string _dir;

    public FindingReviewTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"wsl-review-{Guid.NewGuid():N}");
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

    private static Finding SampleFinding(string id = "WS-101") => new()
    {
        Id = id,
        ProjectId = "WS-TEST",
        RuleId = "R-SIGN-001",
        Title = "可执行文件缺少有效的数字签名",
        Description = "样本未包含受信任的代码签名。",
        Severity = Severity.Medium,
        Confidence = Confidence.High,
        Category = "代码完整性与签名",
        Source = "内置规则引擎",
        Recommendation = "为发布版本配置代码签名证书。",
    };

    [Fact]
    public void UpdateFindingReview_PersistsStatusAndNote_AcrossReopen()
    {
        var path = Path.Combine(_dir, "review.db");

        var db = new ProjectDatabase(path);
        db.SaveFindings(new[] { SampleFinding() });
        var ok = db.UpdateFindingReview("WS-101", FindingStatus.Confirmed, "已与开发确认，确需修复。");
        Assert.True(ok);

        // 断开连接池，模拟"关掉应用再打开"
        ProjectDatabase.ReleasePools();

        var db2 = new ProjectDatabase(path);
        var f = Assert.Single(db2.GetFindings());
        Assert.Equal(FindingStatus.Confirmed, f.Status);
        Assert.Equal("已与开发确认，确需修复。", f.AnalystNote);
    }

    [Fact]
    public void UpdateFindingReview_BlankNote_StoresNull_NotWhitespace()
    {
        var db = NewDb();
        db.SaveFindings(new[] { SampleFinding() });

        db.UpdateFindingReview("WS-101", FindingStatus.FalsePositive, "   ");

        var f = Assert.Single(db.GetFindings());
        Assert.Equal(FindingStatus.FalsePositive, f.Status);
        // 空白串必须归一为 null，否则报告里会渲染出一个空的"人工复核意见"小节
        Assert.Null(f.AnalystNote);
    }

    [Fact]
    public void UpdateFindingReview_UnknownId_ReturnsFalse()
    {
        var db = NewDb();
        db.SaveFindings(new[] { SampleFinding("WS-101") });

        Assert.False(db.UpdateFindingReview("WS-999", FindingStatus.Confirmed, "x"));
    }

    [Fact]
    public void UpdateFindingReview_DoesNotDisturbOtherFindings()
    {
        var db = NewDb();
        db.SaveFindings(new[] { SampleFinding("WS-101"), SampleFinding("WS-102") });

        db.UpdateFindingReview("WS-101", FindingStatus.Accepted, "业务上接受该风险。");

        var list = db.GetFindings().OrderBy(f => f.Id).ToList();
        Assert.Equal(FindingStatus.Accepted, list[0].Status);
        Assert.Equal(FindingStatus.Open, list[1].Status);
        Assert.Null(list[1].AnalystNote);
    }

    [Fact]
    public void FindingsCsv_IncludesReviewStatusAndNote()
    {
        var result = new AnalysisResult { ProjectId = "WS-TEST" };
        var f = SampleFinding();
        f.Status = FindingStatus.Remediated;
        f.AnalystNote = "已在新版本修复，回归通过。";
        result.Findings.Add(f);

        var csvPath = Path.Combine(_dir, "findings.csv");
        CsvExporter.ExportFindings(result, csvPath);
        var text = File.ReadAllText(csvPath, Encoding.UTF8);

        Assert.Contains("人工复核意见", text);
        Assert.Contains("已整改", text);
        Assert.Contains("已在新版本修复，回归通过。", text);
    }

    [Fact]
    public void FindingStatusText_CoversAllStates()
    {
        Assert.Equal("待处理", new Finding { Status = FindingStatus.Open }.StatusText);
        Assert.Equal("已确认", new Finding { Status = FindingStatus.Confirmed }.StatusText);
        Assert.Equal("误报", new Finding { Status = FindingStatus.FalsePositive }.StatusText);
        Assert.Equal("接受风险", new Finding { Status = FindingStatus.Accepted }.StatusText);
        Assert.Equal("已整改", new Finding { Status = FindingStatus.Remediated }.StatusText);
    }
}
