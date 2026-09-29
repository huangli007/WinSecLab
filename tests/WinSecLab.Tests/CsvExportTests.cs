using System.Text;
using WinSecLab.Core.Engines.Reports;
using WinSecLab.Core.Models;

namespace WinSecLab.Tests;

/// <summary>
/// CSV 导出。
///
/// 这类"看起来简单"的导出最容易在细节上翻车：
/// 标题里一个逗号就能把整行列错位，少了 BOM 中文在 Excel 里就是乱码。
/// 所以把这些边界钉进测试。
/// </summary>
public class CsvExportTests : IDisposable
{
    private readonly string _dir;

    public CsvExportTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"wsl-csv-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    private string PathFor(string name) => Path.Combine(_dir, name);

    private static AnalysisResult ResultWith(params Finding[] findings)
    {
        var r = new AnalysisResult { ProjectId = "WS-TEST" };
        r.Findings.AddRange(findings);
        return r;
    }

    [Fact]
    public void ExportFindings_WritesUtf8Bom_SoExcelDoesNotGarbledChinese()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(ResultWith(new Finding { Title = "测试" }), path);

        var bytes = File.ReadAllBytes(path);

        // EF BB BF 是 UTF-8 BOM —— Excel 靠它识别编码，缺了就是乱码
        Assert.True(bytes.Length >= 3);
        Assert.Equal(0xEF, bytes[0]);
        Assert.Equal(0xBB, bytes[1]);
        Assert.Equal(0xBF, bytes[2]);
    }

    [Fact]
    public void ExportFindings_EscapesCommaInField()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(
            ResultWith(new Finding { Title = "标题, 含逗号", Category = "测试" }), path);

        var line = File.ReadAllLines(path)[1];

        // 含逗号的字段必须被引号包裹，否则会串列
        Assert.Contains("\"标题, 含逗号\"", line);
    }

    [Fact]
    public void ExportFindings_EscapesQuoteByDoubling()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(ResultWith(new Finding { Title = "含\"引号\"的标题" }), path);

        var line = File.ReadAllLines(path)[1];

        // RFC 4180：字段内的引号要翻倍
        Assert.Contains("\"含\"\"引号\"\"的标题\"", line);
    }

    [Fact]
    public void ExportFindings_NormalizesNewlineInsideField()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(
            ResultWith(new Finding { Title = "第一行\n第二行", Description = "a\r\nb" }), path);

        var lines = File.ReadAllLines(path);

        // 换行必须被压成空格 —— 否则一条记录会被 Excel 拆成两行
        Assert.Equal(2, lines.Length);   // 表头 + 1 条
        Assert.Contains("第一行 第二行", lines[1]);
    }

    [Fact]
    public void ExportFindings_SortsBySeverityDescending()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(ResultWith(
            new Finding { Title = "低危的", Severity = Severity.Low },
            new Finding { Title = "严重的", Severity = Severity.Critical },
            new Finding { Title = "中危的", Severity = Severity.Medium }), path);

        var lines = File.ReadAllLines(path);

        // 打开 Excel 第一眼就该看到最该处理的
        Assert.Contains("严重的", lines[1]);
        Assert.Contains("中危的", lines[2]);
        Assert.Contains("低危的", lines[3]);
    }

    [Fact]
    public void ExportFindings_UsesChineseSeverityLabel()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(ResultWith(new Finding { Title = "x", Severity = Severity.High }), path);

        var line = File.ReadAllLines(path)[1];

        Assert.Contains("高", line);
        Assert.DoesNotContain("High", line);   // 不该漏出英文枚举名
    }

    [Fact]
    public void ExportFindings_HeaderHasStableColumns()
    {
        var path = PathFor("f.csv");
        CsvExporter.ExportFindings(ResultWith(new Finding { Title = "x" }), path);

        var header = File.ReadAllLines(path)[0];

        // 列数稳定很重要 —— 下游若有脚本按列位置取值，改列序会静默算错
        Assert.Equal(14, header.Split(',').Length);
        Assert.StartsWith("序号,严重级别,标题", header);
    }

    [Fact]
    public void ExportEvidence_WritesRowsForEachEvidence()
    {
        var result = new AnalysisResult { ProjectId = "WS-TEST" };
        result.Evidence.Add(new Evidence { Title = "PE 解析", Source = "builtin.pe", Summary = "节区 3 个" });
        result.Evidence.Add(new Evidence { Title = "YARA 命中", Source = "builtin.yara", Summary = "1 条" });

        var path = PathFor("e.csv");
        CsvExporter.ExportEvidence(result, path);

        var lines = File.ReadAllLines(path);
        Assert.Equal(3, lines.Length);   // 表头 + 2 条
        Assert.Contains("PE 解析", lines[1]);
        Assert.Contains("YARA 命中", lines[2]);
    }

    [Fact]
    public void ExportFindings_EmptyResult_WritesHeaderOnly()
    {
        var path = PathFor("empty.csv");
        CsvExporter.ExportFindings(new AnalysisResult { ProjectId = "WS-EMPTY" }, path);

        var lines = File.ReadAllLines(path);
        Assert.Single(lines);   // 只有表头，不崩
    }
}
