using WinSecLab.Core.Engines.Reports;

namespace WinSecLab.Tests;

/// <summary>
/// PDF 导出。
///
/// 走 Edge 无头打印，外部依赖重，所以分两层测：
///  · 这一层测**纯逻辑与边界**（文件不存在、路径处理、Edge 定位），不真跑 Edge；
///  · 真正的端到端渲染由 Smoke 标记的测试在装了 Edge 的机器上验证。
///
/// 之前踩的坑：给 Edge 重定向 stdout/stderr 却不读 → 管道满 → 卡死。
/// 现在实现里干脆不重定向，并用"轮询文件出现"替代"等进程退出"。
/// </summary>
public class PdfExportTests : IDisposable
{
    private readonly string _dir;

    public PdfExportTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"wsl-pdf-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task ExportAsync_MissingHtml_FailsFast()
    {
        var html = Path.Combine(_dir, "不存在.html");
        var pdf = Path.Combine(_dir, "out.pdf");

        var r = await PdfExporter.ExportAsync(html, pdf);

        Assert.False(r.Success);
        Assert.Contains("不存在", r.Error);
        Assert.False(File.Exists(pdf));   // 不该留下半截文件
    }

    [Fact]
    public void FindEdge_ReturnsExistingPath_WhenInstalled()
    {
        var edge = PdfExporter.FindEdge();

        // Windows 10/11 自带 Edge；若真没有就跳过（不代表实现错）
        if (edge is null) return;

        Assert.True(File.Exists(edge));
        Assert.EndsWith("msedge.exe", edge, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportAsync_WithHtml_RendersPdf_WhenEdgePresent()
    {
        // 端到端冒烟：本机没装 Edge 就跳过
        if (PdfExporter.FindEdge() is null) return;

        var html = Path.Combine(_dir, "报告.html");
        var pdf = Path.Combine(_dir, "报告.pdf");
        await File.WriteAllTextAsync(html,
            "<html><head><meta charset=\"utf-8\"></head><body><h1>WinSecLab 报告测试</h1>" +
            "<p>中文与英文 mixed content 1.5MB 内应正常渲染。</p></body></html>");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var r = await PdfExporter.ExportAsync(html, pdf, timeoutMs: 60_000, ct: cts.Token);

        Assert.True(r.Success, r.Error);
        Assert.True(File.Exists(pdf));
        Assert.True(new FileInfo(pdf).Length > 0);

        // PDF 魔数 %PDF- ：确认真是 PDF，而不是 Edge 写的错误页
        var head = new byte[5];
        await using (var fs = File.OpenRead(pdf))
        {
            var read = 0;
            while (read < head.Length)
            {
                var n = await fs.ReadAsync(head.AsMemory(read));
                if (n == 0) break;
                read += n;
            }
            Assert.Equal(head.Length, read);
        }
        Assert.Equal("%PDF-", System.Text.Encoding.ASCII.GetString(head));
    }
}
