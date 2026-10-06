using System.Text.RegularExpressions;
using WinSecLab.Core.Engines.Reports;
using WinSecLab.Core.Models;

namespace WinSecLab.Tests;

/// <summary>
/// 报告折叠显示。
///
/// 折叠存在的唯一理由是「正文精简 + 附录全量」——但它同时引入了两个致命风险：
///  1. 用了 <c>&lt;details&gt;</c> 而非 checkbox hack：浏览器打印时不展开未 open 的
///     details，PDF 会**静默丢明细**（取证报告不可接受）；
///  2. 折叠块结构不平衡（FoldStart 没有对应 FoldEnd），会把后面所有章节吞进面板里。
/// 这组测试把这两条钉死，避免后续改动把已有结论改坏。
/// </summary>
public class ReportFoldTests
{
    /// <summary>造一个最小可用的 AnalysisResult（含 PE 导入项，才能触发导入清单折叠）。</summary>
    private static AnalysisResult Sample(int importModuleCount = 30, int evidenceCount = 5)
    {
        var pe = new PeImageInfo
        {
            IsValidPe = true,
            Architecture = "x64",
            Subsystem = "WindowsGui",
        };
        pe.Sections.Add(new PeSection
        {
            Name = ".text", Characteristics = 0x60000020, RawSize = 1024, Entropy = 6.5,
        });
        for (var i = 0; i < importModuleCount; i++)
        {
            var m = new PeImportModule { ModuleName = i == 0 ? "USER32.dll" : $"mod{i}.dll" };
            // FunctionCount 是 Functions.Count 的派生属性，必须往里加函数而非赋值
            for (var f = 0; f < 3; f++) m.Functions.Add(new PeImportFunction { Name = $"Fn{i}_{f}" });
            pe.Imports.Add(m);
        }

        var r = new AnalysisResult { Pe = pe };
        for (var i = 0; i < evidenceCount; i++)
            r.Evidence.Add(new Evidence
            {
                Id = $"EV-{i:D3}", Kind = EvidenceKind.ToolOutput, Title = $"证据 {i}", Source = "test",
            });
        return r;
    }

    private static ReportOptions Opts() => new() { OutputDirectory = Path.GetTempPath() };

    /// <summary>
    /// 剥离 &lt;style&gt; 块后的正文 HTML。
    /// 必要性：CSS 注释里为了解释设计取舍会写「为什么不用 &lt;details&gt;」这类文字，
    /// 直接对整页断言会把这些**说明文字**误判成实际标签；
    /// 目录（TOC）里也会重复出现章节标题，干扰按标题回溯。
    /// </summary>
    private static string BodyOf(string html) =>
        Regex.Replace(html, @"<style>.*?</style>", "", RegexOptions.Singleline);

    /// <summary>
    /// 找出包含指定标题的折叠块，返回其 checkbox 起始标签（含 checked 判定）。
    /// 定位锚点是折叠头里的 <c>&lt;span class="fold-title"&gt;</c> —— 章节标题在目录里
    /// 也会出现一次，只按标题文本查找会锚到目录项上。
    /// </summary>
    private static string ToggleTagBefore(string html, string title)
    {
        var body = BodyOf(html);
        var anchor = $"<span class=\"fold-title\">{title}";
        var idx = body.IndexOf(anchor, StringComparison.Ordinal);
        Assert.True(idx > 0, $"报告中找不到折叠标题：{title}");

        var inputStart = body.LastIndexOf("class=\"fold-toggle\"", idx, StringComparison.Ordinal);
        Assert.True(inputStart > 0, $"「{title}」之前找不到折叠输入框");

        // 回到该标签的 '<'，再找它的 '>'
        var tagOpen = body.LastIndexOf('<', inputStart);
        var tagClose = body.IndexOf('>', inputStart);
        Assert.True(tagOpen >= 0 && tagClose > tagOpen, "折叠输入框标签结构异常");
        return body[tagOpen..(tagClose + 1)];
    }

    // ── HTML：折叠机制 ────────────────────────────────────────────────

    [Fact]
    public void Html_NeverUsesDetailsTag_ForFolding()
    {
        // <details> 在打印时不会展开（未 open 的），会导致 PDF 丢明细。
        // 折叠必须走 checkbox hack（.fold > input.fold-toggle + label.fold-head）。
        var html = ReportEngine.BuildHtml(Sample(), Opts());

        Assert.Contains("class=\"fold\"", html);
        Assert.Contains("class=\"fold-toggle\"", html);
        Assert.Contains("class=\"fold-head\"", html);
        Assert.Contains("class=\"fold-body\"", html);

        // 正文里不允许出现 <details> 标签（Markdown 产物才用 details）。
        // 剥离 <style> 再断言：CSS 注释里为解释设计取舍会提到这个词。
        Assert.DoesNotContain("<details", BodyOf(html));
    }

    [Fact]
    public void Html_PrintMediaQuery_ExpandsAllFolds()
    {
        // 打印时强制展开 + 隐藏折叠头，是「PDF 不丢明细」的唯一保障
        var html = ReportEngine.BuildHtml(Sample(), Opts());

        Assert.Contains("@media print", html);
        Assert.Contains(".fold > .fold-body { display: block", html);
        Assert.Contains(".fold > label.fold-head { display: none", html);
    }

    [Fact]
    public void Html_FoldBlocksAreBalanced()
    {
        // 每个折叠块由 FoldEnd 的 </div></div> 收尾，数量不应少于 FoldStart 数
        var html = ReportEngine.BuildHtml(Sample(), Opts());

        var foldCount = Regex.Matches(html, "class=\"fold\"").Count;
        Assert.True(foldCount > 0, "报告应至少包含一个折叠块");

        var foldEnds = Regex.Matches(html, "</div></div>").Count;
        Assert.True(foldEnds >= foldCount,
            $"折叠块未配对：fold={foldCount}，FoldEnd={foldEnds}");
    }

    [Fact]
    public void Html_FoldBadge_ShowsItemCount()
    {
        var html = ReportEngine.BuildHtml(Sample(importModuleCount: 42), Opts());

        // 徽标里应出现明细条数，读者不用展开就知道有多少内容
        Assert.Contains("fold-badge", html);
        Assert.Contains("42 项", html);
    }

    [Fact]
    public void Html_DefaultCollapsed_ForLargeTables()
    {
        // 56 行这种大表默认必须收起，否则正文又被撑爆
        var html = ReportEngine.BuildHtml(Sample(importModuleCount: 56), Opts());

        var tag = ToggleTagBefore(html, "全部 56 个导入模块明细");
        Assert.DoesNotContain("checked", tag);
    }

    [Fact]
    public void Html_SmallTables_DefaultExpanded()
    {
        // 小节区表（8 行以内）默认展开：内容不多时收起反而多一次点击
        var html = ReportEngine.BuildHtml(Sample(), Opts());

        var tag = ToggleTagBefore(html, "节区明细");
        Assert.Contains("checked", tag);
    }

    // ── HTML：宽表横向滚动 ────────────────────────────────────────────

    [Fact]
    public void Html_WideTables_WrappedInScrollContainer()
    {
        // ≥6 列的表必须套 .table-scroll，否则窄屏 / A4 下挤成一团或撑破页宽
        var html = ReportEngine.BuildHtml(Sample(), Opts());

        Assert.Contains("class=\"table-scroll\"", html);
        // 滚动容器后面紧跟的就是 data 表
        var idx = html.IndexOf("class=\"table-scroll\"", StringComparison.Ordinal);
        var next = html[idx..Math.Min(html.Length, idx + 400)];
        Assert.Contains("class=\"data\"", next);
    }

    [Fact]
    public void Html_PrintMediaQuery_DisablesScroll()
    {
        // 打印没有滚动交互，宽表必须完整落在页面上
        var html = ReportEngine.BuildHtml(Sample(), Opts());
        Assert.Contains(".table-scroll { overflow-x: visible; }", html);
    }

    [Fact]
    public void Html_NarrowTables_NotWrapped()
    {
        // 4 列表不需要滚动容器（加了只多一层 DOM，无收益）
        var html = ReportEngine.BuildHtml(Sample(evidenceCount: 3), Opts());
        var idx = html.IndexOf("证据 ID", StringComparison.Ordinal);
        Assert.True(idx > 0);
        // 向前回溯一小段，确认这张 5 列表前面没有 table-scroll
        var before = html[Math.Max(0, idx - 300)..idx];
        var lastScroll = before.LastIndexOf("class=\"table-scroll\"", StringComparison.Ordinal);
        var lastTable = before.LastIndexOf("<table class=\"data\"", StringComparison.Ordinal);
        // 若最近的一个 table 在最近一个 scroll 之后，说明这张表没被包裹
        Assert.True(lastTable > lastScroll || lastScroll < 0);
    }

    // ── Markdown：折叠用 details，且结构闭合 ──────────────────────────

    [Fact]
    public void Markdown_UsesDetails_AndBalanced()
    {
        var md = ReportEngine.BuildMarkdown(Sample(), Opts());

        var opens = Regex.Matches(md, "<details").Count;
        var closes = Regex.Matches(md, "</details>").Count;

        Assert.True(opens > 0, "Markdown 应包含折叠块");
        Assert.Equal(opens, closes);
    }

    [Fact]
    public void Markdown_SectionDetail_ExpandedByDefault()
    {
        var md = ReportEngine.BuildMarkdown(Sample(), Opts());
        Assert.Contains("<details open><summary>节区明细", md);
    }

    [Fact]
    public void Markdown_ImportList_CollapsedByDefault()
    {
        var md = ReportEngine.BuildMarkdown(Sample(importModuleCount: 56), Opts());

        var idx = md.IndexOf("全部 56 个导入模块明细", StringComparison.Ordinal);
        Assert.True(idx > 0);

        var tagStart = md.LastIndexOf("<details", idx, StringComparison.Ordinal);
        var tag = md[tagStart..(md.IndexOf('>', tagStart) + 1)];
        Assert.DoesNotContain("open", tag);
    }

    // ── 单元层面：折叠基础设施输出契约 ────────────────────────────────

    [Fact]
    public void FoldStart_EscapesTitle()
    {
        // 标题里出现 < > & 会破坏结构（甚至注入），必须转义
        var html = ReportEngine.FoldStart("<script>alert(1)</script>");
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void FoldStart_OpenFlag_ControlsChecked()
    {
        Assert.Contains("checked", ReportEngine.FoldStart("t", null, open: true));
        Assert.DoesNotContain("checked", ReportEngine.FoldStart("t", null, open: false));
    }

    [Fact]
    public void FoldStart_NullBadge_OmitsBadgeElement()
    {
        Assert.DoesNotContain("fold-badge", ReportEngine.FoldStart("t", null, false));
        Assert.Contains("fold-badge", ReportEngine.FoldStart("t", "5 项", false));
    }

    [Fact]
    public void FoldStartEnd_ProducesBalancedMarkup()
    {
        // FoldStart 开 2 个 div（容器 + body），FoldEnd 收 2 个
        var start = ReportEngine.FoldStart("t");
        var end = ReportEngine.FoldEnd();
        Assert.Equal(2, Regex.Matches(start, "<div").Count);
        Assert.Equal(2, Regex.Matches(end, "</div>").Count);
    }

    [Fact]
    public void TableScrollStartEnd_WrapsContainer()
    {
        Assert.Equal("<div class=\"table-scroll\">", ReportEngine.TableScrollStart());
        Assert.Contains("</div>", ReportEngine.TableScrollEnd());
    }
}
