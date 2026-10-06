using System.Text.RegularExpressions;
using WinSecLab.Core.Engines.Reports;
using WinSecLab.Core.Models;

namespace WinSecLab.Tests;

/// <summary>
/// 悬浮侧边目录（HTML 报告右侧导航）。
///
/// 需求是「滚动到看不见最上方目录时，右侧出现可点击跳转的目录」。
/// 这里只测**生成出的静态契约**（DOM 结构、锚点、脚本存在性、打印隐藏）——
/// 滚动显隐与点击跳转依赖真实浏览器，由 Playwright 冒烟脚本覆盖。
///
/// 钉死的几个易错点：
///  1. 侧栏章节与顶部目录必须**同源同序**，否则会出现「顶部有 10 章、侧栏 9 章」；
///  2. 每个 data-target 都必须能找到对应 id 的元素，否则点击静默无反应；
///  3. 内联脚本里 C# 转义写错会输出成字面 <c>{{top:0}}</c>（非法 JS，按钮失效）；
///  4. 打印时必须隐藏，否则会印在 PDF 每一页上。
/// </summary>
public class ReportSideTocTests
{
    private static AnalysisResult Sample()
    {
        var pe = new PeImageInfo { IsValidPe = true, Architecture = "x64", Subsystem = "WindowsGui" };
        pe.Sections.Add(new PeSection { Name = ".text", RawSize = 512, Entropy = 6.2 });
        return new AnalysisResult { Pe = pe };
    }

    private static string Html() =>
        ReportEngine.BuildHtml(Sample(), new ReportOptions { OutputDirectory = Path.GetTempPath() });

    [Fact]
    public void SideToc_Rendered_WithId()
    {
        var html = Html();
        Assert.Contains("id=\"side-toc\"", html);
        Assert.Contains("class=\"side-toc\"", html);
    }

    [Fact]
    public void SideToc_HasOneLinkPerSection_TenChapters()
    {
        // 报告固定 10 章；侧栏链接数必须与之相等
        var html = Html();
        var targets = Regex.Matches(html, "id=\"side-toc\".*?</nav>", RegexOptions.Singleline);
        Assert.Single(targets);

        var links = Regex.Matches(targets[0].Value, "data-target=\"([^\"]+)\"");
        Assert.Equal(10, links.Count);
    }

    [Fact]
    public void SideToc_TargetsMatchTopToc_AndSameOrder()
    {
        // 侧栏与顶部目录同源同序：抽出两者的章节顺序做全等比较
        var html = Html();

        var top = Regex.Match(html, "<nav class=\"toc\">.*?</nav>", RegexOptions.Singleline).Value;
        var topHrefs = Regex.Matches(top, "href=\"#(sec-[^\"]+)\"")
            .Select(m => m.Groups[1].Value).ToList();

        var side = Regex.Match(html, "id=\"side-toc\".*?</nav>", RegexOptions.Singleline).Value;
        var sideTargets = Regex.Matches(side, "data-target=\"(sec-[^\"]+)\"")
            .Select(m => m.Groups[1].Value).ToList();

        Assert.Equal(topHrefs.Count, sideTargets.Count);
        Assert.Equal(topHrefs, sideTargets);
    }

    [Fact]
    public void SideToc_EveryTarget_HasMatchingAnchor()
    {
        // 跳转目标必须真实存在，否则点击没反应且很难察觉
        var html = Html();
        var side = Regex.Match(html, "id=\"side-toc\".*?</nav>", RegexOptions.Singleline).Value;

        foreach (Match m in Regex.Matches(side, "data-target=\"([^\"]+)\""))
        {
            var id = m.Groups[1].Value;
            Assert.Contains($"id=\"{id}\"", html);
        }
    }

    [Fact]
    public void SideToc_VisibleLogic_IsDrivenByIntersectionObserver()
    {
        // 纯 CSS 感知不到"另一个元素是否在视口里"，必须靠 JS 切换类名
        var html = Html();
        Assert.Contains("IntersectionObserver", html);
        Assert.Contains("is-visible", html);
        Assert.Contains("nav.toc", html);      // 观察对象是顶部目录
    }

    [Fact]
    public void SideToc_Script_HasNoUnescapedPlaceholder()
    {
        // C# 拼字符串时多写一层花括号会输出字面 {{...}}，成为非法 JS。
        // 这类错误编译期不报、肉眼也容易滑过，必须由测试兜住。
        var html = Html();
        Assert.DoesNotContain("{{", html);
        Assert.DoesNotContain("}}", html);
    }

    [Fact]
    public void SideToc_BackToTop_IsValidJsCall()
    {
        var html = Html();
        var m = Regex.Match(html, "onclick=\"([^\"]*)\"");
        Assert.True(m.Success, "侧栏应有「回到顶部」按钮");
        Assert.Contains("window.scrollTo(", m.Groups[1].Value);
        Assert.Contains("top:0", m.Groups[1].Value.Replace(" ", ""));
    }

    [Fact]
    public void SideToc_HiddenWhenPrinting()
    {
        // 悬浮件必须打印时隐藏，否则每页都印一个导航框
        var html = Html();
        var print = Regex.Match(html, "@media print\\s*\\{.*?\\n\\s*\\}", RegexOptions.Singleline).Value;
        Assert.Contains(".side-toc { display: none !important; }", print);
    }

    [Fact]
    public void SideToc_HiddenOnNarrowViewport()
    {
        // 正文容器 1200px，视口不够宽时侧栏会压住正文 → 必须让位
        var html = Html();
        Assert.Contains("max-width: 1499px", html);
    }

    [Fact]
    public void SideToc_FixedPositioning_AndSlideIn()
    {
        var html = Html();
        var css = Regex.Match(html, "\\.side-toc \\{[^}]+\\}", RegexOptions.Singleline).Value;

        Assert.Contains("position: fixed", css);
        Assert.Contains("visibility: hidden", css);   // 初始不可见
    }

    [Fact]
    public void SideToc_CurrentSection_HighlightStyle_Defined()
    {
        var html = Html();
        Assert.Contains("a.is-current", html);
        Assert.Contains("classList.add('is-current')", html);
    }

    [Fact]
    public void SideToc_Script_PlacedBeforeBodyClose()
    {
        // 脚本要能找到 #side-toc，必须出现在它之后
        var html = Html();
        var sideIdx = html.IndexOf("id=\"side-toc\"", StringComparison.Ordinal);
        var scriptIdx = html.IndexOf("<script>", StringComparison.Ordinal);
        var bodyEnd = html.IndexOf("</body>", StringComparison.Ordinal);

        Assert.True(sideIdx > 0 && scriptIdx > sideIdx);
        Assert.True(bodyEnd > scriptIdx);
    }
}
