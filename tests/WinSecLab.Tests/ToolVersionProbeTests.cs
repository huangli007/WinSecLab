using System.Text;
using WinSecLab.Core.Plugins;

namespace WinSecLab.Tests;

/// <summary>
/// 外部工具版本探测的回归测试。
///
/// 这组测试都来自真机踩坑，不是凭空构造：
/// - Sysinternals 工具的 EULA 页会被误当成版本号（Process Explorer 曾显示 "SYSINTERNALS SOFTWARE LICENSE TERMS"）
/// - 同一套 Sysinternals 工具编码并不统一（sigcheck UTF-16LE / strings UTF-8），硬编码任一种都会乱码
/// - 纯 GUI 工具（procexp）的 /? 会弹窗口而非打印，只能读 PE 版本资源
/// </summary>
[Collection(ExternalProcess.Name)]
public class ToolVersionProbeTests
{
    // ---------- PickVersionLine：从输出里挑版本行 ----------

    [Fact]
    public void PickVersionLine_SysinternalsCliHeader_PicksVersionLine()
    {
        var text = "Sigcheck v2.92 - File version and signature viewer\nCopyright (C) 2004-2026 Mark Russinovich\n";
        Assert.Equal("Sigcheck v2.92 - File version and signature viewer", ExternalToolLocator.PickVersionLine(text));
    }

    [Fact]
    public void PickVersionLine_EulaPage_IsSkipped()
    {
        // procexp 未加 -accepteula 时的真实输出形态：先吐授权页
        var text =
            "SYSINTERNALS SOFTWARE LICENSE TERMS\n" +
            "These license terms are an agreement between you and Microsoft Corporation.\n" +
            "By using this software you accept these terms.\n";
        var picked = ExternalToolLocator.PickVersionLine(text);
        Assert.NotNull(picked);
        Assert.DoesNotContain("LICENSE TERMS", picked, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PickVersionLine_UsageBanner_IsSkipped()
    {
        var text = "Usage: yara [OPTIONS]\n  4.5.5\n";
        Assert.Equal("4.5.5", ExternalToolLocator.PickVersionLine(text));
    }

    [Fact]
    public void PickVersionLine_BareVersionNumber_IsAccepted()
    {
        // yara64 --version 只输出裸版本号，不带 "v" 前缀
        Assert.Equal("4.5.5", ExternalToolLocator.PickVersionLine("4.5.5\n"));
    }

    [Fact]
    public void PickVersionLine_EmptyText_ReturnsNull()
    {
        Assert.Null(ExternalToolLocator.PickVersionLine(""));
        Assert.Null(ExternalToolLocator.PickVersionLine("\r\n\r\n   \r\n"));
    }

    [Fact]
    public void PickVersionLine_StripsBomAndNul()
    {
        var text = "\uFEFF\0  Strings v2.54 - Search for ANSI and Unicode strings\r\n";
        Assert.Equal("Strings v2.54 - Search for ANSI and Unicode strings", ExternalToolLocator.PickVersionLine(text));
    }

    // ---------- DecodeToolOutput：编码自动嗅探 ----------

    [Fact]
    public void DecodeToolOutput_Utf16Le_SigcheckStyle()
    {
        // "Sigcheck v2.92" 的 UTF-16LE 字节，奇数字节为 0x00
        var raw = Encoding.Unicode.GetBytes("Sigcheck v2.92");
        var decoded = ExternalToolLocator.DecodeToolOutput(raw);
        Assert.Equal("Sigcheck v2.92", decoded);
        // 解码正确就不该残留 NUL（按 UTF-8 误读时会变成 "S i g c h e c k" 式的交错串）
        Assert.DoesNotContain('\0', decoded);
    }

    [Fact]
    public void DecodeToolOutput_Utf8_StringsStyle()
    {
        // strings64 输出是 UTF-8/ASCII，奇数字节基本不为 0
        var raw = Encoding.UTF8.GetBytes("Strings v2.54 - Search for ANSI and Unicode strings");
        Assert.Equal("Strings v2.54 - Search for ANSI and Unicode strings",
            ExternalToolLocator.DecodeToolOutput(raw));
    }

    [Fact]
    public void DecodeToolOutput_Utf8WithChinese_IsNotMangled()
    {
        var raw = Encoding.UTF8.GetBytes("工具版本 4.5.5");
        Assert.Equal("工具版本 4.5.5", ExternalToolLocator.DecodeToolOutput(raw));
    }

    [Fact]
    public void DecodeToolOutput_Utf16LeBom_IsHonoured()
    {
        var raw = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("YARA 4.5.5")).ToArray();
        Assert.Equal("YARA 4.5.5", ExternalToolLocator.DecodeToolOutput(raw));
    }

    [Fact]
    public void DecodeToolOutput_Empty_ReturnsEmpty()
    {
        Assert.Equal("", ExternalToolLocator.DecodeToolOutput(Array.Empty<byte>()));
    }

    // ---------- 目录描述符的探测策略标注 ----------

    [Fact]
    public void Catalog_SysinternalsGuiTools_UseFileResourceOnly()
    {
        // Procexp / Procmon 是 GUI 程序：起进程会弹窗且被安全软件拦，必须只读 PE 版本资源
        foreach (var id in new[] { "procexp", "procmon" })
        {
            var d = ExternalToolCatalog.Get(id);
            Assert.NotNull(d);
            Assert.True(d!.AlwaysProbeFromFileResource, $"{id} 应标记为只读文件版本资源");
        }
    }

    [Fact]
    public void Catalog_SysinternalsConsoleTools_AcceptEulaForVersion()
    {
        // sigcheck / strings 是控制台程序，但首次运行先弹 EULA 页，必须带 -accepteula
        foreach (var id in new[] { "sigcheck", "strings" })
        {
            var d = ExternalToolCatalog.Get(id);
            Assert.NotNull(d);
            Assert.True(d!.AcceptEulaForVersion, $"{id} 版本探测应带 -accepteula");
            Assert.False(d.AlwaysProbeFromFileResource, $"{id} 不应强制只读文件版本资源");
        }
    }

    [Fact]
    public void Catalog_NonSysinternalsTools_DoNotAcceptEula()
    {
        foreach (var id in new[] { "yara", "ghidra", "ilspy", "dependencies", "wireshark", "x64dbg" })
        {
            var d = ExternalToolCatalog.Get(id);
            Assert.NotNull(d);
            Assert.False(d!.AcceptEulaForVersion, $"{id} 不是 Sysinternals 工具，不该加 -accepteula");
            Assert.False(d.AlwaysProbeFromFileResource);
        }
    }

    [Fact]
    public void Catalog_AllDescriptors_HaveVersionStrategyConsistent()
    {
        // 两个标记互斥：GUI 工具在读文件资源就已返回，再带 -accepteula 没有意义
        foreach (var d in ExternalToolCatalog.All)
        {
            Assert.False(d.AlwaysProbeFromFileResource && d.AcceptEulaForVersion,
                $"{d.Id}: AlwaysProbeFromFileResource 与 AcceptEulaForVersion 互斥");
        }
    }

    // ---------- LooksLikeVersion：判断 PE 版本资源是否可信 ----------

    [Theory]
    [InlineData("1.10.0.0", true)]
    [InlineData("17.14", true)]
    [InlineData("4.5.5", true)]
    [InlineData("2.92", true)]
    [InlineData("4.6.8.0", true)]
    // ILSpy 的 ProductVersion 形如 "11.1.0.9782+a6909b2e1062d2404a52711926fa74030bd96119"
    // —— 带 +commit 后缀，不适合直接展示，应回退到 CLI 拿可读版本
    [InlineData("11.1.0.9782+a6909b2e1062d2404a52711926fa74030bd96119", false)]
    // 发布者把说明文字塞进版本字段的情况
    [InlineData("Dependencies.exe : command line tool for dumping dependencies", false)]
    [InlineData("SYSINTERNALS SOFTWARE LICENSE TERMS", false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    public void LooksLikeVersion_ClassifiesCorrectly(string input, bool expected)
    {
        Assert.Equal(expected, ExternalToolLocator.LooksLikeVersion(input));
    }

    [Fact]
    public void LooksLikeVersion_RejectsOverlyLongText()
    {
        Assert.False(ExternalToolLocator.LooksLikeVersion(new string('1', 60)));
    }
}
