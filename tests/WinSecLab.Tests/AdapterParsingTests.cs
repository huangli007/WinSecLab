using WinSecLab.Core.Plugins.Builtin;

namespace WinSecLab.Tests;

/// <summary>
/// 外部工具输出的解析器。这些格式来自第三方工具，没有规范约束，
/// 一旦对方升级格式，这里就是最先断的地方 —— 所以把样例钉进测试。
/// </summary>
public class AdapterParsingTests
{
    // ─────────────────────── Procmon CSV ───────────────────────

    [Fact]
    public void SplitCsvLine_HandlesQuotedFieldsWithCommas()
    {
        var fields = ProcmonCsvParser.SplitCsvLine("\"11:20:30.123\",\"app.exe\",\"4321\",\"WriteFile\",\"C:\\a,b\\x.dll\",\"SUCCESS\",\"Length: 8\"");

        Assert.Equal(7, fields.Count);
        Assert.Equal("11:20:30.123", fields[0]);
        Assert.Equal("app.exe", fields[1]);
        Assert.Equal("C:\\a,b\\x.dll", fields[4]);
        Assert.Equal("SUCCESS", fields[5]);
    }

    [Fact]
    public void SplitCsvLine_HandlesEscapedQuotes()
    {
        var fields = ProcmonCsvParser.SplitCsvLine("\"a\",\"say \"\"hi\"\"\",\"c\"");
        Assert.Equal(3, fields.Count);
        Assert.Equal("say \"hi\"", fields[1]);
    }

    [Fact]
    public void SplitCsvLine_PlainLine()
    {
        var fields = ProcmonCsvParser.SplitCsvLine("one,two,,four");
        Assert.Equal(4, fields.Count);
        Assert.Equal("", fields[2]);
    }

    // ─────────────────────── Sigcheck ───────────────────────

    [Fact]
    public void ParseSigcheckCsv_ExtractsVerifiedAndSigner()
    {
        const string csv = """
            "Path","Verified","Signing Date","Publisher","Company","Description","Product Version","File Version"
            "C:\app.exe","Signed","2026-01-02","Contoso Ltd","Contoso","Sample App","1.2.3","1.2.3.4"
            """;

        var row = SigcheckToolAdapter.ParseSigcheckCsv(csv);

        Assert.NotNull(row);
        Assert.Equal("Signed", row!.Verified);
        Assert.Equal("Contoso Ltd", row.Signer);
        Assert.Equal("Contoso", row.Company);
        Assert.Equal("1.2.3", row.ProductVersion);
    }

    [Fact]
    public void ParseSigcheckCsv_EmptyInput_ReturnsNull()
    {
        Assert.Null(SigcheckToolAdapter.ParseSigcheckCsv(""));
        Assert.Null(SigcheckToolAdapter.ParseSigcheckCsv("only one line"));
    }

    // ─────────────────────── tshark ───────────────────────

    [Fact]
    public void ParseInterfaces_ParsesIndexAndDescription()
    {
        const string output = """
            1. \Device\Npf_{A} (Ethernet 2)
            2. \Device\Npf_Loopback (Adapter for loopback traffic capture)
            3. \Device\Npf_{B} (Wi-Fi)
            not-a-line
            """;

        var list = WiresharkToolAdapter.ParseInterfaces(output);

        Assert.Equal(3, list.Count);
        Assert.Equal(1, list[0].Index);
        Assert.Contains("Ethernet 2", list[0].Description);
    }

    /// <summary>选网卡要避开回环与蓝牙 —— 选错网卡抓包结果就是空的，用户只会觉得"工具坏了"。</summary>
    [Fact]
    public void PickInterface_PrefersPhysicalAdapter_OverLoopbackAndBluetooth()
    {
        var list = new List<WiresharkToolAdapter.TsharkInterface>
        {
            new(1, "Adapter for loopback traffic capture"),
            new(2, "Bluetooth Device (Personal Area Network)"),
            new(3, "Ethernet 2"),
        };

        var picked = WiresharkToolAdapter.PickInterface(list, preferred: null);
        Assert.Equal(3, picked.Index);
    }

    [Fact]
    public void PickInterface_RespectsExplicitPreference()
    {
        var list = new List<WiresharkToolAdapter.TsharkInterface>
        {
            new(1, "Ethernet 2"),
            new(7, "Wi-Fi"),
        };

        Assert.Equal(7, WiresharkToolAdapter.PickInterface(list, preferred: 7).Index);
    }

    [Fact]
    public void PickInterface_FallsBackToFirst_WhenOnlyLoopback()
    {
        var list = new List<WiresharkToolAdapter.TsharkInterface> { new(1, "Adapter for loopback traffic capture") };
        Assert.Equal(1, WiresharkToolAdapter.PickInterface(list, null).Index);
    }

    [Fact]
    public void ParseRows_SplitsByTab_AndKeepsEmptyFields()
    {
        var rows = WiresharkToolAdapter.ParseRows("10.0.0.1\thost.example.com\n\n8.8.8.8\t");

        Assert.Equal(2, rows.Count);
        Assert.Equal("10.0.0.1", rows[0][0]);
        Assert.Equal("host.example.com", rows[0][1]);
        Assert.Equal(2, rows[1].Count);
        Assert.Equal("", rows[1][1]);
    }

    // ─────────────────────── Dependencies ───────────────────────

    [Fact]
    public void ParseModuleLines_KeepsOnlyModulePaths()
    {
        const string output = """
            Chain for C:\app.exe
              C:\app.exe
                  C:\Windows\System32\kernel32.dll
                  https://example.com/not-a-module.dll
              short
                  C:\Program Files\Vendor\lib.dll
            """;

        var modules = DependenciesToolAdapter.ParseModuleLines(output);

        // 3 个依赖模块 + 目标自身（C://app.exe 也以 .exe 结尾，属正常输出）
        Assert.Equal(4, modules.Count);
        Assert.Contains(modules, m => m.EndsWith("kernel32.dll", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(modules, m => m.Contains("://"));
    }

    // ─────────────────────── Ghidra 导出 CSV ───────────────────────

    [Fact]
    public void ParseFunctionCsv_ParsesSizesAndFlags()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsl-ghidra-{Guid.NewGuid():N}.csv");
        try
        {
            File.WriteAllLines(path, new[]
            {
                "name,entry,size,thunk,external,bodySize",
                "\"FUN_140001000\",\"140001000\",\"256\",\"False\",\"False\",\"256\"",
                "\"CreateFileW\",\"140005000\",\"64\",\"True\",\"True\",\"64\"",
            });

            var functions = GhidraToolAdapter.ParseFunctionCsv(path);

            Assert.Equal(2, functions.Count);
            Assert.Equal("FUN_140001000", functions[0].Name);
            Assert.Equal(256, functions[0].Size);
            Assert.False(functions[0].IsThunk);
            Assert.True(functions[1].IsExternal);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
