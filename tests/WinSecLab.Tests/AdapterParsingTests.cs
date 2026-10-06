using System.Text;
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

        // 只保留真正的模块路径：
        //   C:\app.exe（目标自身）、kernel32.dll、lib.dll 共 3 条
        // 排除：`Chain for C:\app.exe`（是标题不是模块）、https://...（不是本地模块）、short（长度不足）
        Assert.Equal(3, modules.Count);
        Assert.Contains(modules, m => m.EndsWith("kernel32.dll", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(modules, m => m.EndsWith("lib.dll", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(modules, m => m.Contains("://"));
        Assert.DoesNotContain(modules, m => m.StartsWith("Chain", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// 适配器实际用的是 <c>-imports</c>（-chain -modules 会递归遍历系统目录，慢且被安全软件拦），
    /// 它的输出格式是 `Import from module X.dll :`，必须能解析。
    /// </summary>
    [Fact]
    public void ParseModuleLines_HandlesImportsFormat()
    {
        const string output = """
            [-] Import listing for file : C:/tmp/target.exe
            Import from module GDI32.dll :
            	 Function SetMapMode
            Import from module USER32.dll :
            	 Function MessageBoxW
            Import from module api-ms-win-core-synch-l1-1-0.dll :
            """;

        var modules = DependenciesToolAdapter.ParseModuleLines(output);

        Assert.Equal(3, modules.Count);
        Assert.Contains("GDI32.dll", modules);
        Assert.Contains("USER32.dll", modules);
        Assert.Contains("api-ms-win-core-synch-l1-1-0.dll", modules);
        // 行尾冒号必须被剥掉，否则与内置解析结果的名字对不上
        Assert.DoesNotContain(modules, m => m.EndsWith(':'));
    }

    [Fact]
    public void ParseModuleLines_DeduplicatesRepeatedNames()
    {
        const string output = """
            Import from module KERNEL32.dll :
            	 Function CreateFileW
            Import from module KERNEL32.dll :
            	 Function WriteFile
            """;

        var modules = DependenciesToolAdapter.ParseModuleLines(output);

        // 同一模块多次出现（每个导入函数都可能重复该行）只保留一条
        Assert.Single(modules);
        Assert.Equal("KERNEL32.dll", modules[0]);
    }

    /// <summary>
    /// 适配器实际调 `-imports -json`（结构化输出，避开中文路径的编码错乱）。
    /// JSON 优先解析，格式不对时回退文本 —— 两级兜底。
    /// </summary>
    [Fact]
    public void ParseImportsOutput_ParsesJson()
    {
        const string json = """
            {
              "Imports": [
                { "Flags": 0, "Name": "GDI32.dll", "NumberOfEntries": 25 },
                { "Flags": 0, "Name": "USER32.dll", "NumberOfEntries": 8 },
                { "Flags": 0, "Name": "api-ms-win-core-synch-l1-1-0.dll", "NumberOfEntries": 2 }
              ]
            }
            """;

        var modules = DependenciesToolAdapter.ParseImportsOutput(json);

        Assert.Equal(3, modules.Count);
        Assert.Contains("GDI32.dll", modules);
        Assert.Contains("USER32.dll", modules);
    }

    [Fact]
    public void ParseImportsOutput_FallsBackToText_WhenNotJson()
    {
        const string text = """
            [-] Import listing for file : C:/tmp/target.exe
            Import from module KERNEL32.dll :
            	 Function CreateFileW
            """;

        var modules = DependenciesToolAdapter.ParseImportsOutput(text);

        Assert.Single(modules);
        Assert.Equal("KERNEL32.dll", modules[0]);
    }

    [Fact]
    public void ParseImportsOutput_EmptyOnGarbage()
    {
        Assert.Empty(DependenciesToolAdapter.ParseImportsOutput(""));
        Assert.Empty(DependenciesToolAdapter.ParseImportsOutput("no modules here"));
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

    // ─────────────────────── Sigcheck CSV 编码（实测踩坑） ───────────────────────

    /// <summary>
    /// 真机实测：中文 Windows 上 sigcheck 导出的 CSV 是 **UTF-16LE 无 BOM**。
    /// 按 UTF-8 读会得到每个字符间夹 NUL 的乱码，解析器直接失效。
    /// 这里钉住"UTF-16LE 无 BOM 也能正确解析"。
    /// </summary>
    [Fact]
    public void ReadSigcheckCsv_Utf16LeWithoutBom_IsDecoded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsl-sig-{Guid.NewGuid():N}.csv");
        try
        {
            var csv =
                "\"Path\",\"Verified\",\"Publisher\",\"Company\",\"Description\",\"Product Version\",\"File Version\"\r\n" +
                "\"C:\\app.exe\",\"Signed\",\"Contoso Ltd\",\"Contoso\",\"Sample App\",\"1.2.3\",\"1.2.3.4\"\r\n";

            // 无 BOM 的 UTF-16LE 字节
            File.WriteAllBytes(path, Encoding.Unicode.GetBytes(csv));

            var text = SigcheckToolAdapter.ReadSigcheckCsvForTest(path);
            var row = SigcheckToolAdapter.ParseSigcheckCsv(text);

            Assert.NotNull(row);
            Assert.Equal("Signed", row!.Verified);
            Assert.Equal("Contoso Ltd", row.Signer);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ReadSigcheckCsv_Utf8WithBom_IsDecoded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsl-sig8-{Guid.NewGuid():N}.csv");
        try
        {
            var csv =
                "\"Path\",\"Verified\",\"Publisher\"\r\n" +
                "\"C:\\app.exe\",\"Signed\",\"Contoso Ltd\"\r\n";

            File.WriteAllBytes(path, new UTF8Encoding(true).GetBytes(csv));

            var text = SigcheckToolAdapter.ReadSigcheckCsvForTest(path);
            var row = SigcheckToolAdapter.ParseSigcheckCsv(text);

            Assert.NotNull(row);
            Assert.Equal("Signed", row!.Verified);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ReadSigcheckCsv_PlainAscii_IsDecoded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsl-sigasc-{Guid.NewGuid():N}.csv");
        try
        {
            const string csv = "\"Path\",\"Verified\"\n\"C:\\app.exe\",\"Unsigned\"\n";
            File.WriteAllText(path, csv, new UTF8Encoding(false));

            var text = SigcheckToolAdapter.ReadSigcheckCsvForTest(path);
            var row = SigcheckToolAdapter.ParseSigcheckCsv(text);

            Assert.NotNull(row);
            Assert.Equal("Unsigned", row!.Verified);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
