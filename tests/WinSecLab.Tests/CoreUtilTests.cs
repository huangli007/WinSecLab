using WinSecLab.Core.Engines.Static;
using WinSecLab.Core.Storage;
using WinSecLab.Core.Util;

namespace WinSecLab.Tests;

/// <summary>工具层的基础不变量。这些函数是所有上层判断的地基，错了会带偏一整串结论。</summary>
public class CoreUtilTests
{
    // ─────────────────────────────── 熵 ───────────────────────────────

    [Fact]
    public void Shannon_AllSameBytes_IsZero()
    {
        var entropy = Entropy.Shannon(new byte[1024]);
        Assert.Equal(0.0, entropy, 6);
    }

    [Fact]
    public void Shannon_UniformRandomBytes_IsCloseToEight()
    {
        // 用固定种子的伪随机序列，保证测试可复现
        var data = new byte[65536];
        var seed = 12345;
        for (var i = 0; i < data.Length; i++)
        {
            seed = seed * 1103515245 + 12345 & 0x7FFFFFFF;
            data[i] = (byte)(seed >> 7);
        }

        var entropy = Entropy.Shannon(data);
        Assert.True(entropy > 7.9, $"期望接近 8，实际 {entropy:F3}");
        Assert.True(entropy <= 8.0);
    }

    [Fact]
    public void Shannon_EmptyInput_DoesNotThrow()
    {
        var entropy = Entropy.Shannon(Array.Empty<byte>());
        Assert.Equal(0.0, entropy, 6);
    }

    [Fact]
    public void Ratio_ClampsIntoUnitRange()
    {
        Assert.Equal(0, Entropy.Ratio(-1));
        Assert.Equal(1, Entropy.Ratio(9));
        Assert.Equal(0.5, Entropy.Ratio(4.0), 6);
    }

    [Fact]
    public void IsPackIndicator_RequiresBothHighEntropyAndSize()
    {
        Assert.True(Entropy.IsPackIndicator(7.9, 8192));
        Assert.False(Entropy.IsPackIndicator(7.9, 100), "小 buffer 不该判加壳");
        Assert.False(Entropy.IsPackIndicator(5.0, 8192), "低熵不该判加壳");
    }

    // ─────────────────────────────── 哈希 ───────────────────────────────

    [Fact]
    public void HashText_MatchesKnownSha256()
    {
        // "abc" 的标准 SHA-256。统一小写：与 imphash / VirusTotal 等业界惯例一致，便于人工比对。
        Assert.Equal(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Hashing.HashText("abc"));
    }

    [Fact]
    public void ShortHash_TruncatesAndUppercases()
    {
        Assert.Equal("ba7816", Hashing.ShortHash("ba7816bf8f01cfea", 6));
        // null 显示为 "-" 占位符，避免表格里出现空白单元格
        Assert.Equal("-", Hashing.ShortHash(null));
    }

    [Fact]
    public void ImportHash_FollowsImphashSemantics()
    {
        // imphash 对"导入表在 PE 文件中的出现顺序"做指纹：顺序不同 → 哈希不同。
        // 这是刻意设计 —— 相同导入集合、不同排列的两个样本，其二进制布局大概率不同。
        var a = new List<(string, string)> { ("kernel32.dll", "CreateFileW"), ("user32.dll", "MessageBoxW") };
        var sameOrder = new List<(string, string)> { ("kernel32.dll", "CreateFileW"), ("user32.dll", "MessageBoxW") };
        var reordered = new List<(string, string)> { ("user32.dll", "MessageBoxW"), ("kernel32.dll", "CreateFileW") };
        var fewer = new List<(string, string)> { ("kernel32.dll", "CreateFileW") };

        Assert.Equal(Hashing.ImportHash(a), Hashing.ImportHash(sameOrder));  // 同序 → 同值
        Assert.NotEqual(Hashing.ImportHash(a), Hashing.ImportHash(reordered)); // 换序 → 变
        Assert.NotEqual(Hashing.ImportHash(a), Hashing.ImportHash(fewer));     // 增删 → 变
    }

    [Fact]
    public void HashAll_RoundTripsFileContent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsl-test-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4, 5 });
            var (sha256, md5, sha1) = Hashing.HashAll(path);
            Assert.Equal(64, sha256.Length);
            Assert.Equal(32, md5.Length);
            Assert.Equal(40, sha1.Length);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ─────────────────────────────── 路径语义 ───────────────────────────────

    [Fact]
    public void UserWritable_TempDirectory_IsTrue()
    {
        Assert.True(PathSemantics.IsUserWritable(Path.GetTempPath()));
        Assert.True(PathSemantics.IsUserWritable(@"C:\Users\Public\Desktop\x.exe"));
    }

    [Fact]
    public void UserWritable_SystemLocations_IsFalse()
    {
        Assert.False(PathSemantics.IsUserWritable(@"C:\Windows\System32\kernel32.dll"));
        Assert.False(PathSemantics.IsUserWritable(@"C:\Windows\notepad.exe"));
    }

    /// <summary>回归：只认系统盘的 Program Files 曾把 D:\Program Files 误判为用户可写，造成 DLL 劫持高危误报。</summary>
    [Fact]
    public void UserWritable_ProgramFiles_OnAnyDrive_IsFalse()
    {
        Assert.False(PathSemantics.IsUserWritable(@"C:\Program Files\Vendor\App\app.dll"));
        Assert.False(PathSemantics.IsUserWritable(@"C:\Program Files (x86)\Vendor\App\app.dll"));
        Assert.False(PathSemantics.IsUserWritable(@"D:\Program Files\Vendor\App\app.dll"));
        Assert.False(PathSemantics.IsUserWritable(@"E:\Program Files (x86)\Vendor\tool.exe"));
    }

    [Fact]
    public void UserWritable_OtherDriveRoots_IsTrue()
    {
        // 非系统盘的普通目录，默认 ACL 允许普通用户创建文件
        Assert.True(PathSemantics.IsUserWritable(@"D:\Tools\download.dll"));
    }

    [Fact]
    public void UserWritable_NullOrEmpty_IsFalse()
    {
        Assert.False(PathSemantics.IsUserWritable(null));
        Assert.False(PathSemantics.IsUserWritable(""));
        Assert.False(PathSemantics.IsUserWritable("   "));
    }

    // ─────────────────────────────── 工作区布局 ───────────────────────────────

    [Fact]
    public void SanitizeFolderName_RemovesInvalidCharacters()
    {
        Assert.Equal("a_b__c", WorkspaceLayout.SanitizeFolderName("a<b>:c"));
        Assert.Equal("正常名称", WorkspaceLayout.SanitizeFolderName("正常名称"));
        Assert.Equal("", WorkspaceLayout.SanitizeFolderName("   "));
    }

    [Fact]
    public void SanitizeFolderName_TruncatesLongNames()
    {
        var name = new string('x', 200);
        Assert.True(WorkspaceLayout.SanitizeFolderName(name).Length <= 60);
    }

    [Fact]
    public void NextProjectId_IsSequentialAndUnique()
    {
        var root = Path.Combine(Path.GetTempPath(), $"wsl-ws-{Guid.NewGuid():N}");
        try
        {
            // NextProjectId 通过扫描 Projects 目录下已有目录来编号，
            // 所以测试要先模拟两个已存在的项目目录
            var projectsRoot = Path.Combine(root, "Projects");
            Directory.CreateDirectory(Path.Combine(projectsRoot, "WS-20260929-001_A"));
            Directory.CreateDirectory(Path.Combine(projectsRoot, "WS-20260929-002_B"));

            var next = WorkspaceLayout.NextProjectId(root, new DateTime(2026, 9, 29));
            Assert.Equal("WS-20260929-003", next);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    // ─────────────────────────────── 进程参数 ───────────────────────────────

    [Fact]
    public void Quote_EscapesEmbeddedQuotes()
    {
        Assert.Equal("\"plain\"", ProcessRunner.Quote("plain"));
        Assert.Equal("\"with \\\"quote\\\"\"", ProcessRunner.Quote("with \"quote\""));
    }
}
