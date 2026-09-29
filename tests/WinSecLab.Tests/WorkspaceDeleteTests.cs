using WinSecLab.Core.Models;
using WinSecLab.Core.Storage;

namespace WinSecLab.Tests;

/// <summary>
/// 删除项目。
///
/// 这是全平台唯一的破坏性操作，测试要覆盖三层：
/// ① 正常路径能删掉 ② 路径逃逸被拦住（防误删工作区外的目录）③ 不存在的项目给明确错误。
/// 删除走回收站（可恢复），所以测试用临时工作区，不会污染真实数据。
/// </summary>
public class WorkspaceDeleteTests : IDisposable
{
    private readonly string _root;
    private readonly WorkspaceService _workspace;

    public WorkspaceDeleteTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"wsl-del-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_root);
        _workspace = new WorkspaceService(_root);
    }

    public void Dispose()
    {
        ProjectDatabase.ReleasePools();
        try { Directory.Delete(_root, recursive: true); } catch { /* 回收站已移走文件，可能已不存在 */ }
        GC.SuppressFinalize(this);
    }

    /// <summary>造一个真实项目（含目标文件），返回项目编号。</summary>
    private string CreateProject(string name)
    {
        var target = Path.Combine(Path.GetTempPath(), $"wsl-target-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(target, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });   // 最小 MZ 头

        try
        {
            var outcome = _workspace.CreateProject(target, name);
            Assert.True(outcome.Success, $"建项目失败：{outcome.Error}");
            Assert.NotNull(outcome.Project);
            Assert.NotNull(outcome.Layout);

            // 项目目录必须真实存在，否则删除测试没有意义
            Assert.True(Directory.Exists(outcome.Layout!.Root));
            return outcome.Project!.Id;
        }
        finally
        {
            File.Delete(target);
        }
    }

    [Fact]
    public void DeleteProject_NonExistent_ReturnsError()
    {
        var outcome = _workspace.DeleteProject("WS-19990101-999");

        Assert.False(outcome.Success);
        Assert.False(string.IsNullOrWhiteSpace(outcome.Error));
    }

    /// <summary>
    /// 路径安全兜底：拒绝删除 Projects 根目录之外的任何路径。
    /// 这是防"传进来 ../ 之类的东西删到工作区外面"的最后一道防线。
    /// </summary>
    [Fact]
    public void DeleteProject_PathEscape_IsRejected()
    {
        // 在 Projects 根旁边造一个"不该被删"的目录
        var outside = Path.Combine(_root, "Sensitive");
        Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(outside, "keep.txt"), "must survive");

        // 尝试用相对路径逃逸到 Projects 之外
        var outcome = _workspace.DeleteProject(Path.Combine("..", "Sensitive"));

        Assert.False(outcome.Success);
        Assert.Contains("Projects", outcome.Error ?? "");
        Assert.True(File.Exists(Path.Combine(outside, "keep.txt")), "工作区外的文件必须完好无损");
    }

    /// <summary>
    /// 最关键的安全性质：删除要么成功，要么明确失败且**项目完好无损**。
    /// 受限环境（如 CI/沙箱）里回收站 API 可能不可用，此时绝不允许静默转永久删除 ——
    /// 那会让"删不掉"变成"悄悄删掉了"。
    /// </summary>
    [Fact]
    public void DeleteProject_NeverSilentlyPermanentDeletes()
    {
        var id = CreateProject("待删除项目");
        Assert.Contains(_workspace.ListProjects(), p => p.Id == id);

        var outcome = _workspace.DeleteProject(id);

        if (outcome.Success)
        {
            Assert.False(outcome.Permanent, "默认删除必须走回收站，不能是永久删除");
            Assert.DoesNotContain(_workspace.ListProjects(), p => p.Id == id);
        }
        else
        {
            Assert.False(string.IsNullOrWhiteSpace(outcome.Error), "失败必须给出原因");
            Assert.True(outcome.RecycleUnavailable, "失败应标明是回收站不可用");
            Assert.Contains(_workspace.ListProjects(), p => p.Id == id);
        }
    }

    /// <summary>显式 permanent=true 时才是彻底删除（CLI --permanent 走这条）。</summary>
    [Fact]
    public void DeleteProject_Permanent_RemovesDirectory()
    {
        var id = CreateProject("永久删除项目");
        var dir = _workspace.ResolveProjectDirectory(id);
        Assert.NotNull(dir);

        var outcome = _workspace.DeleteProject(id, permanent: true);

        Assert.True(outcome.Success, outcome.Error);
        Assert.True(outcome.Permanent);
        Assert.False(Directory.Exists(dir), "永久删除后目录必须不存在");
        Assert.DoesNotContain(_workspace.ListProjects(), p => p.Id == id);
    }
}
