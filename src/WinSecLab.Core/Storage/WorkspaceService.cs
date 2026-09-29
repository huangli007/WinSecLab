using System.Text.Json;
using WinSecLab.Core.Engines.Static;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Storage;

/// <summary>工作区设置（<c>工作区/settings.json</c>）。CLI 与 UI 共用，保证两端读同一份配置。</summary>
public sealed class WorkspaceSettings
{
    public string DefaultProfile { get; set; } = "DesktopApplication";
    public bool PreferExternalTools { get; set; } = true;
    public int TargetRunSeconds { get; set; } = 60;
    public bool CopyTargetIntoProject { get; set; } = true;
    public bool AutoGenerateReport { get; set; } = true;
    public string? AnalystName { get; set; }
    public string? Organization { get; set; } = "WinSecLab";
    public string Classification { get; set; } = "内部使用";
}

/// <summary>
/// 工作区门面：项目创建 / 打开 / 列表 / 环境快照。
/// 把"一个 Windows 应用 = 一个项目"（§3.1）的落地细节集中在这里，
/// 避免 CLI 与 GUI 各写一套导入逻辑后行为不一致。
/// </summary>
public sealed class WorkspaceService
{
    public string Root { get; }
    public string RulesRoot => WorkspaceLayout.RulesRoot(Root);
    public string PluginsRoot => WorkspaceLayout.PluginsRoot(Root);

    public WorkspaceService(string? workspaceRoot = null)
    {
        Root = Path.GetFullPath(workspaceRoot ?? WorkspaceLayout.ResolveRoot());
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(WorkspaceLayout.ProjectsRoot(Root));
        Directory.CreateDirectory(RulesRoot);
        Directory.CreateDirectory(PluginsRoot);
    }

    // ─────────────────────────────── 设置 ───────────────────────────────

    public WorkspaceSettings LoadSettings()
    {
        var path = WorkspaceLayout.SettingsPath(Root);
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                var loaded = JsonSerializer.Deserialize<WorkspaceSettings>(json);
                if (loaded is not null) return loaded;
            }
        }
        catch
        {
            // 配置坏了不该让工具起不来，回落到默认值
        }
        return new WorkspaceSettings();
    }

    public void SaveSettings(WorkspaceSettings settings)
    {
        var path = WorkspaceLayout.SettingsPath(Root);
        var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json, new System.Text.UTF8Encoding(false));
    }

    // ─────────────────────────────── 项目 ───────────────────────────────

    /// <summary>列出全部项目（按更新时间倒序）。单个项目打不开时跳过而不是整体失败。</summary>
    public List<TestProject> ListProjects()
    {
        var list = new List<TestProject>();
        var projectsRoot = WorkspaceLayout.ProjectsRoot(Root);
        if (!Directory.Exists(projectsRoot)) return list;

        foreach (var dir in Directory.EnumerateDirectories(projectsRoot))
        {
            var dbPath = Path.Combine(dir, "analysis.db");
            if (!File.Exists(dbPath)) continue;
            try
            {
                var layout = new ProjectLayout(dir);
                var db = new ProjectDatabase(layout);
                var project = db.GetPrimaryProject();
                if (project is not null)
                {
                    project.RootDirectory = dir;
                    list.Add(project);
                }
            }
            catch
            {
                // 数据库损坏 / 版本不兼容：跳过该项目，其余照常列出
            }
        }

        return list.OrderByDescending(p => p.UpdatedAt).ToList();
    }

    /// <summary>按项目编号或目录名打开项目。</summary>
    public (TestProject Project, ProjectLayout Layout, ProjectDatabase Database)? OpenProject(string projectIdOrFolder)
    {
        var dir = ResolveProjectDirectory(projectIdOrFolder);
        if (dir is null) return null;

        var layout = new ProjectLayout(dir);
        var db = new ProjectDatabase(layout);
        var project = db.GetPrimaryProject();
        if (project is null) return null;
        project.RootDirectory = dir;
        return (project, layout, db);
    }

    public string? ResolveProjectDirectory(string projectIdOrFolder)
    {
        var projectsRoot = WorkspaceLayout.ProjectsRoot(Root);

        var direct = Path.Combine(projectsRoot, projectIdOrFolder);
        if (Directory.Exists(direct)) return direct;

        // 支持只给编号（WS-20260929-001）而不带名字后缀
        foreach (var dir in Directory.EnumerateDirectories(projectsRoot))
        {
            var name = Path.GetFileName(dir);
            var idx = name.IndexOf('_');
            var id = idx > 0 ? name[..idx] : name;
            if (string.Equals(id, projectIdOrFolder, StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, projectIdOrFolder, StringComparison.OrdinalIgnoreCase))
                return dir;
        }

        return null;
    }

    /// <summary>
    /// 删除项目。
    ///
    /// 默认送进回收站（可恢复），永久删除需显式 <paramref name="permanent"/>=true。
    /// 删除前必须先释放 SQLite 连接池 —— 连接池持有 analysis.db 的文件句柄，
    /// 不释放的话目录删不掉（报"正被另一进程使用"），这是实测踩过的坑。
    /// </summary>
    public DeleteProjectOutcome DeleteProject(string projectIdOrFolder, bool permanent = false)
    {
        var dir = ResolveProjectDirectory(projectIdOrFolder);
        if (dir is null)
            return new DeleteProjectOutcome(false, false, null, "找不到该项目。");

        // 路径安全兜底：只允许删除 Projects 根目录下的直接子目录，
        // 防止传进来 "../" 之类的东西删到工作区外面
        var projectsRoot = Path.GetFullPath(WorkspaceLayout.ProjectsRoot(Root));
        var fullDir = Path.GetFullPath(dir);
        var parent = Path.GetDirectoryName(fullDir.TrimEnd(Path.DirectorySeparatorChar));
        if (parent is null || !string.Equals(parent, projectsRoot.TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase))
            return new DeleteProjectOutcome(false, false, null, "拒绝删除：目标不在工作区 Projects 目录下。");

        var name = Path.GetFileName(fullDir);

        // 先断开所有 SQLite 连接，否则 analysis.db 被锁住删不掉
        ProjectDatabase.ReleasePools();

        if (!permanent)
        {
            if (RecycleBin.TryMoveToRecycleBin(fullDir, out var recycleError))
                return new DeleteProjectOutcome(true, false, name, null);

            // 回收站不可用时不静默转永久删除 —— 交给调用方决定（UI 会询问，CLI 用 --permanent）
            return new DeleteProjectOutcome(false, false, name,
                $"移入回收站失败：{recycleError}", RecycleUnavailable: true);
        }

        try
        {
            Directory.Delete(fullDir, recursive: true);
            return new DeleteProjectOutcome(true, true, name, null);
        }
        catch (Exception ex)
        {
            return new DeleteProjectOutcome(false, true, name, $"删除失败：{ex.Message}");
        }
    }

    /// <summary>
    /// 创建项目并导入目标文件。
    /// 会把目标文件复制进项目目录（可通过设置关闭）——§25「可重复测试」要求
    /// 事后仍能对同一份样本重跑，只留路径是不够的（文件可能被替换或删除）。
    /// </summary>
    public CreateProjectOutcome CreateProject(string targetPath,
        string? name = null, string? description = null,
        TestProfileKind profile = TestProfileKind.DesktopApplication,
        string? author = null, string? authorization = null,
        bool? copyTarget = null)
    {
        var outcome = new CreateProjectOutcome();

        if (string.IsNullOrWhiteSpace(targetPath))
        {
            outcome.Error = "未指定目标文件。";
            return outcome;
        }

        targetPath = Path.GetFullPath(targetPath);
        if (!File.Exists(targetPath))
        {
            outcome.Error = $"目标文件不存在：{targetPath}";
            return outcome;
        }

        var ext = Path.GetExtension(targetPath).ToLowerInvariant();
        var supported = new[] { ".exe", ".dll", ".msi", ".sys", ".ocx", ".cpl", ".scr", ".node", ".msix", ".appx" };
        if (!supported.Contains(ext))
            outcome.Warnings.Add($"文件扩展名 {ext} 不在常规可执行类型内，仍会尝试按 PE 解析。");

        try
        {
            var projectId = WorkspaceLayout.NextProjectId(Root);
            var projectName = string.IsNullOrWhiteSpace(name)
                ? Path.GetFileNameWithoutExtension(targetPath)
                : name!.Trim();

            var projectDir = WorkspaceLayout.MakeProjectDirectory(Root, projectId, projectName);
            var layout = new ProjectLayout(projectDir);
            layout.CreateAll();

            // 目标导入
            var (sha256, md5, sha1) = Hashing.HashAll(targetPath);
            var storedTarget = targetPath;
            var shouldCopy = copyTarget ?? LoadSettings().CopyTargetIntoProject;

            if (shouldCopy)
            {
                var dest = Path.Combine(layout.Target, Path.GetFileName(targetPath));
                try
                {
                    File.Copy(targetPath, dest, overwrite: true);
                    storedTarget = dest;
                    outcome.Warnings.Add($"目标已复制进项目目录：{dest}（原始路径：{targetPath}）");
                }
                catch (Exception ex)
                {
                    outcome.Warnings.Add($"目标复制失败，项目将引用原始路径：{ex.Message}");
                }
            }

            var project = new TestProject
            {
                Id = projectId,
                Name = projectName,
                Description = description,
                RootDirectory = projectDir,
                PrimaryTargetPath = storedTarget,
                ExecutionTargetPath = targetPath,
                Author = author ?? Environment.UserName,
                Authorization = authorization,
                CreatedAt = DateTime.Now,
                UpdatedAt = DateTime.Now,
                Profile = profile,
                Target = BuildTargetSummary(storedTarget, targetPath, sha256, md5),
                Environment = CaptureEnvironment(),
            };

            // 立刻做一次轻量类型识别 —— 让用户在分析之前就看到"这是什么程序"
            try
            {
                var pe = new PeAnalyzer().Analyze(storedTarget, computeSignature: false);
                if (pe.IsValidPe)
                {
                    project.Target.Architecture = pe.Architecture;
                    project.Target.IsDotNet = pe.IsDotNet;
                    project.Target.FileVersion = pe.Version.FileVersion ?? project.Target.FileVersion;
                    project.Target.ProductName = pe.Version.ProductName ?? project.Target.ProductName;
                    project.Target.CompanyName = pe.Version.CompanyName ?? project.Target.CompanyName;
                    project.Target.FileDescription = pe.Version.FileDescription ?? project.Target.FileDescription;
                    project.Target.Runtime = pe.IsDotNet ? AppRuntimeKind.DotNet : AppRuntimeKind.NativeCpp;
                }
                else
                {
                    outcome.Warnings.Add(pe.ParseError ?? "PE 解析未通过，类型识别可能不准确。");
                }
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add($"导入期类型识别失败（不影响后续分析）：{ex.Message}");
            }

            var db = new ProjectDatabase(layout);
            db.SaveProject(project);
            outcome.Project = project;
            outcome.Layout = layout;
            outcome.Success = true;
            return outcome;
        }
        catch (Exception ex)
        {
            outcome.Error = $"{ex.GetType().Name}: {ex.Message}";
            return outcome;
        }
    }

    /// <summary>
    /// 决定"从哪个路径启动被测程序"，并在样本被替换时给出警告。
    /// 判定顺序：原始路径存在且哈希一致 → 用它；哈希不一致 → 用项目内副本（保证测的是留存的那份样本）；
    /// 原始路径已不存在 → 退回副本。
    /// </summary>
    public static (string Path, string? Warning) ResolveExecutionTarget(TestProject project)
    {
        var stored = project.PrimaryTargetPath;
        var original = project.ExecutionTargetPath;

        if (!string.IsNullOrWhiteSpace(original) && File.Exists(original))
        {
            if (string.IsNullOrWhiteSpace(project.Target.Sha256))
                return (original!, null);

            try
            {
                var current = Hashing.Sha256File(original!);
                if (string.Equals(current, project.Target.Sha256, StringComparison.OrdinalIgnoreCase))
                    return (original!, null);

                if (!string.IsNullOrWhiteSpace(stored) && File.Exists(stored))
                {
                    return (stored!,
                        $"原始文件哈希已变化（导入时 {project.Target.Sha256[..12]}…，当前 {current[..12]}…），"
                        + "本次改为运行项目内留存的样本副本，以保证结论对应的是同一份被测对象。");
                }

                return (original!,
                    $"原始文件哈希已变化且未找到项目内副本，仍将运行当前磁盘上的文件（结论可能不对应导入时的样本）。");
            }
            catch (Exception ex)
            {
                return (original!, $"执行路径哈希校验失败（{ex.Message}），将直接运行原始路径。");
            }
        }

        if (!string.IsNullOrWhiteSpace(stored) && File.Exists(stored))
        {
            return (stored!,
                $"原始路径已不存在（{(string.IsNullOrWhiteSpace(original) ? "未记录" : original)}），"
                + "改为运行项目内留存的样本副本。注意：换了目录启动可能改变程序行为。");
        }

        return (project.Target.FilePath, "既找不到原始路径也找不到样本副本，请重新导入目标文件。");
    }

    private static TargetSummary BuildTargetSummary(string storedPath, string originalPath, string sha256, string md5)
    {
        var info = new FileInfo(storedPath);
        var summary = new TargetSummary
        {
            FilePath = storedPath,
            FileName = info.Name,
            FileSize = info.Length,
            Sha256 = sha256,
            Md5 = md5,
            Kind = ClassifyTarget(info.Extension),
            ImportedAt = DateTime.Now,
        };

        if (!string.Equals(storedPath, originalPath, StringComparison.OrdinalIgnoreCase))
        {
            summary.SupplementaryFiles.Add(new SupplementaryFile
            {
                Path = originalPath,
                Role = "原始路径（样本已复制进项目）",
            });
        }

        try
        {
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(storedPath);
            summary.FileVersion = vi.FileVersion;
            summary.ProductName = vi.ProductName;
            summary.CompanyName = vi.CompanyName;
            summary.FileDescription = vi.FileDescription;
        }
        catch { }

        return summary;
    }

    private static TargetFileKind ClassifyTarget(string extension) => extension.ToLowerInvariant() switch
    {
        ".exe" or ".scr" => TargetFileKind.Executable,
        ".dll" or ".ocx" or ".node" or ".cpl" => TargetFileKind.DynamicLibrary,
        ".msi" or ".msix" or ".appx" => TargetFileKind.Installer,
        ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" => TargetFileKind.Script,
        ".zip" or ".7z" or ".rar" or ".cab" => TargetFileKind.Archive,
        _ => TargetFileKind.Unknown,
    };

    /// <summary>测试环境快照（§3.1）。进报告"测试环境"章节，事后可复现。</summary>
    public static TestEnvironmentInfo CaptureEnvironment()
    {
        var env = new TestEnvironmentInfo
        {
            MachineName = Environment.MachineName,
            UserName = Environment.UserName,
            OsVersion = Environment.OSVersion.VersionString,
            OsBuild = Environment.OSVersion.Version.ToString(),
            OsArchitecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            DotNetVersion = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            IsElevated = IsElevated(),
            LogicalProcessors = Environment.ProcessorCount,
            CapturedAt = DateTime.Now,
        };

        try
        {
            env.TotalMemoryMb = (long)(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1024 / 1024);
        }
        catch { }

        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                env.NetworkInterfaces.Add(new NetworkInterfaceInfo
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    MacAddress = ni.GetPhysicalAddress().ToString(),
                });
            }
        }
        catch { }

        return env;
    }

    public static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}

public sealed class CreateProjectOutcome
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public TestProject? Project { get; set; }
    public ProjectLayout? Layout { get; set; }
    public List<string> Warnings { get; } = new();
}

/// <summary>
/// 删除项目的结果。<paramref name="Permanent"/> 区分是进了回收站还是彻底删除；
/// <paramref name="RecycleUnavailable"/> 为 true 表示回收站不可用（受限环境常见），
/// 此时调用方可显式选择永久删除。
/// </summary>
public sealed record DeleteProjectOutcome(
    bool Success, bool Permanent, string? ProjectName, string? Error, bool RecycleUnavailable = false);
