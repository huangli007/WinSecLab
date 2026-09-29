using WinSecLab.Core.Models;

namespace WinSecLab.Core.Storage;

/// <summary>§3.1 项目目录布局。所有产物都落到固定位置，保证可重复测试与证据可追溯。</summary>
public sealed class ProjectLayout
{
    public ProjectLayout(string rootDirectory)
    {
        Root = rootDirectory;
    }

    public string Root { get; }

    public string Target => Combine("Target");
    public string TargetDependencies => Combine("Target", "dependencies");
    public string StaticAnalysis => Combine("Static Analysis");
    public string DynamicAnalysis => Combine("Dynamic Analysis");
    public string Network => Combine("Network");
    public string FileSystem => Combine("File System");
    public string Registry => Combine("Registry");
    public string Process => Combine("Process");
    public string Findings => Combine("Findings");
    public string Reports => Combine("Reports");
    public string Artifacts => Combine("Artifacts");
    public string Rules => Combine("Rules");
    public string Database => Path.Combine(Root, "analysis.db");

    private string Combine(params string[] parts) =>
        parts.Aggregate(Root, (acc, p) => Path.Combine(acc, p));

    public void CreateAll()
    {
        foreach (var dir in new[]
                 {
                     Root, Target, TargetDependencies, StaticAnalysis, DynamicAnalysis,
                     Network, FileSystem, Registry, Process, Findings, Reports, Artifacts, Rules,
                 })
        {
            Directory.CreateDirectory(dir);
        }
    }
}

/// <summary>工作区根目录解析与项目命名。</summary>
public static class WorkspaceLayout
{
    public const string DefaultFolderName = "WinSecLab";

    /// <summary>默认工作区：%USERPROFILE%\Documents\WinSecLab。可用环境变量 WINSECLAB_WORKSPACE 覆盖。</summary>
    public static string ResolveRoot()
    {
        var env = Environment.GetEnvironmentVariable("WINSECLAB_WORKSPACE");
        if (!string.IsNullOrWhiteSpace(env))
            return Path.GetFullPath(env);

        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrWhiteSpace(docs))
            docs = AppContext.BaseDirectory;
        return Path.Combine(docs, DefaultFolderName);
    }

    public static string ProjectsRoot(string workspaceRoot) => Path.Combine(workspaceRoot, "Projects");

    public static string RulesRoot(string workspaceRoot) => Path.Combine(workspaceRoot, "Rules");

    public static string PluginsRoot(string workspaceRoot) => Path.Combine(workspaceRoot, "Plugins");

    public static string SettingsPath(string workspaceRoot) => Path.Combine(workspaceRoot, "settings.json");

    /// <summary>生成人类可读且唯一的项目编号：WS-20260929-001。</summary>
    public static string NextProjectId(string workspaceRoot, DateTime? now = null)
    {
        var date = (now ?? DateTime.Now).ToString("yyyyMMdd");
        var projectsRoot = ProjectsRoot(workspaceRoot);
        Directory.CreateDirectory(projectsRoot);

        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in Directory.EnumerateDirectories(projectsRoot))
        {
            var name = Path.GetFileName(dir);
            var idx = name.IndexOf('_');
            used.Add(idx > 0 ? name[..idx] : name);
        }

        for (var i = 1; i <= 9999; i++)
        {
            var candidate = $"WS-{date}-{i:000}";
            if (!used.Contains(candidate))
                return candidate;
        }

        return $"WS-{date}-{Guid.NewGuid().ToString("N")[..6]}";
    }

    public static string MakeProjectDirectory(string workspaceRoot, string projectId, string projectName)
    {
        var safeName = SanitizeFolderName(projectName);
        return Path.Combine(ProjectsRoot(workspaceRoot), string.IsNullOrEmpty(safeName) ? projectId : $"{projectId}_{safeName}");
    }

    public static string SanitizeFolderName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var invalid = Path.GetInvalidFileNameChars();
        var chars = name.Select(c => invalid.Contains(c) ? '_' : c).ToArray();
        var result = new string(chars).Trim(' ', '.');
        if (result.Length > 60) result = result[..60].TrimEnd(' ', '.');
        return result;
    }

    public static string SanitizeFileName(string name) => SanitizeFolderName(name);
}
