using WinSecLab.Core.Models;

namespace WinSecLab.Core.Plugins;

/// <summary>
/// 外部工具适配器基类。
///
/// 统一处理三件容易写歪的事：
///  1. 探测不到 → 明确 Skipped + 安装指引，绝不静默返回空结果（否则报告里会出现"已检测"的假象）；
///  2. 需要管理员但当前不是 → 直接说明原因，不让工具跑一半报未知错误；
///  3. 用户禁用了外部工具 → 尊重配置，只走内置引擎。
/// </summary>
public abstract class ExternalToolAdapterBase : IWinSecLabPlugin
{
    /// <summary>对应 <see cref="ExternalToolCatalog"/> 中的工具 Id。</summary>
    protected abstract string ToolId { get; }

    /// <summary>对应 <see cref="ExternalToolCatalog"/> 中的工具描述符（编排与 UI 需要读取角色 / 安装指引）。</summary>
    public ExternalToolDescriptor Descriptor => ExternalToolCatalog.Get(ToolId)
        ?? throw new InvalidOperationException($"未在工具目录中注册：{ToolId}");

    protected ToolLocation Locate() => ExternalToolLocator.Locate(Descriptor);

    public string Id => ToolId;
    public string Name => Descriptor.Name;
    /// <summary>适配器自身版本（工具版本由 Detect() 单独上报）。</summary>
    public string Version => "1.0";
    public string? Description =>
        (Descriptor.Role == ToolRole.Substitutive ? "【替代型】" : "【补充型】") + Descriptor.InvocationHint;
    public PluginKind Kind => PluginKind.ExternalToolAdapter;

    public IReadOnlyList<TestTaskKind> Capabilities => Descriptor.Capabilities;

    private static readonly HashSet<TestTaskKind> LiveSystemTasks = new()
    {
        TestTaskKind.ProcessMonitor, TestTaskKind.FileMonitor, TestTaskKind.RegistryMonitor,
        TestTaskKind.NetworkCapture, TestTaskKind.HttpProxy, TestTaskKind.TlsAnalysis,
    };

    /// <summary>采集实时系统状态的任务必须在动态阶段执行；静态分析类工具不占动态阶段。</summary>
    public bool RequiresDynamicSession => Descriptor.Capabilities.Any(LiveSystemTasks.Contains);
    public bool RequiresAdministrator => Descriptor.RequiresAdministrator;

    public PluginProbeResult Detect()
    {
        var loc = Locate();
        if (!loc.Found)
        {
            return PluginProbeResult.Missing(
                $"未检测到 {Descriptor.Name}。搜索位置：{string.Join("、", loc.Searched.DefaultIfEmpty("（无）").Take(6))}",
                Descriptor.InstallHint);
        }

        return PluginProbeResult.Ready(
            $"已检测到（{loc.Source}）：{loc.ExecutablePath}"
            + (string.IsNullOrWhiteSpace(loc.Version) ? "" : $"；版本：{loc.Version}"),
            loc.ExecutablePath, loc.Version);
    }

    public async Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        if (!context.Options.PreferExternalTools)
            return PluginRunResult.Skipped($"{Descriptor.Name} 已按配置跳过（当前仅使用内置引擎）。");

        var loc = Locate();
        if (!loc.Found || loc.ExecutablePath is null)
        {
            return PluginRunResult.Skipped(
                $"未检测到 {Descriptor.Name}，本任务由内置引擎兜底。如需启用：{Descriptor.InstallHint}");
        }

        if (RequiresAdministrator && !Builtin.SessionProbe.IsElevated())
        {
            return PluginRunResult.Skipped(
                $"{Descriptor.Name} 需要管理员权限（抓包 / 内核级采集），当前为标准用户会话，已跳过。");
        }

        try
        {
            return await RunAsync(context, loc).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return PluginRunResult.Fail($"{Descriptor.Name} 执行被取消。");
        }
        catch (Exception ex)
        {
            return PluginRunResult.Fail($"{Descriptor.Name} 执行异常：{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>工具已确认可用（且权限满足）后执行真正的动作。</summary>
    protected abstract Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location);

    public virtual void Stop() { }

    public virtual IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();

    /// <summary>统一的工作目录：<c>项目/Artifacts/&lt;tool&gt;</c>，所有工具产物都落在这里，便于整体打包取证。</summary>
    protected static string ToolDirectory(PluginContext context, string toolId)
    {
        var dir = Path.Combine(context.Layout.Artifacts, toolId);
        Directory.CreateDirectory(dir);
        return dir;
    }

    protected static Evidence ToolEvidence(PluginContext context, string source, string title, string summary,
        object? payload, params string[] tags)
        => EvidenceFactory.Create(context.Project.Id, EvidenceKind.ToolOutput, title, source,
            context.TargetPath, summary, payload, tags);
}
