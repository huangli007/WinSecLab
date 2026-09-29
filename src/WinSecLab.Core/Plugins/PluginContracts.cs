using WinSecLab.Core.Models;
using WinSecLab.Core.Storage;

namespace WinSecLab.Core.Plugins;

/// <summary>插件可用性探测结果（§17 Detect()）。</summary>
public sealed class PluginProbeResult
{
    public bool Available { get; init; }
    public string? ExecutablePath { get; init; }
    public string? Version { get; init; }
    public string Message { get; init; } = "";
    public List<string> MissingDependencies { get; init; } = new();

    public static PluginProbeResult Ready(string message, string? path = null, string? version = null) =>
        new() { Available = true, Message = message, ExecutablePath = path, Version = version };

    public static PluginProbeResult Missing(string message, params string[] missing) =>
        new() { Available = false, Message = message, MissingDependencies = missing.ToList() };

    public static PluginProbeResult Builtin(string message) =>
        new() { Available = true, Message = message };
}

/// <summary>插件执行时能拿到的全部上下文。</summary>
public sealed class PluginContext
{
    public required TestProject Project { get; init; }
    public required ProjectLayout Layout { get; init; }
    public required ProjectDatabase Database { get; init; }
    public required string TargetPath { get; init; }
    public required TestTaskKind Task { get; init; }

    /// <summary>前置任务的产物；后面的插件可以直接复用，避免重复解析。</summary>
    public AnalysisResult Result { get; init; } = new();

    /// <summary>正在进行的动态会话（仅动态 / 网络插件有值）。</summary>
    public DynamicSessionContext? Session { get; init; }

    /// <summary>插件内埋点输出，UI 实时消费。</summary>
    public Action<string> Log { get; init; } = _ => { };

    /// <summary>进度 0..1，-1 表示不确定进度。</summary>
    public Action<double, string> Progress { get; init; } = (_, _) => { };

    public List<string> SearchDirectories { get; init; } = new();

    public AnalysisOptions Options { get; init; } = new();

    public CancellationToken CancellationToken { get; init; }
}

/// <summary>运行期可调参数（§5 Settings）。</summary>
public sealed class AnalysisOptions
{
    public bool ComputeSignature { get; set; } = true;
    public bool ExtractStrings { get; set; } = true;
    public bool MaxStringResults { get; set; } = true;
    public int StringMinLength { get; set; } = 6;
    public int MaxStrings { get; set; } = 40_000;
    public bool HashDependencies { get; set; } = true;
    public bool DeepDependencyHash { get; set; }
    public int MonitorBufferSize { get; set; } = 200_000;
    public int ConnectionPollIntervalMs { get; set; } = 1500;
    public bool AutoGenerateReport { get; set; } = true;
    public bool KillTargetOnSessionEnd { get; set; } = true;
    public int TargetRunSeconds { get; set; } = 60;
    public List<string> FileWatchRoots { get; set; } = new();
    public List<string> RegistryWatchRoots { get; set; } = new();
    public int HttpProxyPort { get; set; } = 8877;
    public string? YaraRulesDirectory { get; set; }
    /// <summary>YARA 扫描文件数上限（含目标本身），<=1 表示只扫目标文件。</summary>
    public int YaraMaxFiles { get; set; } = 13;
    public double HighEntropyThreshold { get; set; } = 7.2;

    // ── 外部工具适配器开关 ──
    // 原则：能自动跑、结果可验证的默认开启；耗时长或会打断用户操作的默认关闭，需显式打开。
    /// <summary>是否允许外部工具适配器参与分析（关闭后只用内置引擎）。</summary>
    public bool PreferExternalTools { get; set; } = true;
    /// <summary>Process Monitor 全系统采集时长（秒）。0 = 跳过。</summary>
    public int ProcmonCaptureSeconds { get; set; } = 20;
    /// <summary>dumpcap 抓包时长（秒）。0 = 跳过。</summary>
    public int TsharkCaptureSeconds { get; set; } = 20;
    /// <summary>tshark 抓包网卡序号（null = 自动选第一个非回环网卡）。</summary>
    public int? TsharkInterfaceIndex { get; set; }
    /// <summary>是否执行 ilspycmd 反编译导出（会产生大量文件，默认关闭）。</summary>
    public bool EnableIlSpyDecompile { get; set; }
    /// <summary>是否执行 Ghidra headless 分析（很慢，默认关闭）。</summary>
    public bool EnableGhidraHeadless { get; set; }
    /// <summary>Ghidra 单文件分析超时（秒）。</summary>
    public int GhidraAnalysisSeconds { get; set; } = 300;
}

/// <summary>动态会话对插件暴露的只读视图。</summary>
public sealed class DynamicSessionContext
{
    public required string SessionId { get; init; }
    public required uint RootProcessId { get; init; }
    public required string RootProcessPath { get; init; }
    public required Func<uint, bool> IsInTargetTree { get; init; }
    public required Func<MonitorEvent, bool> PublishEvent { get; init; }
    public required Action<string, string> RegisterArtifact { get; init; }
    public required HttpProxyServerHandle? Proxy { get; init; }
    public required Func<string, uint, string, List<NetworkConnection>> ProbeConnections { get; init; }
    public List<MonitorEvent> BufferedEvents { get; init; } = new();
}

/// <summary>HTTP 代理的运行句柄，供 UI 与报告读取请求历史。</summary>
public sealed class HttpProxyServerHandle
{
    public required int Port { get; init; }
    public required Func<IReadOnlyList<HttpExchange>> Snapshot { get; init; }
    public required Action Stop { get; init; }
    public required Func<string, CancellationToken, Task<HttpExchange>> ReplayAsync { get; init; }
}

/// <summary>插件执行结果。</summary>
public sealed class PluginRunResult
{
    public bool Success { get; init; } = true;
    /// <summary>
    /// 插件明确表示"本次没有执行"（前置条件不满足 / 工具未安装 / 用户未启用）。
    /// 与"执行了但没有发现"必须区分开 —— 报告里这两者的含义完全不同。
    /// </summary>
    public bool IsSkipped { get; init; }
    public string Summary { get; init; } = "";
    public string? Error { get; init; }
    public TimeSpan Duration { get; init; }
    public List<Evidence> Evidence { get; init; } = new();
    public List<Finding> Findings { get; init; } = new();
    public List<string> Artifacts { get; init; } = new();
    public List<string> Log { get; init; } = new();
    public List<string> Warnings { get; init; } = new();

    public static PluginRunResult Ok(string summary, List<Evidence>? evidence = null,
        List<Finding>? findings = null, List<string>? artifacts = null) => new()
    {
        Success = true,
        Summary = summary,
        Evidence = evidence ?? new List<Evidence>(),
        Findings = findings ?? new List<Finding>(),
        Artifacts = artifacts ?? new List<string>(),
    };

    public static PluginRunResult Skipped(string reason) => new()
    {
        Success = true,
        IsSkipped = true,
        Summary = reason,
        Warnings = { reason },
    };

    public static PluginRunResult Fail(string error) => new()
    {
        Success = false,
        Error = error,
        Summary = error,
    };
}

/// <summary>§17 插件接口。内置引擎与第三方工具适配器使用同一套契约。</summary>
public interface IWinSecLabPlugin
{
    string Id { get; }
    string Name { get; }
    string Version { get; }
    string? Description { get; }
    PluginKind Kind { get; }

    /// <summary>本插件能承担哪些测试任务。</summary>
    IReadOnlyList<TestTaskKind> Capabilities { get; }

    /// <summary>是否需要目标程序处于运行状态。</summary>
    bool RequiresDynamicSession { get; }

    /// <summary>是否需要管理员权限才能拿到完整数据。</summary>
    bool RequiresAdministrator { get; }

    /// <summary>探测外部依赖是否就位。</summary>
    PluginProbeResult Detect();

    /// <summary>执行分析。</summary>
    Task<PluginRunResult> AnalyzeAsync(PluginContext context);

    /// <summary>停止（用于动态监控类插件）。</summary>
    void Stop();

    /// <summary>导出原始产物（pcap / csv / json），返回路径列表。</summary>
    IReadOnlyList<string> Export(PluginContext context);
}
