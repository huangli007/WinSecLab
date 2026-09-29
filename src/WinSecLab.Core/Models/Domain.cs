using System.Text.Json.Serialization;

namespace WinSecLab.Core.Models;

/// <summary>测试项目（§3.1）。一个 Windows 应用 = 一个项目。</summary>
public sealed class TestProject
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string RootDirectory { get; set; } = "";
    public string? PrimaryTargetPath { get; set; }

    /// <summary>
    /// 实际启动被测程序时使用的路径。
    /// 与 <see cref="PrimaryTargetPath"/>（项目内留存的样本副本）分开是有必要的：
    /// 把可执行文件搬到别的目录再启动会改变 DLL 搜索路径、MUI 资源查找与 AppContainer 上下文，
    /// 很多程序（尤其是系统组件）会因此启动失败或行为失真 —— 那样采集到的动态证据就不可信了。
    /// 副本用于取证与哈希比对，执行走原始安装位置。
    /// </summary>
    public string? ExecutionTargetPath { get; set; }
    public string? Author { get; set; }
    public string? Authorization { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime UpdatedAt { get; set; } = DateTime.Now;
    public TestProfileKind Profile { get; set; } = TestProfileKind.Basic;

    /// <summary>测试环境快照（§3.1 测试环境）。</summary>
    public TestEnvironmentInfo Environment { get; set; } = new();

    public TargetSummary Target { get; set; } = new();
    public AppTypeDetection Detection { get; set; } = new();
    public List<string> Tags { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public bool IsSandboxed { get; set; }
    public string? SandboxHost { get; set; }

    [JsonIgnore]
    public string FindingsDirectory => Path.Combine(RootDirectory, "Findings");

    [JsonIgnore]
    public string ReportsDirectory => Path.Combine(RootDirectory, "Reports");

    [JsonIgnore]
    public string DatabasePath => Path.Combine(RootDirectory, "analysis.db");
}

/// <summary>项目里被测试的目标文件（可能多份：主程序 + 附属 DLL + 安装包）。</summary>
public sealed class TargetSummary
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public string Sha256 { get; set; } = "";
    public string Md5 { get; set; } = "";
    public string? FileVersion { get; set; }
    public string? ProductName { get; set; }
    public string? CompanyName { get; set; }
    public string? FileDescription { get; set; }
    public TargetFileKind Kind { get; set; } = TargetFileKind.Executable;
    public string Architecture { get; set; } = "";
    public bool IsSigned { get; set; }
    public string? Signer { get; set; }
    public bool IsDotNet { get; set; }
    public AppRuntimeKind Runtime { get; set; } = AppRuntimeKind.Unknown;
    public DateTime ImportedAt { get; set; } = DateTime.Now;
    public List<SupplementaryFile> SupplementaryFiles { get; set; } = new();
}

public sealed class SupplementaryFile
{
    public string Path { get; set; } = "";
    public string FileName { get; set; } = "";
    public long Size { get; set; }
    public string Sha256 { get; set; } = "";
    public string Role { get; set; } = "";
}

/// <summary>§3.2 自动识别模块的结果。</summary>
public sealed class AppTypeDetection
{
    public AppRuntimeKind Runtime { get; set; } = AppRuntimeKind.Unknown;
    public string DisplayName { get; set; } = "未识别";
    public int ConfidencePercent { get; set; }
    public List<DetectionSignal> Signals { get; set; } = new();
    public List<string> RecommendedAnalyzers { get; set; } = new();
    public List<string> RecommendedTools { get; set; } = new();
    public bool RequiresManagedDecompiler { get; set; }
    public bool RequiresNativeDecompiler { get; set; }
    public bool HasWebContent { get; set; }
    public bool IsGameEngine { get; set; }
}

public sealed class DetectionSignal
{
    public string Kind { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Weight { get; set; }
}

/// <summary>测试环境快照。</summary>
public sealed class TestEnvironmentInfo
{
    public string MachineName { get; set; } = System.Environment.MachineName;
    public string UserName { get; set; } = System.Environment.UserName;
    public string OsVersion { get; set; } = "";
    public string OsBuild { get; set; } = "";
    public string OsArchitecture { get; set; } = "";
    public string DotNetVersion { get; set; } = "";
    public bool IsElevated { get; set; }
    public bool IsVirtualMachine { get; set; }
    public string? VirtualizationHint { get; set; }
    public int LogicalProcessors { get; set; }
    public long TotalMemoryMb { get; set; }
    public string AnalyzerVersion { get; set; } = "WinSecLab 0.1.0";
    public DateTime CapturedAt { get; set; } = DateTime.Now;
    public List<NetworkInterfaceInfo> NetworkInterfaces { get; set; } = new();
}

public sealed class NetworkInterfaceInfo
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string? MacAddress { get; set; }
    public List<string> Addresses { get; set; } = new();
}

/// <summary>统一证据对象（§25 证据优先）。任何 Finding 都能回到这里。</summary>
public sealed class Evidence
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public EvidenceKind Kind { get; set; }
    public string Title { get; set; } = "";
    public string Source { get; set; } = "";
    public string? Target { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Summary { get; set; } = "";
    /// <summary>结构化载荷（JSON）。UI 与报告都从这里取原始字段。</summary>
    public string DataJson { get; set; } = "{}";
    public string? RawArtifactPath { get; set; }
    public List<string> RelatedFiles { get; set; } = new();
    public List<string> RelatedProcesses { get; set; } = new();
    public List<string> RelatedRegistry { get; set; } = new();
    public List<string> RelatedNetwork { get; set; } = new();
    public List<string> Tags { get; set; } = new();
    public string KindLabel => Kind.ToString();

    public string TimestampText => Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff");
}

/// <summary>统一安全发现（§9）。</summary>
public sealed class Finding
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public Severity Severity { get; set; } = Severity.Info;
    public Confidence Confidence { get; set; } = Confidence.Medium;
    public FindingStatus Status { get; set; } = FindingStatus.Open;
    public string Category { get; set; } = "";
    public string Source { get; set; } = "";
    public string? Target { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public List<string> EvidenceIds { get; set; } = new();
    public string? Reproduction { get; set; }
    public string? Impact { get; set; }
    public string? Recommendation { get; set; }
    public string? CweId { get; set; }
    public string? OwaspCategory { get; set; }
    public List<string> References { get; set; } = new();

    /// <summary>关联实体：进程 / 文件 / 注册表 / 网络，用于 §10 自动关联与 §11 Security Graph。</summary>
    public List<string> RelatedProcesses { get; set; } = new();
    public List<string> RelatedFiles { get; set; } = new();
    public List<string> RelatedRegistry { get; set; } = new();
    public List<string> RelatedNetwork { get; set; } = new();

    public string? AnalystNote { get; set; }

    /// <summary>严重级中文名（UI 与报告共用，避免各处各写一套 switch）。</summary>
    [JsonIgnore]
    public string SeverityText => Severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高",
        Severity.Medium => "中",
        Severity.Low => "低",
        _ => "提示",
    };

    /// <summary>置信度中文名。</summary>
    [JsonIgnore]
    public string ConfidenceText => Confidence switch
    {
        Confidence.High => "高",
        Confidence.Medium => "中",
        _ => "低",
    };

    /// <summary>处理状态中文名。</summary>
    [JsonIgnore]
    public string StatusText => Status switch
    {
        FindingStatus.Open => "待处理",
        FindingStatus.Confirmed => "已确认",
        FindingStatus.FalsePositive => "误报",
        FindingStatus.Accepted => "接受风险",
        FindingStatus.Remediated => "已整改",
        _ => Status.ToString(),
    };
}

/// <summary>运行时监控事件（§4 动态分析中心 / §5 Process Monitor 集成的统一事件）。</summary>
public sealed class MonitorEvent
{
    public long Sequence { get; set; }
    public string ProjectId { get; set; } = "";
    public string SessionId { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public MonitorEventType Type { get; set; }
    public uint ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public uint ParentProcessId { get; set; }
    public string Operation { get; set; } = "";
    public string Target { get; set; } = "";
    public string? Detail { get; set; }
    public string Result { get; set; } = "SUCCESS";
    public bool IsFromTargetTree { get; set; }
    public bool IsSuspicious { get; set; }
    public string? SuspicionReason { get; set; }
    public string Source { get; set; } = "builtin";

    [JsonIgnore] public string TimeText => Timestamp.ToString("HH:mm:ss.fff");
    [JsonIgnore] public string TypeLabel => Type.ToString();
    [JsonIgnore] public int Depth { get; set; }
}

/// <summary>测试会话（§5 会话 / §7 抓包会话）。</summary>
public sealed class AnalysisSession
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string Name { get; set; } = "";
    public SessionPhase Phase { get; set; } = SessionPhase.Idle;
    public DateTime StartedAt { get; set; } = DateTime.Now;
    public DateTime? EndedAt { get; set; }
    public List<TestTaskKind> Tasks { get; set; } = new();
    public TestProfileKind Profile { get; set; } = TestProfileKind.Basic;
    public string? LaunchedProcessPath { get; set; }
    public uint RootProcessId { get; set; }
    public int ExitCode { get; set; }
    public string? FailureReason { get; set; }
    public int EventCount { get; set; }
    public string? PcapPath { get; set; }

    [JsonIgnore] public TimeSpan Duration => (EndedAt ?? DateTime.Now) - StartedAt;
}

/// <summary>进程树中的一个节点（由 ProcessMonitor 采集，UI 树形展示与报告共用）。</summary>
public sealed class ProcessTreeEntry
{
    public uint Pid { get; set; }
    public uint ParentPid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public int Depth { get; set; }
    public DateTime StartTime { get; set; }

    public string IndentedName => Depth <= 0 ? Name : new string(' ', Depth * 2) + "└ " + Name;
}

/// <summary>一次构建出的完整测试结果包，供 UI 与报告引擎消费。</summary>
public sealed class AnalysisResult
{
    public string ProjectId { get; set; } = "";
    public TestProject? Project { get; set; }
    public PeImageInfo? Pe { get; set; }
    public DotNetAssemblyInfo? DotNet { get; set; }
    public List<DependencyInfo> Dependencies { get; set; } = new();
    public List<StringHit> Strings { get; set; } = new();
    public List<PeImageInfo> SiblingBinaries { get; set; } = new();
    /// <summary>同目录二进制的签名普查结果：(文件名, 状态, 签名者)。</summary>
    public List<(string File, string Status, string? Signer)> SiblingSignatures { get; set; } = new();
    public List<Evidence> Evidence { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
    public List<MonitorEvent> Events { get; set; } = new();
    public List<NetworkConnection> Connections { get; set; } = new();
    public List<HttpExchange> Http { get; set; } = new();
    public List<YaraMatch> YaraMatches { get; set; } = new();
    public List<ProcessTreeEntry> ProcessTree { get; set; } = new();
    public List<DnsObservation> DnsObservations { get; set; } = new();
    public List<PluginStatus> Plugins { get; set; } = new();
    public List<SecurityGraphNode> GraphNodes { get; set; } = new();
    public List<SecurityGraphEdge> GraphEdges { get; set; } = new();
    public DateTime GeneratedAt { get; set; } = DateTime.Now;
    public List<string> Analyses { get; set; } = new();
}
