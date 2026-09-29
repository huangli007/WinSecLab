using System.Text.Json.Serialization;

namespace WinSecLab.Core.Models;

public enum GraphNodeKind
{
    Process,
    File,
    Registry,
    Network,
    Module,
    Finding,
}

/// <summary>§11 Security Graph 节点。点击即可定位到原始证据。</summary>
public sealed class SecurityGraphNode
{
    public string Id { get; set; } = "";
    public GraphNodeKind Kind { get; set; }
    public string Label { get; set; } = "";
    public string? Detail { get; set; }
    public string? FullPath { get; set; }
    public bool IsTarget { get; set; }
    public bool IsSuspicious { get; set; }
    public int Weight { get; set; } = 1;
    public Severity Severity { get; set; } = Severity.Info;
    public List<string> EvidenceIds { get; set; } = new();
    public List<string> FindingIds { get; set; } = new();
    public double X { get; set; }
    public double Y { get; set; }

    [JsonIgnore] public string KindLabel => Kind switch
    {
        GraphNodeKind.Process => "进程",
        GraphNodeKind.File => "文件",
        GraphNodeKind.Registry => "注册表",
        GraphNodeKind.Network => "网络",
        GraphNodeKind.Module => "模块",
        _ => "发现",
    };
}

public sealed class SecurityGraphEdge
{
    public string SourceId { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string Relation { get; set; } = "";
    public EvidenceKind? EvidenceKind { get; set; }
    public bool IsSuspicious { get; set; }
    public string? EvidenceId { get; set; }
}

/// <summary>插件运行状态（§17）。</summary>
public sealed class PluginStatus
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public PluginKind Kind { get; set; }
    public string? Description { get; set; }
    public string? Author { get; set; }
    public string? Homepage { get; set; }
    public bool Available { get; set; }
    public string AvailabilityText { get; set; } = "";
    public string? ExecutablePath { get; set; }
    public List<string> Capabilities { get; set; } = new();
    public List<string> MissingDependencies { get; set; } = new();
    public string? LastError { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime LastChecked { get; set; } = DateTime.Now;
    public string InstallHint { get; set; } = "";
}

/// <summary>§13 测试 Profile 定义（内置预设，UI 直接消费）。</summary>
public sealed class TestProfileDefinition
{
    public TestProfileKind Kind { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public List<TestTaskKind> Tasks { get; set; } = new();
    public bool IncludesDynamic { get; set; }
    public bool IncludesNetwork { get; set; }

    public static IReadOnlyList<TestProfileDefinition> All { get; } = new List<TestProfileDefinition>
    {
        new()
        {
            Kind = TestProfileKind.Basic,
            Name = "Basic",
            Description = "仅静态检查：PE、依赖、签名、字符串、YARA、熵值。不启动目标程序。",
            Tasks = new List<TestTaskKind>
            {
                TestTaskKind.PeAnalysis, TestTaskKind.DependencyScan, TestTaskKind.DigitalSignature,
                TestTaskKind.StringsScan, TestTaskKind.EntropyScan, TestTaskKind.YaraScan,
                TestTaskKind.ToolCorrelation,
            },
            IncludesDynamic = false, IncludesNetwork = false,
        },
        new()
        {
            Kind = TestProfileKind.DesktopApplication,
            Name = "Desktop Application",
            Description = "Basic + 动态行为：进程、文件、注册表、DLL、网络连接观测。",
            Tasks = new List<TestTaskKind>
            {
                TestTaskKind.PeAnalysis, TestTaskKind.DependencyScan, TestTaskKind.DigitalSignature,
                TestTaskKind.StringsScan, TestTaskKind.YaraScan,
                TestTaskKind.ProcessMonitor, TestTaskKind.FileMonitor, TestTaskKind.RegistryMonitor,
                TestTaskKind.NetworkCapture, TestTaskKind.ToolCorrelation,
            },
            IncludesDynamic = true, IncludesNetwork = true,
        },
        new()
        {
            Kind = TestProfileKind.DotNetApplication,
            Name = ".NET Application",
            Description = "Basic + 托管代码结构：程序集元数据、命名空间/类型/方法、引用程序集、混淆迹象。",
            Tasks = new List<TestTaskKind>
            {
                TestTaskKind.PeAnalysis, TestTaskKind.DependencyScan, TestTaskKind.DigitalSignature,
                TestTaskKind.StringsScan, TestTaskKind.YaraScan, TestTaskKind.DotNetAnalysis,
                TestTaskKind.ToolCorrelation,
            },
            IncludesDynamic = false, IncludesNetwork = false,
        },
        new()
        {
            Kind = TestProfileKind.FullSecurityAssessment,
            Name = "Full Security Assessment",
            Description = "静态 + 动态 + 网络 + HTTP 代理抓取 + 工具关联，一次跑完。",
            Tasks = new List<TestTaskKind>
            {
                TestTaskKind.PeAnalysis, TestTaskKind.DependencyScan, TestTaskKind.DigitalSignature,
                TestTaskKind.StringsScan, TestTaskKind.EntropyScan, TestTaskKind.DotNetAnalysis,
                TestTaskKind.YaraScan, TestTaskKind.ProcessMonitor, TestTaskKind.FileMonitor,
                TestTaskKind.RegistryMonitor, TestTaskKind.NetworkCapture, TestTaskKind.HttpProxy,
                TestTaskKind.TlsAnalysis, TestTaskKind.ToolCorrelation, TestTaskKind.DeepAnalysis,
            },
            IncludesDynamic = true, IncludesNetwork = true,
        },
    };
}

/// <summary>UI 与 CLI 共用的任务元数据（标题 / 说明 / 是否动态）。</summary>
public sealed class TestTaskDefinition
{
    public TestTaskKind Kind { get; set; }
    public string Name { get; set; } = "";
    /// <summary>界面展示用中文名。报告与日志仍用英文名，便于与工具链对齐。</summary>
    public string ChineseName { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public bool RequiresDynamicSession { get; set; }
    public bool RequiresAdministrator { get; set; }
    public string Source { get; set; } = "builtin";

    public static IReadOnlyList<TestTaskDefinition> All { get; } = new List<TestTaskDefinition>
    {
        new() { Kind = TestTaskKind.PeAnalysis, Name = "PE Analysis", ChineseName = "PE 结构解析", Category = "Static", Source = "builtin", Description = "解析 PE 头、节区、导入导出、资源、调试路径。" },
        new() { Kind = TestTaskKind.DependencyScan, Name = "Dependency Scan", ChineseName = "依赖分析", Category = "Static", Source = "builtin", Description = "解析导入表并解析磁盘上的依赖 DLL，标注可写目录加载。" },
        new() { Kind = TestTaskKind.DigitalSignature, Name = "Digital Signature", ChineseName = "数字签名校验", Category = "Static", Source = "builtin", Description = "WinVerifyTrust 校验与签名链、时间戳。" },
        new() { Kind = TestTaskKind.StringsScan, Name = "Strings Scan", ChineseName = "字符串提取与分类", Category = "Static", Source = "builtin", Description = "ASCII / UTF-16 字符串提取并按 URL、路径、命令、凭据等分类。" },
        new() { Kind = TestTaskKind.EntropyScan, Name = "Entropy Scan", ChineseName = "熵值与加壳检测", Category = "Static", Source = "builtin", Description = "节区与覆盖区熵值分析，识别加壳 / 加密载荷。" },
        new() { Kind = TestTaskKind.DotNetAnalysis, Name = ".NET Analysis", ChineseName = ".NET 元数据分析", Category = "Static", Source = "builtin", Description = "读取程序集元数据，导出命名空间 / 类型 / 成员树与引用程序集。" },
        new() { Kind = TestTaskKind.YaraScan, Name = "YARA", ChineseName = "YARA 规则匹配", Category = "Static", Source = "yara", Description = "内置轻量规则匹配；检测到 yara.exe 时自动切换为完整 YARA 引擎。" },
        new() { Kind = TestTaskKind.ProcessMonitor, Name = "Process Monitoring", ChineseName = "进程与模块监控", Category = "Dynamic", Source = "builtin", RequiresDynamicSession = true, Description = "跟踪进程创建 / 退出与目标进程树。" },
        new() { Kind = TestTaskKind.FileMonitor, Name = "File Monitoring", ChineseName = "文件系统监控", Category = "Dynamic", Source = "builtin", RequiresDynamicSession = true, Description = "监控目标进程写入 / 创建 / 删除的文件路径。" },
        new() { Kind = TestTaskKind.RegistryMonitor, Name = "Registry Monitoring", ChineseName = "注册表监控", Category = "Dynamic", Source = "builtin", RequiresDynamicSession = true, Description = "监控注册表键值创建 / 修改 / 删除与自启动项。" },
        new() { Kind = TestTaskKind.NetworkCapture, Name = "Network Capture", ChineseName = "网络连接与 DNS", Category = "Network", Source = "builtin", RequiresDynamicSession = true, Description = "按 PID 抓取 TCP/UDP 连接与 DNS 观测；检测到 tshark 时可导出 PCAP。" },
        new() { Kind = TestTaskKind.HttpProxy, Name = "HTTP Analyzer", ChineseName = "HTTP 明文分析", Category = "Network", Source = "builtin", RequiresDynamicSession = true, Description = "本地正向代理记录 HTTP 请求历史，支持发送到 Repeater 重放。" },
        new() { Kind = TestTaskKind.TlsAnalysis, Name = "TLS Analysis", ChineseName = "TLS 报文分析", Category = "Network", Source = "wireshark", RequiresDynamicSession = true, RequiresAdministrator = true, Description = "需要 Wireshark/tshark 支持，解析证书与 TLS 版本。" },
        new() { Kind = TestTaskKind.ToolCorrelation, Name = "Tool Correlation", ChineseName = "规则关联与图谱", Category = "Analysis", Source = "builtin", Description = "规则引擎跨证据关联，生成统一 Finding 与 Security Graph。" },
        new() { Kind = TestTaskKind.DeepAnalysis, Name = "Deep Analysis (工具工作流)", ChineseName = "深度分析工作流", Category = "Analysis", Source = "external", Description = "为 Ghidra / x64dbg / Process Explorer 准备工程、脚本与命令，人工深入分析时直接开工。未安装工具则跳过。" },
    };
}
