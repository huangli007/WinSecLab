namespace WinSecLab.Core.Models;

/// <summary>风险等级。对齐 CVSS 直觉分档。</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>结论置信度。自动发现只做提示，置信度必须显式标注。</summary>
public enum Confidence
{
    Low = 0,
    Medium = 1,
    High = 2,
}

/// <summary>证据种类 —— 对应 §10 自动关联的证据源。</summary>
public enum EvidenceKind
{
    Static,
    Pe,
    Signature,
    Strings,
    Entropy,
    Dependency,
    DotNet,
    Process,
    FileSystem,
    Registry,
    Network,
    Http,
    Yara,
    ToolOutput,
    Manual,
}

/// <summary>监控事件类型。</summary>
public enum MonitorEventType
{
    SessionStart,
    SessionStop,
    ProcessStart,
    ProcessStop,
    ChildProcess,
    DllLoad,
    FileCreate,
    FileWrite,
    FileDelete,
    FileRename,
    FileAccess,
    RegistryCreate,
    RegistrySet,
    RegistryDelete,
    NetworkConnect,
    NetworkListen,
    NetworkClose,
    DnsQuery,
    HttpRequest,
    Note,
}

/// <summary>进程类型识别结果（§3.2）。</summary>
public enum AppRuntimeKind
{
    Unknown,
    NativeCpp,
    DotNet,
    Qt,
    Electron,
    Unity,
    Unreal,
    Go,
    Rust,
    PythonPackaged,
    Java,
    NodeJs,
    Flutter,
    Delphi,
}

/// <summary>目标文件形态。</summary>
public enum TargetFileKind
{
    Executable,
    DynamicLibrary,
    Installer,
    Script,
    Archive,
    Unknown,
}

public enum SignatureStatus
{
    NotSigned,
    Valid,
    ValidButUntrusted,
    Invalid,
    UnknownError,
    Unavailable,
}

public enum FindingStatus
{
    Open,
    Confirmed,
    FalsePositive,
    Remediated,
    Accepted,
}

/// <summary>§12 测试任务系统里的勾选项。</summary>
public enum TestTaskKind
{
    PeAnalysis,
    DependencyScan,
    DigitalSignature,
    StringsScan,
    EntropyScan,
    DotNetAnalysis,
    YaraScan,
    ProcessMonitor,
    FileMonitor,
    RegistryMonitor,
    NetworkCapture,
    HttpProxy,
    TlsAnalysis,
    ToolCorrelation,
    /// <summary>需要人工介入的深度分析工作流（Ghidra 反编译、x64dbg 动态调试、Process Explorer 核对）。</summary>
    DeepAnalysis,
}

/// <summary>§13 测试 Profile。</summary>
public enum TestProfileKind
{
    Custom,
    Basic,
    DesktopApplication,
    DotNetApplication,
    FullSecurityAssessment,
}

/// <summary>测试会话阶段。</summary>
public enum SessionPhase
{
    Idle,
    Preparing,
    Monitoring,
    RunningTarget,
    Finishing,
    Completed,
    Failed,
    Cancelled,
}

/// <summary>插件形态：内置引擎 / 外部工具适配器 / 第三方插件 DLL。</summary>
public enum PluginKind
{
    Builtin,
    ExternalToolAdapter,
    ExternalAssembly,
}

/// <summary>报告输出格式（§18）。</summary>
public enum ReportFormat
{
    Html,
    Markdown,
    Json,
}
