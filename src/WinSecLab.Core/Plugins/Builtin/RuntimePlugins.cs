using WinSecLab.Core.Engines.Dynamic;
using WinSecLab.Core.Engines.Network;
using WinSecLab.Core.Engines.Rules;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Plugins.Builtin;

/// <summary>
/// §4/§5 运行期监控三件套。它们不自己采集数据 —— 数据由 <see cref="DynamicSession"/> 统一持有，
/// 插件在这里的作用是：参与任务编排、把会话事件整理成语义化证据、把产物落盘。
/// 这样保证「同一份事件流」既喂给 UI 实时显示，也喂给规则引擎与报告，不会出现两套数据。
/// </summary>
public sealed class ProcessMonitorPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.process";
    public string Name => "Process Monitor";
    public string Version => "1.0";
    public string? Description => "跟踪进程创建 / 退出、子进程与模块加载。有管理员权限时走 WMI 事件，否则 1 秒轮询。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.ProcessMonitor };
    public bool RequiresDynamicSession => true;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect()
    {
        var elevated = SessionProbe.IsElevated();
        return PluginProbeResult.Builtin(elevated
            ? "WMI 进程事件通道可用（管理员），进程创建实时无遗漏"
            : "标准用户：WMI 事件受限，退化为 1 秒轮询，可能漏掉极短命进程");
    }

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context) =>
        Task.FromResult(RuntimeEvidence.BuildProcessEvidence(context, "builtin.process"));

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class FileMonitorPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.filesystem";
    public string Name => "File System Monitor";
    public string Version => "1.0";
    public string? Description => "监控可写目录与自启动目录的文件创建 / 写入 / 删除。按路径相关性与时间窗归因。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.FileMonitor };
    public bool RequiresDynamicSession => true;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin(
        "内置 FileSystemWatcher 监控（无 PID 归因，走路径相关性过滤；精确归因请配合 Process Monitor 适配器）");

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context) =>
        Task.FromResult(RuntimeEvidence.BuildFileEvidence(context, "builtin.filesystem"));

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class RegistryMonitorPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.registry";
    public string Name => "Registry Monitor";
    public string Version => "1.0";
    public string? Description => "监控自启动、服务、IFEO、Winlogon、AppInit、环境变量等关键位置的创建与修改。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.RegistryMonitor };
    public bool RequiresDynamicSession => true;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect()
    {
        var elevated = SessionProbe.IsElevated();
        return PluginProbeResult.Builtin(elevated
            ? "WMI 注册表事件 + 快照差分双通道"
            : "标准用户：WMI 注册表事件不可用，仅快照差分（时间精度为扫描间隔）");
    }

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context) =>
        Task.FromResult(RuntimeEvidence.BuildRegistryEvidence(context, "builtin.registry"));

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class NetworkCapturePlugin : IWinSecLabPlugin
{
    public string Id => "builtin.network";
    public string Name => "Network Capture";
    public string Version => "1.0";
    public string? Description => "按 owning PID 抓取 TCP/UDP 连接表与 DNS 观测；连接归因为精确级。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.NetworkCapture };
    public bool RequiresDynamicSession => true;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() =>
        PluginProbeResult.Builtin("内置 iphlpapi 连接表抓取（GetExtendedTcpTable，带 PID 精确归因）+ DNS 缓存观测");

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context) =>
        Task.FromResult(RuntimeEvidence.BuildNetworkEvidence(context, "builtin.network"));

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

public sealed class HttpProxyPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.http";
    public string Name => "HTTP Analyzer";
    public string Version => "1.0";
    public string? Description => "本地正向代理记录 HTTP 请求历史（Burp 风格），支持 Repeater 重放。HTTPS 仅记录 CONNECT 目标，不解密。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.HttpProxy };
    public bool RequiresDynamicSession => true;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin(
        "内置正向代理（明文 HTTP 完整解析 + HTTPS CONNECT 隧道记录）。需把被测程序的代理指向 127.0.0.1:8877");

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context) =>
        Task.FromResult(RuntimeEvidence.BuildHttpEvidence(context, "builtin.http"));

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}

internal static class SessionProbe
{
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

/// <summary>把会话事件整理成语义化证据。UI、规则引擎、报告共用同一批 Evidence。</summary>
internal static class RuntimeEvidence
{
    public static PluginRunResult BuildProcessEvidence(PluginContext context, string source)
    {
        var events = context.Result.Events;
        var processEvents = events.Where(e => e.Type is MonitorEventType.ProcessStart
            or MonitorEventType.ProcessStop or MonitorEventType.ChildProcess).ToList();
        var dllEvents = events.Where(e => e.Type == MonitorEventType.DllLoad).ToList();

        if (processEvents.Count == 0 && dllEvents.Count == 0)
            return PluginRunResult.Skipped("本次会话未采集到进程事件（目标可能未启动或瞬间退出）");

        var tree = context.Result.ProcessTree;
        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Process, "进程与模块活动", source,
                context.Session?.RootProcessPath ?? context.TargetPath,
                $"进程事件 {processEvents.Count} 条（其中子进程 {processEvents.Count(e => e.Type == MonitorEventType.ChildProcess)} 条），"
                + $"模块加载 {dllEvents.Count} 条（其中来自可写目录 {dllEvents.Count(e => e.IsSuspicious)} 条）",
                processEvents.Take(2000).ToList(), "process", "dynamic"),
        };

        if (tree.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Process, "进程树快照", source,
                context.TargetPath, string.Join("；", tree.Take(20).Select(t => $"{t.Name}(pid={t.Pid})")),
                tree, "process", "dynamic"));
        }

        var suspiciousModules = dllEvents.Where(e => e.IsSuspicious).ToList();
        if (suspiciousModules.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Process, "从可写目录加载的模块", source,
                context.TargetPath,
                string.Join("；", suspiciousModules.Take(10).Select(e => $"{e.ProcessName} → {e.Target}")),
                suspiciousModules, "process", "dynamic", "dll-hijack"));
        }

        var children = processEvents.Where(e => e.Type == MonitorEventType.ChildProcess).ToList();
        if (children.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Process, "子进程创建记录", source,
                context.TargetPath,
                string.Join("；", children.Take(10).Select(e => $"{e.ProcessName}(pid={e.ProcessId})")),
                children, "process", "dynamic"));
        }

        return PluginRunResult.Ok(
            $"进程监控整理完成：{processEvents.Count} 条进程事件，{dllEvents.Count} 条模块加载", evidence);
    }

    public static PluginRunResult BuildFileEvidence(PluginContext context, string source)
    {
        var events = context.Result.Events.Where(e => e.Type is MonitorEventType.FileCreate
            or MonitorEventType.FileWrite or MonitorEventType.FileDelete or MonitorEventType.FileRename).ToList();

        if (events.Count == 0)
            return PluginRunResult.Skipped("本次会话未采集到文件系统事件（文件监控未挂载或目标无文件操作）");

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.FileSystem, "文件系统变更", source,
                context.TargetPath,
                $"共 {events.Count} 条文件事件，涉及 {events.Select(e => Path.GetDirectoryName(e.Target)).Distinct().Count()} 个目录，"
                + $"其中可执行文件相关 {events.Count(e => RuleContext.IsExecutablePath(e.Target))} 条",
                events.Take(2000).ToList(), "filesystem", "dynamic"),
        };

        var executables = events.Where(e => RuleContext.IsExecutablePath(e.Target)).ToList();
        if (executables.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.FileSystem, "可执行文件落地", source,
                context.TargetPath,
                string.Join("；", executables.Take(10).Select(e => $"{e.Type} {e.Target}")),
                executables, "filesystem", "dynamic", "dropped-file"));
        }

        var persistence = events.Where(e => e.Target.Contains("Startup", StringComparison.OrdinalIgnoreCase)).ToList();
        if (persistence.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.FileSystem, "自启动目录变更", source,
                context.TargetPath, string.Join("；", persistence.Take(10).Select(e => e.Target)),
                persistence, "filesystem", "dynamic", "persistence"));
        }

        return PluginRunResult.Ok($"文件监控整理完成：{events.Count} 条事件", evidence);
    }

    public static PluginRunResult BuildRegistryEvidence(PluginContext context, string source)
    {
        var events = context.Result.Events.Where(e => e.Type is MonitorEventType.RegistryCreate
            or MonitorEventType.RegistrySet or MonitorEventType.RegistryDelete).ToList();

        if (events.Count == 0)
            return PluginRunResult.Skipped("本次会话未采集到注册表变更");

        var persistence = events.Where(e => RegistryMonitor.IsPersistencePath(e.Target)).ToList();

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Registry, "注册表变更", source, context.TargetPath,
                $"共 {events.Count} 条变更（新增 {events.Count(e => e.Type == MonitorEventType.RegistryCreate)}，"
                + $"修改 {events.Count(e => e.Type == MonitorEventType.RegistrySet)}，"
                + $"删除 {events.Count(e => e.Type == MonitorEventType.RegistryDelete)}），"
                + $"其中持久化相关 {persistence.Count} 条",
                events.Take(3000).ToList(), "registry", "dynamic"),
        };

        if (persistence.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Registry, "持久化位置变更", source,
                context.TargetPath,
                string.Join("；", persistence.Take(10).Select(e => $"{e.Operation} {e.Target}")),
                persistence, "registry", "dynamic", "persistence"));
        }

        return PluginRunResult.Ok($"注册表监控整理完成：{events.Count} 条变更，持久化相关 {persistence.Count} 条", evidence);
    }

    public static PluginRunResult BuildNetworkEvidence(PluginContext context, string source)
    {
        var connections = context.Result.Connections;
        var dns = context.Result.DnsObservations;

        if (connections.Count == 0 && dns.Count == 0)
            return PluginRunResult.Skipped("本次会话未采集到网络连接或 DNS 观测");

        var external = connections.Where(c => !c.IsLoopback && c.RemoteAddress is not ("0.0.0.0" or "::")).ToList();
        var domains = connections.Where(c => c.Domain is not null).Select(c => c.Domain!).Distinct().ToList();

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Network, "网络连接汇总", source, context.TargetPath,
                $"共 {connections.Count} 条连接记录，对外连接 {external.Count} 条，解析到域名 {domains.Count} 个"
                + (domains.Count > 0 ? $"：{string.Join("、", domains.Take(12))}" : ""),
                new
                {
                    connections,
                    dns,
                    observationCount = connections.Sum(c => c.ObservationCount),
                    resolvedDomains = domains,
                },
                "network", "dynamic"),
        };

        if (dns.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Network, "DNS 观测记录", source,
                context.TargetPath,
                string.Join("；", dns.Take(10).Select(d => $"{d.HostName} → {d.AddressText}")),
                dns, "network", "dynamic", "dns"));
        }

        var listening = connections.Where(c => c.State == ConnectionState.Listen && c.IsFromTargetTree).ToList();
        if (listening.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Network, "本地监听端口", source,
                context.TargetPath,
                string.Join("；", listening.Take(200).Select(c => $"{c.ProcessName} {c.LocalEndpoint}")),
                listening, "network", "dynamic", "listen"));
        }

        return PluginRunResult.Ok($"网络监控整理完成：{connections.Count} 条连接，{domains.Count} 个域名", evidence);
    }

    public static PluginRunResult BuildHttpEvidence(PluginContext context, string source)
    {
        var http = context.Result.Http;
        if (http.Count == 0)
            return PluginRunResult.Skipped("代理未捕获到 HTTP 请求（被测程序可能未走系统代理，或全部流量为 HTTPS）");

        var interesting = http.Where(x => x.IsInteresting).ToList();

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Http, "HTTP 请求历史", source, context.TargetPath,
                $"共 {http.Count} 条请求，覆盖 {http.Select(x => x.Host).Distinct().Count()} 个主机，其中值得关注 {interesting.Count} 条",
                http.Select(Summarize).ToList(), "http", "dynamic"),
        };

        if (interesting.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Http, "值得关注的 HTTP 请求", source,
                context.TargetPath,
                string.Join("；", interesting.Take(8).Select(x => $"{x.Method} {x.Url}（{string.Join("，", x.InterestReasons)}）")),
                interesting.Select(Summarize).ToList(), "http", "dynamic", "interesting"));
        }

        return PluginRunResult.Ok($"HTTP 分析整理完成：{http.Count} 条请求，{interesting.Count} 条值得关注", evidence);
    }

    /// <summary>证据里不保留完整响应体，避免数据库无限膨胀；请求体与头部保留以便复现。</summary>
    private static object Summarize(HttpExchange x) => new
    {
        x.Id,
        x.Method,
        x.Url,
        x.StatusCode,
        x.StatusText,
        RequestHeaders = x.RequestHeaders,
        RequestBody = x.RequestBody,
        ResponseContentType = x.ResponseContentType,
        ResponseBodyPreview = x.ResponseBody is null ? null
            : x.ResponseBody.Length > 4096 ? x.ResponseBody[..4096] + "…（截断）" : x.ResponseBody,
        x.DurationMs,
        x.IsInteresting,
        x.InterestReasons,
        x.Error,
    };
}
