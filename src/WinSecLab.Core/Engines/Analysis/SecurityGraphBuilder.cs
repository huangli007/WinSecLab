using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Analysis;

/// <summary>
/// §11 Security Graph。把静态 / 动态 / 网络 / 注册表的证据连成一张可点击的关系图：
/// 节点带证据 ID，点击即可回到原始记录。
/// 布局用同心圆：中心是被测程序，依次向外是模块 / 网络 / 文件 / 注册表 / 发现。
/// </summary>
public static class SecurityGraphBuilder
{
    private const int MaxNodesPerRing = 14;
    private const int MaxNodesPerKind = 40;

    public static (List<SecurityGraphNode> Nodes, List<SecurityGraphEdge> Edges) Build(AnalysisResult result)
    {
        var nodes = new List<SecurityGraphNode>();
        var edges = new List<SecurityGraphEdge>();
        var index = new Dictionary<string, SecurityGraphNode>(StringComparer.OrdinalIgnoreCase);

        var targetLabel = result.Pe?.FileName ?? result.Project?.Target.FileName ?? "Target";
        var rootId = "root";
        var root = new SecurityGraphNode
        {
            Id = rootId,
            Kind = GraphNodeKind.Process,
            Label = targetLabel,
            Detail = result.Pe is null
                ? "被测目标"
                : $"{result.Pe.Architecture} / {result.Pe.Subsystem} / {(result.Pe.IsDotNet ? ".NET" : "Native")}",
            FullPath = result.Pe?.FilePath ?? result.Project?.Target.FilePath,
            IsTarget = true,
            Weight = 3,
            Severity = Severity.Info,
            EvidenceIds = EvidenceByTag(result, "pe"),
        };
        nodes.Add(root);
        index[rootId] = root;
        root.X = 0;
        root.Y = 0;

        // ---------------------------------------------------------- 静态关联：模块
        foreach (var dependency in result.Dependencies
                     .Where(d => d.IsPresent && !d.IsSystemLibrary)
                     .OrderByDescending(d => d.IsUserWritableLocation)
                     .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                     .Take(MaxNodesPerKind))
        {
            var id = $"mod:{dependency.Name.ToLowerInvariant()}";
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.Module,
                Label = dependency.Name,
                Detail = $"{(dependency.IsSigned == true ? "已签名" : "未签名")} · {dependency.SearchSource}"
                         + (dependency.IsUserWritableLocation ? " · 可写目录" : ""),
                FullPath = dependency.ResolvedPath,
                IsSuspicious = dependency.IsUserWritableLocation,
                Severity = dependency.IsUserWritableLocation ? Severity.High : Severity.Info,
                EvidenceIds = EvidenceByTag(result, "deps"),
                Weight = 1,
            };
            AddNode(node);
            AddEdge(rootId, id, "导入", EvidenceKind.Dependency, dependency.IsUserWritableLocation);
        }

        // ---------------------------------------------------------- 动态关联：进程
        foreach (var group in result.Events
                     .Where(e => e.Type is MonitorEventType.ProcessStart or MonitorEventType.ChildProcess)
                     .GroupBy(e => e.ProcessName, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.First().Depth)
                     .Take(MaxNodesPerKind))
        {
            var first = group.First();
            var id = $"proc:{first.ProcessName.ToLowerInvariant()}";
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.Process,
                Label = first.ProcessName,
                Detail = $"pid={first.ProcessId}，父进程 pid={first.ParentProcessId}，出现 {group.Count()} 次",
                FullPath = first.ProcessPath,
                IsSuspicious = group.Any(e => e.IsSuspicious),
                Severity = group.Any(e => e.IsSuspicious) ? Severity.High : Severity.Info,
                EvidenceIds = EvidenceByTag(result, "process"),
                Weight = 2,
            };
            AddNode(node);
            AddEdge(rootId, id, first.Depth > 0 ? "创建子进程" : "启动", EvidenceKind.Process, node.IsSuspicious);
        }

        // ---------------------------------------------------------- 动态关联：模块加载
        foreach (var group in result.Events
                     .Where(e => e.Type == MonitorEventType.DllLoad)
                     .GroupBy(e => e.Target, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => PathSemantics.IsUserWritable(g.Key))
                     .Take(MaxNodesPerKind))
        {
            var first = group.First();
            var fileName = Path.GetFileName(first.Target);
            var id = $"dll:{first.Target.ToLowerInvariant()}";
            var writable = PathSemantics.IsUserWritable(first.Target);
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.Module,
                Label = fileName.Length > 0 ? fileName : first.Target,
                Detail = $"运行期加载 · {PathSemantics.Shorten(first.Target, 80)}",
                FullPath = first.Target,
                IsSuspicious = writable,
                Severity = writable ? Severity.High : Severity.Info,
                EvidenceIds = EvidenceByTag(result, "process"),
                Weight = 1,
            };
            AddNode(node);
            AddEdge(rootId, id, "加载模块", EvidenceKind.Process, writable);
        }

        // ---------------------------------------------------------- 网络节点
        var networkGroups = result.Connections
            .Where(c => !c.IsLoopback && c.RemoteAddress is not ("0.0.0.0" or "::") && c.IsFromTargetTree)
            .GroupBy(c => c.Domain ?? c.RemoteAddress, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Any(c => c.Domain is null))
            .Take(MaxNodesPerKind)
            .ToList();

        foreach (var group in networkGroups)
        {
            var first = group.First();
            var id = $"net:{group.Key.ToLowerInvariant()}";
            var ports = group.Select(c => c.RemotePort).Distinct().OrderBy(p => p).Take(5).ToList();
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.Network,
                Label = group.Key,
                Detail = $"{group.Count()} 条连接 · 端口 {string.Join("/", ports)}"
                         + (first.Domain is null ? " · 无域名记录" : ""),
                IsSuspicious = group.Any(c => c.Domain is null && !c.IsPrivateAddress && c.RemotePort is not (80 or 443 or 53)),
                Severity = Severity.Medium,
                EvidenceIds = EvidenceByTag(result, "network"),
                Weight = 2,
            };
            AddNode(node);
            AddEdge(rootId, id, "网络连接", EvidenceKind.Network, node.IsSuspicious);
        }

        // DNS 作为网络节点的补充
        foreach (var dns in result.Connections
                     .Where(c => c.Domain is not null)
                     .Select(c => (ProcessName: c.ProcessName, Domain: c.Domain!))
                     .Distinct()
                     .Take(MaxNodesPerKind))
        {
            var procId = $"proc:{dns.ProcessName.ToLowerInvariant()}";
            var netId = $"net:{dns.Domain.ToLowerInvariant()}";
            if (index.ContainsKey(procId) && index.ContainsKey(netId))
                AddEdge(procId, netId, "解析并连接", EvidenceKind.Network, false);
        }

        // ---------------------------------------------------------- 文件节点
        foreach (var group in result.Events
                     .Where(e => e.Type is MonitorEventType.FileCreate or MonitorEventType.FileWrite
                         or MonitorEventType.FileRename or MonitorEventType.FileDelete)
                     .Where(e => e.IsSuspicious || PathSemantics.IsUserWritable(e.Target))
                     .Where(e => !e.Target.Contains(@"\WinSecLab", StringComparison.OrdinalIgnoreCase))
                     .GroupBy(e => Path.GetDirectoryName(e.Target) ?? e.Target, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.Any(e => e.IsSuspicious))
                     .Take(MaxNodesPerKind))
        {
            var first = group.First();
            var id = $"dir:{group.Key.ToLowerInvariant()}";
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.File,
                Label = PathSemantics.Shorten(group.Key, 56),
                Detail = $"{group.Count()} 次文件变更 · 样例 {Path.GetFileName(first.Target)}",
                FullPath = group.Key,
                IsSuspicious = group.Any(e => e.IsSuspicious),
                Severity = group.Any(e => e.IsSuspicious) ? Severity.Medium : Severity.Info,
                EvidenceIds = EvidenceByTag(result, "filesystem"),
                Weight = Math.Min(3, 1 + group.Count() / 10),
            };
            AddNode(node);
            AddEdge(rootId, id, "文件写入", EvidenceKind.FileSystem, node.IsSuspicious);
        }

        // ---------------------------------------------------------- 注册表节点
        foreach (var group in result.Events
                     .Where(e => e.Type is MonitorEventType.RegistryCreate or MonitorEventType.RegistrySet
                         or MonitorEventType.RegistryDelete)
                     .Where(e => e.IsSuspicious || Engines.Dynamic.RegistryMonitor.IsPersistencePath(e.Target))
                     .GroupBy(e => e.Target, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.Any(e => e.IsSuspicious))
                     .Take(MaxNodesPerKind))
        {
            var first = group.First();
            var id = $"reg:{group.Key.ToLowerInvariant()}";
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.Registry,
                Label = ShortenRegistryPath(group.Key),
                Detail = $"{first.Operation} · {group.Count()} 次变更",
                FullPath = group.Key,
                IsSuspicious = group.Any(e => e.IsSuspicious),
                Severity = group.Any(e => e.IsSuspicious) ? Severity.High : Severity.Low,
                EvidenceIds = EvidenceByTag(result, "registry"),
                Weight = 2,
            };
            AddNode(node);
            AddEdge(rootId, id, "注册表变更", EvidenceKind.Registry, node.IsSuspicious);
        }

        // ---------------------------------------------------------- Finding 节点
        foreach (var finding in result.Findings
                     .Where(f => f.Severity >= Severity.Medium)
                     .OrderByDescending(f => f.Severity)
                     .Take(24))
        {
            var id = $"finding:{finding.Id}";
            var node = new SecurityGraphNode
            {
                Id = id,
                Kind = GraphNodeKind.Finding,
                Label = $"{finding.Id} {Truncate(finding.Title, 40)}",
                Detail = $"{finding.Severity} / 置信度 {finding.ConfidenceText}",
                Severity = finding.Severity,
                IsSuspicious = true,
                EvidenceIds = finding.EvidenceIds,
                FindingIds = { finding.Id },
                Weight = 3,
            };
            AddNode(node);

            // 把 Finding 连到它实际引用的实体的节点上，形成「问题挂在哪个对象上」
            var attached = false;
            foreach (var file in finding.RelatedFiles)
            {
                var dir = Path.GetDirectoryName(file);
                var candidate = dir is null ? null : $"dir:{dir.ToLowerInvariant()}";
                if (candidate is not null && index.ContainsKey(candidate))
                {
                    AddEdge(candidate, id, "关联发现", EvidenceKind.Static, true);
                    attached = true;
                }
            }
            foreach (var reg in finding.RelatedRegistry)
            {
                var candidate = $"reg:{reg.ToLowerInvariant()}";
                if (index.ContainsKey(candidate))
                {
                    AddEdge(candidate, id, "关联发现", EvidenceKind.Registry, true);
                    attached = true;
                }
            }
            foreach (var proc in finding.RelatedProcesses)
            {
                var candidate = $"proc:{proc.ToLowerInvariant()}";
                if (index.ContainsKey(candidate))
                {
                    AddEdge(candidate, id, "关联发现", EvidenceKind.Process, true);
                    attached = true;
                }
            }
            foreach (var net in finding.RelatedNetwork)
            {
                var candidate = $"net:{net.ToLowerInvariant()}";
                if (index.ContainsKey(candidate))
                {
                    AddEdge(candidate, id, "关联发现", EvidenceKind.Network, true);
                    attached = true;
                }
            }

            if (!attached) AddEdge(rootId, id, "关联发现", EvidenceKind.Static, true);
        }

        Layout(nodes);
        return (nodes, edges);

        void AddNode(SecurityGraphNode node)
        {
            if (index.ContainsKey(node.Id)) return;
            index[node.Id] = node;
            nodes.Add(node);
        }

        void AddEdge(string source, string target, string relation, EvidenceKind? kind, bool suspicious)
        {
            if (!index.ContainsKey(source) || !index.ContainsKey(target)) return;
            if (source == target) return;
            if (edges.Any(e => e.SourceId == source && e.TargetId == target && e.Relation == relation)) return;
            edges.Add(new SecurityGraphEdge
            {
                SourceId = source,
                TargetId = target,
                Relation = relation,
                EvidenceKind = kind,
                IsSuspicious = suspicious,
            });
        }
    }

    /// <summary>
    /// 同心圆布局：中心是目标，按节点种类分环，同环内均匀分布。
    /// 放在这里而不是 UI 层，保证导出报告时的图形与界面一致。
    /// </summary>
    private static void Layout(List<SecurityGraphNode> nodes)
    {
        var ringByKind = new Dictionary<GraphNodeKind, (double Radius, int Index)>
        {
            [GraphNodeKind.Module] = (180, 0),
            [GraphNodeKind.Network] = (300, 1),
            [GraphNodeKind.Process] = (410, 2),
            [GraphNodeKind.File] = (520, 3),
            [GraphNodeKind.Registry] = (630, 4),
            [GraphNodeKind.Finding] = (740, 5),
        };

        foreach (var group in nodes.Where(n => !n.IsTarget).GroupBy(n => n.Kind))
        {
            if (!ringByKind.TryGetValue(group.Key, out var ring)) continue;

            var items = group
                .OrderByDescending(n => n.IsSuspicious)
                .ThenBy(n => n.Label, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var count = Math.Min(items.Count, MaxNodesPerRing * 4);
            for (var i = 0; i < count; i++)
            {
                var angle = 2 * Math.PI * i / Math.Max(1, count) - Math.PI / 2;
                // 同一环内节点太多时把半径做微小抖动，减少标签重叠
                var radius = ring.Radius + (i / MaxNodesPerRing) * 55;
                items[i].X = Math.Cos(angle) * radius;
                items[i].Y = Math.Sin(angle) * radius;
            }

            // 超出绘制上限的节点叠在环外缘，UI 端可以选择隐藏
            for (var i = count; i < items.Count; i++)
            {
                items[i].X = 0;
                items[i].Y = ring.Radius + 40;
            }
        }
    }

    private static List<string> EvidenceByTag(AnalysisResult result, string tag, int max = 4) =>
        result.Evidence.Where(e => e.Tags.Contains(tag, StringComparer.OrdinalIgnoreCase))
            .Take(max).Select(e => e.Id).ToList();

    private static string ShortenRegistryPath(string path)
    {
        var p = path
            .Replace("HKEY_CURRENT_USER", "HKCU", StringComparison.OrdinalIgnoreCase)
            .Replace("HKEY_LOCAL_MACHINE", "HKLM", StringComparison.OrdinalIgnoreCase)
            .Replace("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "\\...\\CurrentVersion", StringComparison.OrdinalIgnoreCase);
        return PathSemantics.Shorten(p, 52);
    }

    private static string Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) ? "" : value.Length <= max ? value : value[..max] + "…";
}
