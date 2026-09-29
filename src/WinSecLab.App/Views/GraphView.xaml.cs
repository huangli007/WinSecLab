using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

/// <summary>
/// Security Graph 可视化（§11）。
///
/// 用 Canvas + 基础图形手绘，不用第三方图形库：节点规模在几百量级，
/// 手绘足够流畅，且不引入额外的分发依赖（与"最小依赖"的取向一致）。
/// 布局坐标由 Core 的 SecurityGraphBuilder.Layout 预先算好（同心圆分层），
/// 这里只负责画与交互。
/// </summary>
/// <summary>图例项（显式类型，便于绑定）。</summary>
public sealed record LegendItem(string Label, Brush Brush);

public partial class GraphView : UserControl, IRefreshable
{
    private readonly AppState _state;
    private readonly Dictionary<string, Ellipse> _nodeShapes = new();
    private readonly Dictionary<string, SecurityGraphNode> _nodesById = new();

    private double _scale = 1.0;
    private Point _pan;
    private bool _dragging;
    private Point _dragStart;
    private Point _panStart;
    private SecurityGraphNode? _selectedNode;

    public GraphView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;

        // 图例用显式类型而不是匿名类型：WPF 绑定对匿名类型支持不稳，类型明确更省事
        LegendList.ItemsSource = new List<LegendItem>
        {
            new("目标程序", Frozen("#4F46E5")),
            new("模块 / DLL", Frozen("#A5B4FC")),
            new("进程", Frozen("#7DD3FC")),
            new("网络", Frozen("#6EE7B7")),
            new("文件", Frozen("#FCD34D")),
            new("注册表", Frozen("#F9A8D4")),
            new("可疑 / 发现", Frozen("#DC2626")),
        };

        Loaded += (_, _) => Render();
        SizeChanged += (_, _) => Render();
    }

    public void OnActivated() => Render();

    // ─────────────────────────────── 绘制 ───────────────────────────────

    private void Render()
    {
        GraphCanvas.Children.Clear();
        _nodeShapes.Clear();
        _nodesById.Clear();
        _selectedNode = null;
        SelDetailPanel.Visibility = Visibility.Collapsed;

        var result = _state.Result;
        var nodes = result?.GraphNodes ?? new List<SecurityGraphNode>();
        var edges = result?.GraphEdges ?? new List<SecurityGraphEdge>();

        foreach (var n in nodes) _nodesById[n.Id] = n;

        NodeCountText.Text = $"{nodes.Count} 个节点 · {edges.Count} 条关系";
        SummaryText.Text = nodes.Count == 0
            ? "还没有图谱数据。执行一次分析后这里会展开实体关系图。"
            : $"内环是目标与模块，外环依次是进程、网络、文件、注册表、发现；共 {nodes.Count} 个节点、{edges.Count} 条关系，其中可疑节点 {nodes.Count(n => n.IsSuspicious)} 个。";

        EmptyHint.Visibility = nodes.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (nodes.Count == 0)
        {
            NodeGrid.ItemsSource = null;
            return;
        }

        ApplyNodeFilter();

        var width = Math.Max(GraphCanvas.ActualWidth, 400);
        var height = Math.Max(GraphCanvas.ActualHeight, 400);

        // Core 用固定的同心圆半径算坐标，这里等比缩放到当前画布
        var extent = nodes.Max(n => Math.Max(Math.Abs(n.X), Math.Abs(n.Y))) * 2 + 120;
        if (extent <= 0) extent = 800;
        var fit = Math.Min(width / extent, height / extent) * 0.92 * _scale;

        var cx = width / 2 + _pan.X;
        var cy = height / 2 + _pan.Y;

        // 关系线先画，节点压在上面
        foreach (var edge in edges)
        {
            var from = nodes.FirstOrDefault(n => n.Id == edge.SourceId);
            var to = nodes.FirstOrDefault(n => n.Id == edge.TargetId);
            if (from is null || to is null) continue;

            var line = new Line
            {
                X1 = cx + from.X * fit,
                Y1 = cy + from.Y * fit,
                X2 = cx + to.X * fit,
                Y2 = cy + to.Y * fit,
                Stroke = edge.IsSuspicious ? Frozen("#F0A0A0") : Frozen("#D8DCE8"),
                StrokeThickness = edge.IsSuspicious ? 1.6 : 1,
                StrokeDashArray = edge.IsSuspicious ? new DoubleCollection { 3, 2 } : null,
            };
            GraphCanvas.Children.Add(line);
        }

        // 标签取舍：模块节点动辄上百个，全画出来只会糊成一团。
        // 只给"有信息量"的节点加标签（目标、进程、网络、发现，以及权重较高的模块），
        // 并且做矩形碰撞检测，重叠的直接不画 —— 少而准胜过密密麻麻看不清。
        var labelBudget = ShowLabelsCheck.IsChecked == true ? 90 : 0;
        var placed = new List<Rect>();
        var labelled = 0;

        var labelCandidates = nodes
            .Where(n => labelBudget > 0)
            .Where(n => n.Kind != GraphNodeKind.Module || n.IsTarget || n.Weight >= 2 || n.IsSuspicious)
            .OrderByDescending(n => n.IsTarget ? 3 : n.IsSuspicious ? 2 : n.Kind == GraphNodeKind.Module ? 0 : 1)
            .ThenByDescending(n => n.Weight)
            .ToList();

        foreach (var node in nodes)
        {
            var radius = NodeRadius(node);

            var ellipse = new Ellipse
            {
                Width = radius * 2,
                Height = radius * 2,
                Fill = NodeFill(node),
                Stroke = node.IsTarget ? Frozen("#4F46E5") : Frozen("#FFFFFF"),
                StrokeThickness = node.IsTarget ? 2.5 : 1.2,
                ToolTip = BuildTooltip(node),
                Tag = node.Id,   // 点击命中时用 Tag 反查节点，避免 O(n) 遍历
            };

            Canvas.SetLeft(ellipse, cx + node.X * fit - radius);
            Canvas.SetTop(ellipse, cy + node.Y * fit - radius);
            Canvas.SetZIndex(ellipse, node.IsTarget ? 100 : node.Severity is Severity.Critical or Severity.High ? 50 : 10);
            GraphCanvas.Children.Add(ellipse);
            _nodeShapes[node.Id] = ellipse;

            if (labelled >= labelBudget) continue;
            if (radius < 3 || string.IsNullOrEmpty(node.Label)) continue;
            if (!labelCandidates.Contains(node)) continue;

            var text = Shorten(node.Label, 22);
            var labelX = cx + node.X * fit + radius + 4;
            var labelY = cy + node.Y * fit - 7;

            // 估算文本宽度：中文按 10px、西文按 5.6px 计，够用且不用做真实测量
            var approxWidth = EstimateWidth(text, 10);
            var rect = new Rect(labelX - 2, labelY - 1, approxWidth + 4, 14);

            if (placed.Any(r => r.IntersectsWith(rect))) continue;
            placed.Add(rect);
            labelled++;

            var label = new TextBlock
            {
                Text = text,
                FontSize = 10,
                Foreground = Frozen(node.IsTarget ? "#4F46E5" : "#4A5162"),
                FontWeight = node.IsTarget ? FontWeights.SemiBold : FontWeights.Normal,
                IsHitTestVisible = false,
            };
            Canvas.SetLeft(label, labelX);
            Canvas.SetTop(label, labelY);
            Canvas.SetZIndex(label, 120);
            GraphCanvas.Children.Add(label);
        }

        ZoomText.Text = $"缩放 {_scale * 100:F0}% · 滚轮缩放 / 拖拽平移 · 已标注 {labelled} 个节点";
    }

    private static double NodeRadius(SecurityGraphNode node) => node.Kind switch
    {
        GraphNodeKind.Module => node.IsTarget ? 13 : 6,
        GraphNodeKind.Process => 9,
        GraphNodeKind.Network => 7,
        GraphNodeKind.File => 6,
        GraphNodeKind.Registry => 5.5,
        _ => 8,
    };

    private static Brush NodeFill(SecurityGraphNode node)
    {
        if (node.IsTarget) return Frozen("#4F46E5");
        if (node.IsSuspicious)
        {
            return node.Severity switch
            {
                Severity.Critical => Frozen("#B91C1C"),
                Severity.High => Frozen("#DC2626"),
                Severity.Medium => Frozen("#D97706"),
                _ => Frozen("#0284C7"),
            };
        }

        return node.Kind switch
        {
            GraphNodeKind.Module => Frozen("#A5B4FC"),
            GraphNodeKind.Process => Frozen("#7DD3FC"),
            GraphNodeKind.Network => Frozen("#6EE7B7"),
            GraphNodeKind.File => Frozen("#FCD34D"),
            GraphNodeKind.Registry => Frozen("#F9A8D4"),
            _ => Frozen("#C4C9D6"),
        };
    }

    /// <summary>粗略估算文本像素宽度：CJK 约等于字号，ASCII 约等于字号的一半。</summary>
    private static double EstimateWidth(string text, double fontSize)
    {
        double sum = 0;
        foreach (var c in text) sum += c > 0x2E80 ? fontSize : fontSize * 0.56;
        return sum;
    }

    private static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    private static string BuildTooltip(SecurityGraphNode node)
    {
        var lines = new List<string> { $"{node.KindLabel}：{node.Label}" };
        if (!string.IsNullOrWhiteSpace(node.Detail)) lines.Add(node.Detail!);
        if (!string.IsNullOrWhiteSpace(node.FullPath)) lines.Add(node.FullPath!);
        if (node.IsSuspicious) lines.Add($"[可疑] 级别 {node.Severity}");
        if (node.EvidenceIds.Count > 0) lines.Add($"证据 {node.EvidenceIds.Count} 条");
        if (node.FindingIds.Count > 0) lines.Add($"发现 {string.Join("、", node.FindingIds)}");
        return string.Join("\n", lines);
    }

    private static string Shorten(string text, int max) =>
        text.Length <= max ? text : text[..(max - 1)] + "…";

    // ─────────────────────────────── 筛选 ───────────────────────────────

    private void NodeFilter_OnChanged(object sender, RoutedEventArgs e)
    {
        if (IsInitialized) ApplyNodeFilter();
    }

    private void ApplyNodeFilter()
    {
        var nodes = _state.Result?.GraphNodes ?? new List<SecurityGraphNode>();
        var list = SuspiciousOnlyCheck.IsChecked == true
            ? nodes.Where(n => n.IsSuspicious).ToList()
            : nodes;

        NodeGrid.ItemsSource = list
            .OrderByDescending(n => n.IsSuspicious)
            .ThenByDescending(n => n.Weight)
            .ToList();
    }

    private void NodeGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (NodeGrid.SelectedItem is SecurityGraphNode node)
            SelectNode(node);
    }

    /// <summary>选中一个节点：画布高亮 + 右侧详情联动。</summary>
    private void SelectNode(SecurityGraphNode node)
    {
        _selectedNode = node;

        // 同步列表选中（若列表里可见该节点）；WPF 对相同项不会重复触发 SelectionChanged，无递归风险
        if (!ReferenceEquals(NodeGrid.SelectedItem, node))
            NodeGrid.SelectedItem = node;

        // 选中节点高亮：其余节点降透明度，避免在大图里找不到目标
        if (_nodeShapes.TryGetValue(node.Id, out var shape))
        {
            foreach (var s in _nodeShapes.Values) s.Opacity = 0.35;
            shape.Opacity = 1;
            shape.StrokeThickness = 3;
            shape.Stroke = Frozen("#4F46E5");
        }

        SelDetailPanel.Visibility = Visibility.Visible;
        RefreshNodeDetail(node);
    }

    /// <summary>刷新右侧详情：节点自身信息 + 关联证据/发现/关系（回溯到原始证据）。</summary>
    private void RefreshNodeDetail(SecurityGraphNode node)
    {
        SelKind.Text = node.KindLabel;
        SelLabel.Text = node.Label;
        SelPath.Text = node.FullPath ?? "";
        SelPath.Visibility = string.IsNullOrEmpty(node.FullPath) ? Visibility.Collapsed : Visibility.Visible;
        SelDetail.Text = node.Detail ?? "";
        SelDetail.Visibility = string.IsNullOrEmpty(node.Detail) ? Visibility.Collapsed : Visibility.Visible;

        SelSuspectBadge.Visibility = node.IsSuspicious ? Visibility.Visible : Visibility.Collapsed;
        SelSeverity.Text = node.Severity switch
        {
            Severity.Critical => "严重",
            Severity.High => "高",
            Severity.Medium => "中",
            Severity.Low => "低",
            _ => "可疑",
        };

        var result = _state.Result;

        // 关联证据
        var evidence = result?.Evidence ?? new List<Evidence>();
        var evList = node.EvidenceIds
            .Select(id => evidence.FirstOrDefault(x => x.Id == id))
            .Where(x => x is not null)
            .Cast<Evidence>()
            .Select(x => $"· {x.Title}（{x.Source}）")
            .ToList();
        SelEvidenceHeader.Text = $"关联证据（{evList.Count}）";
        SelEvidenceList.ItemsSource = evList;
        SelEvidenceHeader.Visibility = evList.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        // 关联发现
        var findings = result?.Findings ?? new List<Finding>();
        var findList = node.FindingIds
            .Select(id => findings.FirstOrDefault(f => f.Id == id))
            .Where(f => f is not null)
            .Cast<Finding>()
            .Select(f => $"· [{f.SeverityText}] {f.Title}")
            .ToList();
        SelFindingHeader.Text = $"关联发现（{findList.Count}）";
        SelFindingList.ItemsSource = findList;
        SelFindingHeader.Visibility = findList.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        // 关联关系（与其它节点的边）
        var edges = result?.GraphEdges ?? new List<SecurityGraphEdge>();
        var edgeList = edges
            .Where(e => e.SourceId == node.Id || e.TargetId == node.Id)
            .Select(e =>
            {
                var otherId = e.SourceId == node.Id ? e.TargetId : e.SourceId;
                var otherLabel = _nodesById.TryGetValue(otherId, out var other) ? other.Label : otherId;
                var dir = e.SourceId == node.Id ? "→" : "←";
                return $"· {node.Label} {dir} {otherLabel}{(string.IsNullOrEmpty(e.Relation) ? "" : $"（{e.Relation}）")}";
            })
            .Take(30)
            .ToList();
        SelEdgeHeader.Text = $"关联关系（{edgeList.Count}）";
        SelEdgeList.ItemsSource = edgeList;
        SelEdgeHeader.Visibility = edgeList.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    // ─────────────────────────────── 交互 ───────────────────────────────

    private void ToggleLabels_OnChanged(object sender, RoutedEventArgs e)
    {
        if (IsInitialized) Render();
    }

    private void Reset_OnClick(object sender, RoutedEventArgs e)
    {
        _scale = 1.0;
        _pan = new Point(0, 0);
        Render();
    }

    private void GraphCanvas_OnMouseWheel(object sender, MouseWheelEventArgs e)
    {
        var old = _scale;
        _scale = Math.Clamp(_scale * (e.Delta > 0 ? 1.12 : 1 / 1.12), 0.25, 6.0);
        if (Math.Abs(old - _scale) > 0.0001) Render();
        e.Handled = true;
    }

    private void GraphCanvas_OnMouseDown(object sender, MouseButtonEventArgs e)
    {
        _dragging = true;
        _dragStart = e.GetPosition(GraphCanvas);
        _panStart = _pan;
        GraphCanvas.CaptureMouse();
        GraphCanvas.Cursor = Cursors.SizeAll;
    }

    private void GraphCanvas_OnMouseMove(object sender, MouseEventArgs e)
    {
        if (_dragging)
        {
            var now = e.GetPosition(GraphCanvas);
            _pan = new Point(_panStart.X + (now.X - _dragStart.X), _panStart.Y + (now.Y - _dragStart.Y));
            Render();
            return;
        }

        // 悬停提示：命中测试直接用画布，避免为每个节点挂事件
        var hit = GraphCanvas.InputHitTest(e.GetPosition(GraphCanvas)) as Ellipse;
        if (hit?.ToolTip is string tip)
        {
            NodeTip.Text = tip;
            NodeTip.Visibility = Visibility.Visible;
            var pos = e.GetPosition(GraphCanvas);
            Canvas.SetLeft(NodeTip, Math.Min(pos.X + 14, Math.Max(0, GraphCanvas.ActualWidth - 330)));
            Canvas.SetTop(NodeTip, pos.Y + 14);
        }
        else
        {
            NodeTip.Visibility = Visibility.Collapsed;
        }
    }

    private void GraphCanvas_OnMouseUp(object sender, MouseButtonEventArgs e)
    {
        var wasDragging = _dragging;
        _dragging = false;
        GraphCanvas.ReleaseMouseCapture();
        GraphCanvas.Cursor = Cursors.Arrow;

        // 只有"没拖拽"（原地点击）才做节点命中选中；拖拽平移后松开不算点击
        if (wasDragging)
        {
            var now = e.GetPosition(GraphCanvas);
            var moved = Math.Abs(now.X - _dragStart.X) + Math.Abs(now.Y - _dragStart.Y);
            if (moved > 4) return;   // 实际拖拽了，不是点击
        }

        // 命中测试：找到被点中的节点（Ellipse.Tag 存了节点 Id）
        if (GraphCanvas.InputHitTest(e.GetPosition(GraphCanvas)) is Ellipse { Tag: string nodeId }
            && _nodesById.TryGetValue(nodeId, out var node))
        {
            SelectNode(node);
        }
    }
}
