using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

public partial class DynamicView : UserControl, IRefreshable
{
    private readonly AppState _state;
    private List<MonitorEvent> _events = new();
    private List<NetworkConnection> _connections = new();

    public DynamicView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;

        EventSearchBox.ToolTip = "按进程名 / 操作 / 对象搜索";
        ConnSearchBox.ToolTip = "按进程名 / 地址 / 域名搜索";
    }

    public void OnActivated()
    {
        var result = _state.Result;
        _events = result?.Events ?? new List<MonitorEvent>();
        _connections = result?.Connections ?? new List<NetworkConnection>();

        SummaryText.Text = result is null
            ? "还没有动态数据。执行一次包含动态任务的分析后会填充这里。"
            : $"事件 {_events.Count} 条（可疑 {_events.Count(e => e.IsSuspicious)} 条）· "
              + $"进程树 {result.ProcessTree.Count} 个节点 · 连接 {_connections.Count} 条 · "
              + $"DNS {result.DnsObservations.Count} 条 · HTTP {result.Http.Count} 条 · "
              + $"YARA {result.YaraMatches.Count} 条";

        TreeGrid.ItemsSource = result?.ProcessTree ?? new List<ProcessTreeEntry>();
        DnsGrid.ItemsSource = result?.DnsObservations ?? new List<DnsObservation>();
        YaraGrid.ItemsSource = result?.YaraMatches ?? new List<YaraMatch>();

        var http = result?.Http ?? new List<HttpExchange>();
        HttpGrid.ItemsSource = http;
        HttpGrid.Visibility = http.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        HttpHint.Visibility = http.Count > 0 ? Visibility.Collapsed : Visibility.Visible;

        ApplyEventFilter();
        ApplyConnectionFilter();
    }

    // ─────────────────────────────── 事件筛选 ───────────────────────────────

    private void EventSearch_OnChanged(object sender, TextChangedEventArgs e)
    {
        if (IsInitialized) ApplyEventFilter();
    }

    private void EventFilter_OnChanged(object sender, RoutedEventArgs e)
    {
        if (IsInitialized) ApplyEventFilter();
    }

    private void ApplyEventFilter()
    {
        var query = EventSearchBox.Text?.Trim() ?? "";
        var suspiciousOnly = SuspiciousOnlyCheck.IsChecked == true;

        IEnumerable<MonitorEvent> items = _events;
        if (suspiciousOnly) items = items.Where(e => e.IsSuspicious);
        if (query.Length > 0)
        {
            items = items.Where(e =>
                Contains(e.ProcessName, query) || Contains(e.Operation, query) ||
                Contains(e.Target, query) || Contains(e.Detail, query));
        }

        var list = items.OrderByDescending(e => e.Timestamp).Take(6000).ToList();
        EventGrid.ItemsSource = list;
        EventCountText.Text = $"显示 {list.Count} 条 / 共 {_events.Count} 条";
    }

    private void ConnSearch_OnChanged(object sender, TextChangedEventArgs e)
    {
        if (IsInitialized) ApplyConnectionFilter();
    }

    private void ApplyConnectionFilter()
    {
        var query = ConnSearchBox.Text?.Trim() ?? "";

        IEnumerable<NetworkConnection> items = _connections;
        if (query.Length > 0)
        {
            items = items.Where(c =>
                Contains(c.ProcessName, query) || Contains(c.RemoteAddress, query) ||
                Contains(c.Domain, query) || Contains(c.RemoteEndpoint, query));
        }

        var list = items.OrderByDescending(c => c.LastSeen).Take(4000).ToList();
        ConnGrid.ItemsSource = list;
        ConnCountText.Text = $"显示 {list.Count} 条 / 共 {_connections.Count} 条";
    }

    private static bool Contains(string? text, string query) =>
        !string.IsNullOrEmpty(text) && text.Contains(query, StringComparison.OrdinalIgnoreCase);
}
