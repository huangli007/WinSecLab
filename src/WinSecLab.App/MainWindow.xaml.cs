using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.App.Views;

namespace WinSecLab.App;

public partial class MainWindow : Window
{
    private readonly AppState _state = new();
    private readonly Dictionary<string, UserControl> _views = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _state;

        WorkspaceText.Text = _state.Workspace.Root;
        WorkspaceText.ToolTip = _state.Workspace.Root;

        _state.Initialize();

        NavList.SelectedIndex = 0;
    }

    private void NavList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (NavList.SelectedItem is not ListBoxItem item) return;

        var tag = item.Tag as string ?? "Home";
        ShowView(tag);
    }

    /// <summary>供页面之间跳转使用（例如"创建项目后去执行测试"）。</summary>
    public void NavigateTo(string tag)
    {
        foreach (var obj in NavList.Items)
        {
            if (obj is ListBoxItem item && (item.Tag as string) == tag)
            {
                NavList.SelectedItem = item;
                return;
            }
        }
    }

    private void ShowView(string tag)
    {
        // 视图按需创建并缓存：切换页面不重建控件，滚动位置与选中项得以保留
        if (!_views.TryGetValue(tag, out var view))
        {
            view = CreateView(tag);
            _views[tag] = view;
        }

        ContentHost.Content = view;

        if (view is IRefreshable refreshable) refreshable.OnActivated();
    }

    private UserControl CreateView(string tag) => tag switch
    {
        "Home" => new HomeView(_state),
        "Run" => new RunView(_state),
        "Overview" => new OverviewView(_state),
        "Findings" => new FindingsView(_state),
        "Evidence" => new EvidenceView(_state),
        "Dynamic" => new DynamicView(_state),
        "Graph" => new GraphView(_state),
        "Reports" => new ReportsView(_state),
        "Plugins" => new PluginsView(_state),
        "Settings" => new SettingsView(_state),
        _ => new HomeView(_state),
    };

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("确定要停止当前分析吗？\n\n已采集到的证据会保留，但本次会话不会得到完整结论。",
                "停止分析", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        _state.Cancel();
    }

    private void OpenReportFolder_OnClick(object sender, RoutedEventArgs e)
    {
        var dir = _state.Layout?.Reports;
        if (dir is null)
        {
            MessageBox.Show("尚未生成报告。请先执行一次分析。", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        AppState.RevealInExplorer(dir);
    }
}

/// <summary>页面被切换到前台时的刷新钩子（避免每页都自己监听一大串事件）。</summary>
public interface IRefreshable
{
    void OnActivated();
}
