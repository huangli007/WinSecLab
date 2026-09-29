using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;
using WinSecLab.Core.Storage;

namespace WinSecLab.App.Views;

public partial class RunView : UserControl, IRefreshable
{
    private readonly AppState _state;

    public RunView(AppState state)
    {
        _state = state;
        InitializeComponent();

        TaskList.ItemsSource = state.Tasks;
        DataContext = state;

        ProfileBox.SelectedIndex = 1;
        RunSecondsBox.Text = state.Settings.TargetRunSeconds.ToString();
        ReportCheck.IsChecked = state.Settings.AutoGenerateReport;
        ExternalCheck.IsChecked = state.Settings.PreferExternalTools;

        // 自动滚动必须「延迟到布局空闲」再执行，绝不能在这个 CollectionChanged 回调里
        // 直接 ScrollIntoView —— 分析期间日志每秒几十条，集合高频变化时同步滚动会让
        // 虚拟化面板在 Measure 期间检测到「ItemsControl 与项源不一致」直接崩掉（已实测踩过）。
        // 用 BeginInvoke 排队到 Background 优先级 + 合并多次请求，一次布局只滚一次。
        int scrollPending = 0;
        ((INotifyCollectionChanged)state.LogLines).CollectionChanged += (_, _) =>
        {
            if (AutoScrollCheck.IsChecked != true || LogList.Items.Count == 0) return;
            if (Interlocked.Exchange(ref scrollPending, 1) == 1) return;   // 已在排队，合并
            Application.Current?.Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                Interlocked.Exchange(ref scrollPending, 0);
                try
                {
                    if (AutoScrollCheck.IsChecked == true && LogList.Items.Count > 0)
                        LogList.ScrollIntoView(LogList.Items[^1]);
                }
                catch
                {
                    // 布局期间的偶发竞态不该再让程序崩溃 —— 滚到哪算哪，下一条日志会再触发
                }
            });
        };

        ((INotifyCollectionChanged)state.LiveEvents).CollectionChanged += (_, _) =>
            LiveCountText.Text = $"已采集 {state.LiveEvents.Count} 条";

        UpdateRunHint();
    }

    public void OnActivated()
    {
        var kind = _state.CurrentProject?.Profile ?? TestProfileKind.DesktopApplication;
        SelectProfile(kind);
        UpdateRunHint();
    }

    private void SelectProfile(TestProfileKind kind)
    {
        for (var i = 0; i < ProfileBox.Items.Count; i++)
        {
            if (ProfileBox.Items[i] is ComboBoxItem item && (item.Tag as string) == kind.ToString())
            {
                ProfileBox.SelectedIndex = i;
                return;
            }
        }
    }

    private void ProfileBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsInitialized) return;
        var tag = (ProfileBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "DesktopApplication";
        if (Enum.TryParse<TestProfileKind>(tag, out var kind)) _state.ApplyProfile(kind);
        UpdateRunHint();
    }

    private void UpdateRunHint()
    {
        if (_state.CurrentProject is null)
        {
            RunHintText.Text = "请先在「项目」页导入目标文件";
            StartButton.IsEnabled = false;
            return;
        }

        var selected = _state.Tasks.Count(t => t.IsSelected);
        var dynamic = _state.Tasks.Count(t => t.IsSelected && t.RequiresDynamicSession);
        var admin = _state.Tasks.Count(t => t.IsSelected && t.RequiresAdministrator);

        StartButton.IsEnabled = selected > 0 && !_state.IsRunning;

        var parts = new List<string> { $"已选 {selected} 个任务" };
        if (dynamic > 0) parts.Add($"其中 {dynamic} 个需要启动被测程序");
        if (admin > 0 && !WorkspaceService.IsElevated()) parts.Add($"{admin} 个需管理员（当前为受限模式）");
        RunHintText.Text = string.Join("；", parts);
    }

    private async void Start_OnClick(object sender, RoutedEventArgs e)
    {
        if (_state.CurrentProject is null)
        {
            MessageBox.Show("请先在「项目」页导入目标文件。", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_state.Tasks.All(t => !t.IsSelected))
        {
            MessageBox.Show("请至少勾选一个任务。", "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // 动态类任务会真实启动被测程序并改动系统状态，必须先讲清楚
        var dynamicSelected = _state.Tasks.Where(t => t.IsSelected && t.RequiresDynamicSession).ToList();
        if (dynamicSelected.Count > 0)
        {
            var ok = MessageBox.Show(
                "本次包含动态监控任务，将执行以下动作：\n\n"
                + $"· 启动被测程序：{_state.CurrentProject.PrimaryTargetPath}\n"
                + $"· 持续监控 {RunSecondsBox.Text} 秒，采集进程 / 文件 / 注册表 / 网络行为\n"
                + "· 会话结束后自动结束被测进程\n\n"
                + "请在隔离的测试环境中运行，并确认已获得测试授权。是否继续？",
                "确认动态测试", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (ok != MessageBoxResult.Yes) return;
        }

        _state.Settings.TargetRunSeconds = int.TryParse(RunSecondsBox.Text, out var sec) ? Math.Clamp(sec, 3, 3600) : 60;
        _state.Settings.AutoGenerateReport = ReportCheck.IsChecked == true;
        _state.Settings.PreferExternalTools = ExternalCheck.IsChecked == true;
        _state.SaveSettings();

        StartButton.IsEnabled = false;
        RunHintText.Text = "分析进行中…";

        try
        {
            await _state.RunAnalysisAsync(ReportCheck.IsChecked == true);
        }
        finally
        {
            StartButton.IsEnabled = true;
            UpdateRunHint();
        }
    }

    private void ClearLog_OnClick(object sender, RoutedEventArgs e) => _state.LogLines.Clear();
}
