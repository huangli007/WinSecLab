using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;

namespace WinSecLab.App.Views;

public partial class PluginsView : UserControl, IRefreshable
{
    private readonly AppState _state;

    public PluginsView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;
    }

    public void OnActivated() => Reload();

    private void Reload()
    {
        _state.RefreshPlugins();
        PluginList.ItemsSource = _state.Plugins;

        var available = _state.Plugins.Count(p => p.Available);
        var external = _state.Plugins.Count(p => p.Kind == Core.Models.PluginKind.ExternalToolAdapter);
        var externalAvailable = _state.Plugins.Count(p => p.Kind == Core.Models.PluginKind.ExternalToolAdapter && p.Available);

        SummaryText.Text =
            $"共 {_state.Plugins.Count} 个插件，可用 {available} 个。"
            + $"外部工具 {externalAvailable}/{external} 已就绪"
            + (_state.ExternalPluginCount > 0
                ? $"；已加载 {_state.ExternalPluginCount} 个外部程序集插件（与内置代码同等权限运行，请只放可信插件）。"
                : "；插件目录中没有外部程序集插件。");
    }

    private void Reprobe_OnClick(object sender, RoutedEventArgs e)
    {
        Core.Plugins.ExternalToolLocator.InvalidateCache();
        Reload();
        _state.AppendLog("已重新探测外部工具。");
    }

    private void OpenPluginDir_OnClick(object sender, RoutedEventArgs e)
        => AppState.RevealInExplorer(_state.Workspace.PluginsRoot);

    private void TogglePlugin_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { Tag: string id } box) return;

        _state.SetPluginEnabled(id, box.IsChecked == true);
        _state.AppendLog($"插件 {id} 已{(box.IsChecked == true ? "启用" : "禁用")}。");
        Reload();
    }
}
