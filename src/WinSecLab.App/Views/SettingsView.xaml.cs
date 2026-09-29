using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

public partial class SettingsView : UserControl, IRefreshable
{
    private readonly AppState _state;

    public SettingsView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;
        Load();
    }

    public void OnActivated() => Load();

    private void Load()
    {
        _state.ReloadSettings();
        var s = _state.Settings;

        WorkspaceText.Text = _state.Workspace.Root;

        for (var i = 0; i < ProfileBox.Items.Count; i++)
        {
            if (ProfileBox.Items[i] is ComboBoxItem item && (item.Tag as string) == s.DefaultProfile)
            {
                ProfileBox.SelectedIndex = i;
                break;
            }
        }

        RunSecondsBox.Text = s.TargetRunSeconds.ToString();
        AnalystBox.Text = s.AnalystName ?? "";
        OrgBox.Text = s.Organization ?? "";
        PreferExternalCheck.IsChecked = s.PreferExternalTools;
        CopyTargetCheck.IsChecked = s.CopyTargetIntoProject;
        AutoReportCheck.IsChecked = s.AutoGenerateReport;
    }

    private void Save_OnClick(object sender, RoutedEventArgs e)
    {
        var s = _state.Settings;

        s.DefaultProfile = (ProfileBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "DesktopApplication";
        s.TargetRunSeconds = int.TryParse(RunSecondsBox.Text, out var sec) ? Math.Clamp(sec, 3, 3600) : 60;
        s.AnalystName = string.IsNullOrWhiteSpace(AnalystBox.Text) ? null : AnalystBox.Text.Trim();
        s.Organization = string.IsNullOrWhiteSpace(OrgBox.Text) ? null : OrgBox.Text.Trim();
        s.PreferExternalTools = PreferExternalCheck.IsChecked == true;
        s.CopyTargetIntoProject = CopyTargetCheck.IsChecked == true;
        s.AutoGenerateReport = AutoReportCheck.IsChecked == true;

        _state.SaveSettings();

        if (Enum.TryParse<TestProfileKind>(s.DefaultProfile, out var kind))
            _state.ApplyProfile(kind);

        MessageBox.Show("设置已保存。", "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OpenWorkspace_OnClick(object sender, RoutedEventArgs e)
        => AppState.RevealInExplorer(_state.Workspace.Root);

    private void OpenRules_OnClick(object sender, RoutedEventArgs e)
        => AppState.RevealInExplorer(_state.Workspace.RulesRoot);

    private void OpenPlugins_OnClick(object sender, RoutedEventArgs e)
        => AppState.RevealInExplorer(_state.Workspace.PluginsRoot);
}
