using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

public partial class HomeView : UserControl, IRefreshable
{
    private readonly AppState _state;

    public HomeView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;

        // 必须显式绑定：ItemsSource 不设的话表格只有表头，看起来像"没有数据"
        ProjectGrid.ItemsSource = state.Projects;

        ProfileBox.SelectedIndex = 1;
        UpdateProfileHint();
        RefreshProjectList();
    }

    public void OnActivated()
    {
        RefreshProjectList();
        ProjectGrid.SelectedItem = _state.CurrentProject is null
            ? null
            : _state.Projects.FirstOrDefault(p => p.Id == _state.CurrentProject.Id);
    }

    private void RefreshProjectList()
    {
        _state.RefreshProjects();
        ProjectCountText.Text = _state.Projects.Count == 0
            ? "还没有项目。导入一个目标文件开始。"
            : $"共 {_state.Projects.Count} 个项目 · 双击可切换当前项目";
    }

    private void Refresh_OnClick(object sender, RoutedEventArgs e) => RefreshProjectList();

    // ─────────────────────────────── 选择文件 ───────────────────────────────

    private void DropZone_OnClick(object sender, MouseButtonEventArgs e) => PickFile();

    private void DropZone_OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] files || files.Length == 0) return;
        TargetPathBox.Text = files[0];
    }

    private void PickFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择被测目标文件",
            Filter = "可执行文件|*.exe;*.dll;*.msi;*.sys;*.ocx;*.cpl;*.scr|全部文件|*.*",
            CheckFileExists = true,
        };

        if (dialog.ShowDialog() == true) TargetPathBox.Text = dialog.FileName;
    }

    // ─────────────────────────────── 创建项目 ───────────────────────────────

    private void Create_OnClick(object sender, RoutedEventArgs e)
    {
        var path = TargetPathBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show("请先选择目标文件。", "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!File.Exists(path))
        {
            MessageBox.Show($"文件不存在：\n{path}", "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var profile = SelectedProfile();
        var name = ProjectNameBox.Text?.Trim();
        var created = _state.ImportTarget(path, string.IsNullOrWhiteSpace(name) ? null : name, profile, null);

        if (created is null)
        {
            MessageBox.Show("项目创建失败，详情见「测试执行」页日志。", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        RefreshProjectList();
        TargetPathBox.Clear();
        ProjectNameBox.Clear();

        MessageBox.Show($"项目已创建：{created.Id} — {created.Name}\n\n接下来到「测试执行」页勾选任务并开始分析。",
            "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private TestProfileKind SelectedProfile()
    {
        var tag = (ProfileBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "DesktopApplication";
        return Enum.TryParse<TestProfileKind>(tag, out var p) ? p : TestProfileKind.DesktopApplication;
    }

    private void ProfileBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateProfileHint();
        if (IsInitialized) _state.ApplyProfile(SelectedProfile());
    }

    private void UpdateProfileHint()
    {
        var kind = SelectedProfile();
        var def = TestProfileDefinition.All.FirstOrDefault(p => p.Kind == kind);
        ProfileHintText.Text = def is null
            ? ""
            : $"{def.Tasks.Count} 个任务：{string.Join("、", def.Tasks.Take(6))}{(def.Tasks.Count > 6 ? " …" : "")}";
    }

    // ─────────────────────────────── 项目列表交互 ───────────────────────────────

    private void ProjectGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProjectGrid.SelectedItem is not TestProject project) return;
        if (_state.CurrentProject?.Id == project.Id) return;

        _state.OpenProject(project);
        UpdateProfileHint();
    }

    private void ProjectGrid_OnDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ProjectGrid.SelectedItem is TestProject project)
        {
            _state.OpenProject(project);
            GoRun_OnClick(sender, e);
        }
    }

    private void RevealProject_OnClick(object sender, RoutedEventArgs e)
    {
        AppState.RevealInExplorer(_state.Layout?.Root);
    }

    private void GoRun_OnClick(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow main) main.NavigateTo("Run");
    }
}
