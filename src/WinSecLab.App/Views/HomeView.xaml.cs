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

    /// <summary>
    /// 删除项目。破坏性操作，必须明确确认；UI 只做"移入回收站"（可恢复），
    /// 彻底删除留给命令行的 --permanent，避免误点永久丢失分析成果。
    /// </summary>
    private void DeleteProject_OnClick(object sender, RoutedEventArgs e)
    {
        var project = _state.CurrentProject;
        if (project is null) return;

        if (_state.IsRunning)
        {
            MessageBox.Show("分析正在进行中，请等分析结束后再删除项目。", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            $"确定要删除项目「{project.Name}」吗？\n\n"
            + $"项目编号：{project.Id}\n"
            + "该项目的证据、发现与报告会一并处理。\n\n"
            + "项目将移入系统回收站，之后仍可从回收站恢复。",
            "删除项目",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);   // 默认「否」，避免顺手回车误删

        if (confirm != MessageBoxResult.Yes) return;

        var outcome = _state.DeleteProject(project.Id);

        // 回收站不可用（受限环境常见）：不静默永久删除，而是明确问一次
        if (!outcome.Success && outcome.RecycleUnavailable)
        {
            var fallback = MessageBox.Show(
                $"无法移入回收站：{outcome.Error}\n\n"
                + "是否改为彻底删除？此操作不可恢复。",
                "回收站不可用",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);

            if (fallback == MessageBoxResult.Yes)
                outcome = _state.DeleteProject(project.Id, permanent: true);
        }

        if (!outcome.Success)
        {
            MessageBox.Show($"删除失败：{outcome.Error}", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
