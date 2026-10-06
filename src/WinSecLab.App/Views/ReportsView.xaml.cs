using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;

namespace WinSecLab.App.Views;

/// <summary>报告列表条目（显式类型，便于绑定）。</summary>
public sealed class ReportEntry
{
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public string Format { get; init; } = "";
    public DateTime Modified { get; init; }
    public long Size { get; init; }
    public string SizeText => Size < 1024 ? $"{Size} B"
        : Size < 1024 * 1024 ? $"{Size / 1024.0:F0} KB"
        : $"{Size / 1024.0 / 1024.0:F1} MB";
}

public sealed class ReportAction
{
    public string Label { get; init; } = "";
    public string Path { get; init; } = "";

    /// <summary>只有 HTML 能直接打印成 PDF，其它格式不显示导出按钮。</summary>
    public bool CanExportPdf => Path.EndsWith(".html", StringComparison.OrdinalIgnoreCase);
}

public partial class ReportsView : UserControl, IRefreshable
{
    private readonly AppState _state;

    public ReportsView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;
    }

    public void OnActivated() => Reload();

    private void Reload()
    {
        var dir = _state.Layout?.Reports;
        var list = new List<ReportEntry>();

        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.*")
                             .Where(f => f.EndsWith(".html") || f.EndsWith(".md") || f.EndsWith(".json"))
                             .OrderByDescending(File.GetLastWriteTime))
                {
                    var info = new FileInfo(file);
                    list.Add(new ReportEntry
                    {
                        Path = file,
                        Name = info.Name,
                        Format = info.Extension.Trim('.').ToUpperInvariant(),
                        Modified = info.LastWriteTime,
                        Size = info.Length,
                    });
                }
            }
            catch (Exception ex)
            {
                _state.AppendLog($"[报告] 读取报告目录失败：{ex.Message}");
            }
        }

        ReportGrid.ItemsSource = list;
        SummaryText.Text = list.Count == 0
            ? "还没有报告。执行一次分析（勾选「自动生成报告」）或点击下方按钮生成。"
            : $"共 {list.Count} 份报告 · 目录：{dir}";
    }

    private void ReportGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ReportGrid.SelectedItem is not ReportEntry entry)
        {
            SelectedActions.ItemsSource = null;
            NoSelectionText.Visibility = Visibility.Visible;
            return;
        }

        NoSelectionText.Visibility = Visibility.Collapsed;

        // 同一批次的三份报告一起给出，省得用户手动找
        var siblings = Directory.Exists(Path.GetDirectoryName(entry.Path))
            ? Directory.EnumerateFiles(Path.GetDirectoryName(entry.Path)!, Path.GetFileNameWithoutExtension(entry.Path) + ".*")
                .OrderBy(p => p)
                .ToList()
            : new List<string> { entry.Path };

        SelectedActions.ItemsSource = siblings.Select(p => new ReportAction
        {
            Label = Path.GetExtension(p).Trim('.').ToUpperInvariant(),
            Path = p,
        }).ToList();
    }

    private void Regenerate_OnClick(object sender, RoutedEventArgs e)
    {
        if (_state.Result is null)
        {
            MessageBox.Show("还没有分析结果，请先执行一次分析。", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _state.GenerateReportFromStored();
        Reload();
    }

    private void OpenFolder_OnClick(object sender, RoutedEventArgs e)
    {
        var dir = _state.Layout?.Reports;
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
        {
            MessageBox.Show("还没有生成过报告。", "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        AppState.RevealInExplorer(dir);
    }

    private void OpenFile_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path }) AppState.OpenInShell(path);
    }

    private void RevealFile_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path }) AppState.RevealInExplorer(path);
    }

    /// <summary>把选中的 HTML 报告打印成 PDF（Edge 无头，耗时几秒，按钮期间禁用防重复点）。</summary>
    private async void ExportPdf_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string path } btn) return;

        btn.IsEnabled = false;
        var original = btn.Content;
        btn.Content = "导出中…";
        try
        {
            var pdf = await _state.ExportReportPdfAsync(path);
            if (pdf is null)
            {
                MessageBox.Show("PDF 导出失败，详情见运行日志。", "WinSecLab",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Reload();   // 让新生成的 PDF 出现在列表里
            if (MessageBox.Show($"已生成 PDF：\n{Path.GetFileName(pdf)}\n\n现在打开？", "WinSecLab",
                    MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                AppState.OpenInShell(pdf);
        }
        finally
        {
            btn.Content = original;
            btn.IsEnabled = true;
        }
    }
}
