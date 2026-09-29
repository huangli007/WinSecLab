using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

public partial class EvidenceView : UserControl, IRefreshable
{
    private readonly AppState _state;
    private List<Evidence> _all = new();

    public EvidenceView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;

        SearchBox.ToolTip = "按标题 / 摘要 / 来源 / 对象搜索";
    }

    public void OnActivated()
    {
        _all = _state.Result?.Evidence ?? new List<Evidence>();

        // 类型下拉：按实际出现的类型生成，避免列一堆空类别
        var kinds = _all.Select(e => e.Kind).Distinct().OrderBy(k => k.ToString()).ToList();
        KindBox.Items.Clear();
        KindBox.Items.Add(new ComboBoxItem { Content = "全部类型", Tag = null });
        foreach (var k in kinds)
            KindBox.Items.Add(new ComboBoxItem { Content = DescribeKind(k), Tag = k });
        KindBox.SelectedIndex = 0;

        ApplyFilter();
    }

    private void Search_OnChanged(object sender, TextChangedEventArgs e)
    {
        if (IsInitialized) ApplyFilter();
    }

    private void Kind_OnChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsInitialized) ApplyFilter();
    }

    private void ApplyFilter()
    {
        var query = SearchBox.Text?.Trim() ?? "";
        var kind = (KindBox.SelectedItem as ComboBoxItem)?.Tag as EvidenceKind?;

        IEnumerable<Evidence> items = _all;
        if (kind is not null) items = items.Where(x => x.Kind == kind.Value);

        if (query.Length > 0)
        {
            items = items.Where(x =>
                Contains(x.Title, query) || Contains(x.Summary, query) ||
                Contains(x.Source, query) || Contains(x.Target, query) ||
                Contains(x.Id, query));
        }

        var list = items
            .OrderByDescending(x => x.Kind == EvidenceKind.Yara)
            .ThenBy(x => x.Id, StringComparer.Ordinal)
            .ToList();

        EvidenceGrid.ItemsSource = list;
        CountText.Text = $"共 {list.Count} 条 / 总计 {_all.Count} 条";

        if (list.Count > 0) EvidenceGrid.SelectedIndex = 0;
        else
        {
            DetailScroll.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Visible;
            EmptyHint.Text = _all.Count == 0
                ? "还没有证据。执行一次分析后这里会列出原始事实条目。"
                : "当前筛选条件下没有证据。";
        }
    }

    private static bool Contains(string? text, string query) =>
        !string.IsNullOrEmpty(text) && text.Contains(query, StringComparison.OrdinalIgnoreCase);

    private void EvidenceGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EvidenceGrid.SelectedItem is not Evidence evidence)
        {
            DetailScroll.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Visible;
            return;
        }

        EmptyHint.Visibility = Visibility.Collapsed;
        DetailScroll.Visibility = Visibility.Visible;
        DetailScroll.ScrollToTop();

        DetailId.Text = evidence.Id;
        DetailTitle.Text = evidence.Title;
        DetailTarget.Text = evidence.Target ?? "";
        DetailSummary.Text = evidence.Summary;
        DetailKind.Text = DescribeKind(evidence.Kind);
        DetailSource.Text = evidence.Source;
        DetailTime.Text = evidence.TimestampText;

        TagList.ItemsSource = evidence.Tags;
        TagsLabel.Visibility = evidence.Tags.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        TagList.Visibility = evidence.Tags.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        JsonBox.Text = PrettyJson(evidence.DataJson);
    }

    /// <summary>证据里的 JSON 是紧凑存的，展示时重新缩进；解析失败就原样显示（不吞掉数据）。</summary>
    private static string PrettyJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return "{}";
        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            return json;
        }
    }

    private void CopyJson_OnClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!string.IsNullOrEmpty(JsonBox.Text)) Clipboard.SetText(JsonBox.Text);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"复制失败：{ex.Message}", "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string DescribeKind(EvidenceKind kind) => kind switch
    {
        EvidenceKind.Static => "静态",
        EvidenceKind.Pe => "PE 结构",
        EvidenceKind.Signature => "数字签名",
        EvidenceKind.Strings => "字符串",
        EvidenceKind.Entropy => "熵值 / 加壳",
        EvidenceKind.Dependency => "依赖",
        EvidenceKind.DotNet => ".NET 元数据",
        EvidenceKind.Process => "进程与模块",
        EvidenceKind.FileSystem => "文件系统",
        EvidenceKind.Registry => "注册表",
        EvidenceKind.Network => "网络",
        EvidenceKind.Http => "HTTP",
        EvidenceKind.Yara => "YARA 命中",
        EvidenceKind.ToolOutput => "外部工具输出",
        _ => "人工记录",
    };
}
