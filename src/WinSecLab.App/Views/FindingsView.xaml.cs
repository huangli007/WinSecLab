using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

public partial class FindingsView : UserControl, IRefreshable
{
    private readonly AppState _state;
    private Severity? _filter;

    public FindingsView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;
    }

    public void OnActivated()
    {
        var findings = _state.Result?.Findings ?? new List<Finding>();
        SummaryText.Text = findings.Count == 0
            ? "还没有发现。执行一次分析后这里会列出所有问题。"
            : $"{findings.Count} 条：{_state.FindingStats}";

        ApplyFilter();
    }

    /// <summary>把当前发现清单导出为 CSV（Excel 直接打开，可做跟踪表）。</summary>
    private void ExportCsv_OnClick(object sender, RoutedEventArgs e)
    {
        var path = _state.ExportFindingsCsv();
        if (path is null)
        {
            MessageBox.Show("没有可导出的结果，请先执行一次分析。", "WinSecLab",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // 导出成功后直接打开，省一步「去报告目录找文件」
        AppState.OpenInShell(path);
    }

    private void Filter_OnChanged(object sender, RoutedEventArgs e)
    {
        if (!IsInitialized) return;

        _filter = ReferenceEquals(sender, CriticalRadio) ? Severity.Critical
            : ReferenceEquals(sender, HighRadio) ? Severity.High
            : ReferenceEquals(sender, MediumRadio) ? Severity.Medium
            : ReferenceEquals(sender, LowRadio) ? Severity.Low
            : ReferenceEquals(sender, InfoRadio) ? Severity.Info
            : null;

        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var findings = _state.Result?.Findings ?? new List<Finding>();
        var filtered = _filter is null
            ? findings
            : findings.Where(f => f.Severity == _filter.Value).ToList();

        // 已按严重级排序，这里再稳一次，保证报告与界面顺序一致
        FindingGrid.ItemsSource = filtered
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();

        if (FindingGrid.Items.Count > 0) FindingGrid.SelectedIndex = 0;
        else
        {
            DetailScroll.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Visible;
            EmptyHint.Text = findings.Count == 0
                ? "还没有发现。执行一次分析后这里会列出所有问题。"
                : "当前筛选条件下没有发现。";
        }
    }

    private void FindingGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingGrid.SelectedItem is not Finding finding)
        {
            DetailScroll.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Visible;
            return;
        }

        EmptyHint.Visibility = Visibility.Collapsed;
        DetailScroll.Visibility = Visibility.Visible;
        DetailScroll.ScrollToTop();

        DetailSeverity.Text = finding.SeverityText;
        DetailRuleId.Text = $"规则 {finding.RuleId}";
        DetailConfidence.Text = $"置信度 {finding.ConfidenceText}";
        DetailTitle.Text = $"{finding.Id}  {finding.Title}";
        DetailTarget.Text = string.IsNullOrWhiteSpace(finding.Target) ? "" : finding.Target;

        DetailDescription.Text = finding.Description;
        SetBlock(ImpactBlock, DetailImpact, finding.Impact);
        SetBlock(ReproBlock, DetailReproduction, finding.Reproduction);
        SetBlock(RecommendBlock, DetailRecommendation, finding.Recommendation);

        DetailCwe.Text = string.IsNullOrWhiteSpace(finding.CweId) ? "" : finding.CweId;
        DetailOwasp.Text = string.IsNullOrWhiteSpace(finding.OwaspCategory) ? "" : finding.OwaspCategory;
        StandardBlock.Visibility = string.IsNullOrWhiteSpace(finding.CweId) && string.IsNullOrWhiteSpace(finding.OwaspCategory)
            ? Visibility.Collapsed
            : Visibility.Visible;

        // 关联证据：从已载入的证据集合里按 ID 取，保证点得回去
        var evidence = _state.Result?.Evidence ?? new List<Evidence>();
        var related = finding.EvidenceIds
            .Select(id => evidence.FirstOrDefault(x => x.Id == id))
            .Where(x => x is not null)
            .Cast<Evidence>()
            .ToList();
        EvidenceList.ItemsSource = related;

        var entities = new List<string>();
        entities.AddRange(finding.RelatedProcesses.Select(x => $"进程  {x}"));
        entities.AddRange(finding.RelatedFiles.Select(x => $"文件  {x}"));
        entities.AddRange(finding.RelatedRegistry.Select(x => $"注册表 {x}"));
        entities.AddRange(finding.RelatedNetwork.Select(x => $"网络  {x}"));
        EntityList.ItemsSource = entities.Distinct().Take(40).ToList();
    }

    private static void SetBlock(FrameworkElement block, TextBlock text, string? value)
    {
        var has = !string.IsNullOrWhiteSpace(value);
        block.Visibility = has ? Visibility.Visible : Visibility.Collapsed;
        text.Text = value ?? "";
    }
}
