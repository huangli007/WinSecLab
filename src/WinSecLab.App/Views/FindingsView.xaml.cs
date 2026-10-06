using System.Windows;
using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

public partial class FindingsView : UserControl, IRefreshable
{
    private readonly AppState _state;
    private Severity? _filter;
    private bool _loadingReview;   // 装载详情时抑制 ComboBox 的 SelectionChanged，避免误写库

    /// <summary>人工复核下拉项：值 + 中文名。状态枚举与 UI 一一对应。</summary>
    private sealed record ReviewOption(FindingStatus Value, string Label)
    {
        public override string ToString() => Label;
    }

    private static readonly ReviewOption[] ReviewOptions =
    {
        new(FindingStatus.Open, "待处理"),
        new(FindingStatus.Confirmed, "已确认"),
        new(FindingStatus.FalsePositive, "误报"),
        new(FindingStatus.Accepted, "接受风险"),
        new(FindingStatus.Remediated, "已整改"),
    };

    public FindingsView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;
        ReviewStatusBox.ItemsSource = ReviewOptions;
    }

    public void OnActivated()
    {
        var findings = _state.Result?.Findings ?? new List<Finding>();
        SummaryText.Text = findings.Count == 0
            ? "还没有发现。执行一次分析后这里会列出所有问题。"
            : $"{findings.Count} 条：{_state.FindingStats}　·　已复核 {_state.ReviewedCount} 条，待复核 {_state.PendingReviewCount} 条";

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

        // 记住当前选中的发现 ID —— 保存复核后要重建 ItemsSource，
        // 若直接重置 SelectedIndex=0，用户每保存一次就会被踢回第一条。
        var keepId = (FindingGrid.SelectedItem as Finding)?.Id;

        // 已按严重级排序，这里再稳一次，保证报告与界面顺序一致
        var ordered = filtered
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();

        FindingGrid.ItemsSource = null;
        FindingGrid.ItemsSource = ordered;

        if (ordered.Count > 0)
        {
            var idx = keepId is null ? 0 : ordered.FindIndex(f => f.Id == keepId);
            FindingGrid.SelectedIndex = idx >= 0 ? idx : 0;
        }
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

        // 装载该条发现的复核状态与意见。用 _loadingReview 抑制 ComboBox 的
        // SelectionChanged 回写，否则每次切换选中项都会把库里的状态重写一遍。
        _loadingReview = true;
        try
        {
            ReviewStatusBox.SelectedItem = ReviewOptions.FirstOrDefault(o => o.Value == finding.Status)
                                           ?? ReviewOptions[0];
            ReviewNoteBox.Text = finding.AnalystNote ?? "";
            ReviewSavedBadge.Visibility = Visibility.Collapsed;
            ReviewHint.Text = finding.Status == FindingStatus.Open
                ? "复核后状态会写回数据库，并体现在报告与 CSV 清单中。"
                : $"上次复核：{finding.StatusText}";
        }
        finally
        {
            _loadingReview = false;
        }

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

    /// <summary>下拉切换即保存状态（轻量操作），复核意见由「保存复核」按钮统一提交。</summary>
    private void ReviewStatus_OnChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingReview) return;
        if (FindingGrid.SelectedItem is not Finding finding) return;
        if (ReviewStatusBox.SelectedItem is not ReviewOption option) return;
        if (finding.Status == option.Value) return;

        _state.SaveFindingReview(finding, option.Value, ReviewNoteBox.Text);
        ReviewSavedBadge.Visibility = Visibility.Visible;
    }

    private void SaveReview_OnClick(object sender, RoutedEventArgs e)
    {
        if (FindingGrid.SelectedItem is not Finding finding)
        {
            ReviewHint.Text = "请先在左侧选择一条发现。";
            return;
        }

        var status = ReviewStatusBox.SelectedItem is ReviewOption option
            ? option.Value
            : FindingStatus.Open;

        if (_state.SaveFindingReview(finding, status, ReviewNoteBox.Text))
        {
            ReviewSavedBadge.Visibility = Visibility.Visible;
            ReviewHint.Text = $"已保存：{finding.StatusText}";
            OnActivated();   // 刷新左侧统计与网格状态列
        }
        else
        {
            ReviewHint.Text = "保存失败，请查看底部日志。";
        }
    }

    private static void SetBlock(FrameworkElement block, TextBlock text, string? value)
    {
        var has = !string.IsNullOrWhiteSpace(value);
        block.Visibility = has ? Visibility.Visible : Visibility.Collapsed;
        text.Text = value ?? "";
    }
}
