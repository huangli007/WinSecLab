using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

/// <summary>规模指标的一格（值 + 标签 + 与上轮的差值）。</summary>
public sealed class MetricTile
{
    public string Label { get; init; } = "";
    public string Value { get; init; } = "";
    public string Delta { get; init; } = "";
    public Brush Brush { get; init; } = Brushes.Black;
}

/// <summary>快照下拉项。</summary>
public sealed class SnapshotOption
{
    public AnalysisSnapshot Snapshot { get; init; } = new();
    public string Label { get; init; } = "";
    public override string ToString() => Label;
}

public partial class ComparisonView : UserControl, IRefreshable, INotifyPropertyChanged
{
    private readonly AppState _state;
    private List<SnapshotOption> _options = new();
    private bool _loading;   // 装载下拉期间抑制 SelectionChanged，避免把"程序赋值"当"用户选择"

    public ComparisonView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = this;
    }

    // ───────────── 供 XAML 绑定（Visibility 用） ─────────────

    public bool CanCompare { get; private set; }
    public bool HasAdded { get; private set; }
    public bool HasRemoved { get; private set; }
    public bool HasChanged { get; private set; }
    public bool HasUnchanged { get; private set; }
    public bool HasNoDiff { get; private set; }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void OnActivated() => Reload(resetSelection: true);

    private void Refresh_OnClick(object sender, RoutedEventArgs e) => Reload(resetSelection: true);

    private void Reload(bool resetSelection)
    {
        var snapshots = _state.GetSnapshots();

        _loading = true;
        try
        {
            _options = snapshots.Select(s => new SnapshotOption
            {
                Snapshot = s,
                // 快照 ID 尾部是时间戳，标签里给"时间 + 规模"，比裸 ID 好认
                Label = $"{s.CapturedAt:MM-dd HH:mm}　·　发现 {s.TotalFindings}（严重 {s.CriticalCount} / 高 {s.HighCount}）",
            }).ToList();

            BaselineBox.ItemsSource = null;
            CurrentBox.ItemsSource = null;
            BaselineBox.ItemsSource = _options;
            CurrentBox.ItemsSource = _options;

            if (_options.Count >= 2 && resetSelection)
            {
                CurrentBox.SelectedIndex = 0;    // 最新一轮
                BaselineBox.SelectedIndex = 1;   // 它前面那一轮
            }
            else if (_options.Count >= 1 && resetSelection)
            {
                BaselineBox.SelectedIndex = 0;
                CurrentBox.SelectedIndex = 0;
            }
        }
        finally
        {
            _loading = false;
        }

        if (_options.Count == 0)
        {
            EmptyHintText.Text = "该项目还没有任何分析快照。先跑一次分析，第二轮起就能在这里看到差异。";
            CanCompare = false;
            Raise(nameof(CanCompare));
            return;
        }

        if (_options.Count == 1)
        {
            EmptyHintText.Text = "目前只有 1 轮快照，没有可比基线。再跑一次分析（例如改版后复测）即可对比。";
            CanCompare = false;
            Raise(nameof(CanCompare));
            return;
        }

        CanCompare = true;
        Raise(nameof(CanCompare));
        Recompute();
    }

    private void Selector_OnChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        Recompute();
    }

    private void Recompute()
    {
        if (BaselineBox.SelectedItem is not SnapshotOption baseline ||
            CurrentBox.SelectedItem is not SnapshotOption current) return;

        var cmp = _state.CompareRounds(baseline.Snapshot, current.Snapshot);
        if (cmp is null || !cmp.HasBaseline)
        {
            CanCompare = false;
            Raise(nameof(CanCompare));
            return;
        }

        // 同一轮自己跟自己比没有意义，给出提示但仍然展示（全为"持续"）
        VerdictText.Text = baseline.Snapshot.Id == current.Snapshot.Id
            ? "同一轮快照（未变化）"
            : cmp.Verdict;

        BaselineText.Text =
            $"基线：{baseline.Snapshot.CapturedAt:yyyy-MM-dd HH:mm}（{Short(baseline.Snapshot.Id)}）"
            + $"　→　本轮：{current.Snapshot.CapturedAt:yyyy-MM-dd HH:mm}（{Short(current.Snapshot.Id)}）"
            + $"　·　Profile：{current.Snapshot.Profile}";

        // 样本变了要显式警告：差异可能来自版本本身，别误读成行为变化
        if (cmp.TargetChanged)
        {
            TargetChangedBanner.Visibility = Visibility.Visible;
            TargetChangedText.Text =
                $"⚠ 两轮样本哈希不一致（{ShortHash(cmp.Baseline?.TargetSha256)} → {ShortHash(cmp.Current?.TargetSha256)}）。"
                + "被测版本已变化，差异可能来自版本本身而非行为变化，请结合版本信息解读。";
        }
        else
        {
            TargetChangedBanner.Visibility = Visibility.Collapsed;
        }

        // 规模变化
        var tiles = new List<MetricTile>
        {
            Tile("发现项", cmp.Current!.TotalFindings, cmp.DeltaFindings, invertGood: true),
            Tile("事件数", cmp.Current.EventCount, cmp.DeltaEvents, invertGood: false),
            Tile("网络连接", cmp.Current.ConnectionCount, cmp.DeltaConnections, invertGood: false),
            Tile("严重 + 高", cmp.Current.RiskyCount,
                cmp.Current.RiskyCount - (cmp.Baseline?.RiskyCount ?? 0), invertGood: true),
            Tile("证据条数", cmp.Current.EvidenceCount,
                cmp.Current.EvidenceCount - (cmp.Baseline?.EvidenceCount ?? 0), invertGood: false),
        };
        MetricList.ItemsSource = tiles;

        // 新增 / 消失 / 变化 / 持续
        AddedList.ItemsSource = cmp.Added;
        RemovedList.ItemsSource = cmp.Removed;
        ChangedGrid.ItemsSource = cmp.Changed;
        UnchangedList.ItemsSource = cmp.Unchanged;

        HasAdded = cmp.Added.Count > 0;
        HasRemoved = cmp.Removed.Count > 0;
        HasChanged = cmp.Changed.Count > 0;
        HasUnchanged = cmp.Unchanged.Count > 0;
        HasNoDiff = !HasAdded && !HasRemoved && !HasChanged;

        AddedCountText.Text = $"+{cmp.Added.Count}";
        RemovedCountText.Text = $"-{cmp.Removed.Count}";
        ChangedCountText.Text = cmp.Changed.Count.ToString();
        UnchangedCountText.Text = cmp.Unchanged.Count.ToString();

        Raise(nameof(HasAdded));
        Raise(nameof(HasRemoved));
        Raise(nameof(HasChanged));
        Raise(nameof(HasUnchanged));
        Raise(nameof(HasNoDiff));
    }

    /// <summary>
    /// 指标格。<paramref name="invertGood"/> = true 表示"变多不是好事"（发现项、高危项），
    /// 涨了标红、降了标绿；反之（事件/连接/证据）只做中性着色，因为多不一定坏。
    /// </summary>
    private static MetricTile Tile(string label, int value, int delta, bool invertGood)
    {
        var accent = (Brush)Application.Current.FindResource("B.Accent");
        var brush = accent;

        if (invertGood && delta > 0) brush = (Brush)Application.Current.FindResource("B.High");
        else if (invertGood && delta < 0) brush = (Brush)Application.Current.FindResource("B.Success");

        return new MetricTile
        {
            Label = label,
            Value = value.ToString(),
            Delta = delta == 0 ? "与上轮持平" : $"上轮变化 {(delta > 0 ? "+" : "")}{delta}",
            Brush = brush,
        };
    }

    /// <summary>快照 ID 很长，取尾部时间戳段便于人工识别。</summary>
    private static string Short(string id)
    {
        var i = id.IndexOf("-SN", StringComparison.Ordinal);
        return i >= 0 && i + 3 < id.Length ? "SN" + id[(i + 3)..] : id;
    }

    /// <summary>哈希首尾各取一段——只截前 12 位时，两轮前缀相同会看起来一模一样。</summary>
    private static string ShortHash(string? hash) =>
        string.IsNullOrWhiteSpace(hash) ? "—"
        : hash.Length <= 12 ? hash
        : $"{hash[..8]}…{hash[^4..]}";
}
