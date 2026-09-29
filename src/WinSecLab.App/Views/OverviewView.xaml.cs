using System.Windows.Controls;
using WinSecLab.App.Infrastructure;
using WinSecLab.Core.Models;
using WinSecLab.Core.Storage;

namespace WinSecLab.App.Views;

public partial class OverviewView : UserControl, IRefreshable
{
    private readonly AppState _state;

    public OverviewView(AppState state)
    {
        _state = state;
        InitializeComponent();
        DataContext = state;
        RefreshContent();
    }

    public void OnActivated() => RefreshContent();

    private void RefreshContent()
    {
        var project = _state.CurrentProject;
        var result = _state.Result;

        if (project is null || result is null) return;

        // ── PE 层面信息 ──
        var pe = result.Pe;
        SizeText.Text = FormatSize(project.Target.FileSize);
        SubsystemText.Text = pe?.Subsystem ?? "-";
        CompilerText.Text = string.IsNullOrWhiteSpace(pe?.Compiler) ? "-" : pe!.Compiler;

        // ── 类型识别 ──
        var detection = project.Detection;
        RuntimeText.Text = detection?.DisplayName ?? "未识别";
        ConfidenceText.Text = detection is null || detection.ConfidencePercent == 0
            ? "无信号"
            : $"置信度 {detection.ConfidencePercent}%";

        AnalyzerList.ItemsSource = detection?.RecommendedAnalyzers is { Count: > 0 } a
            ? a
            : new List<string> { "未给出建议（先完成一次静态分析）" };

        ToolList.ItemsSource = detection?.RecommendedTools is { Count: > 0 } t
            ? t
            : new List<string> { "无（内置引擎已覆盖基础检查）" };

        SignalList.ItemsSource = detection?.Signals ?? new List<DetectionSignal>();

        // ── 采集规模 ──
        DnsCountText.Text = result.DnsObservations.Count.ToString();
        HttpCountText.Text = result.Http.Count.ToString();

        // ── 最高风险项 ──
        var top = result.Findings
            .Where(f => f.Severity is Severity.Critical or Severity.High or Severity.Medium)
            .OrderByDescending(f => f.Severity)
            .Take(6)
            .ToList();

        TopFindingsList.ItemsSource = top;
        NoFindingText.Visibility = top.Count == 0 ? System.Windows.Visibility.Visible
                                                   : System.Windows.Visibility.Collapsed;

        // ── 测试环境 ──
        var env = project.Environment;
        MachineText.Text = $"{env.MachineName} / {env.UserName}";
        OsText.Text = env.OsVersion;
        RuntimeVersionText.Text = env.DotNetVersion;
        ElevatedText.Text = WorkspaceService.IsElevated()
            ? "管理员（WMI 实时事件 / 抓包可用）"
            : "标准用户（部分通道受限）";
        CpuText.Text = $"{env.LogicalProcessors} 核";
        MemoryText.Text = env.TotalMemoryMb > 0 ? $"{env.TotalMemoryMb / 1024.0:F1} GB" : "-";

        _state.RaiseStats();
    }

    private static string FormatSize(long bytes)
    {
        if (bytes <= 0) return "-";
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / 1024.0 / 1024.0:F2} MB";
    }
}
