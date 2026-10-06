using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace WinSecLab.App;

/// <summary>
/// UI 快照模式：把每个页面渲染成 PNG，用于界面回归检查。
///
/// 为什么放在应用里而不是外部截图工具：安全策略与远程会话下截屏往往不可用，
/// 而且外部截屏会把桌面上的其它窗口一起拍进去。RenderTargetBitmap 直接渲染
/// 自己的视觉树，结果稳定、可重复、与屏幕环境无关。
///
/// 用法：WinSecLab.exe --snapshot &lt;输出目录&gt; [--snapshot-width 1480]
/// </summary>
internal static class UiSnapshot
{
    public static bool IsRequested(string[] args) =>
        args.Any(a => a.Equals("--snapshot", StringComparison.OrdinalIgnoreCase));

    public static string? OutputDirectory(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--snapshot", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                return args[i + 1];
        }
        return null;
    }

    public static async Task CaptureAllAsync(
        MainWindow window, Infrastructure.AppState state, string outputDirectory, double width, double height)
    {
        Directory.CreateDirectory(outputDirectory);

        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -32000;   // 移到屏幕外：不干扰用户，也不依赖窗口获得焦点
        window.Top = -32000;
        window.Width = width;
        window.Height = height;
        window.ShowInTaskbar = false;
        window.Show();
        window.UpdateLayout();

        // 等一帧，让绑定与布局稳定下来（尤其是 DataGrid 的虚拟化行）
        await SettleAsync(window);

        var pages = new (string Tag, string File)[]
        {
            ("Home", "01-projects.png"),
            ("Run", "02-run.png"),
            ("Overview", "03-overview.png"),
            ("Findings", "04-findings.png"),
            ("Evidence", "05-evidence.png"),
            ("Dynamic", "06-dynamic.png"),
            ("Graph", "07-graph.png"),
            ("Comparison", "08-comparison.png"),
            ("Reports", "09-reports.png"),
            ("Plugins", "10-plugins.png"),
            ("Settings", "11-settings.png"),
        };

        foreach (var (tag, file) in pages)
        {
            window.NavigateTo(tag);
            await SettleAsync(window, 3);
            Save(window, Path.Combine(outputDirectory, file));
            if (tag == "Plugins") DumpPluginDiagnostics(state);
        }

        window.Close();
    }

    private static async Task SettleAsync(Window window, int frames = 6)
    {
        for (var i = 0; i < frames; i++)
        {
            window.UpdateLayout();
            await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
            await Task.Delay(90);
        }
    }

    /// <summary>
    /// 快照期插件探测诊断（仅 --snapshot 模式）。截图只能看到"22/23"这种结果，
    /// 看不到是哪一个失败，这里把明细打到标准输出，便于定位。
    /// </summary>
    private static void DumpPluginDiagnostics(Infrastructure.AppState state)
    {
        try
        {
            var total = state.Plugins.Count;
            var avail = state.Plugins.Count(p => p.Available);
            var ext = state.Plugins.Count(p => p.Kind == Core.Models.PluginKind.ExternalToolAdapter);
            var extAvail = state.Plugins.Count(p => p.Kind == Core.Models.PluginKind.ExternalToolAdapter && p.Available);
            Console.WriteLine($"[snapshot] 插件：共 {total}，可用 {avail}；外部工具 {extAvail}/{ext}");
            foreach (var p in state.Plugins.Where(p => !p.Available))
                Console.WriteLine($"[snapshot]   不可用 → {p.Id}：{p.AvailabilityText}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[snapshot] 插件诊断失败：{ex.Message}");
        }
    }

    private static void Save(Window window, string path)
    {
        var root = window.Content as Visual ?? window;
        var w = (int)Math.Ceiling(window.ActualWidth);
        var h = (int)Math.Ceiling(window.ActualHeight);
        if (w <= 0 || h <= 0) return;

        var bmp = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(root);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }
}
