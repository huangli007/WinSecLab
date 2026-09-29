using System.Windows;
using System.Windows.Threading;

namespace WinSecLab.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 兜底：任何未处理异常都要留下痕迹并告诉用户，而不是静默退出。
        // 安全分析工具崩在"没有报错"上，用户就不知道哪些结论其实没采到。
        DispatcherUnhandledException += OnDispatcherUnhandledException;

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            var ex = args.ExceptionObject as Exception;
            WriteCrashLog(ex);
            MessageBox.Show(
                $"发生未处理异常，程序将退出。\n\n{ex?.GetType().Name}: {ex?.Message}\n\n日志：{CrashLogPath}",
                "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            WriteCrashLog(args.Exception);
            args.SetObserved();
        };

        // UI 快照模式：跑完所有页面截图后自动退出，用于界面回归检查
        var snapshotDir = UiSnapshot.OutputDirectory(e.Args);
        if (snapshotDir is not null)
        {
            var width = ReadNumber(e.Args, "--snapshot-width", 1480);
            var height = ReadNumber(e.Args, "--snapshot-height", 900);

            Dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    if (MainWindow is MainWindow window)
                        await UiSnapshot.CaptureAllAsync(window, snapshotDir, width, height);
                }
                catch (Exception ex)
                {
                    WriteCrashLog(ex);
                    Console.Error.WriteLine($"快照失败：{ex.Message}");
                }
                finally
                {
                    Shutdown();
                }
            }, DispatcherPriority.ApplicationIdle);
        }
    }

    private static double ReadNumber(string[] args, string name, double fallback)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length
                && double.TryParse(args[i + 1], out var v))
                return v;
        }
        return fallback;
    }

    private static string CrashLogPath => Path.Combine(Path.GetTempPath(), "WinSecLab-crash.log");

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteCrashLog(e.Exception);
        e.Handled = true;

        MessageBox.Show(
            $"界面操作出现异常（已记录，程序继续运行）：\n\n{e.Exception.GetType().Name}: {e.Exception.Message}\n\n"
            + $"若问题反复出现，请查看日志：{CrashLogPath}",
            "WinSecLab", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private static void WriteCrashLog(Exception? ex)
    {
        if (ex is null) return;
        try
        {
            File.AppendAllText(CrashLogPath, $"\n===== {DateTime.Now:yyyy-MM-dd HH:mm:ss} =====\n{ex}\n");
        }
        catch
        {
            // 日志写不进去也不能再抛
        }
    }
}
