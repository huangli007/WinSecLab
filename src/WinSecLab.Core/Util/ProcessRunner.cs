using System.Diagnostics;
using System.Text;

namespace WinSecLab.Core.Util;

public sealed class ToolRunResult
{
    public bool Started { get; init; }
    public int ExitCode { get; init; } = -1;
    public string StdOut { get; init; } = "";
    public string StdErr { get; init; } = "";
    public bool TimedOut { get; init; }
    public bool Cancelled { get; init; }
    public bool OutputTruncated { get; init; }
    public TimeSpan Duration { get; init; }
    public string CommandLine { get; init; } = "";

    public bool Ok => Started && !TimedOut && !Cancelled && ExitCode == 0;
    public string Combined => string.IsNullOrWhiteSpace(StdErr) ? StdOut : StdOut + "\n[stderr]\n" + StdErr;

    public static ToolRunResult NotStarted(string commandLine, string reason) => new()
    {
        Started = false,
        CommandLine = commandLine,
        StdErr = reason,
    };
}

/// <summary>
/// 外部工具统一执行器。
///
/// 三个必须守住的点（否则"集成"会变成"卡死平台"）：
///  1. 永远带超时 —— Ghidra/Procmon 这类工具能跑几十分钟，必须能被切断；
///  2. 输出有上限 —— 某些工具会吐几十 MB 日志，直接进内存会拖垮 UI；
///  3. 绝不吞 stderr —— 工具失败要让用户看见真实原因，而不是"分析失败"四个字。
/// </summary>
public static class ProcessRunner
{
    public const int DefaultTimeoutMs = 120_000;
    public const int MaxCaptureBytes = 4 * 1024 * 1024;

    public static async Task<ToolRunResult> RunAsync(
        string executable,
        string arguments,
        string? workingDirectory = null,
        int timeoutMs = DefaultTimeoutMs,
        CancellationToken cancellationToken = default,
        Action<string>? log = null,
        Action<string>? onStdoutLine = null,
        int maxCaptureBytes = MaxCaptureBytes)
    {
        var commandLine = $"\"{executable}\" {arguments}";

        if (!File.Exists(executable))
            return ToolRunResult.NotStarted(commandLine, $"可执行文件不存在：{executable}");

        var psi = new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        if (!string.IsNullOrWhiteSpace(workingDirectory) && Directory.Exists(workingDirectory))
            psi.WorkingDirectory = workingDirectory;

        var sw = Stopwatch.StartNew();
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var truncated = false;
        var timedOut = false;
        var cancelled = false;

        using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        // 输出行回调与缓冲都做一次性判断，避免热路径上反复取锁
        void Collect(StringBuilder sink, DataReceivedEventArgs e)
        {
            if (e.Data is null) return;
            lock (sink)
            {
                if (sink.Length < maxCaptureBytes) sink.AppendLine(e.Data);
                else truncated = true;
            }
            onStdoutLine?.Invoke(e.Data);
        }

        process.OutputDataReceived += (_, e) => Collect(stdout, e);
        process.ErrorDataReceived += (_, e) => Collect(stderr, e);

        try
        {
            if (!process.Start())
                return ToolRunResult.NotStarted(commandLine, "进程启动返回 false。");
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            log?.Invoke($"$ {commandLine}");
        }
        catch (Exception ex)
        {
            return ToolRunResult.NotStarted(commandLine, $"启动失败：{ex.Message}");
        }

        using var timeoutCts = new CancellationTokenSource(timeoutMs);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);

        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            // WaitForExitAsync 返回后异步输出事件可能还没冲刷完
            process.WaitForExit(1500);
        }
        catch (OperationCanceledException)
        {
            timedOut = timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested;
            cancelled = cancellationToken.IsCancellationRequested;
            TryKill(process);
            log?.Invoke(timedOut
                ? $"[超时] {Path.GetFileName(executable)} 超过 {timeoutMs / 1000}s，已终止。"
                : $"[取消] {Path.GetFileName(executable)} 被用户中断。");
        }
        catch (Exception ex)
        {
            log?.Invoke($"[异常] {ex.Message}");
        }

        sw.Stop();

        int exitCode = -1;
        try { if (process.HasExited) exitCode = process.ExitCode; } catch { }

        string outText, errText;
        lock (stdout) outText = stdout.ToString();
        lock (stderr) errText = stderr.ToString();

        return new ToolRunResult
        {
            Started = true,
            ExitCode = exitCode,
            StdOut = outText,
            StdErr = errText,
            TimedOut = timedOut,
            Cancelled = cancelled,
            OutputTruncated = truncated,
            Duration = sw.Elapsed,
            CommandLine = commandLine,
        };
    }

    /// <summary>
    /// 启动一个不会自己退出的常驻工具（Procmon、dumpcap 之类），立即返回。
    /// 调用方负责稍后用工具自己的"停止"命令收尾 —— 不要在这里 Kill，
    /// 因为这类工具需要在退出前把缓冲写盘，强杀会丢数据。
    /// </summary>
    public static Process? StartDetached(string executable, string arguments, string? workingDirectory = null,
        Action<string>? log = null)
    {
        if (!File.Exists(executable))
        {
            log?.Invoke($"[不存在] {executable}");
            return null;
        }

        var psi = new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (!string.IsNullOrWhiteSpace(workingDirectory) && Directory.Exists(workingDirectory))
            psi.WorkingDirectory = workingDirectory;

        try
        {
            var p = Process.Start(psi);
            log?.Invoke($"$ {executable} {arguments}  (pid={p?.Id})");
            return p;
        }
        catch (Exception ex)
        {
            log?.Invoke($"[启动失败] {ex.Message}");
            return null;
        }
    }

    private static void TryKill(Process process)    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch
        {
            // 目标可能已退出，或权限不足以 kill 子进程；这里静默即可，调用方已拿到 cancelled/timedOut
        }
    }

    /// <summary>解析形如 "K1=1|K2=2" 的过滤器字符串，供 tshark 这类工具安全传参。</summary>
    public static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
}
