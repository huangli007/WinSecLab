using System.Diagnostics;

namespace WinSecLab.Core.Engines.Reports;

/// <summary>PDF 导出结果。</summary>
public sealed record PdfExportResult(bool Success, string? Path, string? Error);

/// <summary>
/// 把 HTML 报告打印成 PDF。
///
/// 为什么走 Edge 而不是引入 PDF 库：Windows 10/11 自带 Microsoft Edge，
/// 它的无头模式能直接把 HTML 渲染成 PDF（含分页与打印样式），
/// 零额外依赖、零安装 —— 比为了导 PDF 拖进一整个排版库划算得多。
///
/// 三个坑都踩过了，记在这里免得重犯：
/// ① 中文/空格路径必须先转 Uri（否则 file:/// 加载失败，ERR_FILE_NOT_FOUND）；
/// ② Edge 的退出码不可靠（成功也可能非 0），**以 PDF 文件真的生成且非空为准**；
/// ③ headless Edge 打完 PDF 后主进程不一定立刻退出（要等子进程回收），
///    所以**不能**傻等进程退出 —— 轮询目标文件，出现即杀树返回。
/// </summary>
public static class PdfExporter
{
    /// <summary>导出 HTML 为 PDF。返回结果里带文件路径或失败原因。</summary>
    public static async Task<PdfExportResult> ExportAsync(string htmlPath,
        string pdfPath, int timeoutMs = 60_000, CancellationToken ct = default)
    {
        if (!File.Exists(htmlPath))
            return new PdfExportResult(false, null, $"HTML 报告不存在：{htmlPath}");

        var edge = FindEdge();
        if (edge is null)
            return new PdfExportResult(false, null,
                "未找到 Microsoft Edge。PDF 导出依赖系统自带的 Edge（Windows 10/11 默认安装）。");

        var dir = System.IO.Path.GetDirectoryName(pdfPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        try { if (File.Exists(pdfPath)) File.Delete(pdfPath); } catch { }

        // 用 Uri 生成 file:/// URL —— 中文与空格会被正确编码，否则 Edge 加载不到文件
        var url = new Uri(htmlPath).AbsoluteUri;

        // 独立 user-data-dir：避免复用用户正在使用的 Edge 会话（复用会导致 --print-to-pdf 被忽略）
        var profileDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "WinSecLab-PdfProfile-" + Guid.NewGuid().ToString("N")[..8]);

        var args = "--headless=new --disable-gpu --no-first-run --no-pdf-header-footer --log-level=3"
                   + $" --user-data-dir={Quote(profileDir)}"
                   + $" --print-to-pdf={Quote(pdfPath)}"
                   + $" {Quote(url)}";

        var psi = new ProcessStartInfo
        {
            FileName = edge,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            // 关键：不重定向 stdout/stderr。Edge 会往这两条管道写日志，
            // 重定向却不读取 → 缓冲区满 → 子进程永久阻塞。直接让它写进 null 最省事。
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };

        Process? proc = null;
        try
        {
            proc = Process.Start(psi);
            if (proc is null)
                return new PdfExportResult(false, null, "无法启动 Microsoft Edge。");

            // 轮询目标文件：Edge 一般 3-8 秒出 PDF。判定"文件大小连续两次一致"才算写完，
            // 避免读到还在写入的半截文件（PDF 写完前是 0 字节或正在增长）。
            var deadline = Environment.TickCount64 + timeoutMs;
            long lastLen = -1;
            while (Environment.TickCount64 < deadline)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(250, ct).ConfigureAwait(false);

                if (TryGetStableLength(pdfPath, ref lastLen, out var len))
                    return new PdfExportResult(true, pdfPath, null);

                // Edge 自己退出了但没出 PDF —— 不用再等
                try { if (proc.HasExited && !File.Exists(pdfPath)) break; } catch { }
            }

            return new PdfExportResult(false, null,
                $"Edge 在 {timeoutMs / 1000} 秒内未生成 PDF。");
        }
        catch (OperationCanceledException)
        {
            return new PdfExportResult(false, null, "已取消。");
        }
        catch (Exception ex)
        {
            return new PdfExportResult(false, null, $"PDF 导出异常：{ex.Message}");
        }
        finally
        {
            // Edge 打完 PDF 常驻不退，这里主动收掉我们启动的那棵树
            try
            {
                if (proc is { HasExited: false })
                {
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(3000);   // 等它真的退，profile 句柄才释放得掉
                }
            }
            catch { }
            try { proc?.Dispose(); } catch { }
            // 杀树后 Edge 子进程释放 profile 句柄需要一点时间，所以删除放在 Kill 之后并带退避重试
            TryDeleteProfile(profileDir);
        }
    }

    /// <summary>判断文件是否已写完：大小稳定（连续两次一致）且非空。</summary>
    private static bool TryGetStableLength(string path, ref long lastLen, out long len)
    {
        len = 0;
        try
        {
            if (!File.Exists(path)) { lastLen = -1; return false; }
            var info = new FileInfo(path);
            if (info.Length <= 0) return false;
            if (info.Length == lastLen) { len = info.Length; return true; }
            lastLen = info.Length;
            return false;
        }
        catch
        {
            return false; // 文件仍被占用，等下一轮
        }
    }

    private static void TryDeleteProfile(string profileDir)
    {
        try
        {
            if (!Directory.Exists(profileDir)) return;
            // 递增退避：Kill 刚下发时子进程还可能持有句柄
            for (var i = 0; i < 5; i++)
            {
                try { Directory.Delete(profileDir, recursive: true); return; }
                catch { Thread.Sleep(300 + i * 400); }
            }
        }
        catch { /* 临时 profile 删不掉不影响主流程 */ }
    }

    /// <summary>定位 Edge 可执行文件（覆盖 32 位与 64 位安装位置）。</summary>
    public static string? FindEdge()
    {
        var candidates = new[]
        {
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Microsoft", "Edge", "Application", "msedge.exe"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Microsoft", "Edge", "Application", "msedge.exe"),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
}
