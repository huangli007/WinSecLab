using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WinSecLab.Core.Util;

/// <summary>
/// 把文件/目录送进 Windows 回收站。
///
/// 为什么不用 Directory.Delete：删除项目是不可逆操作，直接删掉用户几十分钟的分析成果
/// 太粗暴。送进回收站让用户可以从系统层面恢复 —— 这是"破坏性操作也要留退路"的底线。
/// 永久删除由调用方显式指定，且必须经过二次确认。
/// </summary>
[SupportedOSPlatform("windows")]
internal static class RecycleBin
{
    private const uint FO_DELETE = 0x0003;
    private const ushort FOF_SILENT = 0x0004;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOERRORUI = 0x0400;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCTW
    {
        public IntPtr hwnd;
        public uint wFunc;
        [MarshalAs(UnmanagedType.LPWStr)] public string pFrom;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszProgressTitle;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int SHFileOperationW(ref SHFILEOPSTRUCTW lpFileOp);

    /// <summary>
    /// 把指定路径送进回收站。成功返回 true；失败返回 false 并给出原因
    /// （回收站不可用时要让调用方知道，而不是静默永久删除）。
    ///
    /// 关键：SHFileOperation 要求 COM 已初始化，且实际上只在 STA 线程上可靠工作。
    /// WPF 的 UI 线程是 STA 没问题，但 CLI / 单元测试的主线程通常是 MTA，
    /// 直接调用会失败（实测返回 0x2 / ERROR_FILE_NOT_FOUND，很有迷惑性）。
    /// 所以统一起一个专用 STA 线程执行，与调用方线程模型解耦。
    /// </summary>
    internal static bool TryMoveToRecycleBin(string path, out string? error)
    {
        error = null;

        // 先做存在性预检：SHFileOperation 对不存在的路径只返回 0x2（ERROR_FILE_NOT_FOUND），
        // 信息量太低，这里给出明确的路径提示，便于定位。
        if (!Directory.Exists(path) && !File.Exists(path))
        {
            error = $"路径不存在：{path}";
            return false;
        }

        var success = false;
        string? threadError = null;

        var worker = new Thread(() =>
        {
            try
            {
                // pFrom 必须是双 null 结尾（LPWStr 会自动补一个终止符，这里再手动补一个）
                var op = new SHFILEOPSTRUCTW
                {
                    wFunc = FO_DELETE,
                    pFrom = path + "\0",
                    fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI,
                };

                var result = SHFileOperationW(ref op);

                if (result != 0)
                {
                    // 某些受限环境会出现"操作已生效但返回非 0"（部分成功语义 / 沙箱拦截返回值）。
                    // 以文件系统的实际状态为准：路径已经不在了就是成功，避免把已完成的事报成失败。
                    if (!Directory.Exists(path) && !File.Exists(path))
                    {
                        success = true;
                        return;
                    }

                    threadError = $"SHFileOperation 返回 0x{result:X}（路径：{path}）";
                    return;
                }

                if (op.fAnyOperationsAborted)
                {
                    threadError = "操作被中止";
                    return;
                }

                success = true;
            }
            catch (Exception ex)
            {
                threadError = ex.Message;
            }
        })
        {
            IsBackground = true,
            Name = "WinSecLab-RecycleBin",
        };

        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
        worker.Join();

        error = threadError;
        return success;
    }
}
