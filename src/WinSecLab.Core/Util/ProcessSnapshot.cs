using System.Runtime.Versioning;

namespace WinSecLab.Core.Util;

public readonly record struct ProcessSnapshotEntry(uint Pid, uint ParentPid, string Name);

/// <summary>
/// 一次性进程快照。
///
/// 为什么不用 WMI：`SELECT ParentProcessId FROM Win32_Process WHERE ProcessId=N` 这种
/// "每个进程查一次"的写法，在数百个进程的机器上要几百次 WMI 往返 —— 实测会把会话启动
/// 卡住几十秒甚至更久，而且每秒轮询时还会再来一遍。
/// Toolhelp32 的 CreateToolhelp32Snapshot 一次调用就能拿到全部 PID / 父进程 / 名称，
/// 耗时是微秒级，且不需要管理员权限。
/// </summary>
[SupportedOSPlatform("windows")]
public static class ProcessSnapshot
{
    /// <summary>取当前全部进程。失败时返回空列表（调用方自行决定降级策略）。</summary>
    public static List<ProcessSnapshotEntry> Capture()
    {
        var result = new List<ProcessSnapshotEntry>(512);
        var handle = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return result;

        try
        {
            var entry = new NativeMethods.PROCESSENTRY32W
            {
                dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>(),
                szExeFile = "",
            };

            if (!NativeMethods.Process32FirstW(handle, ref entry)) return result;

            do
            {
                result.Add(new ProcessSnapshotEntry(
                    entry.th32ProcessID,
                    entry.th32ParentProcessID,
                    string.IsNullOrEmpty(entry.szExeFile) ? "(unknown)" : entry.szExeFile));
                entry.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>();
            }
            while (NativeMethods.Process32NextW(handle, ref entry));
        }
        catch
        {
            // 极少数受限环境下可能失败；返回已收集到的部分
        }
        finally
        {
            try { NativeMethods.CloseHandle(handle); } catch { }
        }

        return result;
    }
}
