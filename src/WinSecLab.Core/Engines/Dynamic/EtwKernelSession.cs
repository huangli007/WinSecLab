using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Dynamic;

/// <summary>ETW 内核事件回调的结果：一条解析好的监控事件。</summary>
public readonly record struct EtwEvent(
    DateTime Timestamp,
    uint ProcessId,
    uint ThreadId,
    int EventKind,          // 见 EtwEventKind 常量
    string ProcessName,
    string Target,          // 文件路径 / 注册表键 / 进程名
    string Operation,
    uint ParentPid);

public static class EtwEventKind
{
    public const int ProcessStart = 1;
    public const int ProcessStop = 2;
    public const int FileCreate = 3;
    public const int FileWrite = 4;
    public const int FileDelete = 5;
    public const int FileRead = 6;
    public const int RegistrySet = 7;
    public const int RegistryCreate = 8;
    public const int RegistryDelete = 9;
}

/// <summary>
/// ETW 内核会话：消费 Microsoft-Windows-Kernel-Process 的进程创建/终止事件。
///
/// 为什么做这个：内核 Provider 的进程事件是**内核级、带准确父 PID、低开销**的，
/// 不需要管理员做轮询也能拿到精确的父子关系 —— 这正是标准用户下
/// "进程事件退化为 1 秒轮询"短板的补丁。
///
/// 为什么先只做 Kernel-Process 一个 Provider：内核 File/Registry Provider 的
/// payload 是未解码的 MOF 二进制，字段偏移随事件类型变化、极易出错；而进程
/// 事件的 payload 是稳定的固定结构，先把这个做对、验证端到端，再扩展其它 Provider。
///
/// 权限：内核 Provider 需要管理员。标准用户下 <see cref="Start"/> 返回 false，
/// 调用方（DynamicSession）降级到现有轮询通道。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EtwKernelSession : IDisposable
{
    private static readonly Guid KernelProcessProvider =
        new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    // ProcessStart（EventId 1）的固定 payload 布局：
    //   struct Process_TypeGroup1 {
    //     UInt32 UniqueProcessKey;   // offset 0
    //     UInt32 ProcessId;          // offset 4
    //     UInt32 ParentId;           // offset 8
    //     UInt32 SessionId;          // offset 12
    //     SInt32 ExitStatus;         // offset 16
    //     ... 之后是 UserSID / ImageFileName 等变长字段
    //   }
    private const int ProcessStart_PidOffset = 4;
    private const int ProcessStart_PpidOffset = 8;
    private const int ProcessStart_FixedHeaderBytes = 20;   // 到 ExitStatus 结束

    // ProcessEnd（EventId 2）payload：只有 UniqueProcessKey + ProcessId
    private const int ProcessEnd_PidOffset = 4;

    private long _traceHandle;
    private long _consumeHandle;
    private bool _started;
    private bool _disposed;
    private Thread? _consumeThread;

    /// <summary>回调委托必须存为字段保持存活（见 _callback 说明）。</summary>
    private readonly EtwNative.EventRecordCallback _callback;

    public EtwKernelSession()
    {
        _callback = OnEventRecord;
    }

    /// <summary>解析出事件时触发（在消费线程上，调用方负责跨线程封送）。</summary>
    public event Action<EtwEvent>? OnEvent;

    public string? LastError { get; private set; }

    /// <summary>
    /// 启动内核会话并订阅进程事件。需要管理员权限；失败返回 false 并设置 LastError。
    /// </summary>
    public bool Start()
    {
        if (_started) return true;
        if (_disposed) throw new ObjectDisposedException(nameof(EtwKernelSession));

        // ── 1) 创建内核会话 ──
        // 会话名字符串内嵌在 EVENT_TRACE_PROPERTIES 的 Tail 字节区，
        // LoggerNameOffset 指向它。这是 StartTraceW 唯一可靠的会话命名方式。
        var properties = BuildProperties();
        var ret = EtwNative.StartTraceW(out _traceHandle, EtwNative.KERNEL_LOGGER_NAME, ref properties);
        if (ret != 0 && ret != 0x000000B7)   // ERROR_ALREADY_EXISTS 说明会话已存在，可复用
        {
            LastError = $"StartTraceW 失败：0x{ret:X8}（{new Win32Exception((int)ret).Message}）";
            return false;
        }

        // ── 2) 启用 Kernel-Process provider ──
        var providerGuid = KernelProcessProvider;
        var enableParams = new EtwNative.ENABLE_TRACE_PARAMETERS
        {
            Version = 2,
            EnableProperty = EtwNative.EVENT_ENABLE_PROPERTY_SID,
        };

        ret = EtwNative.EnableTraceEx2(
            _traceHandle, ref providerGuid,
            EtwNative.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EtwNative.TRACE_LEVEL_INFO,
            EtwNative.TRACE_MATCH_ALL_KEYWORD, EtwNative.TRACE_MATCH_ALL_KEYWORD,
            0, ref enableParams);

        if (ret != 0)
        {
            LastError = $"EnableTraceEx2 失败：0x{ret:X8}（{new Win32Exception((int)ret).Message}）";
            StopTrace();
            return false;
        }

        // ── 3) 打开实时消费 ──
        var logfile = BuildLogfile();
        _consumeHandle = EtwNative.OpenTraceW(ref logfile);
        if (_consumeHandle == 0)
        {
            LastError = $"OpenTraceW 失败：{Marshal.GetLastWin32Error()}";
            StopTrace();
            return false;
        }

        // ── 4) 后台消费线程（ProcessTrace 阻塞直到 StopTrace） ──
        _started = true;
        _consumeThread = new Thread(ConsumeLoop)
        {
            IsBackground = true,
            Name = "WinSecLab-Etw-Consumer",
        };
        _consumeThread.Start();
        return true;
    }

    private void ConsumeLoop()
    {
        try
        {
            var handle = _consumeHandle;
            EtwNative.ProcessTrace(new[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);
        }
        catch (Exception ex)
        {
            LastError = $"ETW 消费循环异常：{ex.Message}";
        }
    }

    public void Stop()
    {
        if (!_started) return;

        // ControlTraceW(STOP) 会让 ProcessTrace 返回，消费线程自然退出
        StopTrace();
        _started = false;
    }

    private void StopTrace()
    {
        if (_traceHandle != 0)
        {
            try
            {
                var props = new EtwNative.EVENT_TRACE_PROPERTIES
                {
                    // ByValArray 字段必须是非 null 数组，否则 StructureToPtr 会抛异常
                    Tail = new byte[256],
                };
                EtwNative.ControlTraceW(_traceHandle, EtwNative.KERNEL_LOGGER_NAME, ref props,
                    EtwNative.EVENT_TRACE_CONTROL_STOP);
            }
            catch { }
        }
        if (_consumeHandle != 0)
        {
            try { EtwNative.CloseTrace(_consumeHandle); } catch { }
            _consumeHandle = 0;
        }
        _traceHandle = 0;
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _disposed = true;
    }

    // ─────────────────────────────── 结构与回调 ───────────────────────────────

    /// <summary>
    /// 构造 EVENT_TRACE_PROPERTIES，会话名内嵌到 Tail 字节区，LoggerNameOffset 指向它。
    /// </summary>
    private static EtwNative.EVENT_TRACE_PROPERTIES BuildProperties()
    {
        var loggerName = EtwNative.KERNEL_LOGGER_NAME;
        var nameBytes = System.Text.Encoding.Unicode.GetBytes(loggerName + "\0");

        // 会话名相对结构体起点的偏移 = 结构体固定部分大小（不含 Tail）
        var structSizeWithoutTail = Marshal.SizeOf<EtwNative.EVENT_TRACE_PROPERTIES>() - 256;
        var nameOffset = (structSizeWithoutTail + 7) & ~7;   // 8 字节对齐

        var tail = new byte[256];
        Array.Copy(nameBytes, 0, tail, 0, Math.Min(nameBytes.Length, tail.Length));

        return new EtwNative.EVENT_TRACE_PROPERTIES
        {
            Wnode = new EtwNative.WNODE_HEADER
            {
                BufferSize = (uint)(structSizeWithoutTail + 256),
                Flags = EtwNative.WNODE_FLAG_TRACED_GUID,
                Guid = Guid.NewGuid(),
                ClientContext = 1, // QPC
            },
            BufferSize = 64,       // 64 KB / buffer
            MinimumBuffers = 4,
            MaximumBuffers = 32,
            LogFileMode = EtwNative.EVENT_TRACE_REAL_TIME_MODE | EtwNative.EVENT_TRACE_SYSTEM_LOGGER_MODE,
            FlushTimer = 1,
            EnableFlags = EtwNative.EVENT_TRACE_FLAG_PROCESS,  // 进程创建/终止
            LoggerNameOffset = (uint)nameOffset,
            Tail = tail,
        };
    }

    private EtwNative.EVENT_TRACE_LOGFILEW BuildLogfile()
    {
        var logfile = new EtwNative.EVENT_TRACE_LOGFILEW
        {
            LoggerName = Marshal.StringToHGlobalUni(EtwNative.KERNEL_LOGGER_NAME),
            ProcessTraceMode = EtwNative.PROCESS_TRACE_MODE_REAL_TIME
                             | EtwNative.PROCESS_TRACE_MODE_EVENT_RECORD,
            EventCallback = _callback,
        };
        return logfile;
    }

    private void OnEventRecord(ref EtwNative.EVENT_RECORD record)
    {
        try
        {
            var header = record.EventHeader;
            if (header.ProviderId != KernelProcessProvider) return;

            var userData = record.UserData;
            var userDataLen = record.UserDataLength;
            if (userData == IntPtr.Zero || userDataLen == 0) return;

            // 把 payload 复制到托管数组，交给纯函数解析（可单测）
            var payload = new byte[userDataLen];
            Marshal.Copy(userData, payload, 0, userDataLen);

            var evt = ParseProcessEvent(header.ProcessId, header.ThreadId, header.TimeStamp,
                header.EventDescriptor.Id, payload);
            if (evt is not null) OnEvent?.Invoke(evt.Value);
        }
        catch
        {
            // 单条事件解析失败不应中断整个消费流 —— ETW 事件格式偶有变体
        }
    }

    /// <summary>
    /// 解析内核进程事件的 payload（纯函数，可单测）。
    /// </summary>
    /// <param name="headerPid">EVENT_HEADER 里的进程 ID。</param>
    /// <param name="headerTid">EVENT_HEADER 里的线程 ID。</param>
    /// <param name="fileTime">事件时间戳（FILETIME）。</param>
    /// <param name="eventId">EventDescriptor.Id：1=ProcessStart，2=ProcessEnd。</param>
    /// <param name="payload">UserData 原始字节。</param>
    internal static EtwEvent? ParseProcessEvent(uint headerPid, uint headerTid, long fileTime,
        ushort eventId, byte[] payload)
    {
        if (payload.Length == 0) return null;
        var timestamp = FileTimeToDateTime(fileTime);

        if (eventId == 1)
        {
            if (payload.Length < ProcessStart_FixedHeaderBytes) return null;

            var targetPid = BitConverter.ToUInt32(payload, ProcessStart_PidOffset);
            var parentPid = BitConverter.ToUInt32(payload, ProcessStart_PpidOffset);
            var imageName = ReadImageName(payload);

            return new EtwEvent(timestamp, targetPid, headerTid, EtwEventKind.ProcessStart,
                imageName, imageName, "Process Start", parentPid);
        }

        if (eventId == 2)
        {
            if (payload.Length < ProcessEnd_PidOffset + 4) return null;

            var targetPid = BitConverter.ToUInt32(payload, ProcessEnd_PidOffset);
            return new EtwEvent(timestamp, targetPid, headerTid, EtwEventKind.ProcessStop,
                "", "", "Process Stop", 0);
        }

        return null;
    }

    // ─────────────────────────────── 解析辅助 ───────────────────────────────

    /// <summary>
    /// 从 Process_TypeGroup1 的 payload 提取进程映像名。
    ///
    /// 内核进程事件的 ImageFileName 前面还有 UserSID 等变长字段，固定偏移不可靠。
    /// 这里用「尽力解析」：在 payload 里搜索以 .exe 结尾、含路径分隔符的 Unicode 字符串
    /// —— 这比假设固定偏移稳健得多，且进程名不是关键归因依据（PID/父 PID 才是，它们在固定偏移）。
    /// </summary>
    private static string ReadImageName(byte[] payload)
    {
        var chars = payload.Length / 2;
        var sb = new System.Text.StringBuilder();
        string? best = null;

        for (var i = 0; i < chars; i++)
        {
            var c = (char)BitConverter.ToUInt16(payload, i * 2);

            if (c == '\0')
            {
                var candidate = sb.ToString();
                if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    // 优先取含路径分隔符的完整路径，其次取纯文件名
                    if (best is null || (candidate.Contains('\\') && !best.Contains('\\')))
                        best = candidate;
                }
                sb.Clear();
            }
            else if (c is >= ' ' and <= '~' or '\\' or '/' or ':' or '.' or '_' or '-')
            {
                sb.Append(c);
                if (sb.Length > 512) sb.Clear();   // 防异常超长
            }
            else
            {
                sb.Clear();
            }
        }

        return best ?? "";
    }

    private static DateTime FileTimeToDateTime(long fileTime)
    {
        if (fileTime <= 0) return DateTime.Now;
        try { return DateTime.FromFileTimeUtc(fileTime).ToLocalTime(); }
        catch { return DateTime.Now; }
    }
}
