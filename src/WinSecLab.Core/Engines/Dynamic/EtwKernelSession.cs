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

    private static readonly Guid KernelFileProvider =
        new("EDD08927-9CC4-4E65-B970-C2560FB5C289");

    private static readonly Guid KernelRegistryProvider =
        new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");

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

    // FileIo_Create（EventId 64）的 payload 布局（继承 FileIo → DiskIo_TypeGroup1）：
    //   uint32 IrpPtr;          // 0
    //   uint32 TTID;            // 4
    //   uint32 FileObject;      // 8
    //   uint32 CreateOptions;   // 12
    //   uint32 FileAttributes;  // 16
    //   uint32 ShareAccess;     // 20
    //   string OpenPath;        // 24（null 结尾宽字符串，含盘符的完整路径）
    private const int FileCreate_OpenPathOffset = 24;

    // Registry_TypeGroup1 的 payload 布局（EventType 10~27，见微软 MOF）：
    //   sint64 InitialTime;   // 0（8 字节）
    //   uint32 Status;        // 8
    //   uint32 Index;         // 12
    //   uint32 KeyHandle;     // 16
    //   string KeyName;       // 20（null 结尾宽字符串，注册表键的完整路径）
    // EventType → 操作：10=Create 12=Delete 14=SetValue 15=DeleteValue 24=KCBCreate
    private const int Registry_KeyNameOffset = 20;

    // FileIo_ReadWrite（EventType 67=Read 68=Write）的 payload 布局：
    //   uint64 Offset;     // 0（8 字节）
    //   uint32 IrpPtr;     // 8
    //   uint32 TTID;       // 12
    //   uint32 FileObject; // 16  ← 关键：关联 FileIo_Create 的路径
    //   uint32 FileKey;    // 20
    //   uint32 IoSize;     // 24
    //   uint32 IoFlags;    // 28
    private const int FileReadWrite_FileObjectOffset = 16;

    // FileIo_Create 的 FileObject 偏移（见 FileCreate_OpenPathOffset 的注释布局）
    private const int FileCreate_FileObjectOffset = 8;

    // FileObject → 路径 的映射。FileObject 是内核指针，文件关闭后会被系统复用，
    // 所以映射必须有容量上限，超限时整体清空（宁可丢旧映射，不可串路径）。
    private readonly Dictionary<uint, string> _fileObjectPaths = new(8192);

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

        // ── 2) 启用 Kernel-Process 与 Kernel-File provider ──
        var enableParams = new EtwNative.ENABLE_TRACE_PARAMETERS
        {
            Version = 2,
            EnableProperty = EtwNative.EVENT_ENABLE_PROPERTY_SID,
        };

        // Kernel-Process：进程创建/终止（带父 PID）
        var processGuid = KernelProcessProvider;
        ret = EtwNative.EnableTraceEx2(
            _traceHandle, ref processGuid,
            EtwNative.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EtwNative.TRACE_LEVEL_INFO,
            EtwNative.TRACE_MATCH_ALL_KEYWORD, EtwNative.TRACE_MATCH_ALL_KEYWORD,
            0, ref enableParams);

        if (ret != 0)
        {
            LastError = $"EnableTraceEx2(Process) 失败：0x{ret:X8}（{new Win32Exception((int)ret).Message}）";
            StopTrace();
            return false;
        }

        // Kernel-File：文件创建（FileIo_Create 的 OpenPath 含完整路径 + PID）
        var fileGuid = KernelFileProvider;
        ret = EtwNative.EnableTraceEx2(
            _traceHandle, ref fileGuid,
            EtwNative.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EtwNative.TRACE_LEVEL_INFO,
            EtwNative.TRACE_MATCH_ALL_KEYWORD, EtwNative.TRACE_MATCH_ALL_KEYWORD,
            0, ref enableParams);

        if (ret != 0)
        {
            // 文件 Provider 失败不影响进程监控 —— 记录并继续
            LastError = $"EnableTraceEx2(File) 失败：0x{ret:X8}（{new Win32Exception((int)ret).Message}）";
        }

        // Kernel-Registry：注册表键创建/删除/设值（KeyName 含完整路径 + PID）
        var registryGuid = KernelRegistryProvider;
        ret = EtwNative.EnableTraceEx2(
            _traceHandle, ref registryGuid,
            EtwNative.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EtwNative.TRACE_LEVEL_INFO,
            EtwNative.TRACE_MATCH_ALL_KEYWORD, EtwNative.TRACE_MATCH_ALL_KEYWORD,
            0, ref enableParams);

        if (ret != 0)
        {
            LastError = $"EnableTraceEx2(Registry) 失败：0x{ret:X8}（{new Win32Exception((int)ret).Message}）";
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
            // 进程事件 + 文件创建事件 + 注册表事件。
            // 注意：收 FileIo_Create 必须用 FILE_IO_INIT(0x04000000) 而非 FILE_IO(0x02000000)，
            // 收注册表用 REGISTRY(0x00020000)。官方文档对 EnableFlags 有严格区分，开错采不到。
            EnableFlags = EtwNative.EVENT_TRACE_FLAG_PROCESS
                          | EtwNative.EVENT_TRACE_FLAG_FILE_IO_INIT
                          | EtwNative.EVENT_TRACE_FLAG_REGISTRY,
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

            var userData = record.UserData;
            var userDataLen = record.UserDataLength;
            if (userData == IntPtr.Zero || userDataLen == 0) return;

            // 把 payload 复制到托管数组，交给纯函数解析（可单测）
            var payload = new byte[userDataLen];
            Marshal.Copy(userData, payload, 0, userDataLen);

            EtwEvent? evt;
            if (header.ProviderId == KernelProcessProvider)
            {
                evt = ParseProcessEvent(header.ProcessId, header.ThreadId, header.TimeStamp,
                    header.EventDescriptor.Id, payload);
            }
            else if (header.ProviderId == KernelFileProvider)
            {
                evt = HandleFileEvent(header.ProcessId, header.ThreadId, header.TimeStamp,
                    header.EventDescriptor.Id, payload);
            }
            else if (header.ProviderId == KernelRegistryProvider)
            {
                evt = ParseRegistryEvent(header.ProcessId, header.ThreadId, header.TimeStamp,
                    header.EventDescriptor.Id, payload);
            }
            else
            {
                return;
            }

            if (evt is not null) OnEvent?.Invoke(evt.Value);
        }
        catch
        {
            // 单条事件解析失败不应中断整个消费流 —— ETW 事件格式偶有变体
        }
    }

    /// <summary>
    /// 处理文件事件，并维护 FileObject → 路径 的关联映射。
    ///
    /// FileIo_Create（64）带完整 OpenPath，写入映射；FileIo_Write（68）/Read（67）
    /// 只带 FileObject，靠映射反查路径。FileObject 是内核指针会被复用，
    /// 所以映射有容量上限（见 _fileObjectPaths 声明）。
    /// </summary>
    internal EtwEvent? HandleFileEvent(uint pid, uint tid, long fileTime, ushort eventId, byte[] payload)
    {
        var timestamp = FileTimeToDateTime(fileTime);

        if (eventId == 64)   // FileIo_Create：记录 FileObject → OpenPath 映射，并产出 FileCreate
        {
            if (payload.Length < FileCreate_OpenPathOffset + 2) return null;
            var openPath = ReadNullTerminatedWideString(payload, FileCreate_OpenPathOffset);
            if (string.IsNullOrEmpty(openPath)) return null;

            if (payload.Length >= FileCreate_FileObjectOffset + 4)
            {
                var fileObject = BitConverter.ToUInt32(payload, FileCreate_FileObjectOffset);
                if (fileObject != 0) RememberPath(fileObject, openPath);
            }

            return new EtwEvent(timestamp, pid, tid, EtwEventKind.FileCreate,
                "", openPath, "File Create", 0);
        }

        if (eventId is 67 or 68)   // FileIo_Read/Write：通过 FileObject 反查路径
        {
            if (payload.Length < FileReadWrite_FileObjectOffset + 4) return null;
            var fileObject = BitConverter.ToUInt32(payload, FileReadWrite_FileObjectOffset);
            if (fileObject == 0) return null;

            // 只对"写入"产出事件（读操作量大且安全分析价值低）
            if (eventId != 68) return null;

            if (!_fileObjectPaths.TryGetValue(fileObject, out var path) || string.IsNullOrEmpty(path))
                return null;

            return new EtwEvent(timestamp, pid, tid, EtwEventKind.FileWrite,
                "", path, "File Write", 0);
        }

        return null;
    }

    private void RememberPath(uint fileObject, string path)
    {
        if (_fileObjectPaths.Count >= 8192) _fileObjectPaths.Clear();   // 容量保护，防指针复用串路径
        _fileObjectPaths[fileObject] = path;
    }

    /// <summary>
    /// 解析 FileIo_Create 的字段（纯函数，可单测，不含关联逻辑）。
    /// </summary>
    internal static EtwEvent? ParseFileEvent(uint pid, uint tid, long fileTime,
        ushort eventId, byte[] payload)
    {
        if (payload.Length < FileCreate_OpenPathOffset + 2) return null;
        var timestamp = FileTimeToDateTime(fileTime);

        if (eventId == 64)   // FileIo_Create
        {
            var openPath = ReadNullTerminatedWideString(payload, FileCreate_OpenPathOffset);
            if (string.IsNullOrEmpty(openPath)) return null;

            return new EtwEvent(timestamp, pid, tid, EtwEventKind.FileCreate,
                "", openPath, "File Create", 0);
        }

        return null;
    }

    /// <summary>
    /// 解析内核注册表事件的 payload（纯函数，可单测）。
    /// Registry_TypeGroup1：KeyName 在固定偏移 20（sint64 + 3×uint32 之后），含完整键路径。
    /// EventType：10=CreateKey 12=DeleteKey 14=SetValue 15=DeleteValue 24=KCBCreate。
    /// </summary>
    internal static EtwEvent? ParseRegistryEvent(uint pid, uint tid, long fileTime,
        ushort eventType, byte[] payload)
    {
        if (payload.Length < Registry_KeyNameOffset + 2) return null;
        var timestamp = FileTimeToDateTime(fileTime);

        var keyName = ReadNullTerminatedWideString(payload, Registry_KeyNameOffset);
        if (string.IsNullOrEmpty(keyName)) return null;

        var (kind, operation) = eventType switch
        {
            10 => (EtwEventKind.RegistryCreate, "Registry Create Key"),
            12 => (EtwEventKind.RegistryDelete, "Registry Delete Key"),
            14 => (EtwEventKind.RegistrySet, "Registry Set Value"),
            15 => (EtwEventKind.RegistryDelete, "Registry Delete Value"),
            24 => (EtwEventKind.RegistryCreate, "Registry KCB Create"),
            _ => ((int)EtwEventKind.RegistrySet, (string?)null)!,
        };

        if (operation is null) return null;

        return new EtwEvent(timestamp, pid, tid, kind, "", keyName, operation, 0);
    }

    /// <summary>从 payload 指定偏移读取 null 结尾的宽字符串。</summary>
    private static string ReadNullTerminatedWideString(byte[] payload, int offset)
    {
        if (offset < 0 || offset >= payload.Length) return "";
        var sb = new System.Text.StringBuilder();
        for (var i = offset; i + 1 < payload.Length; i += 2)
        {
            var c = (char)BitConverter.ToUInt16(payload, i);
            if (c == '\0') break;
            sb.Append(c);
            if (sb.Length > 1024) break;   // 防异常超长
        }
        return sb.ToString();
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
