using System.Runtime.InteropServices;

namespace WinSecLab.Core.Util;

/// <summary>
/// ETW（Event Tracing for Windows）原生声明。
///
/// 单独放在这个文件，而不是塞进 NativeMethods.cs：ETW 的 P/Invoke 面很大
/// （会话管理 + 消费回调 + 内核事件 MOF 解码），需要独立的上下文。
///
/// 定位：内核 Provider（Kernel-Process / Kernel-File / Kernel-Registry）需要管理员权限，
/// 因此 ETW 是「管理员时的精确归因增强通道」——与 Procmon / tshark 同级，标准用户下降级。
/// </summary>
internal static class EtwNative
{
    // ─────────────────────────────── 会话管理 ───────────────────────────────

    internal const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
    internal const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
    internal const uint EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000;   // 系统内核会话
    internal const uint EVENT_TRACE_FLAG_PROCESS = 0x00000001;         // 进程创建/终止
    internal const uint EVENT_TRACE_FLAG_THREAD = 0x00000002;
    internal const uint EVENT_TRACE_FLAG_FILE_IO = 0x02000000;         // 文件 I/O
    internal const uint EVENT_TRACE_FLAG_REGISTRY = 0x00020000;        // 注册表

    internal const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    internal const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;  // 用 EVENT_RECORD 回调（而非旧 MOF）
    internal const uint PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000;

    internal const byte TRACE_LEVEL_INFO = 0x04;
    internal const ulong TRACE_MATCH_ALL_KEYWORD = 0;

    /// <summary>内核日志记录器会话名（系统预定义）。</summary>
    internal const string KERNEL_LOGGER_NAME = "WinSecLab-Etw";

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct EVENT_TRACE_PROPERTIES
    {
        public WNODE_HEADER Wnode;
        public uint BufferSize;               // KB
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;

        /// <summary>
        /// 尾部字节区：承载内嵌的会话名字符串（LoggerNameOffset 指向这里）。
        /// 会话名长度不固定，这里给足余量；StartTraceW 按 Wnode.BufferSize 读取。
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] Tail;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WNODE_HEADER
    {
        public uint BufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public ulong TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    /// <summary>EnableTraceEx2 用的 provider 配置。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ENABLE_TRACE_PARAMETERS
    {
        public uint Version;
        public uint EnableProperty;
        public uint ControlFlags;
        public Guid SourceId;
        public IntPtr FilterDescCount;         // PEVENT_FILTER_DESCRIPTOR*
        public IntPtr FilterDesc;              // PEVENT_FILTER_DESCRIPTOR*
    }

    internal const uint EVENT_ENABLE_PROPERTY_SID = 0x00000001;
    internal const uint EVENT_ENABLE_PROPERTY_TS_ID = 0x00000002;
    internal const uint EVENT_ENABLE_PROPERTY_STACK_TRACE = 0x00000004;

    // ─────────────────────────────── 消费回调 ───────────────────────────────

    /// <summary>实时消费的日志文件描述（OpenTrace 用）。</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct EVENT_TRACE_LOGFILEW
    {
        public IntPtr LoggerName;
        public IntPtr LogFileName;
        public long TimeZoneBias;
        public uint BufferSize;
        public uint ProcessTraceMode;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint CurrentEvent;
        public IntPtr BuffersRead;
        public IntPtr LogFileHeader;
        public EventRecordCallback EventCallback;
        public IntPtr Context;
    }

    internal delegate void EventRecordCallback([In] ref EVENT_RECORD EventRecord);

    /// <summary>内核事件记录（ProcessTrace 回调参数）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;
        public ETW_BUFFER_CONTEXT BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_HEADER
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;                 // FILETIME（100ns 间隔）
        public Guid ProviderId;
        public EVENT_DESCRIPTOR EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_DESCRIPTOR
    {
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ETW_BUFFER_CONTEXT
    {
        public byte ProcessorNumber;
        public byte Alignment;
        public ushort LoggerId;
    }

    // ─────────────────────────────── 函数 ───────────────────────────────

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint StartTraceW(
        out long TraceHandle,
        [MarshalAs(UnmanagedType.LPWStr)] string InstanceName,
        ref EVENT_TRACE_PROPERTIES Properties);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint EnableTraceEx2(
        long TraceHandle,
        ref Guid ProviderId,
        uint ControlCode,                     // EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
        byte Level,
        ulong MatchAnyKeyword,
        ulong MatchAllKeyword,
        uint Timeout,
        ref ENABLE_TRACE_PARAMETERS EnableParameters);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint OpenTraceW(ref EVENT_TRACE_LOGFILEW Logfile);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint ProcessTrace(
        [MarshalAs(UnmanagedType.LPArray)] long[] HandleArray,
        uint HandleCount,
        IntPtr StartTime,
        IntPtr EndTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint CloseTrace(long TraceHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint ControlTraceW(
        long TraceHandle,
        [MarshalAs(UnmanagedType.LPWStr)] string InstanceName,
        ref EVENT_TRACE_PROPERTIES Properties,
        uint ControlCode);                    // EVENT_TRACE_CONTROL_STOP = 2

    // 控制码
    internal const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
    internal const uint EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0;
    internal const uint EVENT_TRACE_CONTROL_STOP = 2;
}
