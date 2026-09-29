using System.Text;
using WinSecLab.Core.Engines.Dynamic;

namespace WinSecLab.Tests;

/// <summary>
/// ETW 内核进程事件解析。
///
/// 内核 Provider 的 payload 是未解码的二进制，字段偏移和字符串提取是最容易出错的地方，
/// 而这里的错误不会报异常——只会悄悄产出错误的 PID 或空进程名，污染整个进程树归因。
/// 所以把真实 payload 布局钉进测试。
/// </summary>
public class EtwParseTests
{
    /// <summary>构造 ProcessStart（EventId 1）的 payload：固定头 + 变长区（含 .exe 映像名）。</summary>
    private static byte[] BuildProcessStartPayload(uint pid, uint parentPid, string imageName)
    {
        // 固定头（前 20 字节）：UniqueProcessKey(4) ProcessId(4) ParentId(4) SessionId(4) ExitStatus(4)
        var bytes = new List<byte>();
        void AddU32(uint v) => bytes.AddRange(BitConverter.GetBytes(v));

        AddU32(0x12345678);            // UniqueProcessKey
        AddU32(pid);                   // ProcessId @ 4
        AddU32(parentPid);             // ParentId @ 8
        AddU32(1);                     // SessionId @ 12
        AddU32(0);                     // ExitStatus @ 16
        bytes.AddRange(new byte[16]);  // DirectoryTableBase + Flags 等杂项（真实结构里 image 前还有字段）
        // UserSID 区（占位）
        bytes.AddRange(new byte[12]);
        // ImageFileName（Unicode + null 结尾）
        bytes.AddRange(Encoding.Unicode.GetBytes(imageName));
        bytes.AddRange(new byte[2]);   // \0\0

        return bytes.ToArray();
    }

    [Fact]
    public void ParseProcessStart_ExtractsPidParentPidAndImageName()
    {
        var payload = BuildProcessStartPayload(pid: 4321, parentPid: 1234, imageName: @"C:\Windows\System32\notepad.exe");

        var evt = EtwKernelSession.ParseProcessEvent(
            headerPid: 4321, headerTid: 999, fileTime: 0, eventId: 1, payload);

        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.ProcessStart, evt.Value.EventKind);
        Assert.Equal((uint)4321, evt.Value.ProcessId);
        Assert.Equal((uint)1234, evt.Value.ParentPid);
        Assert.Equal(@"C:\Windows\System32\notepad.exe", evt.Value.ProcessName);
    }

    [Fact]
    public void ParseProcessEnd_ExtractsPid()
    {
        // ProcessEnd（EventId 2）payload：UniqueProcessKey(4) + ProcessId(4)
        var payload = new List<byte>();
        payload.AddRange(BitConverter.GetBytes(0xABCDEF01u));
        payload.AddRange(BitConverter.GetBytes(4321u));

        var evt = EtwKernelSession.ParseProcessEvent(
            headerPid: 4321, headerTid: 999, fileTime: 0, eventId: 2, payload.ToArray());

        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.ProcessStop, evt.Value.EventKind);
        Assert.Equal((uint)4321, evt.Value.ProcessId);
        Assert.Equal((uint)0, evt.Value.ParentPid);   // 终止事件没有父进程信息
    }

    /// <summary>payload 太短（不足固定头）时必须返回 null，而不是读出越界的垃圾值。</summary>
    [Fact]
    public void ParseProcessStart_TooShortPayload_ReturnsNull()
    {
        var evt = EtwKernelSession.ParseProcessEvent(0, 0, 0, 1, new byte[] { 1, 2, 3 });
        Assert.Null(evt);
    }

    [Fact]
    public void ParseProcessStart_EmptyPayload_ReturnsNull()
    {
        Assert.Null(EtwKernelSession.ParseProcessEvent(0, 0, 0, 1, Array.Empty<byte>()));
    }

    /// <summary>未知 eventId 不解析 —— 内核 Provider 还有线程、句柄等事件，不应误判成进程事件。</summary>
    [Fact]
    public void ParseProcessEvent_UnknownEventId_ReturnsNull()
    {
        var payload = BuildProcessStartPayload(100, 50, "x.exe");
        Assert.Null(EtwKernelSession.ParseProcessEvent(0, 0, 0, eventId: 3, payload));
    }

    /// <summary>映像名里没有 .exe 时，进程名留空但不影响 PID/父 PID 的提取（关键归因信息）。</summary>
    [Fact]
    public void ParseProcessStart_MissingImageName_StillHasPid()
    {
        var payload = new List<byte>();
        payload.AddRange(BitConverter.GetBytes(0u));   // UniqueProcessKey
        payload.AddRange(BitConverter.GetBytes(777u)); // ProcessId
        payload.AddRange(BitConverter.GetBytes(100u)); // ParentId
        payload.AddRange(new byte[12]);                // 补齐到固定头 20 字节
        payload.AddRange(Encoding.Unicode.GetBytes("no_extension_here"));
        payload.AddRange(new byte[2]);

        var evt = EtwKernelSession.ParseProcessEvent(777, 0, 0, 1, payload.ToArray());

        Assert.NotNull(evt);
        Assert.Equal((uint)777, evt.Value.ProcessId);
        Assert.Equal((uint)100, evt.Value.ParentPid);
        Assert.Equal("", evt.Value.ProcessName);   // 没 .exe 就留空，不误填
    }

    // ─────────────────────────────── Kernel-File 文件创建 ───────────────────────────────

    /// <summary>构造 FileIo_Create（EventId 64）payload：6 个 uint32 + OpenPath 宽字符串。</summary>
    private static byte[] BuildFileCreatePayload(string openPath)
    {
        var bytes = new List<byte>();
        void AddU32(uint v) => bytes.AddRange(BitConverter.GetBytes(v));

        AddU32(0x11111111);            // IrpPtr
        AddU32(0x22222222);            // TTID
        AddU32(0x33333333);            // FileObject
        AddU32(0x44444444);            // CreateOptions
        AddU32(0x55555555);            // FileAttributes
        AddU32(0x66666666);            // ShareAccess
        bytes.AddRange(Encoding.Unicode.GetBytes(openPath));   // OpenPath @ 24
        bytes.AddRange(new byte[2]);   // \0\0

        return bytes.ToArray();
    }

    [Fact]
    public void ParseFileCreate_ExtractsOpenPathAndPid()
    {
        var payload = BuildFileCreatePayload(@"C:\Users\Tester\AppData\Local\Temp\dropped.exe");

        var evt = EtwKernelSession.ParseFileEvent(
            pid: 4321, tid: 99, fileTime: 0, eventId: 64, payload);

        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.FileCreate, evt.Value.EventKind);
        Assert.Equal((uint)4321, evt.Value.ProcessId);
        Assert.Equal(@"C:\Users\Tester\AppData\Local\Temp\dropped.exe", evt.Value.Target);
        Assert.Equal("File Create", evt.Value.Operation);
    }

    /// <summary>OpenPath 为空字符串时返回 null —— 不产出无路径的文件事件。</summary>
    [Fact]
    public void ParseFileCreate_EmptyPath_ReturnsNull()
    {
        var payload = BuildFileCreatePayload("");
        Assert.Null(EtwKernelSession.ParseFileEvent(1, 2, 0, 64, payload));
    }

    [Fact]
    public void ParseFileCreate_TooShortPayload_ReturnsNull()
    {
        Assert.Null(EtwKernelSession.ParseFileEvent(1, 2, 0, 64, new byte[] { 1, 2, 3, 4 }));
    }

    /// <summary>FileIo_Write（EventId 67）目前未实现（需 FileObject 关联），应返回 null 而非误判。</summary>
    [Fact]
    public void ParseFileEvent_UnsupportedEventId_ReturnsNull()
    {
        var payload = BuildFileCreatePayload(@"C:\x.exe");
        Assert.Null(EtwKernelSession.ParseFileEvent(1, 2, 0, eventId: 67, payload));
    }
}
