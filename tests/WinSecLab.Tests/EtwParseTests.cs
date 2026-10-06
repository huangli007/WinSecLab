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
[Collection(ExternalProcess.Name)]
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
    private static byte[] BuildFileCreatePayload(string openPath, uint fileObject = 0x33333333)
    {
        var bytes = new List<byte>();
        void AddU32(uint v) => bytes.AddRange(BitConverter.GetBytes(v));

        AddU32(0x11111111);            // IrpPtr
        AddU32(0x22222222);            // TTID
        AddU32(fileObject);            // FileObject
        AddU32(0x44444444);            // CreateOptions
        AddU32(0x55555555);            // FileAttributes
        AddU32(0x66666666);            // ShareAccess
        bytes.AddRange(Encoding.Unicode.GetBytes(openPath));   // OpenPath @ 24
        bytes.AddRange(new byte[2]);   // \0\0

        return bytes.ToArray();
    }

    /// <summary>构造 FileIo_ReadWrite（EventType 68=Write）payload：uint64 + 6×uint32。</summary>
    private static byte[] BuildFileWritePayload(uint fileObject)
    {
        var bytes = new List<byte>();
        bytes.AddRange(BitConverter.GetBytes(0L));      // Offset (uint64)
        bytes.AddRange(BitConverter.GetBytes(0xAAAA1111u));  // IrpPtr
        bytes.AddRange(BitConverter.GetBytes(0xBBBB2222u));  // TTID
        bytes.AddRange(BitConverter.GetBytes(fileObject));   // FileObject @ 16
        bytes.AddRange(BitConverter.GetBytes(0xCCCC3333u));  // FileKey
        bytes.AddRange(BitConverter.GetBytes(1024u));        // IoSize
        bytes.AddRange(BitConverter.GetBytes(0u));           // IoFlags
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

    // ─────────────────────────────── Kernel-Registry 注册表操作 ───────────────────────────────

    /// <summary>构造 Registry_TypeGroup1 payload：sint64 + 3×uint32 + KeyName 宽字符串。</summary>
    private static byte[] BuildRegistryPayload(string keyName)
    {
        var bytes = new List<byte>();
        bytes.AddRange(BitConverter.GetBytes(1234567890L));  // InitialTime (sint64)
        bytes.AddRange(BitConverter.GetBytes(0u));            // Status (NTSTATUS)
        bytes.AddRange(BitConverter.GetBytes(0u));            // Index
        bytes.AddRange(BitConverter.GetBytes(0xDEADBEEFu));   // KeyHandle
        bytes.AddRange(Encoding.Unicode.GetBytes(keyName));   // KeyName @ 20
        bytes.AddRange(new byte[2]);                          // \0\0
        return bytes.ToArray();
    }

    [Fact]
    public void ParseRegistryCreate_ExtractsKeyNameAndPid()
    {
        var payload = BuildRegistryPayload(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

        var evt = EtwKernelSession.ParseRegistryEvent(
            pid: 4321, tid: 99, fileTime: 0, eventType: 10, payload);

        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.RegistryCreate, evt.Value.EventKind);
        Assert.Equal((uint)4321, evt.Value.ProcessId);
        Assert.Equal(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", evt.Value.Target);
    }

    [Fact]
    public void ParseRegistrySetValue_MapsToRegistrySet()
    {
        var payload = BuildRegistryPayload(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

        var evt = EtwKernelSession.ParseRegistryEvent(100, 0, 0, eventType: 14, payload);

        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.RegistrySet, evt.Value.EventKind);
    }

    [Fact]
    public void ParseRegistryDelete_MapsToRegistryDelete()
    {
        var payload = BuildRegistryPayload(@"\REGISTRY\MACHINE\SOFTWARE\x");
        var evt = EtwKernelSession.ParseRegistryEvent(100, 0, 0, eventType: 12, payload);
        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.RegistryDelete, evt.Value.EventKind);
    }

    /// <summary>KCBCreate（EventType 24）是最贴近真实键创建的事件，也应识别为 RegistryCreate。</summary>
    [Fact]
    public void ParseRegistryKcbCreate_MapsToRegistryCreate()
    {
        var payload = BuildRegistryPayload(@"\REGISTRY\MACHINE\SOFTWARE\newkey");
        var evt = EtwKernelSession.ParseRegistryEvent(100, 0, 0, eventType: 24, payload);
        Assert.NotNull(evt);
        Assert.Equal(EtwEventKind.RegistryCreate, evt.Value.EventKind);
    }

    /// <summary>不支持的事件类型（如 Open=11、Query=13）应返回 null，不误判为修改。</summary>
    [Fact]
    public void ParseRegistry_UnsupportedEventType_ReturnsNull()
    {
        var payload = BuildRegistryPayload(@"\REGISTRY\MACHINE\SOFTWARE\x");
        Assert.Null(EtwKernelSession.ParseRegistryEvent(100, 0, 0, eventType: 11, payload));
        Assert.Null(EtwKernelSession.ParseRegistryEvent(100, 0, 0, eventType: 13, payload));
    }

    [Fact]
    public void ParseRegistry_EmptyKeyName_ReturnsNull()
    {
        var payload = BuildRegistryPayload("");
        Assert.Null(EtwKernelSession.ParseRegistryEvent(100, 0, 0, 10, payload));
    }

    // ─────────────────────────────── FileObject 关联（FileIo_Write） ───────────────────────────────

    /// <summary>
    /// 回归：FileIo_Write 只带 FileObject，路径必须靠前面 FileIo_Create 建立的映射反查。
    /// 这是"谁写了哪个文件"归因的关键 —— 漏了关联，写事件就会变成没有路径的孤证。
    /// </summary>
    [Fact]
    public void HandleFileEvent_WriteResolvesPathViaFileObject()
    {
        const uint fileObject = 0xDEADBEEF;
        var session = new EtwKernelSession();

        // 先 Create，建立 FileObject → 路径 映射
        var createPayload = BuildFileCreatePayload(@"C:\Users\Tester\AppData\Roaming\malware.log", fileObject);
        var createEvt = session.HandleFileEvent(4321, 0, 0, eventId: 64, createPayload);
        Assert.NotNull(createEvt);
        Assert.Equal(EtwEventKind.FileCreate, createEvt.Value.EventKind);

        // 再 Write，通过同一个 FileObject 反查路径
        var writePayload = BuildFileWritePayload(fileObject);
        var writeEvt = session.HandleFileEvent(4321, 0, 0, eventId: 68, writePayload);

        Assert.NotNull(writeEvt);
        Assert.Equal(EtwEventKind.FileWrite, writeEvt.Value.EventKind);
        Assert.Equal(@"C:\Users\Tester\AppData\Roaming\malware.log", writeEvt.Value.Target);
    }

    /// <summary>没有先 Create 就 Write，映射里查不到路径，应返回 null（不产出孤证）。</summary>
    [Fact]
    public void HandleFileEvent_WriteWithoutCreate_ReturnsNull()
    {
        var session = new EtwKernelSession();
        var writePayload = BuildFileWritePayload(0x12345678);
        Assert.Null(session.HandleFileEvent(4321, 0, 0, eventId: 68, writePayload));
    }

    /// <summary>读事件（EventType 67）不产出事件 —— 读操作量大且安全分析价值低。</summary>
    [Fact]
    public void HandleFileEvent_Read_ReturnsNull()
    {
        const uint fileObject = 0xDEADBEEF;
        var session = new EtwKernelSession();
        session.HandleFileEvent(4321, 0, 0, 64, BuildFileCreatePayload(@"C:\x.txt", fileObject));

        var readPayload = BuildFileWritePayload(fileObject);   // payload 结构相同
        Assert.Null(session.HandleFileEvent(4321, 0, 0, eventId: 67, readPayload));
    }
}
