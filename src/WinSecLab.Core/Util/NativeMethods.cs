using System.Runtime.InteropServices;

namespace WinSecLab.Core.Util;

/// <summary>平台原生调用集中地。全部带安全兜底，任何一项失败都不影响其他分析。</summary>
internal static class NativeMethods
{
    // ------------------------------------------------------------------ 进程 / 权限

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);

    // ------------------------------------------------------------------ 签名验证

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    internal static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    // ------------------------------------------------------------------ TCP / UDP 表

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf,
        TCP_TABLE_CLASS tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf,
        UDP_TABLE_CLASS tableClass, uint reserved);

    internal enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL,
    }

    internal enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE,
    }

    internal const int AF_INET = 2;
    internal const int AF_INET6 = 23;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }

    // ------------------------------------------------------------------ DNS 缓存

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", SetLastError = true)]
    internal static extern int DnsGetCacheDataTable(IntPtr pDataTable);

    [DllImport("dnsapi.dll")]
    internal static extern void DnsFree(IntPtr pData, int freeType);

    [StructLayout(LayoutKind.Sequential)]
    internal struct DNS_CACHE_ENTRY
    {
        public IntPtr pNext;
        public IntPtr pszName;
        public ushort wType;
        public ushort wDataLength;
        public uint dwFlags;
    }

    // ------------------------------------------------------------------ Toolhelp32 进程快照

    internal const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    // ------------------------------------------------------------------ 文件大小 / 版本（备用）

    [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetFileVersionInfoSizeW(string lptstrFilename, out uint lpdwHandle);
}
