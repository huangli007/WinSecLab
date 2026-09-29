using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Network;

/// <summary>
/// §6 网络分析中心 —— Connections / DNS。
/// 用 iphlpapi 的 GetExtendedTcpTable / GetExtendedUdpTable 取连接表，天然带 owning PID，
/// 因此连接归因是 <see cref="AttributionQuality.Exact"/>，比抓包后再猜进程可靠得多。
/// PCAP 级别的原始流量交给 Wireshark / tshark 适配器（§7）。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NetworkMonitor : IDisposable
{
    private readonly Dictionary<string, NetworkConnection> _connections = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _dnsCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _ipToHost = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private Timer? _dnsTimer;
    private long _sequence;
    private volatile bool _polling;
    private readonly bool _resolveDns;
    private string? _processNameCacheKey;
    private readonly Dictionary<uint, (string Name, string? Path)> _processCache = new();

    public Action<NetworkConnection>? OnConnection { get; set; }
    public Action<DnsObservation>? OnDns { get; set; }
    public Action<MonitorEvent>? OnEvent { get; set; }
    public Func<uint, bool>? IsInTargetTree { get; set; }
    public Func<uint, string?>? ProcessPathResolver { get; set; }
    public List<string> Warnings { get; } = new();

    public int PollIntervalMs { get; set; } = 1500;
    public bool CaptureClosedConnections { get; set; } = true;
    public HashSet<string> ObservationLocalAddresses { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool EnableDnsCache { get; set; } = true;

    public NetworkMonitor(bool resolveDns = true)
    {
        _resolveDns = resolveDns;
    }

    public void Start()
    {
        PollOnce();
        _timer = Util.SafeTimer.Create(PollOnce, PollIntervalMs, PollIntervalMs);
        if (_resolveDns && EnableDnsCache)
        {
            _dnsTimer = Util.SafeTimer.Create(PollDnsCache, 1500, 5000);
        }
    }

    // ------------------------------------------------------------ 连接表轮询

    private void PollOnce()
    {
        if (_polling) return;
        _polling = true;
        try
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var row in QueryTcpV4()) ProcessConnection(row, seen);
            foreach (var row in QueryTcpV6()) ProcessConnection(row, seen);
            foreach (var row in QueryUdpV4()) ProcessConnection(row, seen);
            foreach (var row in QueryUdpV6()) ProcessConnection(row, seen);

            if (CaptureClosedConnections)
            {
                foreach (var key in _connections.Keys.Where(k => !seen.Contains(k)).ToList())
                {
                    if (!_connections.TryGetValue(key, out var conn)) continue;
                    if (conn.State is ConnectionState.TimeWait or ConnectionState.CloseWait) continue;

                    // 只上报目标进程树的连接关闭，避免系统噪声
                    if (!conn.IsFromTargetTree) continue;

                    conn.State = ConnectionState.Closed;
                    conn.LastSeen = DateTime.Now;
                    OnEvent?.Invoke(new MonitorEvent
                    {
                        Type = MonitorEventType.NetworkClose,
                        ProcessId = conn.ProcessId,
                        ProcessName = conn.ProcessName,
                        ProcessPath = conn.ProcessPath,
                        Operation = "Connection Closed",
                        Target = $"{conn.ProcessName} → {conn.DisplayHost}:{conn.RemotePort}",
                        IsFromTargetTree = conn.IsFromTargetTree,
                        Detail = $"会话持续 {(conn.LastSeen - conn.FirstSeen).TotalSeconds:F1}s，观测 {conn.ObservationCount} 次",
                        Source = "iphlpapi",
                    });
                }
                _connections.Clear();
            }
        }
        catch (Exception ex)
        {
            if (Warnings.Count < 20) Warnings.Add($"连接表轮询失败：{ex.Message}");
        }
        finally
        {
            _polling = false;
        }
    }

    private void ProcessConnection(RawConnection row, HashSet<string> seen)
    {
        // 只看有明确对端的连接；纯 Listen 单独处理
        var key = $"{row.Protocol}|{row.Pid}|{row.LocalAddress}:{row.LocalPort}|{row.RemoteAddress}:{row.RemotePort}";
        seen.Add(key);

        var now = DateTime.Now;
        if (_connections.TryGetValue(key, out var existing))
        {
            existing.LastSeen = now;
            existing.ObservationCount++;
            existing.State = row.State;
            return;
        }

        var (processName, processPath) = ResolveProcess(row.Pid);
        // 未挂上进程树过滤器时视为「非目标」，避免把全机流量都当成本次测试的发现
        var inTree = IsInTargetTree?.Invoke(row.Pid) ?? false;

        var connection = new NetworkConnection
        {
            Id = $"NET-{Interlocked.Increment(ref _sequence):D6}",
            FirstSeen = now,
            LastSeen = now,
            Protocol = row.Protocol,
            ProcessId = row.Pid,
            ProcessName = processName,
            ProcessPath = processPath,
            IsFromTargetTree = inTree,
            LocalAddress = row.LocalAddress,
            LocalPort = row.LocalPort,
            RemoteAddress = row.RemoteAddress,
            RemotePort = row.RemotePort,
            State = row.State,
            ObservationCount = 1,
            Attribution = row.Pid != 0 ? AttributionQuality.Exact : AttributionQuality.Unattributed,
            Source = "iphlpapi",
        };

        // 观测到的本地地址表用于后续过滤（避免把本机监听噪声算成外部通信）
        if (!string.IsNullOrEmpty(row.LocalAddress) && !row.LocalAddress.StartsWith("0.") && row.LocalAddress != "::")
            ObservationLocalAddresses.Add(row.LocalAddress);

        if (_ipToHost.TryGetValue(row.RemoteAddress, out var host))
            connection.Domain = host;

        _connections[key] = connection;

        if (!inTree && !IsInterestingNonTarget(connection)) return;

        var type = row.State == ConnectionState.Listen ? MonitorEventType.NetworkListen : MonitorEventType.NetworkConnect;
        var suspicious = IsSuspiciousConnection(connection);

        OnConnection?.Invoke(connection);
        OnEvent?.Invoke(new MonitorEvent
        {
            Type = type,
            ProcessId = connection.ProcessId,
            ProcessName = connection.ProcessName,
            ProcessPath = connection.ProcessPath,
            Operation = type == MonitorEventType.NetworkListen ? "Listen" : "TCP/UDP Connection",
            Target = $"{connection.DisplayHost}:{connection.RemotePort}",
            IsFromTargetTree = inTree,
            IsSuspicious = suspicious,
            SuspicionReason = suspicious ? DescribeSuspicion(connection) : null,
            Detail = $"{connection.Protocol} {connection.LocalEndpoint} → {connection.RemoteEndpoint} [{connection.StateText}] {connection.ServiceHint}"
                     + (connection.Domain is not null ? $"；域名 {connection.Domain}" : ""),
            Source = "iphlpapi",
        });
    }

    private static bool IsInterestingNonTarget(NetworkConnection c)
    {
        // 非目标进程的连接只在「可疑外联」时保留，避免把系统后台流量全量入库
        if (c.IsLoopback) return false;
        if (c.State is ConnectionState.Listen) return false;
        return IsSuspiciousConnection(c);
    }

    private static bool IsSuspiciousConnection(NetworkConnection c)
    {
        if (c.IsLoopback) return false;
        if (c.State != ConnectionState.Established) return false;
        // 直连硬编码 IP（没有域名解析记录）且端口是非标准端口
        if (c.Domain is null && !c.IsPrivateAddress && c.RemotePort is not (80 or 443 or 53)) return true;
        return false;
    }

    private static string DescribeSuspicion(NetworkConnection c) =>
        c.Domain is null && !c.IsPrivateAddress
            ? $"直连外部 IP {c.RemoteEndpoint}，未观测到域名解析记录，端口 {c.RemotePort}（{c.ServiceHint}）"
            : $"连接 {c.RemoteEndpoint}，端口 {c.RemotePort}（{c.ServiceHint}）";

    private (string Name, string? Path) ResolveProcess(uint pid)
    {
        if (pid == 0) return ("System Idle", null);
        if (pid == 4) return ("System", null);
        if (_processCache.TryGetValue(pid, out var cached)) return cached;

        try
        {
            using var process = Process.GetProcessById((int)pid);
            var name = $"{process.ProcessName}.exe";
            string? path = null;
            try
            {
                path = process.MainModule?.FileName;
            }
            catch
            {
                path = null;
            }
            // 进程名解析结果可能随进程退出失效，缓存规模限制住
            if (_processCache.Count > 4000) _processCache.Clear();
            _processCache[pid] = (name, path);
            return (name, path);
        }
        catch
        {
            var fallback = ($"pid-{pid}", (string?)null);
            _processCache[pid] = fallback;
            return fallback;
        }
    }

    // ------------------------------------------------------------- TCP/UDP 查询

    private sealed class RawConnection
    {
        public NetworkProtocol Protocol;
        public string LocalAddress = "";
        public int LocalPort;
        public string RemoteAddress = "";
        public int RemotePort;
        public ConnectionState State;
        public uint Pid;
    }

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const int NO_ERROR = 0;

    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    private static IEnumerable<RawConnection> QueryTcpV4() => QueryTcp(AF_INET);
    private static IEnumerable<RawConnection> QueryTcpV6() => QueryTcp(AF_INET6);

    private static IEnumerable<RawConnection> QueryTcp(int family)
    {
        var size = 0;
        var result = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, family,
            (NativeMethods.TCP_TABLE_CLASS)TCP_TABLE_OWNER_PID_ALL, 0);

        if (result != ERROR_INSUFFICIENT_BUFFER || size <= 0) yield break;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = NativeMethods.GetExtendedTcpTable(buffer, ref size, false, family,
                (NativeMethods.TCP_TABLE_CLASS)TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != NO_ERROR) yield break;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = family == AF_INET
                ? Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>()
                : Marshal.SizeOf<NativeMethods.MIB_TCP6ROW_OWNER_PID>();

            var pointer = IntPtr.Add(buffer, 4);
            for (var i = 0; i < count; i++)
            {
                var rowPtr = IntPtr.Add(pointer, i * rowSize);
                RawConnection? row = null;
                try
                {
                    if (family == AF_INET)
                    {
                        var r = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                        row = new RawConnection
                        {
                            Protocol = NetworkProtocol.Tcp,
                            LocalAddress = V4Address(r.localAddr),
                            LocalPort = V4Port(r.localPort),
                            RemoteAddress = V4Address(r.remoteAddr),
                            RemotePort = V4Port(r.remotePort),
                            State = MapTcpState(r.state),
                            Pid = r.owningPid,
                        };
                    }
                    else
                    {
                        var r = Marshal.PtrToStructure<NativeMethods.MIB_TCP6ROW_OWNER_PID>(rowPtr);
                        row = new RawConnection
                        {
                            Protocol = NetworkProtocol.Tcp,
                            LocalAddress = V6Address(r.localAddr),
                            LocalPort = V4Port(r.localPort),
                            RemoteAddress = V6Address(r.remoteAddr),
                            RemotePort = V4Port(r.remotePort),
                            State = MapTcpState(r.state),
                            Pid = r.owningPid,
                        };
                    }
                }
                catch (Exception)
                {
                    // 结构体解析失败（表在读取过程中变化），跳过该行
                }
                if (row is not null) yield return row;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IEnumerable<RawConnection> QueryUdpV4() => QueryUdp(AF_INET);
    private static IEnumerable<RawConnection> QueryUdpV6() => QueryUdp(AF_INET6);

    private static IEnumerable<RawConnection> QueryUdp(int family)
    {
        var size = 0;
        var result = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, false, family,
            (NativeMethods.UDP_TABLE_CLASS)UDP_TABLE_OWNER_PID, 0);
        if (result != ERROR_INSUFFICIENT_BUFFER || size <= 0) yield break;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = NativeMethods.GetExtendedUdpTable(buffer, ref size, false, family,
                (NativeMethods.UDP_TABLE_CLASS)UDP_TABLE_OWNER_PID, 0);
            if (result != NO_ERROR) yield break;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = family == AF_INET
                ? Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>()
                : Marshal.SizeOf<NativeMethods.MIB_UDP6ROW_OWNER_PID>();

            var pointer = IntPtr.Add(buffer, 4);
            for (var i = 0; i < count; i++)
            {
                var rowPtr = IntPtr.Add(pointer, i * rowSize);
                RawConnection? row = null;
                try
                {
                    if (family == AF_INET)
                    {
                        var r = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(rowPtr);
                        row = new RawConnection
                        {
                            Protocol = NetworkProtocol.Udp,
                            LocalAddress = V4Address(r.localAddr),
                            LocalPort = V4Port(r.localPort),
                            RemoteAddress = "0.0.0.0",
                            RemotePort = 0,
                            State = ConnectionState.Listen,
                            Pid = r.owningPid,
                        };
                    }
                    else
                    {
                        var r = Marshal.PtrToStructure<NativeMethods.MIB_UDP6ROW_OWNER_PID>(rowPtr);
                        row = new RawConnection
                        {
                            Protocol = NetworkProtocol.Udp,
                            LocalAddress = V6Address(r.localAddr),
                            LocalPort = V4Port(r.localPort),
                            RemoteAddress = "::",
                            RemotePort = 0,
                            State = ConnectionState.Listen,
                            Pid = r.owningPid,
                        };
                    }
                }
                catch
                {
                    // 跳过损坏行
                }
                if (row is not null) yield return row;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// MIB 表里的 IPv4 地址是网络字节序。小端机器上按 uint 读出来的 4 个字节正好就是网络序，
    /// 直接送给 IPAddress 即可 —— 这里不需要再做一次反转。
    /// </summary>
    private static string V4Address(uint networkOrder)
    {
        if (networkOrder == 0) return "0.0.0.0";
        return new IPAddress(BitConverter.GetBytes(networkOrder)).ToString();
    }

    private static string V6Address(byte[]? address)
    {
        if (address is null || address.Length != 16) return "::";
        if (address.All(b => b == 0)) return "::";
        try
        {
            return new IPAddress(address).ToString();
        }
        catch
        {
            return "::";
        }
    }

    private static int V4Port(uint portField) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(portField & 0xFFFF));

    private static ConnectionState MapTcpState(uint state) => state switch
    {
        1 => ConnectionState.Closed,
        2 => ConnectionState.Listen,
        3 => ConnectionState.SynSent,
        4 => ConnectionState.SynReceived,
        5 => ConnectionState.Established,
        6 => ConnectionState.FinWait1,
        7 => ConnectionState.FinWait2,
        8 => ConnectionState.CloseWait,
        9 => ConnectionState.Closing,
        10 => ConnectionState.LastAck,
        11 => ConnectionState.TimeWait,
        12 => ConnectionState.DeleteTcb,
        _ => ConnectionState.Unknown,
    };

    // ---------------------------------------------------------------- DNS

    /// <summary>
    /// DNS 观测走 ipconfig /displaydns 的结构化解析。
    /// 用 Latin1 解码：缓存内容本身是 ASCII（主机名 + IP），中文只出现在记录类型标题里，
    /// 这样既不引入编码包依赖，也不会因为系统语言不同而解析失败。
    /// </summary>
    private void PollDnsCache()
    {
        try
        {
            var psi = new ProcessStartInfo("ipconfig", "/displaydns")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.Latin1,
            };

            using var process = Process.Start(psi);
            if (process is null) return;
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(4000);

            var parsed = ParseDnsOutput(output);
            foreach (var (host, addresses) in parsed)
            {
                if (_dnsCache.TryGetValue(host, out var known) && known.Count == addresses.Count) continue;
                _dnsCache[host] = addresses;

                foreach (var ip in addresses)
                    _ipToHost[ip] = host;

                // 反向补齐已观测连接的域名字段
                foreach (var conn in _connections.Values)
                {
                    if (conn.Domain is null && addresses.Contains(conn.RemoteAddress, StringComparer.OrdinalIgnoreCase))
                        conn.Domain = host;
                }

                var observation = new DnsObservation
                {
                    HostName = host,
                    Addresses = addresses,
                    ObservedAt = DateTime.Now,
                    Source = "dns-cache",
                    Attribution = AttributionQuality.Heuristic,
                };

                var matched = _connections.Values.FirstOrDefault(c =>
                    addresses.Contains(c.RemoteAddress, StringComparer.OrdinalIgnoreCase));
                if (matched is not null)
                {
                    observation.ProcessId = matched.ProcessId;
                    observation.ProcessName = matched.ProcessName;
                }

                OnDns?.Invoke(observation);
                OnEvent?.Invoke(new MonitorEvent
                {
                    Type = MonitorEventType.DnsQuery,
                    ProcessId = observation.ProcessId,
                    ProcessName = observation.ProcessName,
                    Operation = "DNS Resolve",
                    Target = host,
                    IsFromTargetTree = observation.ProcessId != 0 && (IsInTargetTree?.Invoke(observation.ProcessId) ?? false),
                    Detail = $"解析为 {string.Join(", ", addresses)}（来自本机 DNS 缓存，进程归属为时间窗匹配）",
                    Source = "dns-cache",
                });
            }
        }
        catch (Exception ex)
        {
            if (Warnings.Count < 20) Warnings.Add($"DNS 缓存读取失败：{ex.Message}");
        }
    }

    /// <summary>
    /// 解析 ipconfig /displaydns 的输出。
    /// 用「横线分隔线」作为块边界：分隔线之前最靠近它的非空行就是记录名，之后的行是字段。
    /// 这样不依赖「Record Name / 记录名称」这类被本地化的标签，中英文系统都能解析。
    /// </summary>
    public static List<(string Host, List<string> Addresses)> ParseDnsOutput(string output)
    {
        var results = new List<(string, List<string>)>();
        string? pendingLine = null;
        string? currentHost = null;
        var addresses = new List<string>();
        var inBlock = false;

        void Flush()
        {
            if (inBlock && !string.IsNullOrEmpty(currentHost) && addresses.Count > 0)
                results.Add((currentHost, addresses.Distinct().ToList()));
            addresses = new List<string>();
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;

            // 用字符集合判断分隔线，而不是写死 ASCII 的 '-'
            var isSeparator = trimmed.Length >= 8 &&
                              trimmed.Distinct().All(c => c is '-' or '=' or '\u2014' or '\u2013' or '_');

            if (isSeparator)
            {
                Flush();
                currentHost = NormalizeRecordName(pendingLine);
                inBlock = true;
                continue;
            }

            if (!inBlock)
            {
                pendingLine = trimmed;
                continue;
            }

            // 块内字段行：label . . . . : value
            var colon = trimmed.LastIndexOf(':');
            if (colon < 0) continue;

            var tail = trimmed[(colon + 1)..].Trim().TrimEnd('.');
            if (tail.Length == 0) continue;

            if (TryParseStrictAddress(tail, out var ip))
            {
                var text = ip.ToString();
                if (!addresses.Contains(text)) addresses.Add(text);
            }
        }

        Flush();

        return results
            .Where(r => r.Item1.Length >= 3 && r.Item1.Contains('.'))
            .DistinctBy(r => r.Item1, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// 严格地址判定。.NET 的 IPAddress.TryParse 兼容 inet_aton 旧式写法，
    /// 会把「4」「106300」当成 0.0.0.4 / 0.1.158.127，从而把「数据长度」「生存时间」这类
    /// 数字字段误判成地址。这里要求点分四段（或含冒号的 IPv6）才认。
    /// </summary>
    private static bool TryParseStrictAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrEmpty(text)) return false;

        if (text.Contains(':'))
            return IPAddress.TryParse(text, out address!);

        var parts = text.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3) return false;
            if (!part.All(char.IsAsciiDigit)) return false;
            if (!byte.TryParse(part, out _)) return false;
        }

        return IPAddress.TryParse(text, out address!);
    }

    private static string? NormalizeRecordName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var name = raw.Trim().TrimEnd('.');
        if (name.Length is < 3 or > 255) return null;
        if (!name.Contains('.')) return null;
        if (IPAddress.TryParse(name, out _)) return null;
        if (name.Any(char.IsWhiteSpace)) return null;
        // 反向查询记录（in-addr.arpa / ip6.arpa）对「应用访问了哪个域名」没有价值
        if (name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase)) return null;
        return name;
    }

    public IReadOnlyCollection<NetworkConnection> Snapshot() => _connections.Values.ToList();

    public IReadOnlyDictionary<string, string> IpToHostMap() => _ipToHost;

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        _dnsTimer?.Dispose();
        _dnsTimer = null;
    }

    public void Dispose() => Stop();
}
