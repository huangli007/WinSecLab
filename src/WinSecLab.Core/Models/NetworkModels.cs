using System.Text.Json.Serialization;

namespace WinSecLab.Core.Models;

public enum NetworkProtocol { Tcp, Udp }

public enum ConnectionState
{
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

/// <summary>连接归因精确度。网络 / 文件 / 注册表在没有内核级监控时只能做到启发式归因，必须如实标注。</summary>
public enum AttributionQuality
{
    /// <summary>由内核事件或按 PID 查询得到的精确归属。</summary>
    Exact,
    /// <summary>按时间窗口 + 进程树推断的归属。</summary>
    Heuristic,
    /// <summary>无法归属到具体进程。</summary>
    Unattributed,
}

/// <summary>按进程归因的网络连接（§6 Network 的 Connections 页）。</summary>
public sealed class NetworkConnection
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string SessionId { get; set; } = "";
    public DateTime FirstSeen { get; set; } = DateTime.Now;
    public DateTime LastSeen { get; set; } = DateTime.Now;
    public NetworkProtocol Protocol { get; set; } = NetworkProtocol.Tcp;

    public uint ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public bool IsFromTargetTree { get; set; }

    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public ConnectionState State { get; set; } = ConnectionState.Unknown;

    public string? Domain { get; set; }
    public string? TlsSni { get; set; }
    public string? TlsVersion { get; set; }
    public string? ServerCertificateSubject { get; set; }
    public string? Organization { get; set; }
    public string? Country { get; set; }
    public string? AsnInfo { get; set; }

    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public int ObservationCount { get; set; }
    public AttributionQuality Attribution { get; set; } = AttributionQuality.Exact;
    public string Source { get; set; } = "iphlpapi";

    public bool IsLoopback =>
        RemoteAddress.StartsWith("127.", StringComparison.Ordinal) || RemoteAddress == "::1";

    public bool IsPrivateAddress
    {
        get
        {
            if (IsLoopback) return true;
            if (RemoteAddress.StartsWith("10.", StringComparison.Ordinal)) return true;
            if (RemoteAddress.StartsWith("192.168.", StringComparison.Ordinal)) return true;
            if (RemoteAddress.StartsWith("169.254.", StringComparison.Ordinal)) return true;
            if (RemoteAddress.StartsWith("172.", StringComparison.Ordinal))
            {
                var parts = RemoteAddress.Split('.');
                if (parts.Length > 1 && int.TryParse(parts[1], out var second) && second is >= 16 and <= 31)
                    return true;
            }
            if (RemoteAddress.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase)) return true;
            if (RemoteAddress.StartsWith("fc", StringComparison.OrdinalIgnoreCase) ||
                RemoteAddress.StartsWith("fd", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }

    public string RemoteEndpoint => $"{RemoteAddress}:{RemotePort}";
    public string LocalEndpoint => $"{LocalAddress}:{LocalPort}";
    public string DisplayHost => Domain ?? RemoteAddress;

    /// <summary>固定端口 → 常见服务与机构，用于报告里的客观描述。</summary>
    public string ServiceHint => RemotePort switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        1433 => "MSSQL",
        1521 => "Oracle",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        _ => Protocol == NetworkProtocol.Udp ? "UDP" : "TCP",
    };

    public string StateText => State switch
    {
        ConnectionState.Listen => "LISTEN",
        ConnectionState.Established => "ESTABLISHED",
        ConnectionState.SynSent => "SYN_SENT",
        ConnectionState.SynReceived => "SYN_RECV",
        ConnectionState.TimeWait => "TIME_WAIT",
        ConnectionState.CloseWait => "CLOSE_WAIT",
        ConnectionState.Closed => "CLOSED",
        _ => State.ToString().ToUpperInvariant(),
    };
}

/// <summary>DNS 观测记录（§6 DNS）。</summary>
public sealed class DnsObservation
{
    public string HostName { get; set; } = "";
    public List<string> Addresses { get; set; } = new();
    public string RecordType { get; set; } = "A";
    public DateTime ObservedAt { get; set; } = DateTime.Now;
    public uint ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public AttributionQuality Attribution { get; set; } = AttributionQuality.Heuristic;
    public string Source { get; set; } = "dns-cache";

    public string AddressText => Addresses.Count == 0 ? "-" : string.Join(", ", Addresses);
}

/// <summary>一次 HTTP 事务（§8 HTTP / API 测试）。</summary>
public sealed class HttpExchange
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string SessionId { get; set; } = "";
    public long Index { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public string Method { get; set; } = "";
    public string Scheme { get; set; } = "http";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string Path { get; set; } = "/";
    public string QueryString { get; set; } = "";
    public string HttpVersion { get; set; } = "HTTP/1.1";

    public string Url => $"{Scheme}://{Host}{(Port is 80 or 443 or 0 ? "" : ":" + Port)}{Path}{QueryString}";

    public List<KeyValuePair<string, string>> RequestHeaders { get; set; } = new();
    public string? RequestBody { get; set; }
    public long RequestBodyLength { get; set; }
    public string? RequestContentType { get; set; }

    public int StatusCode { get; set; }
    public string? StatusText { get; set; }
    public List<KeyValuePair<string, string>> ResponseHeaders { get; set; } = new();
    public string? ResponseBody { get; set; }
    public long ResponseBodyLength { get; set; }
    public string? ResponseContentType { get; set; }

    public long DurationMs { get; set; }
    public string Source { get; set; } = "proxy";
    public bool IsTlsIntercepted { get; set; }
    public uint ProcessId { get; set; }
    public string ClientAddress { get; set; } = "";
    public string? Error { get; set; }
    public bool IsInteresting { get; set; }
    public List<string> InterestReasons { get; set; } = new();
    /// <summary>记录来源说明（代理抓取 / 隧道 / Repeater 重放）。</summary>
    public string? ExchangeNote { get; set; }

    [JsonIgnore] public string DisplayUrl => $"{Host}{Path}";
    [JsonIgnore] public string StatusTextCombined => StatusCode == 0 ? (Error ?? "PENDING") : $"{StatusCode}";
    [JsonIgnore] public string MimeShort => (ResponseContentType ?? RequestContentType ?? "-").Split(';')[0].Trim();
}

/// <summary>YARA 命中结果。</summary>
public sealed class YaraMatch
{
    public string RuleName { get; set; } = "";
    public string? RuleSet { get; set; }
    public string FilePath { get; set; } = "";
    public string Severity { get; set; } = "info";
    public string? Description { get; set; }
    public string? Author { get; set; }
    public List<string> MatchedStrings { get; set; } = new();
    public List<string> Tags { get; set; } = new();
    public string? Meta { get; set; }
    public string Source { get; set; } = "builtin";
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public bool IsBuiltinLightweight => Source == "builtin";
}
