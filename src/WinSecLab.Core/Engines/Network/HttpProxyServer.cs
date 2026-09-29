using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Network;

/// <summary>
/// §8 HTTP / API 测试 —— 本地正向代理，工作方式对齐 Burp Suite 的 Proxy + HTTP History + Repeater。
/// 明文 HTTP 完整解析请求与响应；HTTPS 走 CONNECT 隧道，只记录目标主机与 SNI，
/// 不做中间人解密（不安装根证书、不篡改流量），因此不会破坏被测程序的证书校验。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HttpProxyServer : IDisposable
{
    private const int MaxBodyBytes = 1024 * 1024;

    private readonly ConcurrentQueue<HttpExchange> _history = new();
    private readonly ConcurrentDictionary<string, HttpExchange> _byId = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private long _sequence;
    private readonly int _maxHistory;

    public int Port { get; }
    public bool IsRunning { get; private set; }
    public string? LastError { get; private set; }
    public bool CaptureSensitiveBodies { get; set; } = true;
    public HashSet<string> IgnoredHosts { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Action<HttpExchange>? OnExchange { get; set; }
    public Action<MonitorEvent>? OnEvent { get; set; }

    public HttpProxyServer(int port = 8877, int maxHistory = 5000)
    {
        Port = port;
        _maxHistory = maxHistory;
    }

    public IReadOnlyList<HttpExchange> Snapshot() => _history.ToList();

    public void Start()
    {
        if (IsRunning) return;
        try
        {
            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, Port);
            _listener.Start();
            IsRunning = true;
            LastError = null;
            _ = AcceptLoopAsync(_cts.Token);
        }
        catch (SocketException ex)
        {
            IsRunning = false;
            LastError = $"无法在 127.0.0.1:{Port} 启动代理：{ex.Message}";
        }
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _listener is not null)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                await Task.Delay(200, CancellationToken.None).ConfigureAwait(false);
                continue;
            }

            _ = Task.Run(() => HandleClientAsync(client, token), CancellationToken.None);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        var started = Stopwatch.StartNew();
        using (client)
        {
            client.ReceiveTimeout = 30_000;
            client.SendTimeout = 30_000;

            try
            {
                await using var clientStream = client.GetStream();
                var requestHead = await ReadHeadersAsync(clientStream, token).ConfigureAwait(false);
                if (requestHead is null) return;

                var (requestLine, headers, _) = requestHead.Value;
                var parts = requestLine.Split(' ');
                if (parts.Length < 3) return;

                var method = parts[0].ToUpperInvariant();
                var target = parts[1];
                var version = parts[2];

                if (method == "CONNECT")
                    await HandleConnectAsync(clientStream, target, started, token).ConfigureAwait(false);
                else
                    await HandlePlainHttpAsync(clientStream, method, target, version, headers, started, token)
                        .ConfigureAwait(false);
            }
            catch (Exception)
            {
                // 客户端提前断开 / 目标不可达，都在 ClientError 路径体现
            }
        }
    }

    // ------------------------------------------------------------- HTTPS 隧道

    private async Task HandleConnectAsync(NetworkStream clientStream, string target, Stopwatch started,
        CancellationToken token)
    {
        var hostPort = target.Split(':');
        var host = hostPort[0];
        var port = hostPort.Length > 1 && int.TryParse(hostPort[1], out var p) ? p : 443;

        var exchange = NewExchange("CONNECT", "https", host, port, "/", "", "HTTP/1.1", started);
        exchange.StatusCode = 200;
        exchange.StatusText = "Tunnel Established";
        exchange.ExchangeNote = "HTTPS CONNECT 隧道：仅记录目标主机与端口，未解密流量";

        using var upstream = new TcpClient();
        try
        {
            await upstream.ConnectAsync(host, port, token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            exchange.StatusCode = 502;
            exchange.Error = $"隧道建立失败：{ex.Message}";
            await clientStream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n"), token)
                .ConfigureAwait(false);
            Complete(exchange, started);
            return;
        }

        await clientStream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), token)
            .ConfigureAwait(false);

        using var upstreamStream = upstream.GetStream();
        var clientToServer = PumpAsync(clientStream, upstreamStream, token);
        var serverToClient = PumpAsync(upstreamStream, clientStream, token);
        await Task.WhenAny(clientToServer, serverToClient).ConfigureAwait(false);
        upstream.Close();
        Complete(exchange, started);
    }

    private static async Task PumpAsync(NetworkStream from, NetworkStream to, CancellationToken token)
    {
        var buffer = new byte[16 * 1024];
        try
        {
            while (!token.IsCancellationRequested)
            {
                var read = await from.ReadAsync(buffer, token).ConfigureAwait(false);
                if (read <= 0) break;
                await to.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            }
        }
        catch
        {
            // 任一方向结束即终止会话
        }
    }

    // -------------------------------------------------------------- 明文 HTTP

    private async Task HandlePlainHttpAsync(NetworkStream clientStream, string method, string target,
        string version, List<KeyValuePair<string, string>> headers, Stopwatch started, CancellationToken token)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
            return;

        if (IgnoredHosts.Contains(uri.Host))
            return;

        var bodyLength = ReadContentLength(headers);
        var body = bodyLength > 0
            ? await ReadBodyAsync(clientStream, bodyLength, token).ConfigureAwait(false)
            : null;

        var exchange = NewExchange(method, uri.Scheme, uri.Host, uri.Port, uri.AbsolutePath,
            uri.Query, version, started);
        exchange.RequestHeaders = headers;
        exchange.RequestBody = BodyText(body, headers);
        exchange.RequestBodyLength = body?.Length ?? 0;
        exchange.RequestContentType = FindHeader(headers, "Content-Type");

        using var upstream = new TcpClient();
        try
        {
            await upstream.ConnectAsync(uri.Host, uri.Port, token).ConfigureAwait(false);
            using var upstreamStream = upstream.GetStream();

            var rebuilt = RebuildRequest(exchange, body);
            await upstreamStream.WriteAsync(rebuilt, token).ConfigureAwait(false);

            var (statusCode, statusText, responseHeaders, responseBody, truncated) =
                await ReadResponseAsync(upstreamStream, token).ConfigureAwait(false);

            exchange.StatusCode = statusCode;
            exchange.StatusText = statusText;
            exchange.ResponseHeaders = responseHeaders;
            exchange.ResponseBody = responseBody;
            exchange.ResponseBodyLength = Encoding.UTF8.GetByteCount(responseBody ?? "");
            exchange.ResponseContentType = FindHeader(responseHeaders, "Content-Type");
            if (truncated) exchange.ResponseBody += "\n…（响应体超过 1 MB，已在代理侧截断）";

            var raw = RebuildResponse(statusCode, statusText, responseHeaders, responseBody);
            await clientStream.WriteAsync(raw, token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            exchange.Error = ex.Message;
            exchange.StatusCode = 502;
            var error = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            try
            {
                await clientStream.WriteAsync(error, token).ConfigureAwait(false);
            }
            catch
            {
                // 客户端已断开
            }
        }

        Complete(exchange, started);
    }

    private static byte[] RebuildRequest(HttpExchange exchange, byte[]? body)
    {
        var builder = new StringBuilder();
        builder.Append($"{exchange.Method} {exchange.Path}{exchange.QueryString} {exchange.HttpVersion}\r\n");
        foreach (var (name, value) in exchange.RequestHeaders)
            builder.Append($"{name}: {value}\r\n");
        builder.Append("\r\n");

        var head = Encoding.UTF8.GetBytes(builder.ToString());
        if (body is null || body.Length == 0) return head;

        var result = new byte[head.Length + body.Length];
        Buffer.BlockCopy(head, 0, result, 0, head.Length);
        Buffer.BlockCopy(body, 0, result, head.Length, body.Length);
        return result;
    }

    private static byte[] RebuildResponse(int status, string statusText, List<KeyValuePair<string, string>> headers,
        string? body)
    {
        var bodyBytes = body is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(body);
        var builder = new StringBuilder();
        builder.Append($"HTTP/1.1 {status} {statusText}\r\n");
        foreach (var (name, value) in headers)
        {
            if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Connection", StringComparison.OrdinalIgnoreCase)) continue;
            builder.Append($"{name}: {value}\r\n");
        }
        builder.Append($"Content-Length: {bodyBytes.Length}\r\n");
        builder.Append("Connection: close\r\n\r\n");

        var head = Encoding.UTF8.GetBytes(builder.ToString());
        var result = new byte[head.Length + bodyBytes.Length];
        Buffer.BlockCopy(head, 0, result, 0, head.Length);
        Buffer.BlockCopy(bodyBytes, 0, result, head.Length, bodyBytes.Length);
        return result;
    }

    // ------------------------------------------------------------- 报文解析

    private static async Task<(string RequestLine, List<KeyValuePair<string, string>> Headers, int ByteCount)?>
        ReadHeadersAsync(NetworkStream stream, CancellationToken token)
    {
        var buffer = new List<byte>(4096);
        var one = new byte[1];
        while (buffer.Count < 64 * 1024)
        {
            var read = await stream.ReadAsync(one, token).ConfigureAwait(false);
            if (read <= 0) break;
            buffer.Add(one[0]);
            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' && buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' && buffer[^1] == (byte)'\n')
                break;
        }

        if (buffer.Count == 0) return null;

        var text = Encoding.UTF8.GetString(buffer.ToArray());
        var lines = text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) return null;

        var headers = new List<KeyValuePair<string, string>>();
        for (var i = 1; i < lines.Length; i++)
        {
            var idx = lines[i].IndexOf(':');
            if (idx <= 0) continue;
            headers.Add(new KeyValuePair<string, string>(lines[i][..idx].Trim(), lines[i][(idx + 1)..].Trim()));
        }

        return (lines[0], headers, buffer.Count);
    }

    private static int ReadContentLength(List<KeyValuePair<string, string>> headers)
    {
        var value = FindHeader(headers, "Content-Length");
        return int.TryParse(value, out var length) ? Math.Clamp(length, 0, MaxBodyBytes) : 0;
    }

    private static async Task<byte[]?> ReadBodyAsync(NetworkStream stream, int length, CancellationToken token)
    {
        if (length <= 0) return null;
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), token).ConfigureAwait(false);
            if (read <= 0) break;
            offset += read;
        }
        return offset == 0 ? null : buffer[..offset];
    }

    private static async Task<(int Status, string StatusText, List<KeyValuePair<string, string>> Headers,
        string? Body, bool Truncated)> ReadResponseAsync(NetworkStream stream, CancellationToken token)
    {
        var head = await ReadHeadersAsync(stream, token).ConfigureAwait(false);
        if (head is null) return (0, "", new List<KeyValuePair<string, string>>(), null, false);

        var statusParts = head.Value.RequestLine.Split(' ', 3);
        var status = statusParts.Length > 1 && int.TryParse(statusParts[1], out var s) ? s : 0;
        var statusText = statusParts.Length > 2 ? statusParts[2] : "";
        var headers = head.Value.Headers;

        var contentLength = ReadContentLength(headers);
        var chunked = (FindHeader(headers, "Transfer-Encoding") ?? "").Contains("chunked", StringComparison.OrdinalIgnoreCase);

        string? body = null;
        var truncated = false;

        if (contentLength > 0)
        {
            var bytes = await ReadBodyAsync(stream, contentLength, token).ConfigureAwait(false);
            body = bytes is null ? null : DecodeBody(bytes, headers);
        }
        else if (chunked)
        {
            var (text, wasTruncated) = await ReadChunkedAsync(stream, token).ConfigureAwait(false);
            body = text;
            truncated = wasTruncated;
        }

        return (status, statusText, headers, body, truncated);
    }

    private static async Task<(string? Text, bool Truncated)> ReadChunkedAsync(NetworkStream stream,
        CancellationToken token)
    {
        var builder = new StringBuilder();
        var total = 0;
        while (true)
        {
            var line = await ReadLineAsync(stream, token).ConfigureAwait(false);
            if (line is null) break;
            var sizeText = line.Split(';')[0].Trim();
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size)) break;
            if (size == 0) break;

            var chunk = new byte[size];
            var offset = 0;
            while (offset < size)
            {
                var read = await stream.ReadAsync(chunk.AsMemory(offset, size - offset), token).ConfigureAwait(false);
                if (read <= 0) break;
                offset += read;
            }
            total += offset;
            if (total > MaxBodyBytes)
                return (Encoding.UTF8.GetString(chunk, 0, Math.Min(offset, MaxBodyBytes)), true);

            builder.Append(Encoding.UTF8.GetString(chunk, 0, offset));
            await ReadLineAsync(stream, token).ConfigureAwait(false); // 尾部 CRLF
        }
        return (builder.ToString(), false);
    }

    private static async Task<string?> ReadLineAsync(NetworkStream stream, CancellationToken token)
    {
        var buffer = new List<byte>(128);
        var one = new byte[1];
        while (buffer.Count < 8192)
        {
            var read = await stream.ReadAsync(one, token).ConfigureAwait(false);
            if (read <= 0) break;
            if (one[0] == (byte)'\n')
            {
                if (buffer.Count > 0 && buffer[^1] == (byte)'\r') buffer.RemoveAt(buffer.Count - 1);
                return Encoding.ASCII.GetString(buffer.ToArray());
            }
            buffer.Add(one[0]);
        }
        return buffer.Count > 0 ? Encoding.ASCII.GetString(buffer.ToArray()) : null;
    }

    private static string? BodyText(byte[]? body, List<KeyValuePair<string, string>> headers)
    {
        if (body is null || body.Length == 0) return null;
        return DecodeBody(body, headers);
    }

    private static string DecodeBody(byte[] body, List<KeyValuePair<string, string>> headers)
    {
        var encoding = FindHeader(headers, "Content-Encoding");
        if (!string.IsNullOrEmpty(encoding))
        {
            if (encoding.Contains("gzip", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    using var input = new MemoryStream(body);
                    using var gzip = new System.IO.Compression.GZipStream(input, System.IO.Compression.CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    gzip.CopyTo(output);
                    return Encoding.UTF8.GetString(output.ToArray());
                }
                catch
                {
                    return $"<gzip 体解压失败，{body.Length} 字节>";
                }
            }
            if (encoding.Contains("deflate", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    using var input = new MemoryStream(body);
                    using var deflate = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    deflate.CopyTo(output);
                    return Encoding.UTF8.GetString(output.ToArray());
                }
                catch
                {
                    return $"<deflate 体解压失败，{body.Length} 字节>";
                }
            }
            return $"<{encoding} 编码体，{body.Length} 字节>";
        }

        var text = Encoding.UTF8.GetString(body);
        // 二进制体不往 JSON 里塞，改为长度摘要
        var printable = text.Count(c => c is >= ' ' or '\r' or '\n' or '\t');
        return printable * 100 / Math.Max(1, text.Length) > 90
            ? text
            : $"<二进制体 {body.Length} 字节，前 64 字节：{Convert.ToHexString(body.AsSpan(0, Math.Min(64, body.Length)))}>";
    }

    internal static string? FindHeader(List<KeyValuePair<string, string>> headers, string name)
    {
        foreach (var (key, value) in headers)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase)) return value;
        }
        return null;
    }

    // ------------------------------------------------------------- Repeater

    /// <summary>§8 Send to Repeater —— 在授权测试环境里重放一次已记录的请求。</summary>
    public async Task<HttpExchange> ReplayAsync(string exchangeId, CancellationToken token)
    {
        if (!_byId.TryGetValue(exchangeId, out var original))
            return new HttpExchange { Id = exchangeId, Error = "未找到原始请求" };

        var started = Stopwatch.StartNew();
        var replay = NewExchange(original.Method, original.Scheme, original.Host, original.Port, original.Path,
            original.QueryString, original.HttpVersion, started);
        replay.RequestHeaders = original.RequestHeaders.ToList();
        replay.RequestBody = original.RequestBody;
        replay.RequestContentType = original.RequestContentType;
        replay.ExchangeNote = $"Repeater 重放，来源 {original.Id}";
        replay.Source = "repeater";

        try
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(original.Host, original.Port, token).ConfigureAwait(false);
            using var stream = upstream.GetStream();

            var body = original.RequestBody is null ? null : Encoding.UTF8.GetBytes(original.RequestBody);
            var raw = RebuildRequest(replay, body);
            await stream.WriteAsync(raw, token).ConfigureAwait(false);

            var (status, statusText, headers, responseBody, truncated) =
                await ReadResponseAsync(stream, token).ConfigureAwait(false);

            replay.StatusCode = status;
            replay.StatusText = statusText;
            replay.ResponseHeaders = headers;
            replay.ResponseBody = responseBody;
            if (truncated) replay.ResponseBody += "\n…（已截断）";
        }
        catch (Exception ex)
        {
            replay.Error = ex.Message;
            replay.StatusCode = 0;
        }

        replay.DurationMs = started.ElapsedMilliseconds;
        return replay;
    }

    // ---------------------------------------------------------------- 记录

    private HttpExchange NewExchange(string method, string scheme, string host, int port, string path,
        string query, string version, Stopwatch started)
    {
        var exchange = new HttpExchange
        {
            Id = $"HTTP-{Interlocked.Increment(ref _sequence):D5}",
            Index = _sequence,
            Timestamp = DateTime.Now,
            Method = method,
            Scheme = scheme,
            Host = host,
            Port = port,
            Path = path,
            QueryString = query,
            HttpVersion = version,
            DurationMs = started.ElapsedMilliseconds,
        };
        return exchange;
    }

    private void Complete(HttpExchange exchange, Stopwatch started)
    {
        exchange.DurationMs = started.ElapsedMilliseconds;
        AnalyzeInterest(exchange);

        _history.Enqueue(exchange);
        _byId[exchange.Id] = exchange;

        while (_history.Count > _maxHistory && _history.TryDequeue(out var old))
            _byId.TryRemove(old.Id, out _);

        OnExchange?.Invoke(exchange);
        OnEvent?.Invoke(new MonitorEvent
        {
            Type = MonitorEventType.HttpRequest,
            Operation = exchange.Method,
            Target = exchange.Url,
            IsFromTargetTree = true,
            IsSuspicious = exchange.IsInteresting,
            SuspicionReason = exchange.InterestReasons.Count > 0 ? string.Join("；", exchange.InterestReasons) : null,
            Detail = exchange.Error is not null
                ? $"错误：{exchange.Error}"
                : $"{exchange.StatusCode} {exchange.MimeShort}，{exchange.DurationMs} ms"
                  + (string.IsNullOrEmpty(exchange.QueryString) ? "" : $"；查询参数 {exchange.QueryString}"),
            Source = "builtin-proxy",
        });
    }

    /// <summary>把「值得人工看一眼」的请求挑出来，其余留在全量历史里。</summary>
    private void AnalyzeInterest(HttpExchange exchange)
    {
        var reasons = exchange.InterestReasons;

        if (!CaptureSensitiveBodies)
        {
            exchange.RequestBody = exchange.RequestBody is null ? null : "<已按设置屏蔽请求体>";
            exchange.ResponseBody = exchange.ResponseBody is null ? null : "<已按设置屏蔽响应体>";
        }

        if (exchange.Method is "POST" or "PUT" or "PATCH" or "DELETE")
            reasons.Add("写操作请求（" + exchange.Method + "）");

        if (exchange.StatusCode >= 400)
            reasons.Add($"服务端返回 {exchange.StatusCode}");

        if (exchange.QueryString.Contains("token", StringComparison.OrdinalIgnoreCase) ||
            exchange.QueryString.Contains("key", StringComparison.OrdinalIgnoreCase) ||
            exchange.QueryString.Contains("password", StringComparison.OrdinalIgnoreCase))
            reasons.Add("URL 查询串中出现 token / key / password 参数");

        foreach (var (name, value) in exchange.RequestHeaders)
        {
            if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                reasons.Add("携带 Authorization 头（" + ShortenForDisplay(value) + "）");
            if (name.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                reasons.Add("携带 Cookie 会话凭据");
        }

        if (exchange.Scheme == "http" && exchange.RequestHeaders.Count > 0)
            reasons.Add("明文 HTTP 传输（无 TLS 保护）");

        if (exchange.RequestBody is { Length: > 0 } reqBody &&
            (reqBody.Contains("password", StringComparison.OrdinalIgnoreCase) ||
             reqBody.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
             reqBody.Contains("token", StringComparison.OrdinalIgnoreCase)))
            reasons.Add("请求体疑似包含凭据字段");

        if (exchange.ResponseHeaders.Any(h =>
                h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)))
            reasons.Add("响应下发 Set-Cookie");

        if (exchange.ResponseHeaders.Any(h =>
                h.Key.Equals("Access-Control-Allow-Origin", StringComparison.OrdinalIgnoreCase) &&
                h.Value.Contains('*')))
            reasons.Add("响应 CORS 允许任意来源（Access-Control-Allow-Origin: *）");

        exchange.IsInteresting = reasons.Count > 0;
    }

    private static string ShortenForDisplay(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length <= 24) return trimmed;
        // 凭据类头部只保留方案与片段，避免把完整 token 写进报告
        var space = trimmed.IndexOf(' ');
        var scheme = space > 0 ? trimmed[..space] : "";
        return string.IsNullOrEmpty(scheme)
            ? trimmed[..8] + "…"
            : $"{scheme} {trimmed[(space + 1)..Math.Min(trimmed.Length, space + 9)]}…";
    }

    public void Stop()
    {
        try
        {
            _cts?.Cancel();
            _listener?.Stop();
        }
        catch
        {
            // 忽略
        }
        _listener = null;
        IsRunning = false;
    }

    public void Dispose() => Stop();
}
