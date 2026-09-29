using System.Text;
using System.Text.RegularExpressions;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Static;

/// <summary>
/// §3.3 Strings 与 §3.2 类型识别共用的字符串提取器。
/// 输出带节区与文件偏移，报告里可以直接指向原始证据位置。
/// </summary>
public sealed class StringExtractor
{
    public int MinLength { get; init; } = 6;
    public int MaxResults { get; init; } = 40_000;
    public bool IncludeUnicode { get; init; } = true;
    public bool IncludeAscii { get; init; } = true;

    private static readonly Regex AsciiPattern = new(
        @"[\x20-\x7E]{" + 4 + @",}", RegexOptions.Compiled);

    // 字符串分类用到的模式。分类本身不是结论，只是把噪声排开方便人工筛。
    private static readonly (string Category, Regex Pattern)[] Classifiers =
    {
        ("URL", new Regex(@"\b(?:https?|ftp|ws|wss)://[^\s""'<>]{4,}", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("IPAddress", new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)),
        ("Domain", new Regex(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|co|dev|app|cloud|xyz|top|info|biz|ru|de|jp|me)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("RegistryPath", new Regex(@"^(?:HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)|\\Software\\|\\CurrentVersion\\Run", RegexOptions.Compiled)),
        ("FilePath", new Regex(@"^[A-Za-z]:\\|^\\\\|%[A-Za-z_]+%|\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|lnk|msi|ini|dat|log|json|xml|db)$", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("Command", new Regex(@"\b(?:cmd\.exe|powershell|pwsh|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks|net\s+user|whoami|taskkill|sc\.exe|reg\.exe|curl|wget)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("Credential", new Regex(@"\b(?:password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key|credential|bearer)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("Crypto", new Regex(@"\b(?:AES|RSA|SHA256|SHA1|MD5|HMAC|Base64|XOR|RC4|ChaCha|Bcrypt|CryptoAPI)\b", RegexOptions.Compiled)),
        ("Sql", new Regex(@"\b(?:SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+SELECT)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("Format", new Regex(@"%(?:s|d|n|x|p|ls|ws|hu)", RegexOptions.Compiled)),
        ("SecurityApi", new Regex(@"\b(?:VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx|NtUnmapViewOfSection|QueueUserAPC|LoadLibrary|GetProcAddress|WinExec|ShellExecute|CreateProcess)\w*\b", RegexOptions.Compiled)),
        ("UserAgent", new Regex(@"^Mozilla/|^curl/|^Wget/|User-Agent", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("Json", new Regex(@"^[\[{]\s*""|[`""]\s*:\s*(?:""|\d|true|false|null)", RegexOptions.Compiled)),
        ("Guid", new Regex(@"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$", RegexOptions.Compiled)),
    };

    /// <summary>按节区提取，返回带偏移与分类的命中。</summary>
    public List<StringHit> Extract(PeImageInfo pe, byte[] fileBytes)
    {
        var results = new List<StringHit>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var section in pe.Sections)
        {
            if (section.RawSize == 0) continue;
            // 不给节区名做白名单限制：加壳后节区名可能被混淆，漏掉 .rsrc / 未知节的字符串会丢证据
            var start = (int)section.RawOffset;
            var length = (int)Math.Min(section.RawSize, (uint)Math.Max(0, fileBytes.Length - start));
            if (length <= 0 || start < 0 || start >= fileBytes.Length) continue;

            var span = fileBytes.AsSpan(start, length);

            if (IncludeAscii)
                ScanAscii(results, seen, span, section.Name, start);

            if (IncludeUnicode)
                ScanUnicode(results, seen, span, section.Name, start);

            if (results.Count >= MaxResults) break;
        }

        // overlay 区（安装包的自解压数据等）也扫一遍，节区遍历覆盖不到
        if (pe.HasOverlay && results.Count < MaxResults)
        {
            long overlayStart = fileBytes.Length - pe.OverlaySize;
            if (overlayStart > 0 && overlayStart < fileBytes.Length)
            {
                var span = fileBytes.AsSpan((int)overlayStart);
                if (IncludeAscii) ScanAscii(results, seen, span, "OVERLAY", (int)overlayStart);
                if (IncludeUnicode) ScanUnicode(results, seen, span, "OVERLAY", (int)overlayStart);
            }
        }

        return results;
    }

    private void ScanAscii(List<StringHit> results, HashSet<string> seen, ReadOnlySpan<byte> span,
        string sectionName, int baseOffset)
    {
        // 用固定窗口滑动，避免为整节分配大字符串
        const int chunkSize = 1024 * 1024;
        var processed = 0;
        while (processed < span.Length && results.Count < MaxResults)
        {
            var len = Math.Min(chunkSize, span.Length - processed);
            var chunk = span.Slice(processed, len);
            var text = Encoding.Latin1.GetString(chunk);
            foreach (Match m in AsciiPattern.Matches(text))
            {
                if (m.Length < MinLength) continue;
                var value = Sanitize(m.Value);
                if (value is null) continue;
                if (!seen.Add(value)) continue;
                results.Add(new StringHit
                {
                    Value = value,
                    Offset = baseOffset + processed + m.Index,
                    Section = sectionName,
                    IsUnicode = false,
                    Category = Classify(value),
                });
                if (results.Count >= MaxResults) return;
            }
            processed += len;
        }
    }

    private void ScanUnicode(List<StringHit> results, HashSet<string> seen, ReadOnlySpan<byte> span,
        string sectionName, int baseOffset)
    {
        const int chunkSize = 1024 * 1024;
        var processed = 0;
        while (processed < span.Length && results.Count < MaxResults)
        {
            var len = Math.Min(chunkSize, span.Length - processed);
            var chunk = span.Slice(processed, len);
            var text = Encoding.Unicode.GetString(chunk);
            var matches = Regex.Matches(text, @"[\x20-\x7E]{" + MinLength + @",}");
            foreach (Match m in matches)
            {
                var value = Sanitize(m.Value);
                if (value is null) continue;
                if (!seen.Add(value)) continue;
                results.Add(new StringHit
                {
                    Value = value,
                    Offset = baseOffset + processed + m.Index * 2,
                    Section = sectionName,
                    IsUnicode = true,
                    Category = Classify(value),
                });
                if (results.Count >= MaxResults) return;
            }
            processed += len;
        }
    }

    /// <summary>丢掉纯符号 / 纯数字填充这类无信息量的命中。</summary>
    private static string? Sanitize(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length < 4) return null;

        var alnum = 0;
        foreach (var c in trimmed)
        {
            if (char.IsLetterOrDigit(c)) alnum++;
        }
        if (alnum < 3) return null;

        // 单个字符反复填充（如 "aaaaaa"、"------"）是节区对齐产物
        var distinct = trimmed.Distinct().Count();
        if (distinct <= 2) return null;

        if (trimmed.Length > 2048) trimmed = trimmed[..2048];
        return trimmed;
    }

    public static string Classify(string value)
    {
        foreach (var (category, pattern) in Classifiers)
        {
            try
            {
                if (pattern.IsMatch(value)) return category;
            }
            catch (RegexMatchTimeoutException)
            {
                // 忽略
            }
        }
        return "General";
    }

    /// <summary>把命中的字符串归档为可直接展示的证据分组。</summary>
    public static Dictionary<string, List<StringHit>> GroupByCategory(IEnumerable<StringHit> hits) =>
        hits.GroupBy(h => h.Category)
            .OrderByDescending(g => g.Key is "URL" or "IPAddress" or "Command" or "Credential" or "SecurityApi")
            .ThenByDescending(g => g.Count())
            .ToDictionary(g => g.Key, g => g.ToList());

    /// <summary>按类别导出字典，供报告与规则引擎快速取值（不区分大小写）。</summary>
    public static Dictionary<string, List<StringHit>> ToLookup(IEnumerable<StringHit> hits)
    {
        var map = new Dictionary<string, List<StringHit>>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hits)
        {
            if (!map.TryGetValue(h.Value, out var list))
            {
                list = new List<StringHit>();
                map[h.Value] = list;
            }
            list.Add(h);
        }
        return map;
    }
}
