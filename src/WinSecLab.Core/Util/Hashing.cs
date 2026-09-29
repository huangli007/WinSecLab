using System.Security.Cryptography;

namespace WinSecLab.Core.Util;

/// <summary>文件与 PE 指纹计算。</summary>
public static class Hashing
{
    private const int BufferSize = 1 << 20;

    public static string Sha256File(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BufferSize);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "";
        }
    }

    public static (string Sha256, string Md5, string Sha1) HashAll(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BufferSize);
            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

            var buffer = new byte[BufferSize];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha256.AppendData(buffer, 0, read);
                md5.AppendData(buffer, 0, read);
                sha1.AppendData(buffer, 0, read);
            }

            return (
                Convert.ToHexString(sha256.GetHashAndReset()).ToLowerInvariant(),
                Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant(),
                Convert.ToHexString(sha1.GetHashAndReset()).ToLowerInvariant());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ("", "", "");
        }
    }

    /// <summary>Import Hash（imphash）—— 导入表指纹，恶意样本聚类与关联分析的常用键。</summary>
    public static string ImportHash(IEnumerable<(string Module, string Function)> imports)
    {
        var parts = new List<string>();
        foreach (var (module, function) in imports)
        {
            if (string.IsNullOrWhiteSpace(module)) continue;
            var mod = StripExtension(module).ToLowerInvariant();
            var fn = (function ?? "").ToLowerInvariant();
            parts.Add($"{mod}.{fn}");
        }
        if (parts.Count == 0) return "";
        var bytes = System.Text.Encoding.ASCII.GetBytes(string.Join(",", parts));
        return Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();
    }

    private static string StripExtension(string name)
    {
        var idx = name.LastIndexOf('.');
        return idx > 0 ? name[..idx] : name;
    }

    public static string HashText(string text)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    public static string ShortHash(string? hash, int length = 12)
    {
        if (string.IsNullOrEmpty(hash)) return "-";
        return hash.Length > length ? hash[..length] : hash;
    }
}
