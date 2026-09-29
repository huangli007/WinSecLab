namespace WinSecLab.Core.Util;

/// <summary>Shannon 熵计算。用于识别加壳 / 加密 / 压缩载荷。</summary>
public static class Entropy
{
    /// <summary>0..8 bits/byte。随机或加密数据接近 8.0。</summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> histogram = stackalloc int[256];
        foreach (var b in data) histogram[b]++;
        double entropy = 0;
        var length = (double)data.Length;
        for (var i = 0; i < 256; i++)
        {
            if (histogram[i] == 0) continue;
            var p = histogram[i] / length;
            entropy -= p * Math.Log2(p);
        }
        return Math.Round(entropy, 4);
    }

    public static double Shannon(byte[] data) => Shannon(data.AsSpan());

    /// <summary>把熵值映射成 0..1，便于 UI 画进度条。</summary>
    public static double Ratio(double entropy) => Math.Clamp(entropy / 8.0, 0, 1);

    public static string Describe(double entropy, bool isDotNetSection = false)
    {
        if (entropy <= 0) return "空节区";
        if (entropy < 1.5) return "极低（大量零填充）";
        if (entropy < 4.0) return "偏低（结构化数据）";
        if (entropy < 5.5) return "正常（代码/资源）";
        if (entropy < 6.8) return isDotNetSection ? "正常（托管元数据）" : "偏高";
        if (entropy < 7.2) return "高（可能已压缩）";
        return "极高（疑似加壳/加密）";
    }

    public static bool IsPackIndicator(double entropy, long size) => entropy >= 7.2 && size >= 4096;
}
