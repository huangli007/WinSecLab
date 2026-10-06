using System.Text;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Reports;

/// <summary>
/// 把分析结果导出成 CSV —— 给"要拿去做跟踪表"的场景用。
///
/// 为什么不只靠 HTML/JSON 报告：报告是给人读的成品，CSV 是给 Excel 做二次加工的原料。
/// 缺陷清单进 Excel 后能排序、筛选、加负责人和修复状态列，这是报告做不到的。
///
/// 两个关键细节：
/// ① 写 UTF-8 BOM —— 否则 Excel 打开中文全是乱码（这是最常见的"导出不好用"投诉）；
/// ② 字段按 RFC 4180 转义 —— 标题/描述里常有逗号、引号、换行，不转义会串列。
/// </summary>
public static class CsvExporter
{
    /// <summary>导出发现（缺陷）清单。</summary>
    public static string ExportFindings(AnalysisResult result, string outputPath)
    {
        var sb = new StringBuilder();

        sb.AppendLine("序号,严重级别,标题,类别,规则编号,CWE,OWASP,置信度,状态,影响目标,关联证据数,影响说明,整改建议,人工复核意见,发现时间");

        var index = 1;
        // 严重级别高的排前面 —— 打开 Excel 第一眼就该看到最该处理的
        foreach (var f in result.Findings
                     .OrderByDescending(f => f.Severity)
                     .ThenByDescending(f => f.Timestamp))
        {
            sb.Append(index++).Append(',');
            sb.Append(Escape(f.SeverityText)).Append(',');
            sb.Append(Escape(f.Title)).Append(',');
            sb.Append(Escape(f.Category)).Append(',');
            sb.Append(Escape(f.RuleId)).Append(',');
            sb.Append(Escape(f.CweId ?? "")).Append(',');
            sb.Append(Escape(f.OwaspCategory ?? "")).Append(',');
            sb.Append(Escape(f.ConfidenceText)).Append(',');
            sb.Append(Escape(f.StatusText)).Append(',');
            sb.Append(Escape(f.Target ?? "")).Append(',');
            sb.Append(f.EvidenceIds.Count).Append(',');
            sb.Append(Escape(f.Impact ?? "")).Append(',');
            sb.Append(Escape(f.Recommendation ?? "")).Append(',');
            sb.Append(Escape(f.AnalystNote ?? "")).Append(',');
            sb.Append(Escape(f.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")));
            sb.AppendLine();
        }

        WriteWithBom(outputPath, sb.ToString());
        return outputPath;
    }

    /// <summary>导出证据清单（供人工核对每条结论的原始依据）。</summary>
    public static string ExportEvidence(AnalysisResult result, string outputPath)
    {
        var sb = new StringBuilder();

        sb.AppendLine("序号,证据类型,标题,来源,目标,摘要,关联文件数,关联进程数,采集时间");

        var index = 1;
        foreach (var e in result.Evidence.OrderBy(e => e.Timestamp))
        {
            sb.Append(index++).Append(',');
            sb.Append(Escape(e.KindLabel)).Append(',');
            sb.Append(Escape(e.Title)).Append(',');
            sb.Append(Escape(e.Source)).Append(',');
            sb.Append(Escape(e.Target ?? "")).Append(',');
            sb.Append(Escape(e.Summary)).Append(',');
            sb.Append(e.RelatedFiles.Count).Append(',');
            sb.Append(e.RelatedProcesses.Count).Append(',');
            sb.Append(Escape(e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")));
            sb.AppendLine();
        }

        WriteWithBom(outputPath, sb.ToString());
        return outputPath;
    }

    /// <summary>按 RFC 4180 转义：含逗号/引号/换行时用引号包裹，内部引号翻倍。</summary>
    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";

        // 换行统一成空格，避免多行字段把 CSV 行数撑乱（Excel 里也更整齐）
        var normalized = value.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ');

        if (normalized.Contains(',') || normalized.Contains('"'))
            return "\"" + normalized.Replace("\"", "\"\"") + "\"";

        return normalized;
    }

    private static void WriteWithBom(string path, string content)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // UTF8Encoding(true) 才会写 BOM —— Excel 靠它识别 UTF-8，否则中文乱码
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
    }
}
