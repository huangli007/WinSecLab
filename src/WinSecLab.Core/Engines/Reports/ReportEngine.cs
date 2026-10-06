using System.Net;
using System.Text;
using WinSecLab.Core.Engines.Rules;
using WinSecLab.Core.Models;
using WinSecLab.Core.Serialization;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Reports;

public sealed class ReportOptions
{
    public string OutputDirectory { get; set; } = "";
    public string Title { get; set; } = "Windows 应用程序安全测试报告";
    public string? Subtitle { get; set; }
    public string? AnalystName { get; set; }
    public string? Organization { get; set; } = "WinSecLab";
    public string Classification { get; set; } = "内部使用";
    public string? DocumentId { get; set; }
    public bool IncludeEvidenceAppendix { get; set; } = true;
    public bool IncludeRawEventSample { get; set; } = true;
    public bool IncludeSecurityGraph { get; set; } = true;
    public bool IncludeStringsSample { get; set; } = true;
    public int MaxEventRowsInReport { get; set; } = 400;
    public int MaxEvidenceRows { get; set; } = 120;
    public List<ReportFormat> Formats { get; set; } = new() { ReportFormat.Html, ReportFormat.Markdown, ReportFormat.Json };

    /// <summary>
    /// 与上一轮的对比结果（可选）。有值且存在基线时，报告会多出一节「与上次对比」，
    /// 把新增/消失/变化摆出来 —— 这是回归测试最想先看到的东西。
    /// </summary>
    public ComparisonResult? Comparison { get; set; }
}

public sealed class ReportResult
{
    public List<string> Files { get; } = new();
    public string? PrimaryFile => Files.FirstOrDefault(f => f.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
                                  ?? Files.FirstOrDefault();
    public List<string> Warnings { get; } = new();
}

/// <summary>
/// §18 报告系统。三份产物同源：HTML（自包含，可直接浏览器打印成 PDF）、Markdown（进仓库评审）、
/// JSON（机器可读，供流水线二次消费）。
/// </summary>
public sealed class ReportEngine
{
    public ReportResult Generate(AnalysisResult result, ReportOptions options)
    {
        var report = new ReportResult();
        Directory.CreateDirectory(options.OutputDirectory);

        var stem = BuildFileName(result, options);

        foreach (var format in options.Formats.Distinct())
        {
            try
            {
                var path = format switch
                {
                    ReportFormat.Html => Path.Combine(options.OutputDirectory, stem + ".html"),
                    ReportFormat.Markdown => Path.Combine(options.OutputDirectory, stem + ".md"),
                    ReportFormat.Json => Path.Combine(options.OutputDirectory, stem + ".json"),
                    _ => null,
                };
                if (path is null) continue;

                var content = format switch
                {
                    ReportFormat.Html => BuildHtml(result, options),
                    ReportFormat.Markdown => BuildMarkdown(result, options),
                    ReportFormat.Json => BuildJson(result, options),
                    _ => "",
                };

                File.WriteAllText(path, content, new UTF8Encoding(false));
                report.Files.Add(path);
            }
            catch (Exception ex)
            {
                report.Warnings.Add($"{format} 报告生成失败：{ex.Message}");
            }
        }

        return report;
    }

    private static string BuildFileName(AnalysisResult result, ReportOptions options)
    {
        var name = Path.GetFileNameWithoutExtension(result.Pe?.FileName ?? "target");
        var safe = Storage.WorkspaceLayout.SanitizeFileName(name);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return $"WinSecLab-{safe}-{stamp}";
    }

    // =====================================================================
    // HTML
    // =====================================================================

    internal static string BuildHtml(AnalysisResult result, ReportOptions options)
    {
        var html = new StringBuilder(256 * 1024);
        var stats = ComputeSeverityStats(result);
        var target = result.Project?.Target ?? new TargetSummary();
        var sectionNumber = 0;
        string? openSectionTitle = null;

        // 章内内容按顺序追加，靠这个状态在下一章开始前收尾
        void Section(string slug, string title, int number)
        {
            if (openSectionTitle is not null) html.Append("</div>\n");
            sectionNumber = number;
            openSectionTitle = title;
            html.Append($"<h2 class=\"section\" id=\"{Slug(slug)}\">{number}. {E(title)}</h2>\n<div class=\"sec-body\">\n");
        }

        void EndSections()
        {
            if (openSectionTitle is not null) html.Append("</div>\n");
            openSectionTitle = null;
        }

        void FRow(string key, string? value) =>
            html.Append($"<tr><th>{E(key)}</th><td>{E(value ?? "—")}</td></tr>\n");

        void StatCard(int count, string label, string cssClass) =>
            html.Append($"<div class=\"stat {cssClass}\"><span class=\"num\">{count}</span>")
                .Append($"<span class=\"lbl\">{E(label)}</span></div>\n");

        html.Append("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n");
        html.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        html.Append($"<title>{E(options.Title)} — {E(target.FileName)}</title>\n");
        html.Append("<style>\n").Append(Css).Append("</style>\n</head>\n<body>\n");

        // ---------------------------------------------------------- 封面
        html.Append("<header class=\"cover\">\n");
        html.Append($"<div class=\"classification\">{E(options.Classification)}</div>\n");
        html.Append($"<h1>{E(options.Title)}</h1>\n");
        html.Append($"<p class=\"subtitle\">{E(options.Subtitle ?? target.FileName ?? "")}</p>\n");
        html.Append("<table class=\"meta\">\n");
        FRow("报告编号", options.DocumentId ?? $"WSL-{DateTime.Now:yyyyMMddHHmmss}");
        FRow("被测程序", target.FileName);
        FRow("程序版本", target.FileVersion ?? "—");
        FRow("SHA-256", target.Sha256);
        FRow("分析员", options.AnalystName ?? Environment.UserName);
        FRow("生成时间", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        FRow("分析主机", $"{result.Project?.Environment.MachineName} / {result.Project?.Environment.OsVersion}");
        FRow("风险结论", stats.OverallVerdict);
        html.Append("</table>\n</header>\n");

        // ---------------------------------------------------------- 目录
        html.Append("<nav class=\"toc\"><h2>目录</h2><ul class=\"toc-list\">\n");
        foreach (var (slug, title, number) in SectionList)
            html.Append($"<li><a href=\"#{Slug(slug)}\"><span class=\"toc-num\">{number}</span>{E(title)}</a></li>\n");
        html.Append("</ul></nav>\n");

        // 1. 执行摘要
        Section("executive", "执行摘要", 1);
        html.Append("<div class=\"summary-grid\">\n");
        StatCard(stats.Critical, "严重", "sev-critical");
        StatCard(stats.High, "高危", "sev-high");
        StatCard(stats.Medium, "中危", "sev-medium");
        StatCard(stats.Low, "低危", "sev-low");
        StatCard(stats.Info, "信息", "sev-info");
        StatCard(stats.Total, "合计", "sev-total");
        html.Append("</div>\n");

        html.Append("<div class=\"verdict\">");
        html.Append($"<p><strong>总体结论：</strong>{E(stats.OverallVerdict)}</p>");
        html.Append($"<p>{E(stats.VerdictDetail)}</p>");
        html.Append("</div>\n");

        // 需立即关注：只列中危及以上（低危/信息归到下面完整清单），按严重级排序。
        // 领导/客户视角最需要的就这一小块 —— 先说要做什么，再给完整列表。
        var actionables = result.Findings
            .Where(f => f.Severity >= Severity.Medium)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Id, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (actionables.Count > 0)
        {
            html.Append("<h3>需立即关注</h3>\n");
            html.Append("<table class=\"data\"><thead><tr>");
            html.Append("<th style=\"width:80px\">编号</th><th style=\"width:70px\">等级</th><th>问题</th>");
            html.Append("<th style=\"width:270px\">建议动作</th></tr></thead><tbody>\n");
            foreach (var f in actionables)
            {
                html.Append($"<tr><td><a href=\"#finding-{E(f.Id)}\">{E(f.Id)}</a></td>");
                html.Append($"<td>{SeverityBadge(f.Severity)}</td>");
                html.Append($"<td>{E(f.Title)}</td>");
                html.Append($"<td>{E(FirstSentence(f.Recommendation))}</td></tr>\n");
            }
            html.Append("</tbody></table>\n");
        }
        else if (result.Findings.Count == 0)
        {
            html.Append("<p class=\"note\">本次未产生任何发现项。</p>\n");
        }
        else
        {
            html.Append("<p class=\"note\">本次未发现中危及以上问题，"
                        + $"{result.Findings.Count} 个低危 / 信息项见「安全发现」章节。</p>\n");
        }

        // 全部发现の完整清单（含低危/信息）
        if (result.Findings.Count > 0)
        {
            var reviewed = result.Findings.Count(f => f.Status != FindingStatus.Open);
            html.Append("<h3>发现项清单</h3>\n");
            if (reviewed > 0)
            {
                html.Append($"<p class=\"note\">共 {result.Findings.Count} 条，其中 <strong>{reviewed} 条已经人工复核</strong>"
                            + $"（已确认 / 误报 / 接受风险 / 已整改），{result.Findings.Count - reviewed} 条待处理。</p>\n");
            }
            html.Append("<table class=\"data\"><thead><tr>");
            html.Append("<th style=\"width:80px\">编号</th><th style=\"width:70px\">等级</th><th>标题</th>");
            html.Append("<th style=\"width:70px\">置信度</th><th style=\"width:150px\">类别</th><th style=\"width:96px\">处理状态</th></tr></thead><tbody>\n");
            foreach (var f in result.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Id))
            {
                html.Append($"<tr><td><a href=\"#finding-{E(f.Id)}\">{E(f.Id)}</a></td>");
                html.Append($"<td>{SeverityBadge(f.Severity)}</td>");
                html.Append($"<td>{E(f.Title)}</td>");
                html.Append($"<td>{E(f.ConfidenceText)}</td>");
                html.Append($"<td>{E(f.Category)}</td>");
                html.Append($"<td>{E(f.StatusText)}</td></tr>\n");
            }
            html.Append("</tbody></table>\n");
        }

        // 采集覆盖一览：让读者一眼知道"这次测到什么程度"，避免把"没测"误读成"没问题"
        html.Append("<h3>采集覆盖一览</h3>\n");
        var dynOk = result.Events.Any(e => e.Type == MonitorEventType.SessionStart);
        var elevated = result.Project?.Environment.IsElevated == true;
        AppendTable(html, new[] { "维度", "覆盖情况" }, new[]
        {
            new[] { "静态分析", result.Pe is not null ? "已完成（PE 结构 / 字符串 / 依赖 / 签名）" : "未执行" },
            new[] { "类型识别", result.Project?.Detection.DisplayName is { Length: > 0 } t ? $"已完成（{t}）" : "未执行" },
            new[] { "动态分析", dynOk ? "已执行" : "未执行" },
            new[] { "网络采集", result.Connections.Count > 0 ? "已采集" : "未采集" },
            new[] { "权限级别", elevated ? "管理员（内核级归因可用）" : "标准用户（部分证据精度受限）" },
            new[] { "证据条数", result.Evidence.Count.ToString() },
            new[] { "人工复核", result.Findings.Count == 0
                ? "无发现项需复核"
                : $"{result.Findings.Count(f => f.Status != FindingStatus.Open)}/{result.Findings.Count} 条已复核" },
        });

        // 与上次对比（回归测试）—— 只有拿到基线快照时才出这一节
        if (options.Comparison is { Baseline: not null, Current: not null } cmp)
        {
            html.Append("<h3>与上次对比</h3>\n");
            html.Append($"<p>本轮与上一轮快照（{cmp.Baseline!.CapturedAt:yyyy-MM-dd HH:mm}）对比结果："
                        + $"<strong>{E(cmp.Verdict)}</strong></p>\n");

            if (cmp.TargetChanged)
            {
                html.Append("<p class=\"note\">⚠ 两轮样本哈希不一致（"
                            + $"{Short(cmp.Baseline.TargetSha256)} → {Short(cmp.Current!.TargetSha256)}），"
                            + "说明被测版本已变化，差异可能来自版本本身而非行为变化，请结合版本信息解读。</p>\n");
            }

            AppendTable(html, new[] { "类别", "数量", "说明" }, new[]
            {
                new[] { "发现项总数", $"{cmp.Current!.TotalFindings}", $"上轮 {cmp.Baseline.TotalFindings}，变化 {Signed(cmp.DeltaFindings)}" },
                new[] { "新增", cmp.Added.Count.ToString(), cmp.Added.Count == 0 ? "无" : "本轮新命中，需重点复核" },
                new[] { "消失", cmp.Removed.Count.ToString(), cmp.Removed.Count == 0 ? "无" : "上轮有、本轮未再命中（可能已修复）" },
                new[] { "发生变化", cmp.Changed.Count.ToString(), cmp.Changed.Count == 0 ? "无" : "严重级或处理状态变化" },
                new[] { "事件总数", cmp.Current.EventCount.ToString(), $"上轮 {cmp.Baseline.EventCount}，变化 {Signed(cmp.DeltaEvents)}" },
                new[] { "网络连接", cmp.Current.ConnectionCount.ToString(), $"上轮 {cmp.Baseline.ConnectionCount}，变化 {Signed(cmp.DeltaConnections)}" },
            });

            if (cmp.Added.Count > 0)
            {
                html.Append("<h4>新增发现</h4>\n");
                AppendTable(html, new[] { "编号", "等级", "标题", "类别" },
                    cmp.Added.Select(f => new[] { f.Id, f.SeverityText, f.Title, f.Category }));
            }

            if (cmp.Removed.Count > 0)
            {
                html.Append("<h4>消失发现（上轮有、本轮未再命中）</h4>\n");
                AppendTable(html, new[] { "编号", "等级", "标题", "类别" },
                    cmp.Removed.Select(f => new[] { f.Id, f.SeverityText, f.Title, f.Category }));
            }

            if (cmp.Changed.Count > 0)
            {
                html.Append("<h4>变化明细</h4>\n");
                AppendTable(html, new[] { "编号", "标题", "字段", "变化前", "变化后" },
                    cmp.Changed.Select(c => new[] { c.Id, c.Title, c.Field, c.Before, c.After }));
            }
        }
        else if (options.Comparison is { } noBaseline)
        {
            html.Append("<h3>与上次对比</h3>\n");
            html.Append($"<p class=\"note\">{E(noBaseline.Verdict)}</p>\n");
        }

        // 2. 程序信息
        Section("application", "程序信息", 2);
        AppendKeyValueTable(html, new (string, string?)[]
        {
            ("文件名", target.FileName),
            ("完整路径", target.FilePath),
            ("文件大小", target.FileSize > 0 ? $"{target.FileSize:N0} 字节（{target.FileSize / 1024.0 / 1024:F2} MB）" : "—"),
            ("SHA-256", target.Sha256),
            ("MD5", target.Md5),
            ("IMPHASH", result.Pe?.ImpHash),
            ("文件版本", target.FileVersion),
            ("产品名称", target.ProductName),
            ("公司", target.CompanyName),
            ("文件说明", target.FileDescription),
            ("签名状态", result.Pe?.Signature.StatusText ?? (target.IsSigned ? "有效" : "未签名")),
            ("签名者", result.Pe?.Signature.SignerSubject),
            ("签名时间戳", result.Pe?.Signature.IsTimestamped == true ? (result.Pe.Signature.TimestampAuthority ?? "有") : "无"),
            ("识别类型", result.Project?.Detection.DisplayName),
            ("识别置信度", result.Project is null ? "—" : $"{result.Project.Detection.ConfidencePercent}%"),
        });
        if (result.Project is not null && result.Project.Detection.Signals.Count > 0)
        {
            html.Append("<h3>类型识别依据</h3>\n");
            AppendTable(html, new[] { "信号", "说明", "权重" },
                result.Project.Detection.Signals.Select(s => new[] { s.Kind, s.Detail, s.Weight.ToString() }));
        }

        // 3. 测试环境
        Section("environment", "测试环境", 3);
        var env = result.Project?.Environment;
        AppendKeyValueTable(html, new (string, string?)[]
        {
            ("主机名", env?.MachineName),
            ("测试账号", env?.UserName),
            ("操作系统", $"{env?.OsVersion} (Build {env?.OsBuild})"),
            ("系统架构", env?.OsArchitecture),
            (".NET 运行时", env?.DotNetVersion),
            ("管理员权限", env?.IsElevated == true ? "是" : "否（部分证据精度受限）"),
            ("虚拟化环境", env?.IsVirtualMachine == true ? $"是（{env.VirtualizationHint}）" : "未检测到虚拟化特征"),
            ("处理器 / 内存", $"{env?.LogicalProcessors} 逻辑核心 / {env?.TotalMemoryMb / 1024.0:F1} GB"),
            ("分析器版本", env?.AnalyzerVersion),
            ("环境快照时间", env?.CapturedAt.ToString("yyyy-MM-dd HH:mm:ss")),
            ("会话 ID", result.Analyses.Count > 0 ? result.Analyses[0] : "—"),
        });
        if (!string.IsNullOrEmpty(env?.VirtualizationHint) && env.IsVirtualMachine)
            html.Append("<p class=\"note\">本次测试在虚拟化环境中进行，符合 §14 沙箱设计要求。</p>\n");
        else
            html.Append("<p class=\"warning\">未检测到虚拟化环境。按 §14 沙箱设计要求，"
                        + "未知或高风险程序应在 Hyper-V / Windows Sandbox 等隔离环境中运行。</p>\n");

        // 插件与工具链状态
        if (result.Plugins.Count > 0)
        {
            html.Append("<h3>分析引擎与外部工具状态</h3>\n");
            AppendTable(html, new[] { "引擎 / 工具", "类型", "状态", "说明" },
                result.Plugins.Select(p => new[]
                {
                    p.Name + (string.IsNullOrEmpty(p.Version) ? "" : $" {p.Version}"),
                    p.Kind switch
                    {
                        PluginKind.Builtin => "内置引擎",
                        PluginKind.ExternalToolAdapter => "外部工具适配器",
                        _ => "插件程序集",
                    },
                    p.Available ? "可用" : "不可用",
                    p.Available ? p.AvailabilityText : $"{p.AvailabilityText}（{p.InstallHint}）",
                }));
        }

        // 4. 静态分析
        Section("static", "静态分析", 4);
        if (result.Pe is not null)
        {
            var pe = result.Pe;
            AppendKeyValueTable(html, new (string, string?)[]
            {
                ("PE 有效性", pe.IsValidPe ? "有效" : $"解析失败：{pe.ParseError}"),
                ("架构 / 子系统", $"{pe.Architecture} / {pe.Subsystem}"),
                ("CLR 映像类型", pe.ClrImageKind),
                ("编译器", $"{pe.Compiler}（链接器 {pe.LinkerMajor}.{pe.LinkerMinor}）"),
                ("编译依据", pe.CompilerEvidence),
                ("时间戳", pe.TimeDateStamp?.ToString("yyyy-MM-dd HH:mm:ss") +
                           (pe.IsReproducibleBuildStamp ? "（可复现构建伪时间戳）" : pe.TimeStampIsPlausible ? "" : "（不合理）")),
                ("入口点 RVA", $"0x{pe.EntryPointRva:X}"),
                ("镜像基址", $"0x{pe.ImageBase:X}"),
                ("节区数", pe.Sections.Count.ToString()),
                ("导入", $"{pe.ImportedDllCount} 个模块 / {pe.ImportedFunctionCount} 个函数"),
                ("延迟导入", pe.DelayImports.Count == 0 ? "无" : $"{pe.DelayImports.Count} 项"),
                ("导出", pe.ExportCount.ToString()),
                ("资源条目", pe.Resources.Count.ToString()),
                ("整体熵值", $"{pe.OverallEntropy}（{Util.Entropy.Describe(pe.OverallEntropy)}）"),
                ("Overlay", pe.HasOverlay ? $"{pe.OverlaySize / 1024} KB，熵 {pe.OverlayEntropy}" : "无"),
                ("缓解措施", string.IsNullOrEmpty(pe.DllCharacteristics) ? "—" : pe.DllCharacteristics),
                ("Rich Header", pe.RichHeader.Summary),
                ("PDB 路径", pe.DebugPaths.Count == 0 ? "无" : string.Join("；", pe.DebugPaths)),
            });

            html.Append("<h3>节区明细</h3>\n");
            html.Append(FoldStart($"节区明细（{pe.Sections.Count} 个节区）", $"{pe.Sections.Count} 项", true));
            AppendTable(html, new[] { "节区", "权限", "虚拟大小", "原始大小", "熵值", "性质" },
                pe.Sections.Select(s => new[]
                {
                    s.Name,
                    s.Permissions + (s.IsWritableAndExecutable ? " ⚠" : ""),
                    s.VirtualSize.ToString("N0"),
                    s.RawSize.ToString("N0"),
                    s.Entropy.ToString("F4"),
                    Util.Entropy.Describe(s.Entropy),
                }));
            html.Append(FoldEnd());

            if (pe.Imports.Count > 0)
            {
                // 分两层：正文只列"有分析价值"的模块，全量清单折叠。
                //
                // 过滤规则来自实际报告的问题 —— 原来 Top 60 里混着 50+ 个 api-ms-win-* API Set
                // 和 6 行函数数为 0 的空条目，真正的业务模块（USER32/GDI32 等）反被淹没。
                static bool IsApiSetModule(string name) =>
                    name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase);

                var notable = pe.Imports
                    .Where(m => m.FunctionCount > 0 && !IsApiSetModule(m.ModuleName))
                    .OrderByDescending(m => m.FunctionCount)
                    .ToList();
                var apiSetModules = pe.Imports.Count(m => IsApiSetModule(m.ModuleName));
                var emptyModules = pe.Imports.Count(m => m.FunctionCount == 0);

                AppendKeyValueTable(html, new (string, string?)[]
                {
                    ("导入模块总数", pe.Imports.Count.ToString()),
                    ("其中 API Set 转发", $"{apiSetModules} 个（api-ms-win-* 转发模块，属系统机制）"),
                    ("其中无函数导入", $"{emptyModules} 个（仅声明依赖，未实际调用）"),
                });

                if (notable.Count > 0)
                {
                    html.Append("<h3>关键导入模块</h3>\n");
                    AppendTable(html, new[] { "模块", "函数数", "代表性函数" },
                        notable.Take(15).Select(m => new[]
                        {
                            m.ModuleName,
                            m.FunctionCount.ToString(),
                            string.Join(", ", m.Functions.Take(10).Select(f => f.Name)),
                        }));
                }

                // 全量导入清单默认收起 —— 正文已给关键模块，56 行明细只服务于逐条核对
                html.Append(FoldStart($"全部 {pe.Imports.Count} 个导入模块明细", $"{pe.Imports.Count} 项", false));
                AppendTable(html, new[] { "模块", "函数数", "代表性函数" },
                    pe.Imports.OrderByDescending(m => m.FunctionCount)
                        .Select(m => new[]
                        {
                            m.ModuleName,
                            m.FunctionCount.ToString(),
                            string.Join(", ", m.Functions.Take(8).Select(f => f.Name)),
                        }));
                html.Append(FoldEnd());
            }

            if (pe.Exports.Count > 0)
            {
                html.Append("<h3>导出函数</h3>\n");
                html.Append(FoldStart($"导出函数清单（{pe.Exports.Count} 项）", $"{pe.Exports.Count} 项", pe.Exports.Count <= 20));
                AppendTable(html, new[] { "序号", "名称", "RVA", "前向导出" },
                    pe.Exports.Take(80).Select(x => new[]
                    {
                        x.Ordinal.ToString(),
                        x.Name,
                        $"0x{x.Rva:X}",
                        x.ForwarderTarget ?? "",
                    }));
                html.Append(FoldEnd());
            }
        }

        // 5. 运行期观测（动态/网络/文件/注册表合并）
        //
        // 合并理由：这四个维度都来自"目标程序实际跑起来"的采集。原来各占一章、各进目录，
        // 而多数静态分析场景下四章都是空的（各自只有一句"未采集到"），
        // 翻四页看不到任何信息。合并后先给一张覆盖状态总览，有数据的再展开细看。
        Section("runtime", "运行期观测", 5);

        var sessions = result.Events.Where(e => e.Type == MonitorEventType.SessionStart).ToList();
        var fileEvents = result.Events.Where(e => e.Type is MonitorEventType.FileCreate
            or MonitorEventType.FileWrite or MonitorEventType.FileDelete or MonitorEventType.FileRename).ToList();
        var regEvents = result.Events.Where(e => e.Type is MonitorEventType.RegistryCreate
            or MonitorEventType.RegistryDelete or MonitorEventType.RegistrySet).ToList();
        var procEvents = result.Events.Where(e => e.Type is MonitorEventType.ProcessStart
            or MonitorEventType.ChildProcess).ToList();
        var connections = result.Connections;

        html.Append("<h3>采集覆盖状态</h3>\n");
        AppendTable(html, new[] { "观测维度", "状态", "数据量", "说明" }, new[]
        {
            new[] { "动态会话", sessions.Count > 0 ? "已执行" : "未执行",
                    sessions.Count.ToString(),
                    sessions.Count > 0 ? "目标程序已启动并完成监控"
                                       : "测试 Profile 未包含动态任务，或目标未启动" },
            new[] { "进程活动", procEvents.Count > 0 ? "已采集" : "无记录",
                    $"{procEvents.Count} 条", procEvents.Count > 0 ? "含进程创建与子进程派生" : "未观测到进程创建" },
            new[] { "文件系统", fileEvents.Count > 0 ? "已采集" : "无记录",
                    $"{fileEvents.Count} 条", fileEvents.Count > 0 ? "含创建/写入/删除/重命名" : "目标未改动文件，或监控权限不足" },
            new[] { "注册表", regEvents.Count > 0 ? "已采集" : "无记录",
                    $"{regEvents.Count} 条", regEvents.Count > 0 ? "含键创建/删除/设值" : "目标未改动注册表，或监控权限不足" },
            new[] { "网络连接", connections.Count > 0 ? "已采集" : "无记录",
                    $"{connections.Count} 条", connections.Count > 0 ? "含连接表与域名解析" : "未采集到连接记录（标准用户下无抓包能力）" },
        });
        html.Append("<p class=\"note\">「未采集」表示该维度没有数据，"
                    + "<strong>不代表该维度没有问题</strong> —— 请对照说明确认是目标行为如此，还是采集能力受限于权限/工具缺失。</p>\n");

        if (sessions.Count == 0 && fileEvents.Count == 0 && regEvents.Count == 0
            && procEvents.Count == 0 && connections.Count == 0)
        {
            html.Append("<p class=\"note\">本次为纯静态分析，未产生任何运行期数据。"
                        + "如需观测运行行为，请在「测试执行」页面选择包含动态任务的 Profile 后重跑。</p>\n");
        }
        else
        {
            if (sessions.Count > 0)
            {
                foreach (var s in sessions)
                    html.Append($"<p class=\"note\">{E(s.Detail)}</p>\n");
            }

            // 可疑事件时间线 —— 运行期最值得看的一张表，放在最前
            var suspicious = result.Events.Where(e => e.IsSuspicious).ToList();
            if (suspicious.Count > 0)
            {
                html.Append("<h3>可疑行为时间线</h3>\n");
                AppendTable(html, new[] { "时间", "类型", "对象", "原因" },
                    suspicious.Take(options.MaxEventRowsInReport).Select(e => new[]
                    {
                        e.TimeText, e.TypeLabel, e.Target, e.SuspicionReason ?? "—",
                    }));
            }

            if (procEvents.Count > 0)
            {
                html.Append("<h3>进程创建</h3>\n");
                html.Append(FoldStart($"进程创建明细（{procEvents.Count} 条）", $"{procEvents.Count} 条", procEvents.Count <= 30));
                AppendTable(html, new[] { "时间", "进程", "PID", "父 PID", "路径" },
                    procEvents.Take(120).Select(e => new[]
                    {
                        e.TimeText, e.ProcessName, e.ProcessId.ToString(), e.ParentProcessId.ToString(),
                        e.ProcessPath ?? "—",
                    }));
                html.Append(FoldEnd());
            }

            var dllEvents = result.Events.Where(e => e.Type == MonitorEventType.DllLoad)
                .Where(e => e.IsSuspicious).ToList();
            if (dllEvents.Count > 0)
            {
                html.Append("<h3>可疑模块加载（来自用户可写目录）</h3>\n");
                html.Append(FoldStart($"可疑模块加载（{dllEvents.Count} 条）", $"{dllEvents.Count} 条", true));
                AppendTable(html, new[] { "时间", "进程", "模块路径" },
                    dllEvents.Take(60).Select(e => new[] { e.TimeText, e.ProcessName, e.Target }));
                html.Append(FoldEnd());
            }

            if (connections.Count > 0)
            {
                html.Append("<h3>网络连接</h3>\n");
                html.Append($"<p>共 {connections.Count} 条连接，"
                            + $"其中目标进程树相关 {connections.Count(c => c.IsFromTargetTree)} 条，"
                            + $"解析到域名 {connections.Count(c => c.Domain is not null)} 条。</p>\n");

                var domains = connections.Where(c => c.Domain is not null)
                    .GroupBy(c => c.Domain!, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(g => g.Count()).ToList();
                if (domains.Count > 0)
                {
                    html.Append("<h4>DNS / 域名</h4>\n");
                    html.Append(FoldStart($"域名解析清单（{domains.Count} 个域名）", $"{domains.Count} 个", domains.Count <= 30));
                    AppendTable(html, new[] { "域名", "解析地址", "连接数", "端口" },
                        domains.Take(60).Select(g => new[]
                        {
                            g.Key,
                            string.Join(", ", g.Select(c => c.RemoteAddress).Distinct().Take(4)),
                            g.Count().ToString(),
                            string.Join("/", g.Select(c => c.RemotePort).Distinct().OrderBy(p => p).Take(5)),
                        }));
                    html.Append(FoldEnd());
                }

                html.Append("<h4>连接明细（目标进程树相关）</h4>\n");
                var treeConns = connections.Where(c => c.IsFromTargetTree).ToList();
                // 空明细不出折叠块 —— 一个「展开后什么都没有」的面板只会让人以为渲染坏了
                if (treeConns.Count == 0)
                {
                    html.Append("<p class=\"note\">本次未采集到与目标进程树相关的连接记录。</p>\n");
                }
                else
                {
                    html.Append(FoldStart($"连接明细（{treeConns.Count} 条）", $"{treeConns.Count} 条", treeConns.Count <= 30));
                    AppendTable(html, new[] { "进程", "本地端点", "远端端点", "域名", "状态", "服务", "归因" },
                        treeConns.OrderByDescending(c => c.LastSeen)
                            .Take(200)
                            .Select(c => new[]
                            {
                                $"{c.ProcessName}({c.ProcessId})",
                                c.LocalEndpoint,
                                c.RemoteEndpoint,
                                c.Domain ?? "—",
                                c.StateText,
                                c.ServiceHint,
                                c.Attribution.ToString(),
                            }));
                    html.Append(FoldEnd());
                }
            }

            if (fileEvents.Count > 0)
            {
                html.Append("<h3>文件系统变更</h3>\n");
                html.Append($"<p>共 {fileEvents.Count} 条文件事件，其中可执行文件相关 "
                            + $"{fileEvents.Count(e => RuleContext.IsExecutablePath(e.Target))} 条。</p>\n");
                html.Append(FoldStart($"文件事件明细（{fileEvents.Count} 条）", $"{fileEvents.Count} 条", fileEvents.Count <= 30));
                AppendTable(html, new[] { "时间", "操作", "路径", "结果" },
                    fileEvents.Take(options.MaxEventRowsInReport)
                        .Select(e => new[] { e.TimeText, e.Operation, e.Target, e.Result }));
                html.Append(FoldEnd());
            }

            if (regEvents.Count > 0)
            {
                html.Append("<h3>注册表变更</h3>\n");
                html.Append($"<p>共 {regEvents.Count} 条注册表变更，其中自启动 / 持久化相关 "
                            + $"{regEvents.Count(e => Engines.Dynamic.RegistryMonitor.IsPersistencePath(e.Target))} 条。</p>\n");
                html.Append(FoldStart($"注册表变更明细（{regEvents.Count} 条）", $"{regEvents.Count} 条", regEvents.Count <= 30));
                AppendTable(html, new[] { "时间", "操作", "键 / 值", "变化内容" },
                    regEvents.Take(options.MaxEventRowsInReport).Select(e => new[]
                    {
                        e.TimeText, e.Operation, e.Target, e.Detail ?? "—",
                    }));
                html.Append(FoldEnd());
            }

            // 事件构成统计放最后 —— 它是"仪表盘"性质，读者看完具体内容才需要这个总览
            var eventGroups = result.Events.GroupBy(e => e.Type).OrderByDescending(g => g.Count()).ToList();
            if (eventGroups.Count > 0)
            {
                html.Append("<h3>事件构成统计</h3>\n");
                AppendTable(html, new[] { "事件类型", "数量" },
                    eventGroups.Select(g => new[] { g.Key.ToString(), g.Count().ToString() }));
            }
        }

        // 6. 依赖分析

        // 9. 依赖
        Section("dependencies", "依赖分析", 6);
        if (result.Dependencies.Count == 0)
        {
            html.Append("<p class=\"note\">未解析到依赖项。</p>\n");
        }
        else
        {
            // 关键：把三类"看起来像问题、其实不是"的项分开，避免读者被噪声误导。
            //
            // 1) API Set 虚拟模块（api-ms-win-* / ext-ms-*）—— Windows 的 API 转发机制，
            //    磁盘上本就没有对应文件，"未解析"是**正常现象**。原来逐条标"缺失"，
            //    一次能刷出 50+ 行红色警报，把真正的风险项彻底淹没。
            // 2) System32 / SysWOW64 的系统库—— 正常解析，无需逐个列。
            // 3) 真正需要关注的：可写目录加载（劫持风险）、本地目录加载、真实未找到。
            static bool IsApiSet(DependencyInfo d) =>
                d.SearchSource.Contains("API Set", StringComparison.OrdinalIgnoreCase);

            var apiSets = result.Dependencies.Where(IsApiSet).ToList();
            var suspicious = result.Dependencies
                .Where(d => !IsApiSet(d))
                .Where(d => d.IsUserWritableLocation || !d.IsPresent
                            || d.SearchSource is "应用目录" or "附加搜索目录")
                .OrderByDescending(d => d.IsUserWritableLocation)
                .ThenBy(d => d.IsPresent)
                .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var sysLibs = result.Dependencies.Count - apiSets.Count - suspicious.Count;

            AppendKeyValueTable(html, new (string, string?)[]
            {
                ("依赖总数", result.Dependencies.Count.ToString()),
                ("API Set 虚拟模块", $"{apiSets.Count} 个（Windows API 转发机制，磁盘无实体文件，未解析属正常）"),
                ("系统库（System32 / SysWOW64）", $"{sysLibs} 个，正常解析"),
                ("需关注项", suspicious.Count == 0 ? "无" : $"{suspicious.Count} 个（见下表）"),
            });

            if (suspicious.Count == 0)
            {
                html.Append("<p class=\"note\">未发现从可写目录加载、或真实缺失的依赖项 —— "
                            + "依赖加载路径未见劫持风险。</p>\n");
            }
            else
            {
                html.Append("<h3>需关注的依赖项</h3>\n");
                AppendTable(html, new[] { "模块", "状态", "解析路径", "来源", "可写目录", "版本", "签名" },
                    suspicious.Select(d => new[]
                    {
                        d.Name,
                        d.IsPresent ? "已解析" : "未找到",
                        d.ResolvedPath ?? "—",
                        d.SearchSource,
                        d.IsUserWritableLocation ? "是 ⚠" : "否",
                        d.Version ?? "—",
                        d.IsSigned switch { true => "有效", false => "无签名", null => "—" },
                    }));
            }

            // 全量依赖清单折叠进附录区，供需要逐条核对时展开
            if (result.Dependencies.Count > suspicious.Count)
            {
                html.Append(FoldStart($"全部 {result.Dependencies.Count} 个依赖项明细",
                    $"{result.Dependencies.Count} 项", false));
                AppendTable(html, new[] { "模块", "状态", "来源", "版本", "签名" },
                    result.Dependencies.OrderByDescending(d => d.IsUserWritableLocation)
                        .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                        .Select(d => new[]
                        {
                            d.Name,
                            d.IsPresent ? "已解析" : "未解析",
                            d.SearchSource,
                            d.Version ?? "—",
                            d.IsSigned switch { true => "有效", false => "无签名", null => "—" },
                        }));
                html.Append(FoldEnd());
            }
        }

        // 10. Security Findings
        Section("findings", "安全发现", 7);
        if (result.Findings.Count == 0)
        {
            html.Append("<p class=\"note\">规则引擎未产生任何发现。这表示「在本次测试覆盖面内未发现问题」，"
                        + "不等于产品没有安全问题 —— 请结合第 3 节的工具链状态确认证据完整性。</p>\n");
        }
        else
        {
            foreach (var finding in result.Findings)
            {
                html.Append($"<article class=\"finding\" id=\"finding-{E(finding.Id)}\">\n");
                html.Append("<div class=\"finding-head\">");
                html.Append($"<span class=\"finding-id\">{E(finding.Id)}</span>");
                html.Append(SeverityBadge(finding.Severity));
                html.Append($"<span class=\"finding-title\">{E(finding.Title)}</span></div>\n");

                html.Append("<table class=\"data compact\"><tbody>\n");
                FRow("规则", $"{finding.RuleId}（{finding.Category}）");
                FRow("置信度", finding.ConfidenceText);
                // 处理状态统一取模型上的 StatusText（唯一口径），并标出是否已人工复核
                FRow("处理状态", finding.Status == FindingStatus.Open
                    ? "待处理（未经人工复核）"
                    : $"{finding.StatusText}（已人工复核）");
                FRow("命中对象", finding.Target);
                if (finding.CweId is not null) FRow("CWE", finding.CweId);
                if (finding.OwaspCategory is not null) FRow("OWASP", finding.OwaspCategory);
                FRow("来源", finding.Source);
                html.Append("</tbody></table>\n");

                html.Append("<h4>说明</h4>\n");
                html.Append($"<div class=\"prose\">{E(finding.Description).Replace("\n", "<br>")}</div>\n");

                if (!string.IsNullOrEmpty(finding.Impact))
                {
                    html.Append("<h4>影响</h4>\n");
                    html.Append($"<div class=\"prose\">{E(finding.Impact)}</div>\n");
                }

                if (!string.IsNullOrEmpty(finding.Reproduction))
                {
                    html.Append("<h4>复现步骤</h4>\n");
                    html.Append($"<div class=\"prose\">{E(finding.Reproduction).Replace("\n", "<br>")}</div>\n");
                }

                if (!string.IsNullOrEmpty(finding.Recommendation))
                {
                    html.Append("<h4>整改建议</h4>\n");
                    html.Append($"<div class=\"prose recommend\">{E(finding.Recommendation)}</div>\n");
                }

                // 人工复核意见（§9 人工深入分析）——只有复核过的条目才有，放在整改建议之后
                if (!string.IsNullOrWhiteSpace(finding.AnalystNote))
                {
                    html.Append("<h4>人工复核意见</h4>\n");
                    html.Append($"<div class=\"prose note\">{E(finding.AnalystNote).Replace("\n", "<br>")}</div>\n");
                }

                var linkedEvidence = result.Evidence.Where(e => finding.EvidenceIds.Contains(e.Id)).ToList();
                if (linkedEvidence.Count > 0)
                {
                    html.Append("<h4>关联证据</h4>\n");
                    AppendTable(html, new[] { "证据 ID", "类型", "标题", "来源" },
                        linkedEvidence.Select(e => new[] { e.Id, e.KindLabel, e.Title, e.Source }));
                }

                var related = new List<string>();
                if (finding.RelatedProcesses.Count > 0) related.Add("进程：" + string.Join(", ", finding.RelatedProcesses));
                if (finding.RelatedFiles.Count > 0) related.Add("文件：" + string.Join(", ", finding.RelatedFiles));
                if (finding.RelatedRegistry.Count > 0) related.Add("注册表：" + string.Join(", ", finding.RelatedRegistry));
                if (finding.RelatedNetwork.Count > 0) related.Add("网络：" + string.Join(", ", finding.RelatedNetwork));
                if (related.Count > 0)
                {
                    html.Append("<h4>关联实体</h4>\n<ul class=\"related\">\n");
                    foreach (var item in related) html.Append($"<li>{E(item)}</li>\n");
                    html.Append("</ul>\n");
                }

                html.Append("</article>\n");
            }
        }

        // 11. 证据
        Section("evidence", "证据链", 8);
        if (!options.IncludeEvidenceAppendix)
        {
            html.Append("<p class=\"note\">按报告设置，证据附录已在本次导出中省略。</p>\n");
        }
        else
        {
            html.Append($"<p>共 {result.Evidence.Count} 条证据，全部落盘在项目目录下，可通过证据 ID 在数据库中检索原始记录。</p>\n");
            html.Append(FoldStart($"证据清单（{result.Evidence.Count} 条）", $"{result.Evidence.Count} 条", result.Evidence.Count <= 30));
            AppendTable(html, new[] { "证据 ID", "类型", "标题", "来源", "时间" },
                result.Evidence.Take(options.MaxEvidenceRows).Select(e => new[]
                {
                    e.Id, e.KindLabel, e.Title, e.Source, e.TimestampText,
                }));
            html.Append(FoldEnd());
        }

        // 12. 风险整改
        Section("remediation", "风险整改", 9);
        if (result.Findings.Count == 0)
        {
            html.Append("<p class=\"note\">无待整改项。</p>\n");
        }
        else
        {
            html.Append("<p>按严重级与整改成本排序，建议按以下顺序推进。优先级 P0 应立即处理，"
                        + "P1 在下一个迭代修复，P2 纳入技术债跟踪，P3 视情况优化。</p>\n");
            AppendTable(html, new[] { "优先级", "编号", "处理状态", "问题", "建议动作", "验证方式" },
                result.Findings.Select(f => new[]
                {
                    PriorityOf(f.Severity),
                    f.Id,
                    f.StatusText,
                    f.Title,
                    f.Recommendation ?? "—",
                    VerificationOf(f),
                }));
        }

        // 13. 附录
        Section("appendix", "附录", 10);
        html.Append("<h3>10.1 分析产物</h3>\n");
        html.Append("<ul class=\"related\">\n");
        foreach (var artifact in result.Project is null ? Array.Empty<string>() : new[]
                 {
                     "Target/ —— 被测文件与依赖副本",
                     "Static Analysis/ —— PE 画像、字符串、依赖、.NET 元数据",
                     "Dynamic Analysis/ —— 事件流（JSONL）与进程树",
                     "Network/ —— 连接表、DNS、HTTP 历史",
                     "Findings/ —— 统一发现（JSON）",
                     "Reports/ —— 本报告",
                     "analysis.db —— SQLite 证据库（可用任意 SQLite 客户端查询）",
                 })
            html.Append($"<li>{E(artifact)}</li>\n");
        html.Append("</ul>\n");

        if (options.IncludeStringsSample && result.Strings.Count > 0)
        {
            // 各类别只给统计 + 抽样。原来 General 类别（通常是 800+ 条编译器/汇编碎片）
            // 会刷满整页无信息量的字符串，把有意义的 URL / 路径 / API 名埋掉。
            html.Append("<h3>10.2 字符串提取统计</h3>\n");
            var allGroups = Strings.ExtractCategoriesInOrder(result.Strings).ToList();
            AppendTable(html, new[] { "类别", "条数", "说明" },
                allGroups.Select(g => new[]
                {
                    g.Key,
                    g.Value.Count.ToString(),
                    Strings.CategoryHint(g.Key),
                }));
            html.Append($"<p class=\"note\">共提取 {result.Strings.Count} 条字符串。"
                        + "下方按类别给出代表性样本（每类最多 20 条，按偏移排序）；"
                        + "全量数据见 <code>Static Analysis/strings.json</code>。</p>\n");

            foreach (var group in allGroups.Where(g => g.Key != "General").Take(7))
            {
                html.Append(FoldStart($"{group.Key}（显示前 20）", $"{group.Value.Count} 条", false));
                AppendTable(html, new[] { "字符串", "节区", "偏移", "编码" },
                    group.Value.Take(20).Select(s => new[]
                    {
                        Truncate(s.Value, 160), s.Section, $"0x{s.Offset:X}", s.Encoding,
                    }));
                html.Append(FoldEnd());
            }
        }

        if (options.IncludeRawEventSample && result.Events.Count > 0)
        {
            html.Append("<h3>10.3 事件流样例</h3>\n");
            html.Append(FoldStart($"原始事件流样例（前 200 / 共 {result.Events.Count} 条）",
                $"{Math.Min(200, result.Events.Count)} 条", false));
            AppendTable(html, new[] { "时间", "类型", "进程", "对象", "操作", "结果" },
                result.Events.Take(200).Select(e => new[]
                {
                    e.TimeText, e.TypeLabel, e.ProcessName, e.Target, e.Operation, e.Result,
                }));
            html.Append(FoldEnd());
        }

        html.Append("<h3>10.4 报告局限与免责说明</h3>\n");
        html.Append("<div class=\"prose\">\n");
        html.Append("<p>本报告的所有结论均基于 WinSecLab 在本次会话中实际采集到的证据。以下因素会影响结论的完整性：</p>\n<ul>\n");
        html.Append("<li>内置文件与注册表监控采用「路径相关性 + 时间窗」归因，无法像内核级监控那样把每个事件精确绑定到发起线程；"
                    + "需要精确定性时请启用 Process Monitor 适配器复现。</li>\n");
        html.Append("<li>未安装的第三方工具（Wireshark / YARA / Ghidra 等）对应的分析维度为空白，不代表该维度没有问题。</li>\n");
        html.Append("<li>HTTPS 流量未做中间人解密，仅记录 CONNECT 目标主机，无法审计加密后的请求内容。</li>\n");
        html.Append("<li>自动发现只负责提示；所有中高危结论都应经人工复核证据后确认。</li>\n");
        html.Append("</ul>\n<p>测试对象应为本人拥有或已明确获得书面授权测试的 Windows 应用与测试环境。</p>\n</div>\n");

        if (options.IncludeSecurityGraph && result.GraphNodes.Count > 0)
        {
            html.Append("<h3>10.5 安全关系图（Security Graph）</h3>\n");
            html.Append("<p>中心为被测程序，向外依次为模块 / 网络 / 进程 / 文件 / 注册表 / 发现。红色节点表示可疑。</p>\n");
            html.Append(BuildGraphSvg(result));
        }

        EndSections();

        html.Append("<footer>\n<p>本报告由 WinSecLab 自动生成 · 证据优先，结论可回溯 · 生成时间 ")
            .Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"))
            .Append("</p>\n</footer>\n");

        html.Append("</body>\n</html>\n");
        return html.ToString();
    }

    /// <summary>
    /// 章节目录。标题用纯中文（原来中英双写 `Executive Summary 执行摘要` 冗长且不美观），
    /// 锚点用显式 slug —— 中文标题无法从字符推导出稳定的 URL 片段。
    /// </summary>
    private static readonly (string Slug, string Title, int Number)[] SectionList =
    {
        ("executive", "执行摘要", 1),
        ("application", "程序信息", 2),
        ("environment", "测试环境", 3),
        ("static", "静态分析", 4),
        ("runtime", "运行期观测", 5),
        ("dependencies", "依赖分析", 6),
        ("findings", "安全发现", 7),
        ("evidence", "证据链", 8),
        ("remediation", "风险整改", 9),
        ("appendix", "附录", 10),
    };

    private static string Slug(string slug) => "sec-" + slug;

    /// <summary>
    /// 折叠块。屏幕上是可点击展开的面板；打印时由 CSS 强制展开，保证 PDF 不丢明细。
    /// 用 checkbox 而非 &lt;details&gt;：浏览器不会在打印时展开未 open 的 details。
    /// </summary>
    internal static string FoldStart(string title) => FoldStart(title, null, false);

    /// <summary>
    /// 折叠块（可指定初始展开状态与副标题计数）。
    /// </summary>
    /// <param name="title">折叠头标题</param>
    /// <param name="badge">右侧计数徽标，如「56 项」，无则传 null</param>
    /// <param name="open">是否默认展开。默认收起，保持正文精简</param>
    internal static string FoldStart(string title, string? badge, bool open)
    {
        var id = "fold-" + Math.Abs(title.GetHashCode()).ToString("x");
        var check = open ? " checked" : "";
        var badgeHtml = badge is null ? "" : $"<span class=\"fold-badge\">{E(badge)}</span>";
        return $"<div class=\"fold\"><input type=\"checkbox\" class=\"fold-toggle\" id=\"{id}\"{check}>"
             + $"<label class=\"fold-head\" for=\"{id}\"><span class=\"fold-title\">{E(title)}</span>"
             + badgeHtml + "</label><div class=\"fold-body\">";
    }

    internal static string FoldEnd() => "</div></div>\n";

    /// <summary>
    /// 可横向滚动的表格容器。用于列数多（≥6 列）的宽表 ——
    /// 窄屏与 A4 打印宽度下，宽表若不加滚动容器会被挤成每列几个字，
    /// 或撑破页面宽度导致右侧内容被裁掉。
    /// </summary>
    internal static string TableScrollStart() => "<div class=\"table-scroll\">";
    internal static string TableScrollEnd() => "</div>\n";

    /// <summary>
    /// 取整改建议的第一句，用于摘要里的一行式"建议动作"。
    /// 完整建议往往两三句（含验证方式），摘要把整段塞进去会撑爆表格。
    /// </summary>
    private static string FirstSentence(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "—";
        var t = text.Trim();
        foreach (var sep in new[] { "。", "；", "\n" })
        {
            var idx = t.IndexOf(sep, StringComparison.Ordinal);
            if (idx > 0 && idx < 120) return t[..(idx + 1)];
        }
        return t.Length > 120 ? t[..120] + "…" : t;
    }

    /// <summary>哈希只显示前 12 位（完整值在「程序信息」节里，这里只需够区分）。</summary>
    /// <summary>
    /// 哈希截断展示。截前 12 位在"两轮哈希前缀相同"的场景下毫无区分度
    /// （看起来一模一样，读者以为没变），所以这里改成首尾各取一段。
    /// </summary>
    private static string Short(string? hash) =>
        string.IsNullOrWhiteSpace(hash) ? "—"
        : hash.Length <= 12 ? hash
        : $"{hash[..8]}…{hash[^4..]}";

    /// <summary>带符号的差值：0 显示 "0"，正数带 +，负数自带 -。</summary>
    private static string Signed(int delta) => delta > 0 ? $"+{delta}" : delta.ToString();

    private static string PriorityOf(Severity severity) => severity switch
    {        Severity.Critical => "P0 立即",
        Severity.High => "P0 立即",
        Severity.Medium => "P1 下个迭代",
        Severity.Low => "P2 技术债",
        _ => "P3 可选",
    };

    private static string VerificationOf(Finding finding) =>
        finding.Category switch
        {
            "持久化" => "复测时导出 Run / RunOnce / Services 分支对比，确认不再新增",
            "文件系统与落地" => "在干净快照中运行后 diff 受影响目录，确认无新增可执行文件",
            "代码完整性与签名" => "用 signtool verify /pa /v 校验产物签名与时间戳",
            "网络与会话安全" => "用代理或抓包确认不再出现明文 HTTP 与查询串凭据",
            "依赖与加载安全" => "用 Process Monitor 过滤 Load Image 事件，确认无来自可写目录的模块",
            "内存保护与缓解措施" => "用 dumpbin /headers 检查 DYNAMIC_BASE、NX_COMPAT、GUARD_CF",
            "敏感信息暴露" => "对产物执行 strings 扫描并复核关键字命中",
            "威胁情报匹配" => "用 YARA 规则单独复扫并人工比对命中位置",
            _ => "按整改建议复测一次，保留前后证据对比",
        };

    private static void AppendKeyValueTable(StringBuilder html, IEnumerable<(string Key, string? Value)> rows)
    {
        html.Append("<table class=\"data kv\"><tbody>\n");
        foreach (var (key, value) in rows)
            html.Append($"<tr><th>{E(key)}</th><td>{E(value ?? "—")}</td></tr>\n");
        html.Append("</tbody></table>\n");
    }

    /// <summary>
    /// 渲染数据表。
    /// 列数 ≥6 时自动套 <c>.table-scroll</c> 横向滚动容器 —— 宽表在窄屏/PDF 下
    /// 不加容器会被挤压或撑破页宽，逐处手写容易漏，故在此统一处理。
    /// </summary>
    private static void AppendTable(StringBuilder html, string[] headers, IEnumerable<string[]> rows)
    {
        var wide = headers.Length >= 6;
        if (wide) html.Append(TableScrollStart());

        html.Append("<table class=\"data\"><thead><tr>");
        foreach (var h in headers) html.Append($"<th>{E(h)}</th>");
        html.Append("</tr></thead><tbody>\n");
        var any = false;
        foreach (var row in rows)
        {
            any = true;
            html.Append("<tr>");
            foreach (var cell in row) html.Append($"<td>{E(Truncate(cell, 400))}</td>");
            html.Append("</tr>\n");
        }
        if (!any) html.Append("<tr><td colspan=\"" + headers.Length + "\">（无数据）</td></tr>\n");
        html.Append("</tbody></table>\n");

        if (wide) html.Append(TableScrollEnd());
    }

    private static string SeverityBadge(Severity severity)
    {
        var (cls, text) = severity switch
        {
            Severity.Critical => ("sev-critical", "严重"),
            Severity.High => ("sev-high", "高危"),
            Severity.Medium => ("sev-medium", "中危"),
            Severity.Low => ("sev-low", "低危"),
            _ => ("sev-info", "信息"),
        };
        return $"<span class=\"badge {cls}\">{text}</span>";
    }

    // =====================================================================
    // Markdown
    // =====================================================================

    internal static string BuildMarkdown(AnalysisResult result, ReportOptions options)
    {
        var md = new StringBuilder(96 * 1024);
        var stats = ComputeSeverityStats(result);
        var target = result.Project?.Target ?? new TargetSummary();

        md.Append($"# {options.Title}\n\n");
        md.Append($"**被测程序：** {target.FileName}　　**报告编号：** {options.DocumentId ?? $"WSL-{DateTime.Now:yyyyMMddHHmmss}"}\n\n");
        md.Append($"**生成时间：** {DateTime.Now:yyyy-MM-dd HH:mm:ss}　　**分析员：** {options.AnalystName ?? Environment.UserName}");
        md.Append($"　　**密级：** {options.Classification}\n\n");
        md.Append("> 本报告由 WinSecLab 自动生成；所有结论均可回溯到原始证据。\n\n");

        md.Append("## 1. 执行摘要\n\n");
        md.Append("| 严重 | 高危 | 中危 | 低危 | 信息 | 合计 |\n|---|---|---|---|---|---|\n");
        md.Append($"| {stats.Critical} | {stats.High} | {stats.Medium} | {stats.Low} | {stats.Info} | {stats.Total} |\n\n");
        md.Append($"**总体结论：** {stats.OverallVerdict}\n\n{stats.VerdictDetail}\n\n");

        // 需立即关注（中危及以上）—— Markdown 版的行动清单
        var mdActionables = result.Findings
            .Where(f => f.Severity >= Severity.Medium)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Id, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (mdActionables.Count > 0)
        {
            md.Append("### 需立即关注\n\n");
            md.Append("| 编号 | 等级 | 问题 | 建议动作 |\n|---|---|---|---|\n");
            foreach (var f in mdActionables)
                md.Append($"| {f.Id} | {f.SeverityText} | {f.Title} | {FirstSentence(f.Recommendation)} |\n");
            md.Append('\n');
        }

        if (result.Findings.Count > 0)
        {
            var mdReviewed = result.Findings.Count(f => f.Status != FindingStatus.Open);
            md.Append("### 发现项清单\n\n");
            if (mdReviewed > 0)
            {
                md.Append($"共 {result.Findings.Count} 条，其中 **{mdReviewed} 条已经人工复核**"
                          + $"（已确认 / 误报 / 接受风险 / 已整改），{result.Findings.Count - mdReviewed} 条待处理。\n\n");
            }
            md.Append("| 编号 | 等级 | 标题 | 置信度 | 类别 | 处理状态 |\n|---|---|---|---|---|---|\n");
            foreach (var f in result.Findings.OrderByDescending(x => x.Severity).ThenBy(x => x.Id))
                md.Append($"| {f.Id} | {f.SeverityText} | {f.Title} | {f.ConfidenceText} | {f.Category} | {f.StatusText} |\n");
            md.Append('\n');
        }

        md.Append("### 采集覆盖一览\n\n| 维度 | 覆盖情况 |\n|---|---|\n");
        md.Append($"| 静态分析 | {(result.Pe is not null ? "已完成" : "未执行")} |\n");
        md.Append($"| 动态分析 | {(result.Events.Any(e => e.Type == MonitorEventType.SessionStart) ? "已执行" : "未执行")} |\n");
        md.Append($"| 网络采集 | {(result.Connections.Count > 0 ? "已采集" : "未采集")} |\n");
        md.Append($"| 权限级别 | {(result.Project?.Environment.IsElevated == true ? "管理员" : "标准用户（部分证据精度受限）")} |\n");
        md.Append($"| 证据条数 | {result.Evidence.Count} |\n");
        md.Append($"| 人工复核 | {(result.Findings.Count == 0 ? "无发现项需复核" : $"{result.Findings.Count(f => f.Status != FindingStatus.Open)}/{result.Findings.Count} 条已复核")} |\n\n");

        // 与上次对比（回归测试）—— Markdown 版
        if (options.Comparison is { Baseline: not null, Current: not null } mcmp)
        {
            md.Append("### 与上次对比\n\n");
            md.Append($"与上一轮快照（{mcmp.Baseline!.CapturedAt:yyyy-MM-dd HH:mm}）对比：**{mcmp.Verdict}**\n\n");
            if (mcmp.TargetChanged)
            {
                md.Append($"> ⚠ 两轮样本哈希不一致（{Short(mcmp.Baseline.TargetSha256)} → {Short(mcmp.Current!.TargetSha256)}），"
                          + "差异可能来自版本本身而非行为变化。\n\n");
            }
            md.Append("| 类别 | 数量 | 说明 |\n|---|---|---|\n");
            md.Append($"| 发现项总数 | {mcmp.Current!.TotalFindings} | 上轮 {mcmp.Baseline.TotalFindings}，变化 {Signed(mcmp.DeltaFindings)} |\n");
            md.Append($"| 新增 | {mcmp.Added.Count} | {(mcmp.Added.Count == 0 ? "无" : "本轮新命中，需重点复核")} |\n");
            md.Append($"| 消失 | {mcmp.Removed.Count} | {(mcmp.Removed.Count == 0 ? "无" : "上轮有、本轮未再命中（可能已修复）")} |\n");
            md.Append($"| 发生变化 | {mcmp.Changed.Count} | {(mcmp.Changed.Count == 0 ? "无" : "严重级或处理状态变化")} |\n");
            md.Append($"| 事件总数 | {mcmp.Current.EventCount} | 上轮 {mcmp.Baseline.EventCount}，变化 {Signed(mcmp.DeltaEvents)} |\n");
            md.Append($"| 网络连接 | {mcmp.Current.ConnectionCount} | 上轮 {mcmp.Baseline.ConnectionCount}，变化 {Signed(mcmp.DeltaConnections)} |\n\n");

            if (mcmp.Added.Count > 0)
            {
                md.Append("**新增发现**\n\n| 编号 | 等级 | 标题 | 类别 |\n|---|---|---|---|\n");
                foreach (var f in mcmp.Added)
                    md.Append($"| {f.Id} | {f.SeverityText} | {f.Title} | {f.Category} |\n");
                md.Append('\n');
            }
            if (mcmp.Removed.Count > 0)
            {
                md.Append("**消失发现**\n\n| 编号 | 等级 | 标题 | 类别 |\n|---|---|---|---|\n");
                foreach (var f in mcmp.Removed)
                    md.Append($"| {f.Id} | {f.SeverityText} | {f.Title} | {f.Category} |\n");
                md.Append('\n');
            }
            if (mcmp.Changed.Count > 0)
            {
                md.Append("**变化明细**\n\n| 编号 | 标题 | 字段 | 变化前 | 变化后 |\n|---|---|---|---|---|\n");
                foreach (var c in mcmp.Changed)
                    md.Append($"| {c.Id} | {c.Title} | {c.Field} | {c.Before} | {c.After} |\n");
                md.Append('\n');
            }
        }
        else if (options.Comparison is { } mnoBaseline)
        {
            md.Append("### 与上次对比\n\n");
            md.Append($"{mnoBaseline.Verdict}\n\n");
        }

        md.Append("## 2. 程序信息\n\n");
        md.Append("| 项 | 值 |\n|---|---|\n");
        md.Append($"| 文件路径 | `{target.FilePath}` |\n");
        md.Append($"| 文件大小 | {target.FileSize:N0} 字节 |\n");
        md.Append($"| SHA-256 | `{target.Sha256}` |\n");
        md.Append($"| MD5 | `{target.Md5}` |\n");
        md.Append($"| Imphash | `{result.Pe?.ImpHash ?? "—"}` |\n");
        md.Append($"| 版本 | {target.FileVersion ?? "—"} |\n");
        md.Append($"| 产品 | {target.ProductName ?? "—"} / {target.CompanyName ?? "—"} |\n");
        md.Append($"| 签名 | {result.Pe?.Signature.StatusText ?? "—"} |\n");
        md.Append($"| 签名者 | {result.Pe?.Signature.SignerSubject ?? "—"} |\n");
        md.Append($"| 识别类型 | {result.Project?.Detection.DisplayName ?? "—"}（{result.Project?.Detection.ConfidencePercent ?? 0}%）|\n\n");

        md.Append("## 3. 测试环境\n\n");
        var env = result.Project?.Environment;
        md.Append("| 项 | 值 |\n|---|---|\n");
        md.Append($"| 主机 | {env?.MachineName} |\n| 账号 | {env?.UserName} |\n");
        md.Append($"| 系统 | {env?.OsVersion} (Build {env?.OsBuild}) |\n");
        md.Append($"| 管理员权限 | {(env?.IsElevated == true ? "是" : "否")} |\n");
        md.Append($"| 虚拟化 | {(env?.IsVirtualMachine == true ? "是" : "否")} |\n");
        md.Append($"| 分析器 | {env?.AnalyzerVersion} |\n\n");

        if (result.Plugins.Count > 0)
        {
            md.Append("### 引擎与工具状态\n\n| 名称 | 类型 | 状态 | 说明 |\n|---|---|---|---|\n");
            foreach (var p in result.Plugins)
                md.Append($"| {p.Name} | {p.Kind} | {(p.Available ? "可用" : "不可用")} | {p.AvailabilityText} |\n");
            md.Append('\n');
        }

        md.Append("## 4. 静态分析\n\n");
        if (result.Pe is not null)
        {
            var pe = result.Pe;
            md.Append("| 项 | 值 |\n|---|---|\n");
            md.Append($"| 架构 / 子系统 | {pe.Architecture} / {pe.Subsystem} |\n");
            md.Append($"| 编译器 | {pe.Compiler} |\n");
            md.Append($"| 时间戳 | {pe.TimeDateStamp:yyyy-MM-dd HH:mm:ss}{(pe.IsReproducibleBuildStamp ? "（可复现构建）" : "")} |\n");
            md.Append($"| 节区数 | {pe.Sections.Count} |\n");
            md.Append($"| 导入 | {pe.ImportedDllCount} 模块 / {pe.ImportedFunctionCount} 函数 |\n");
            md.Append($"| 导出 | {pe.ExportCount} |\n");
            md.Append($"| 整体熵 | {pe.OverallEntropy} |\n");
            md.Append($"| 缓解措施 | {pe.DllCharacteristics} |\n\n");

            md.Append("<details open><summary>节区明细（" + pe.Sections.Count + " 个节区）</summary>\n\n");
            md.Append("| 节区 | 权限 | 原始大小 | 熵 | 性质 |\n|---|---|---|---|---|\n");
            foreach (var s in pe.Sections)
                md.Append($"| {s.Name} | {s.Permissions} | {s.RawSize:N0} | {s.Entropy:F4} | {Util.Entropy.Describe(s.Entropy)} |\n");
            md.Append("\n</details>\n\n");

            // 导入 / 导出清单默认收起 —— 与 HTML 侧结构保持一致（正文精简、明细按需展开）
            if (pe.Imports.Count > 0)
            {
                static bool IsApiSetMd2(string name) =>
                    name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase);

                var mdNotable = pe.Imports
                    .Where(m => m.FunctionCount > 0 && !IsApiSetMd2(m.ModuleName))
                    .OrderByDescending(m => m.FunctionCount).ToList();

                if (mdNotable.Count > 0)
                {
                    md.Append("### 关键导入模块\n\n| 模块 | 函数数 | 代表性函数 |\n|---|---|---|\n");
                    foreach (var m in mdNotable.Take(15))
                        md.Append($"| {m.ModuleName} | {m.FunctionCount} | {string.Join(", ", m.Functions.Take(10).Select(f => f.Name))} |\n");
                    md.Append('\n');
                }

                md.Append($"<details><summary>全部 {pe.Imports.Count} 个导入模块明细</summary>\n\n");
                md.Append("| 模块 | 函数数 | 代表性函数 |\n|---|---|---|\n");
                foreach (var m in pe.Imports.OrderByDescending(m => m.FunctionCount))
                    md.Append($"| {m.ModuleName} | {m.FunctionCount} | {string.Join(", ", m.Functions.Take(8).Select(f => f.Name))} |\n");
                md.Append("\n</details>\n\n");
            }

            if (pe.Exports.Count > 0)
            {
                md.Append($"<details{(pe.Exports.Count <= 20 ? " open" : "")}><summary>导出函数清单（{pe.Exports.Count} 项）</summary>\n\n");
                md.Append("| 序号 | 名称 | RVA | 前向导出 |\n|---|---|---|---|\n");
                foreach (var x in pe.Exports.Take(80))
                    md.Append($"| {x.Ordinal} | {x.Name} | 0x{x.Rva:X} | {x.ForwarderTarget ?? ""} |\n");
                md.Append("\n</details>\n\n");
            }
        }

        // ── 5. 运行期观测（原动态/网络/文件/注册表四章合并） ─────────────────
        md.Append("## 5. 运行期观测\n\n");

        var mdSessions = result.Events.Where(e => e.Type == MonitorEventType.SessionStart).ToList();
        var mdFileEvents = result.Events.Where(e => e.Type is MonitorEventType.FileCreate
            or MonitorEventType.FileWrite or MonitorEventType.FileDelete or MonitorEventType.FileRename).ToList();
        var mdRegEvents = result.Events.Where(e => e.Type is MonitorEventType.RegistryCreate
            or MonitorEventType.RegistryDelete or MonitorEventType.RegistrySet).ToList();
        var mdProcEvents = result.Events.Where(e => e.Type is MonitorEventType.ProcessStart
            or MonitorEventType.ChildProcess).ToList();
        var mdConnections = result.Connections;

        // 采集覆盖状态 —— 先给"哪些维度采到了、哪些没采到"的全景，避免空章节被误读为"没问题"
        md.Append("### 采集覆盖状态\n\n");
        md.Append("| 观测维度 | 状态 | 数据量 | 说明 |\n|---|---|---|---|\n");
        md.Append($"| 动态会话 | {(mdSessions.Count > 0 ? "已执行" : "未执行")} | {mdSessions.Count} | "
                  + $"{(mdSessions.Count > 0 ? "目标程序已启动并完成监控" : "测试 Profile 未包含动态任务，或目标未启动")} |\n");
        md.Append($"| 进程活动 | {(mdProcEvents.Count > 0 ? "已采集" : "无记录")} | {mdProcEvents.Count} 条 | "
                  + $"{(mdProcEvents.Count > 0 ? "含进程创建与子进程派生" : "未观测到进程创建")} |\n");
        md.Append($"| 文件系统 | {(mdFileEvents.Count > 0 ? "已采集" : "无记录")} | {mdFileEvents.Count} 条 | "
                  + $"{(mdFileEvents.Count > 0 ? "含创建/写入/删除/重命名" : "目标未改动文件，或监控权限不足")} |\n");
        md.Append($"| 注册表 | {(mdRegEvents.Count > 0 ? "已采集" : "无记录")} | {mdRegEvents.Count} 条 | "
                  + $"{(mdRegEvents.Count > 0 ? "含键创建/删除/设值" : "目标未改动注册表，或监控权限不足")} |\n");
        md.Append($"| 网络连接 | {(mdConnections.Count > 0 ? "已采集" : "无记录")} | {mdConnections.Count} 条 | "
                  + $"{(mdConnections.Count > 0 ? "含连接表与域名解析" : "未采集到连接记录（标准用户下无抓包能力）")} |\n\n");
        md.Append("> 「未采集」表示该维度没有数据，**不代表该维度没有问题** —— "
                  + "请对照说明确认是目标行为如此，还是采集能力受限于权限 / 工具缺失。\n\n");

        if (mdSessions.Count == 0 && mdFileEvents.Count == 0 && mdRegEvents.Count == 0
            && mdProcEvents.Count == 0 && mdConnections.Count == 0)
        {
            md.Append("本次为纯静态分析，未产生任何运行期数据。"
                      + "如需观测运行行为，请在「测试执行」页面选择包含动态任务的 Profile 后重跑。\n\n");
        }
        else
        {
            foreach (var s in mdSessions) md.Append($"- {s.Detail}\n");
            if (mdSessions.Count > 0) md.Append('\n');

            var mdSuspicious = result.Events.Where(e => e.IsSuspicious).ToList();
            if (mdSuspicious.Count > 0)
            {
                md.Append("### 可疑行为时间线\n\n| 时间 | 类型 | 对象 | 原因 |\n|---|---|---|---|\n");
                foreach (var e in mdSuspicious.Take(options.MaxEventRowsInReport))
                    md.Append($"| {e.TimeText} | {e.TypeLabel} | `{e.Target}` | {e.SuspicionReason ?? "—"} |\n");
                md.Append('\n');
            }

            if (mdProcEvents.Count > 0)
            {
                md.Append($"<details><summary>进程创建明细（{mdProcEvents.Count} 条）</summary>\n\n");
                md.Append("| 时间 | 进程 | PID | 父 PID | 路径 |\n|---|---|---|---|---|\n");
                foreach (var e in mdProcEvents.Take(120))
                    md.Append($"| {e.TimeText} | {e.ProcessName} | {e.ProcessId} | {e.ParentProcessId} | `{e.ProcessPath ?? "—"}` |\n");
                md.Append("\n</details>\n\n");
            }

            var mdDllEvents = result.Events.Where(e => e.Type == MonitorEventType.DllLoad)
                .Where(e => e.IsSuspicious).ToList();
            if (mdDllEvents.Count > 0)
            {
                md.Append($"<details open><summary>可疑模块加载（来自用户可写目录）（{mdDllEvents.Count} 条）</summary>\n\n");
                md.Append("| 时间 | 进程 | 模块路径 |\n|---|---|---|\n");
                foreach (var e in mdDllEvents.Take(60))
                    md.Append($"| {e.TimeText} | {e.ProcessName} | `{e.Target}` |\n");
                md.Append("\n</details>\n\n");
            }

            if (mdConnections.Count > 0)
            {
                md.Append("### 网络连接\n\n");
                md.Append($"共 {mdConnections.Count} 条连接，其中目标进程树相关 "
                          + $"{mdConnections.Count(c => c.IsFromTargetTree)} 条，"
                          + $"解析到域名 {mdConnections.Count(c => c.Domain is not null)} 条。\n\n");

                var mdDomains = mdConnections.Where(c => c.Domain is not null)
                    .GroupBy(c => c.Domain!, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(g => g.Count()).ToList();
                if (mdDomains.Count > 0)
                {
                    md.Append($"<details><summary>DNS / 域名（{mdDomains.Count} 个域名）</summary>\n\n");
                    md.Append("| 域名 | 解析地址 | 连接数 | 端口 |\n|---|---|---|---|\n");
                    foreach (var g in mdDomains.Take(60))
                        md.Append($"| {g.Key} | {string.Join(", ", g.Select(c => c.RemoteAddress).Distinct().Take(4))} "
                                  + $"| {g.Count()} | {string.Join("/", g.Select(c => c.RemotePort).Distinct().OrderBy(p => p).Take(5))} |\n");
                    md.Append("\n</details>\n\n");
                }

                var mdTreeConns = mdConnections.Where(c => c.IsFromTargetTree).ToList();
                if (mdTreeConns.Count == 0)
                {
                    md.Append("本次未采集到与目标进程树相关的连接记录。\n\n");
                }
                else
                {
                    md.Append($"<details{(mdTreeConns.Count <= 30 ? " open" : "")}><summary>连接明细（目标进程树相关）（{mdTreeConns.Count} 条）</summary>\n\n");
                    md.Append("| 进程 | 本地端点 | 远端端点 | 域名 | 状态 |\n|---|---|---|---|---|\n");
                    foreach (var c in mdTreeConns.OrderByDescending(c => c.LastSeen).Take(200))
                        md.Append($"| {c.ProcessName}({c.ProcessId}) | {c.LocalEndpoint} | {c.RemoteEndpoint} "
                                  + $"| {c.Domain ?? "—"} | {c.StateText} |\n");
                    md.Append("\n</details>\n\n");
                }
            }

            if (result.Http.Count > 0)
            {
                md.Append("### HTTP 请求历史（代理捕获）\n\n| 方法 | URL | 状态 | 值得关注 |\n|---|---|---|---|\n");
                foreach (var x in result.Http.Take(80))
                    md.Append($"| {x.Method} | `{x.Url}` | {x.StatusTextCombined} | {string.Join("；", x.InterestReasons)} |\n");
                md.Append('\n');
            }

            if (mdFileEvents.Count > 0)
            {
                md.Append("### 文件系统变更\n\n");
                md.Append($"共 {mdFileEvents.Count} 条文件事件，其中可执行文件相关 "
                          + $"{mdFileEvents.Count(e => RuleContext.IsExecutablePath(e.Target))} 条。\n\n");
                md.Append($"<details><summary>文件事件明细（{mdFileEvents.Count} 条）</summary>\n\n");
                md.Append("| 时间 | 操作 | 路径 | 结果 |\n|---|---|---|---|\n");
                foreach (var e in mdFileEvents.Take(options.MaxEventRowsInReport))
                    md.Append($"| {e.TimeText} | {e.Operation} | `{e.Target}` | {e.Result} |\n");
                md.Append("\n</details>\n\n");
            }

            if (mdRegEvents.Count > 0)
            {
                md.Append("### 注册表变更\n\n");
                md.Append($"共 {mdRegEvents.Count} 条注册表变更，其中自启动 / 持久化相关 "
                          + $"{mdRegEvents.Count(e => Engines.Dynamic.RegistryMonitor.IsPersistencePath(e.Target))} 条。\n\n");
                md.Append($"<details><summary>注册表变更明细（{mdRegEvents.Count} 条）</summary>\n\n");
                md.Append("| 时间 | 操作 | 键 / 值 | 变化内容 |\n|---|---|---|---|\n");
                foreach (var e in mdRegEvents.Take(options.MaxEventRowsInReport))
                    md.Append($"| {e.TimeText} | {e.Operation} | `{e.Target}` | {e.Detail ?? "—"} |\n");
                md.Append("\n</details>\n\n");
            }

            // 事件构成统计放最后 —— 仪表盘性质，读者看完具体内容才需要这个总览
            var mdEventGroups = result.Events.GroupBy(e => e.Type).OrderByDescending(g => g.Count()).ToList();
            if (mdEventGroups.Count > 0)
            {
                md.Append("### 事件构成统计\n\n| 事件类型 | 数量 |\n|---|---|\n");
                foreach (var g in mdEventGroups) md.Append($"| {g.Key} | {g.Count()} |\n");
                md.Append('\n');
            }
        }

        // ── 6. 依赖分析 ────────────────────────────────────────────────
        md.Append("## 6. 依赖分析\n\n");
        if (result.Dependencies.Count == 0)
        {
            md.Append("未解析到依赖项。\n\n");
        }
        else
        {
            static bool IsApiSetMd(DependencyInfo d) =>
                d.SearchSource.Contains("API Set", StringComparison.OrdinalIgnoreCase);

            var mdApiSets = result.Dependencies.Where(IsApiSetMd).ToList();
            var mdDepSuspicious = result.Dependencies
                .Where(d => !IsApiSetMd(d))
                .Where(d => d.IsUserWritableLocation || !d.IsPresent
                            || d.SearchSource is "应用目录" or "附加搜索目录")
                .OrderByDescending(d => d.IsUserWritableLocation)
                .ThenBy(d => d.IsPresent)
                .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var mdSysLibs = result.Dependencies.Count - mdApiSets.Count - mdDepSuspicious.Count;

            md.Append("| 项目 | 数量 / 说明 |\n|---|---|\n");
            md.Append($"| 依赖总数 | {result.Dependencies.Count} |\n");
            md.Append($"| API Set 虚拟模块 | {mdApiSets.Count} 个（Windows API 转发机制，磁盘无实体文件，未解析属正常） |\n");
            md.Append($"| 系统库（System32 / SysWOW64） | {mdSysLibs} 个，正常解析 |\n");
            md.Append($"| 需关注项 | {(mdDepSuspicious.Count == 0 ? "无" : mdDepSuspicious.Count + " 个（见下表）")} |\n\n");

            if (mdDepSuspicious.Count == 0)
            {
                md.Append("未发现从可写目录加载、或真实缺失的依赖项 —— 依赖加载路径未见劫持风险。\n\n");
            }
            else
            {
                md.Append("### 需关注的依赖项\n\n| 模块 | 状态 | 解析路径 | 来源 | 可写目录 | 版本 | 签名 |\n|---|---|---|---|---|---|---|\n");
                foreach (var d in mdDepSuspicious)
                    md.Append($"| {d.Name} | {(d.IsPresent ? "已解析" : "未找到")} | `{d.ResolvedPath ?? "—"}` "
                              + $"| {d.SearchSource} | {(d.IsUserWritableLocation ? "是 ⚠" : "否")} "
                              + $"| {d.Version ?? "—"} | {d.IsSigned switch { true => "有效", false => "无签名", null => "—" }} |\n");
                md.Append('\n');
            }

            if (result.Dependencies.Count > mdDepSuspicious.Count)
            {
                md.Append("<details><summary>全部 " + result.Dependencies.Count + " 个依赖项明细</summary>\n\n");
                md.Append("| 模块 | 状态 | 来源 | 版本 | 签名 |\n|---|---|---|---|---|\n");                foreach (var d in result.Dependencies.OrderByDescending(d => d.IsUserWritableLocation)
                             .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase))
                    md.Append($"| {d.Name} | {(d.IsPresent ? "已解析" : "未解析")} | {d.SearchSource} "
                              + $"| {d.Version ?? "—"} | {d.IsSigned switch { true => "有效", false => "无签名", null => "—" }} |\n");
                md.Append("\n</details>\n\n");
            }
        }

        // ── 7. 安全发现 ────────────────────────────────────────────────
        md.Append("## 7. 安全发现\n\n");
        if (result.Findings.Count == 0)
        {
            md.Append("本次规则引擎未产生发现。\n\n");
        }
        else
        {
            foreach (var f in result.Findings)
            {
                md.Append($"### {f.Id} · {f.Title}\n\n");
                md.Append($"- **等级：** {f.SeverityText}　**置信度：** {f.ConfidenceText}　**类别：** {f.Category}\n");
                md.Append($"- **处理状态：** {(f.Status == FindingStatus.Open ? "待处理（未经人工复核）" : $"{f.StatusText}（已人工复核）")}\n");
                md.Append($"- **规则：** {f.RuleId}");
                if (f.CweId is not null) md.Append($"　**CWE：** {f.CweId}");
                if (f.OwaspCategory is not null) md.Append($"　**OWASP：** {f.OwaspCategory}");
                md.Append('\n');
                if (!string.IsNullOrEmpty(f.Target)) md.Append($"- **命中对象：** `{f.Target}`\n");
                md.Append($"\n{f.Description}\n\n");
                if (!string.IsNullOrEmpty(f.Impact)) md.Append($"**影响：** {f.Impact}\n\n");
                if (!string.IsNullOrEmpty(f.Reproduction)) md.Append($"**复现步骤：**\n\n```\n{f.Reproduction}\n```\n\n");
                if (!string.IsNullOrEmpty(f.Recommendation)) md.Append($"**整改建议：** {f.Recommendation}\n\n");
                if (!string.IsNullOrWhiteSpace(f.AnalystNote)) md.Append($"**人工复核意见：** {f.AnalystNote}\n\n");
                if (f.EvidenceIds.Count > 0) md.Append($"**关联证据：** {string.Join(", ", f.EvidenceIds)}\n\n");
                md.Append("---\n\n");
            }
        }

        md.Append("## 8. 证据链\n\n");
        if (!options.IncludeEvidenceAppendix)
        {
            md.Append("按报告设置，证据附录已在本次导出中省略。\n\n");
        }
        else
        {
            md.Append($"共 {result.Evidence.Count} 条证据，全部落盘在项目目录下，可通过证据 ID 在数据库中检索原始记录。\n\n");
            md.Append($"<details{(result.Evidence.Count <= 30 ? " open" : "")}><summary>证据清单（{result.Evidence.Count} 条）</summary>\n\n");
            md.Append("| 证据 ID | 类型 | 标题 | 来源 | 时间 |\n|---|---|---|---|---|\n");
            foreach (var e in result.Evidence.Take(options.MaxEvidenceRows))
                md.Append($"| {e.Id} | {e.KindLabel} | {e.Title} | {e.Source} | {e.TimestampText} |\n");
            md.Append("\n</details>\n\n");
        }

        // ── 9. 风险整改 ────────────────────────────────────────────────
        md.Append("## 9. 风险整改\n\n");
        if (result.Findings.Count == 0) md.Append("无待整改项。\n\n");
        else
        {
            md.Append("按严重级与整改成本排序，建议按以下顺序推进。优先级 P0 应立即处理，"
                      + "P1 在下一个迭代修复，P2 纳入技术债跟踪，P3 视情况优化。\n\n");
            md.Append("| 优先级 | 编号 | 处理状态 | 问题 | 建议动作 | 验证方式 |\n|---|---|---|---|---|---|\n");
            foreach (var f in result.Findings)
                md.Append($"| {PriorityOf(f.Severity)} | {f.Id} | {f.StatusText} | {f.Title} | {f.Recommendation ?? "—"} | {VerificationOf(f)} |\n");
            md.Append('\n');
        }

        // ── 10. 附录 ───────────────────────────────────────────────────
        md.Append("## 10. 附录\n\n");
        md.Append("### 10.1 分析产物\n\n");
        if (result.Project is not null)
        {
            md.Append("- `Target/` —— 被测文件与依赖副本\n");
            md.Append("- `Static Analysis/` —— PE 画像、字符串、依赖、.NET 元数据\n");
            md.Append("- `Dynamic Analysis/` —— 事件流（JSONL）与进程树\n");
            md.Append("- `Network/` —— 连接表、DNS、HTTP 历史\n");
            md.Append("- `Findings/` —— 统一发现（JSON）\n");
            md.Append("- `Reports/` —— 本报告\n");
            md.Append("- `analysis.db` —— SQLite 证据库（可用任意 SQLite 客户端查询）\n\n");
        }

        if (options.IncludeStringsSample && result.Strings.Count > 0)
        {
            md.Append("### 10.2 字符串提取统计\n\n");
            var mdGroups = Strings.ExtractCategoriesInOrder(result.Strings).ToList();
            md.Append("| 类别 | 条数 | 说明 |\n|---|---|---|\n");
            foreach (var g in mdGroups)
                md.Append($"| {g.Key} | {g.Value.Count} | {Strings.CategoryHint(g.Key)} |\n");
            md.Append('\n');
            md.Append($"共提取 {result.Strings.Count} 条字符串。下方按类别给出代表性样本"
                      + "（每类最多 20 条，按偏移排序）；全量数据见 `Static Analysis/strings.json`。\n\n");

            foreach (var group in mdGroups.Where(g => g.Key != "General").Take(7))
            {
                md.Append($"<details><summary>{group.Key}（{group.Value.Count} 条，显示前 20）</summary>\n\n");
                md.Append("| 字符串 | 节区 | 偏移 | 编码 |\n|---|---|---|---|\n");
                foreach (var s in group.Value.Take(20))
                    md.Append($"| `{Truncate(s.Value, 160)}` | {s.Section} | 0x{s.Offset:X} | {s.Encoding} |\n");
                md.Append("\n</details>\n\n");
            }
        }

        if (options.IncludeRawEventSample && result.Events.Count > 0)
        {
            md.Append($"### 10.3 事件流样例\n\n<details><summary>原始事件流样例（前 {Math.Min(200, result.Events.Count)} / 共 {result.Events.Count} 条）</summary>\n\n");
            md.Append("| 时间 | 类型 | 进程 | 对象 | 操作 | 结果 |\n|---|---|---|---|---|---|\n");
            foreach (var e in result.Events.Take(200))
                md.Append($"| {e.TimeText} | {e.TypeLabel} | {e.ProcessName} | `{e.Target}` | {e.Operation} | {e.Result} |\n");
            md.Append("\n</details>\n\n");
        }

        md.Append("### 10.4 报告局限与免责说明\n\n");
        md.Append("本报告的所有结论均基于 WinSecLab 在本次会话中实际采集到的证据。以下因素会影响结论的完整性：\n\n");
        md.Append("1. 内置文件与注册表监控采用「路径相关性 + 时间窗」归因，无法像内核级监控那样把每个事件精确绑定到发起线程；"
                  + "需要精确定性时请启用 Process Monitor 适配器复现。\n");
        md.Append("2. 未安装的第三方工具（Wireshark / YARA / Ghidra 等）对应的分析维度为空白，不代表该维度没有问题。\n");
        md.Append("3. HTTPS 流量未做中间人解密，仅记录 CONNECT 目标主机，无法审计加密后的请求内容。\n");
        md.Append("4. 自动发现只负责提示；所有中高危结论都应经人工复核证据后确认。\n\n");
        md.Append("测试对象应为本人拥有或已明确获得书面授权测试的 Windows 应用与测试环境。\n\n");

        md.Append("---\n\n_本报告由 WinSecLab 自动生成。_\n");
        return md.ToString();
    }

    // =====================================================================
    // JSON
    // =====================================================================

    private static string BuildJson(AnalysisResult result, ReportOptions options)
    {
        var payload = new
        {
            generator = "WinSecLab",
            generatorVersion = result.Project?.Environment.AnalyzerVersion ?? "0.1.0",
            generatedAt = DateTime.Now,
            reportTitle = options.Title,
            classification = options.Classification,
            analyst = options.AnalystName ?? Environment.UserName,
            project = result.Project,
            summary = new
            {
                severity = new
                {
                    critical = result.Findings.Count(f => f.Severity == Severity.Critical),
                    high = result.Findings.Count(f => f.Severity == Severity.High),
                    medium = result.Findings.Count(f => f.Severity == Severity.Medium),
                    low = result.Findings.Count(f => f.Severity == Severity.Low),
                    info = result.Findings.Count(f => f.Severity == Severity.Info),
                },
                verdict = ComputeSeverityStats(result).OverallVerdict,
                evidenceCount = result.Evidence.Count,
                eventCount = result.Events.Count,
                connectionCount = result.Connections.Count,
                httpExchangeCount = result.Http.Count,
                yaraMatchCount = result.YaraMatches.Count,
            },
            target = result.Pe,
            dotNet = result.DotNet,
            dependencies = result.Dependencies,
            findings = result.Findings,
            evidence = result.Evidence,
            connections = result.Connections,
            http = result.Http,
            yara = result.YaraMatches,
            plugins = result.Plugins,
            securityGraph = new { nodes = result.GraphNodes, edges = result.GraphEdges },
            events = result.Events.Count <= 20_000 ? result.Events : result.Events.Take(20_000).ToList(),
            eventsTruncated = result.Events.Count > 20_000,
        };

        return WslJson.Serialize(payload, indented: true);
    }

    // =====================================================================
    // SVG 关系图
    // =====================================================================

    private static string BuildGraphSvg(AnalysisResult result)
    {
        const int width = 1000;
        const int height = 1000;
        const int centerX = width / 2;
        const int centerY = height / 2;
        // 图坐标的环最大半径约 800，缩放到画布内
        const double scale = 0.6;

        var svg = new StringBuilder(64 * 1024);
        svg.Append($"<div class=\"graph-wrap\"><svg viewBox=\"0 0 {width} {height}\" width=\"100%\" ");
        svg.Append("style=\"max-width:1000px;background:#fbfcfe;border:1px solid #dfe4ee;border-radius:10px\">\n");
        svg.Append("<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\">");
        svg.Append("<path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#b9c2d6\"/></marker></defs>\n");

        var byId = result.GraphNodes.ToDictionary(n => n.Id, n => n, StringComparer.OrdinalIgnoreCase);
        double Px(SecurityGraphNode n) => centerX + n.X * scale;
        double Py(SecurityGraphNode n) => centerY + n.Y * scale;

        foreach (var edge in result.GraphEdges)
        {
            if (!byId.TryGetValue(edge.SourceId, out var from) || !byId.TryGetValue(edge.TargetId, out var to)) continue;
            var color = edge.IsSuspicious ? "#e05252" : "#c7cee0";
            var dash = edge.IsSuspicious ? "" : " stroke-dasharray=\"3 3\"";
            svg.Append($"<line x1=\"{Px(from):F0}\" y1=\"{Py(from):F0}\" x2=\"{Px(to):F0}\" y2=\"{Py(to):F0}\" ")
                .Append($"stroke=\"{color}\" stroke-width=\"{(edge.IsSuspicious ? 1.6 : 1)}\"{dash} marker-end=\"url(#arrow)\"/>\n");
        }

        foreach (var node in result.GraphNodes.OrderByDescending(n => n.IsTarget))
        {
            var radius = node.IsTarget ? 26 : node.Kind == GraphNodeKind.Finding ? 14 : 10;
            var fill = node.IsTarget
                ? "#2e5b9f"
                : node.Severity switch
                {
                    Severity.Critical => "#b3261e",
                    Severity.High => "#e05252",
                    Severity.Medium => "#e8a33d",
                    Severity.Low => "#4a90d9",
                    _ => "#8a94a6",
                };
            if (node.Kind == GraphNodeKind.Finding) fill = "#7a4bd0";

            var x = Px(node);
            var y = Py(node);
            svg.Append($"<circle cx=\"{x:F0}\" cy=\"{y:F0}\" r=\"{radius}\" fill=\"{fill}\" opacity=\"0.92\"/>\n");
            svg.Append($"<title>{E(node.KindLabel)} · {E(node.Label)} — {E(node.Detail ?? "")}</title>\n");

            var label = node.Label.Length > 22 ? node.Label[..22] + "…" : node.Label;
            var anchor = x > centerX ? "start" : "end";
            var textX = x > centerX ? x + radius + 4 : x - radius - 4;
            // <title> 不能包住 circle 后再单独写，这里用 g 包一层保证 tooltip 生效
            svg.Append($"<text x=\"{textX:F0}\" y=\"{y + 4:F0}\" font-size=\"{(node.IsTarget ? 15 : 11)}\" ")
                .Append($"font-family=\"Segoe UI, Microsoft YaHei, sans-serif\" fill=\"#2b3242\" text-anchor=\"{anchor}\">")
                .Append(E(label)).Append("</text>\n");
        }

        svg.Append("</svg></div>\n");
        return svg.ToString();
    }

    // =====================================================================
    // 统计与样式
    // =====================================================================

    private sealed class SeverityStats
    {
        public int Critical, High, Medium, Low, Info, Total;
        public string OverallVerdict = "";
        public string VerdictDetail = "";
    }

    private static SeverityStats ComputeSeverityStats(AnalysisResult result)
    {
        var stats = new SeverityStats
        {
            Critical = result.Findings.Count(f => f.Severity == Severity.Critical),
            High = result.Findings.Count(f => f.Severity == Severity.High),
            Medium = result.Findings.Count(f => f.Severity == Severity.Medium),
            Low = result.Findings.Count(f => f.Severity == Severity.Low),
            Info = result.Findings.Count(f => f.Severity == Severity.Info),
        };
        stats.Total = stats.Critical + stats.High + stats.Medium + stats.Low + stats.Info;

        var (verdict, detail) = (stats.Critical, stats.High) switch
        {
            (> 0, _) => ("存在严重风险，建议在修复前限制分发",
                "本次测试发现了严重级别的安全问题。这类问题通常直接影响二进制完整性或可被用于权限提升，"
                + "应在完成修复并复测通过之前避免在生产环境大规模分发。"),
            (_, > 0) => ("存在高风险问题，建议优先修复",
                "本次测试发现了高危问题。它们未必能直接导致系统沦陷，但会显著降低攻击门槛或扩大影响面，"
                + "建议纳入近期迭代修复。"),
            _ when stats.Medium > 0 => ("存在中风险问题，建议按迭代修复",
                "本次测试未发现严重或高危问题，但存在若干中风险项。建议纳入技术债跟踪，在后续版本中逐步收敛。"),
            _ when stats.Low + stats.Info > 0 => ("以低风险与信息级问题为主",
                "本次测试未发现中高危问题。低风险项与信息级项可作为加固建议择机处理。"),
            _ => ("在本次测试覆盖面内未发现安全问题",
                "规则引擎未产生任何发现。请注意这仅代表「在本次测试覆盖面内未发现问题」，"
                + "须结合测试环境与工具链状态确认证据完整性，不能等同于产品安全性结论。"),
        };

        stats.OverallVerdict = verdict;

        var dynamicRan = result.Events.Any(e => e.Type == MonitorEventType.SessionStart);
        var elevated = result.Project?.Environment.IsElevated == true;
        var coverage = new List<string>
        {
            $"静态分析：{(result.Pe?.IsValidPe == true ? "已完成" : "未完成")}",
            $"动态分析：{(dynamicRan ? "已执行" : "未执行")}",
            $"网络采集：{(result.Connections.Count > 0 ? $"{result.Connections.Count} 条连接" : "无记录")}",
            $"权限：{(elevated ? "管理员" : "标准用户")}",
            $"证据条数：{result.Evidence.Count}",
        };

        stats.VerdictDetail = detail + " 本次测试覆盖情况：" + string.Join("；", coverage) + "。";
        return stats;
    }

    private const string Css = """
        * { box-sizing: border-box; }
        body { margin: 0; padding: 0 0 60px; font-family: "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
               font-size: 14px; line-height: 1.7; color: #23272f; background: #f5f7fa; }
        .cover { background: linear-gradient(135deg, #1f3a63 0%, #2e5b9f 55%, #3f7ad1 100%); color: #fff;
                 padding: 54px 56px 40px; }
        .cover h1 { margin: 6px 0 4px; font-size: 30px; font-weight: 650; letter-spacing: .5px; }
        .cover .subtitle { margin: 0 0 26px; font-size: 15px; opacity: .88; }
        .cover .classification { display: inline-block; padding: 2px 12px; border: 1px solid rgba(255,255,255,.55);
                 border-radius: 999px; font-size: 12px; letter-spacing: 2px; opacity: .95; }
        table.meta { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
        table.meta th { text-align: left; width: 130px; font-weight: 500; opacity: .78; padding: 4px 12px 4px 0; }
        table.meta td { padding: 4px 0; word-break: break-all; }
        nav.toc { max-width: 1200px; margin: 26px auto 0; background: #fff; border: 1px solid #e3e8f0;
                  border-radius: 10px; padding: 18px 30px; }
        nav.toc h2 { margin: 0 0 8px; font-size: 16px; color: #2e5b9f; }
        nav.toc ul.toc-list { margin: 0; padding: 0; list-style: none; columns: 2; column-gap: 28px; }
        nav.toc ul.toc-list li { margin: 0 0 5px; break-inside: avoid; }
        nav.toc a { color: #2e5b9f; text-decoration: none; }
        nav.toc a .toc-num { display: inline-block; min-width: 20px; color: #8a95a8; font-variant-numeric: tabular-nums; }
        nav.toc a:hover { text-decoration: underline; }
        h2.section, section { max-width: 1200px; }
        h2.section { margin: 32px auto 12px; padding: 10px 18px; background: #fff; border-left: 5px solid #2e5b9f;
                     border-radius: 6px; font-size: 19px; color: #1f3a63; }
        .sec-body { max-width: 1200px; margin: 0 auto; background: #fff; border: 1px solid #e3e8f0;
                    border-radius: 10px; padding: 20px 26px; }
        h3 { font-size: 15px; color: #2e5b9f; margin: 22px 0 8px; }
        h4 { font-size: 13.5px; color: #44506b; margin: 16px 0 6px; }
        table.data { width: 100%; border-collapse: collapse; margin: 8px 0 14px; font-size: 12.5px; }
        table.data th, table.data td { border: 1px solid #e2e7f0; padding: 6px 9px; text-align: left;
                                       vertical-align: top; word-break: break-word; }
        table.data thead th { background: #eef2f9; font-weight: 600; color: #2b3a55; position: sticky; top: 0; }
        table.data tbody tr:nth-child(even) { background: #fafbfe; }
        table.data.kv th { width: 190px; background: #f4f6fb; font-weight: 500; color: #47536b; }
        .summary-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin: 14px 0; }
        .stat { border-radius: 10px; padding: 14px 8px; text-align: center; border: 1px solid #e3e8f0; background: #fff; }
        .stat .num { display: block; font-size: 26px; font-weight: 700; line-height: 1.2; }
        .stat .lbl { font-size: 12px; color: #66708a; }
        .stat.sev-critical .num { color: #b3261e; } .stat.sev-high .num { color: #e05252; }
        .stat.sev-medium .num { color: #c8860d; } .stat.sev-low .num { color: #4a90d9; }
        .stat.sev-info .num { color: #7b8496; } .stat.sev-total .num { color: #2e5b9f; }
        .badge { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: 11.5px;
                 font-weight: 600; white-space: nowrap; }
        .badge.sev-critical { background: #fce8e6; color: #b3261e; border: 1px solid #f3c1bd; }
        .badge.sev-high { background: #fdeaea; color: #c0332f; border: 1px solid #f6c6c4; }
        .badge.sev-medium { background: #fdf3e2; color: #a2690a; border: 1px solid #f0dcb4; }
        .badge.sev-low { background: #e9f2fc; color: #2f6ea8; border: 1px solid #c8ddf2; }
        .badge.sev-info { background: #f0f2f6; color: #5b6478; border: 1px solid #dde1ea; }
        .verdict { border-left: 4px solid #2e5b9f; background: #f2f6fd; padding: 12px 18px; border-radius: 6px;
                   margin: 14px 0; }
        .verdict p { margin: 4px 0; }
        .finding { border: 1px solid #e3e8f0; border-radius: 10px; padding: 16px 20px; margin: 16px 0;
                   background: #fff; }
        .finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
        .finding-id { font-family: Consolas, monospace; font-size: 13px; color: #2e5b9f; font-weight: 700; }
        .finding-title { font-size: 15.5px; font-weight: 600; }
        .prose { color: #333a48; }
        .prose.recommend { background: #f2f9f3; border-left: 3px solid #3f9c52; padding: 8px 14px; border-radius: 4px; }
        .prose.note { background: #f3f6fb; border-left: 3px solid #2e5b9f; padding: 8px 14px; border-radius: 4px; }
        .note { color: #5b6478; font-size: 12.5px; background: #f6f8fb; border-radius: 6px; padding: 8px 12px; }
        .warning { color: #8a5a00; background: #fff8e8; border-left: 3px solid #e8a33d; border-radius: 4px;
                   padding: 8px 12px; font-size: 12.5px; }
        ul.related { margin: 6px 0 12px; padding-left: 20px; font-size: 12.5px; color: #46506a; }
        ul.related li { word-break: break-all; }
        code { background: #f1f3f8; padding: 1px 5px; border-radius: 4px; font-family: Consolas, monospace;
               font-size: 12px; }
        /* 折叠明细：正文保持精简，全量数据按需展开。
           为什么不用 <details>：浏览器无法在打印时强制展开未 open 的 details，
           导出的 PDF 会静默丢掉明细数据（这对取证报告是致命的）。
           改用 checkbox 折叠 —— 屏幕上可收可展，打印时用媒体查询强制全部展开。 */
        .fold { margin: 10px 0 16px; border: 1px solid #e3e8f0; border-radius: 8px; background: #fbfcfe; }
        .fold > input.fold-toggle { position: absolute; opacity: 0; pointer-events: none; }
        .fold > label.fold-head { display: flex; align-items: center; gap: 8px; cursor: pointer;
                                  padding: 9px 14px; font-size: 12.5px; color: #2e5b9f;
                                  font-weight: 600; user-select: none; }
        .fold > label.fold-head::before { content: "▸"; color: #7b8aa5; font-size: 11px;
                                          transition: transform .12s ease; }
        .fold > input.fold-toggle:checked + label.fold-head::before { content: "▾"; }
        .fold > label.fold-head:hover { background: #f2f6fd; border-radius: 8px; }
        .fold > label.fold-head > .fold-title { flex: 1; }
        .fold-badge { font-weight: 500; font-size: 11.5px; color: #6b7891; background: #eef2f9;
                      border-radius: 10px; padding: 1px 9px; white-space: nowrap; }
        .fold > .fold-body { display: none; }
        .fold > input.fold-toggle:checked + label.fold-head + .fold-body { display: block; }
        .fold > .fold-body { border-top: 1px solid #e8ecf4; padding: 0 12px; }
        .fold > .fold-body > table.data { margin: 10px 0; width: 100%; }

        /* 宽表横向滚动：列数多的表（连接明细、事件流等）在窄屏或 A4 打印宽度下
           若不加容器会被挤成每列数字，或撑破页宽裁掉右侧列。 */
        .table-scroll { overflow-x: auto; margin: 10px 0; -webkit-overflow-scrolling: touch; }
        .table-scroll > table.data { margin: 0; min-width: 100%; }
        .table-scroll::-webkit-scrollbar { height: 8px; }
        .table-scroll::-webkit-scrollbar-thumb { background: #ccd5e4; border-radius: 4px; }
        .table-scroll::-webkit-scrollbar-track { background: #f1f4f9; border-radius: 4px; }
        footer { max-width: 1200px; margin: 30px auto 0; color: #8a93a8; font-size: 12px; text-align: center; }
        @media print {
          body { background: #fff; }
          h2.section, .sec-body, nav.toc, .finding { break-inside: avoid; }
          nav.toc { break-after: page; }
          /* 打印时展开全部折叠内容，确保 PDF 不丢取证明细 */
          .fold > label.fold-head { display: none; }
          .fold > .fold-body { display: block; border-top: none; padding: 0; }
          /* 打印时不滚动 —— 打印没有滚动交互，必须让宽表完整落在页面上 */
          .table-scroll { overflow-x: visible; }
          .table-scroll > table.data { table-layout: fixed; word-break: break-word; }
        }
        """;

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? "");

    private static string Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) ? "" : value.Length <= max ? value : value[..max] + "…";
}

/// <summary>字符串类别的展示顺序（把最相关的排在前面，General 垫底）。</summary>
internal static class Strings
{
    private static readonly string[] Order =
    {
        "Credential", "Command", "URL", "Domain", "IPAddress", "SecurityApi",
        "RegistryPath", "FilePath", "Crypto", "Sql", "UserAgent", "Guid", "Json", "Format", "General",
    };

    /// <summary>类别的中文解释 —— 光看英文类别名读者不知道它在说什么。</summary>
    public static string CategoryHint(string category) => category switch
    {
        "Credential" => "口令 / 密钥 / Token 相关字面量，重点关注",
        "Command" => "命令行调用与可执行程序名",
        "URL" => "HTTP(S) / FTP 等网络地址",
        "Domain" => "域名",
        "IPAddress" => "IP 地址",
        "SecurityApi" => "敏感 API 名称（进程创建、注入、加密等）",
        "RegistryPath" => "注册表键路径",
        "FilePath" => "文件与目录路径",
        "Crypto" => "加密算法 / 证书相关标识",
        "Sql" => "SQL 语句片段",
        "UserAgent" => "HTTP User-Agent 字符串",
        "Guid" => "GUID / CLSID 标识",
        "Json" => "JSON 片段",
        "Format" => "格式化字符串（常用于日志与拼接）",
        "General" => "一般字符串，多为编译器常量与代码片段，信息量较低",
        _ => "—",
    };

    public static IEnumerable<KeyValuePair<string, List<StringHit>>> ExtractCategoriesInOrder(IEnumerable<StringHit> hits)
    {
        var groups = hits.GroupBy(h => h.Category).ToDictionary(g => g.Key, g => g.ToList());
        foreach (var category in Order)
        {
            if (groups.TryGetValue(category, out var list) && list.Count > 0)
                yield return new KeyValuePair<string, List<StringHit>>(category, list);
        }

        foreach (var (category, list) in groups)
        {
            if (Order.Contains(category)) continue;
            yield return new KeyValuePair<string, List<StringHit>>(category, list);
        }
    }
}
