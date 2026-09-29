using WinSecLab.Core.Engines.Rules;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Plugins.Builtin;

/// <summary>
/// §9 Findings Engine + §11 Security Graph 的任务归属者。
///
/// 为什么做成插件而不是编排器里的"隐藏步骤"：任务清单里的每一项都必须有明确的执行者，
/// 否则用户在「测试执行」页勾选/取消「规则关联与图谱」时，行为会和其它任务不一致
/// （取消勾选却依然生成发现，等于设置不起作用）。
/// 编排器只负责把它排在动态阶段之后执行 —— 关联必须看到完整的动态证据。
/// </summary>
public sealed class ToolCorrelationPlugin : IWinSecLabPlugin
{
    public string Id => "builtin.correlation";
    public string Name => "Rule Correlation";
    public string Version => "1.0";
    public string? Description => "规则引擎跨证据归纳，生成统一 Finding；并构建 Security Graph（实体关系 + 同心圆布局）。";
    public PluginKind Kind => PluginKind.Builtin;
    public IReadOnlyList<TestTaskKind> Capabilities { get; } = new[] { TestTaskKind.ToolCorrelation };
    public bool RequiresDynamicSession => false;
    public bool RequiresAdministrator => false;

    public PluginProbeResult Detect() => PluginProbeResult.Builtin(
        $"内置规则引擎：{BuiltinRules.All.Count} 条规则，全部带 CWE / OWASP / 影响 / 整改建议，每个结论可回溯到原始证据");

    public Task<PluginRunResult> AnalyzeAsync(PluginContext context)
    {
        var result = context.Result;
        var summaryParts = new List<string>();

        // ── 规则关联 ──
        context.Progress(0.3, "规则引擎关联分析");
        RuleEngine.RuleEngineReport report;
        try
        {
            var ruleContext = new RuleContext
            {
                Result = result,
                Project = context.Project,
                Evidence = result.Evidence,
                Options = context.Options,
            };

            var engine = new RuleEngine();
            report = engine.Run(ruleContext, context.Project.Id);
        }
        catch (Exception ex)
        {
            return Task.FromResult(PluginRunResult.Fail($"规则引擎执行失败：{ex.GetType().Name}: {ex.Message}"));
        }

        // 规则产出按严重级降序追加，保证报告与界面顺序稳定
        result.Findings.AddRange(report.Findings);

        var fired = report.FiredRuleCounts;
        if (fired.Count > 0)
            summaryParts.Add($"命中 {fired.Count} 条规则，生成 {report.Findings.Count} 个发现"
                             + $"（{string.Join("、", fired.Take(6).Select(kv => $"{kv.Key}×{kv.Value}"))}）");
        else
            summaryParts.Add("没有规则命中");

        foreach (var err in report.RuleErrors)
        {
            context.Log($"[规则异常] {err}");
            summaryParts.Add($"规则异常 {report.RuleErrors.Count} 条");
        }

        // ── Security Graph ──
        context.Progress(0.8, "构建 Security Graph");
        var (nodes, edges) = (0, 0);
        try
        {
            var graph = Engines.Analysis.SecurityGraphBuilder.Build(result);
            result.GraphNodes.AddRange(graph.Nodes);
            result.GraphEdges.AddRange(graph.Edges);
            nodes = graph.Nodes.Count;
            edges = graph.Edges.Count;
            summaryParts.Add($"图谱 {nodes} 节点 / {edges} 关系");
        }
        catch (Exception ex)
        {
            context.Log($"[图谱] 构建失败：{ex.Message}");
            summaryParts.Add("图谱构建失败");
        }

        var evidence = new List<Evidence>
        {
            EvidenceFactory.Create(context.Project.Id, EvidenceKind.Static, "关联分析汇总", Id,
                context.TargetPath,
                string.Join("；", summaryParts),
                new
                {
                    firedRules = fired.ToDictionary(kv => kv.Key, kv => kv.Value),
                    findingCount = report.Findings.Count,
                    ruleErrors = report.RuleErrors,
                    graphNodes = nodes,
                    graphEdges = edges,
                    severityCounts = report.Findings.GroupBy(f => f.Severity)
                        .ToDictionary(g => g.Key.ToString(), g => g.Count()),
                },
                "correlation", "analysis"),
        };

        if (report.Findings.Count > 0)
        {
            evidence.Add(EvidenceFactory.Create(context.Project.Id, EvidenceKind.Static, "发现项汇总", Id,
                context.TargetPath,
                $"{report.Findings.Count} 个发现，按严重级排序",
                report.Findings.Select(f => new
                {
                    f.Id,
                    f.RuleId,
                    f.Title,
                    severity = f.Severity.ToString(),
                    confidence = f.Confidence.ToString(),
                    f.Target,
                    evidenceCount = f.EvidenceIds.Count,
                }).ToList(),
                "correlation", "findings"));
        }

        return Task.FromResult(PluginRunResult.Ok(string.Join("；", summaryParts), evidence));
    }

    public void Stop() { }
    public IReadOnlyList<string> Export(PluginContext context) => Array.Empty<string>();
}
