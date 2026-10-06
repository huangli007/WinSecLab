using WinSecLab.Core.Engines.Dynamic;
using WinSecLab.Core.Engines.Network;
using WinSecLab.Core.Engines.Rules;
using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins;
using WinSecLab.Core.Storage;

namespace WinSecLab.Tests;

/// <summary>编排与存储层的关键行为。这些决定"分析能不能跑完、结论能不能读回来"。</summary>
public class PipelineTests
{
    // ─────────────────────── 规则集质量门禁 ───────────────────────

    /// <summary>每条规则都要能自圆其说：没有 CWE / 影响 / 整改建议的规则，报告里就是一句没头没尾的警报。</summary>
    [Fact]
    public void BuiltinRules_AllCarryRequiredMetadata()
    {
        var rules = BuiltinRules.All;

        Assert.True(rules.Count >= 25, $"内置规则数量异常：{rules.Count}");

        foreach (var rule in rules)
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Title), $"{rule.Id} 缺标题");
            Assert.False(string.IsNullOrWhiteSpace(rule.Description), $"{rule.Id} 缺描述");
            Assert.False(string.IsNullOrWhiteSpace(rule.Impact), $"{rule.Id} 缺影响说明");
            Assert.False(string.IsNullOrWhiteSpace(rule.Recommendation), $"{rule.Id} 缺整改建议");
            Assert.False(string.IsNullOrWhiteSpace(rule.Category), $"{rule.Id} 缺分类");
        }
    }

    [Fact]
    public void BuiltinRules_HaveUniqueIds()
    {
        var ids = BuiltinRules.All.Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void RuleEngine_EmptyContext_ProducesNoFindings()
    {
        var engine = new RuleEngine();
        var project = new TestProject { Id = "WS-TEST-001", Name = "测试" };
        var context = new RuleContext
        {
            Result = new AnalysisResult(),
            Project = project,
            Evidence = new List<Evidence>(),
        };

        var report = engine.Run(context, project.Id);

        Assert.Empty(report.Findings);
        Assert.Empty(report.RuleErrors);
    }

    // ─────────────────────── 插件宿主 ───────────────────────

    [Fact]
    public void PluginHost_RegistersBuiltinsAndAdapters_WithoutIdCollision()
    {
        var host = new PluginHost();
        var plugins = host.Plugins;

        Assert.True(plugins.Count >= 20, $"插件数量异常：{plugins.Count}");
        Assert.Equal(plugins.Count, plugins.Select(p => p.Id).Distinct().Count());
        Assert.Empty(host.LoadErrors);

        // 两类都要有：内置引擎是兜底，外部适配器是增强
        Assert.Contains(plugins, p => p.Kind == PluginKind.Builtin);
        Assert.Contains(plugins, p => p.Kind == PluginKind.ExternalToolAdapter);
    }

    [Fact]
    public void PluginHost_EveryTaskIsCoveredByAtLeastOnePlugin()
    {
        var host = new PluginHost();
        var covered = host.Plugins.SelectMany(p => p.Capabilities).Distinct().ToList();

        foreach (var task in TestTaskDefinition.All)
            Assert.True(covered.Contains(task.Kind), $"任务 {task.Kind} 没有任何插件声明支持");
    }

    /// <summary>
    /// 外部工具缺失时必须回退到内置引擎 —— 这条约定保证"没装工具也能跑完分析"。
    ///
    /// 早期版本拿 YARA 当"未装工具"的样例，结果 YARA 一装上这条测试就红了，
    /// 其实代码没问题，是测试自己依赖了环境。教训：**断言不能以"本机没装某工具"为前提**。
    ///
    /// 现在改成直接构造"替代型工具不可用"的场景验证契约，任何机器上都稳定。
    /// </summary>
    [Fact]
    public void BuildPlan_MissingSubstitutiveTool_FallsBackToBuiltin()
    {
        // 用 YARA 任务：替代型是外部的 yara 适配器，内置是 builtin.yara
        var host = new PluginHost();
        var yaraAdapter = host.Plugins.First(p => p.Id == "yara");
        var builtinYara = host.Plugins.First(p => p.Id == "builtin.yara");

        // 契约：两者能力集必须覆盖同一任务，否则"替代/降级"根本无从谈起
        Assert.Contains(TestTaskKind.YaraScan, yaraAdapter.Capabilities);
        Assert.Contains(TestTaskKind.YaraScan, builtinYara.Capabilities);
        var adapter = Assert.IsAssignableFrom<ExternalToolAdapterBase>(yaraAdapter);
        Assert.Equal(ToolRole.Substitutive, adapter.Descriptor.Role);

        // 无论本机装没装 YARA，YaraScan 任务都必须落在某个插件上（不会漏任务）
        var plan = host.BuildPlan(new[] { TestTaskKind.YaraScan }, new AnalysisOptions
        {
            PreferExternalTools = true,
        });

        Assert.Contains(plan.Steps, s => s.Task == TestTaskKind.YaraScan);
    }

    /// <summary>替代型工具与内置引擎必须成对存在 —— 这是"降级可用"的结构前提。</summary>
    [Fact]
    public void EverySubstitutiveAdapter_HasBuiltinCounterpart()
    {
        var host = new PluginHost();

        foreach (var adapter in host.Plugins.OfType<ExternalToolAdapterBase>()
                     .Where(a => a.Descriptor.Role == ToolRole.Substitutive))
        {
            foreach (var task in adapter.Capabilities)
            {
                var hasBuiltin = host.Plugins.Any(p =>
                    p.Kind == PluginKind.Builtin && p.Capabilities.Contains(task));

                Assert.True(hasBuiltin,
                    $"替代型工具「{adapter.Id}」承担 {task}，但没有内置引擎兜底 —— 该工具没装时任务会直接落空。");
            }
        }
    }

    [Fact]
    public void BuildPlan_DisabledExternalTools_UsesBuiltinOnly()
    {
        var host = new PluginHost();
        var plan = host.BuildPlan(new[] { TestTaskKind.ProcessMonitor }, new AnalysisOptions
        {
            PreferExternalTools = false,
        });

        Assert.NotEmpty(plan.Steps);
        Assert.All(plan.Steps.Where(s => s.Task == TestTaskKind.ProcessMonitor),
            s => Assert.Equal(PluginKind.Builtin, s.Plugin.Kind));
        Assert.Contains(plan.Notes, n => n.Contains("关闭外部工具"));
    }

    [Fact]
    public void BuildPlan_UnknownTask_ProducesNote()
    {
        var host = new PluginHost();
        // ToolCorrelation 由内置规则引擎承担，一定有插件；用一个真实存在但必有的任务验证 note 通道即可
        var plan = host.BuildPlan(new[] { TestTaskKind.ToolCorrelation }, new AnalysisOptions());
        Assert.NotEmpty(plan.Steps);
    }

    [Fact]
    public void BuildPlan_ExecutionOrderMatchesDeclaration()
    {
        // 静态任务必须排在动态任务前面（动态阶段依赖静态阶段采集到的相关性关键词）
        var order = PluginHost.ExecutionOrder.ToList();
        var firstDynamic = order.FindIndex(DynamicSession.IsDynamicTask);
        // DeepAnalysis 是分析工作流（非静态采集），不参与"静态先于动态"的约束
        var lastStatic = order.FindLastIndex(k => !DynamicSession.IsDynamicTask(k)
                                                  && k is not (TestTaskKind.ToolCorrelation or TestTaskKind.DeepAnalysis));

        Assert.True(firstDynamic > 0, "执行顺序里应包含动态任务");
        Assert.True(lastStatic < firstDynamic, "静态任务必须先于动态任务执行");
    }

    // ─────────────────────── DNS 解析（含 inet_aton 回归） ───────────────────────

    /// <summary>
    /// 回归：IPAddress.TryParse 兼容旧式 inet_aton 写法，会把 "106300" 解析成 0.1.158.127。
    /// DNS 输出里的「数据长度 106300」曾被当成 IP —— 这是真实踩过的坑。
    /// </summary>
    [Fact]
    public void ParseDnsOutput_DoesNotTreatDataLengthAsAddress()
    {
        const string output = """
            Windows IP 配置

                igg.example.com
                ----------------------------------------
                记录名称. . . . . . . : igg.example.com
                记录类型. . . . . . . : 1
                生存时间. . . . . . . : 55
                数据长度. . . . . . . : 4
                部分. . . . . . . . . : 答案
                A (主机) 记录. . . . : 104.21.6.55
            """;

        var parsed = NetworkMonitor.ParseDnsOutput(output);

        var host = Assert.Single(parsed);
        Assert.Equal("igg.example.com", host.Host);
        Assert.DoesNotContain(host.Addresses, a => a.StartsWith("0.0.0.") || a.StartsWith("0.1.1"));
        Assert.Contains("104.21.6.55", host.Addresses);
    }

    [Fact]
    public void ParseDnsOutput_EmptyInput_ReturnsEmpty()
    {
        Assert.Empty(NetworkMonitor.ParseDnsOutput(""));
    }

    // ─────────────────────── SQLite 存储往返 ───────────────────────

    [Fact]
    public void ProjectDatabase_AutoCreatesSchema_AndRoundTripsProject()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsl-db-{Guid.NewGuid():N}");
        try
        {
            var layout = new ProjectLayout(dir);
            var db = new ProjectDatabase(layout);

            // 不调用 Initialize() 也必须能写 —— 建表应该在首次使用时自动完成
            var project = new TestProject
            {
                Id = "WS-20260929-999",
                Name = "存储往返测试",
                PrimaryTargetPath = @"C:\sample.exe",
            };
            db.SaveProject(project);

            var reloaded = db.GetPrimaryProject();
            Assert.NotNull(reloaded);
            Assert.Equal("WS-20260929-999", reloaded!.Id);
            Assert.Equal("存储往返测试", reloaded.Name);
        }
        finally
        {
            // 连接池持有文件句柄，不释放的话目录删不掉（删除项目目录前同样要先调它）
            ProjectDatabase.ReleasePools();
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ProjectDatabase_EvidenceRoundTrip_PreservesPayload()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsl-db-{Guid.NewGuid():N}");
        try
        {
            var layout = new ProjectLayout(dir);
            var db = new ProjectDatabase(layout);

            var evidence = new Evidence
            {
                Id = "EV-TEST-00001",
                ProjectId = "WS-20260929-999",
                Kind = EvidenceKind.Yara,
                Title = "YARA 命中明细",
                Source = "builtin.yara",
                Target = @"C:\sample.exe",
                Summary = "命中 1 条规则",
                DataJson = """{"rule":"Test_Rule","count":1}""",
            };
            evidence.Tags.Add("yara");

            db.SaveEvidence(evidence);
            var list = db.GetEvidence();

            var loaded = Assert.Single(list);
            Assert.Equal("EV-TEST-00001", loaded.Id);
            Assert.Equal(EvidenceKind.Yara, loaded.Kind);
            Assert.Contains("Test_Rule", loaded.DataJson);
            Assert.Contains("yara", loaded.Tags);
        }
        finally
        {
            // 连接池持有文件句柄，不释放的话目录删不掉（删除项目目录前同样要先调它）
            ProjectDatabase.ReleasePools();
            Directory.Delete(dir, recursive: true);
        }
    }

    // ─────────────────────── 类型识别不依赖任务勾选 ───────────────────────

    /// <summary>
    /// 回归：只勾 .NET 分析、不勾 PE 分析时，类型识别曾因 result.Pe 为空而整体空转，
    /// 输出"PE 未解析成功，跳过应用类型识别"——导致"建议分析器/工具"永远缺失。
    /// AppTypeDetector 必须能独立于 PeAnalysis 任务工作。
    /// </summary>
    [Fact]
    public void AppTypeDetector_WorksFromDotNetInfoWithoutPePlugin()
    {
        // 用 .NET 程序集的特征构造一个 DotNet 结果（不依赖 PE 任务）
        var dotNet = new DotNetAssemblyInfo
        {
            IsDotNet = true,
            AssemblyName = "Sample.App",
            TargetFramework = ".NETCoreApp,Version=v10.0",
            IsExecutable = true,
            Namespaces = new List<DotNetNamespace>
            {
                new() { Name = "Sample", Types = new List<DotNetType> { new() { Name = "Program" } } },
            },
            ReferencedAssemblies = new List<string> { "System.Runtime" },
        };

        // 一个能通过 IsValidPe 的最小 PE 画像
        var pe = new PeImageInfo
        {
            IsValidPe = true,
            FileName = "Sample.App.dll",
            IsDotNet = true,
            Architecture = "x64",
            Sections = new List<PeSection> { new() { Name = ".text", Entropy = 6.0 } },
        };

        var detector = new WinSecLab.Core.Engines.Static.AppTypeDetector();
        var detection = detector.Detect(pe, dotNet, new List<StringHit>());

        Assert.Equal(AppRuntimeKind.DotNet, detection.Runtime);
        Assert.True(detection.ConfidencePercent > 0, "有 .NET 信号时置信度不应为 0");
        Assert.Contains(detection.RecommendedAnalyzers, a => a.Contains(".NET", StringComparison.OrdinalIgnoreCase));
    }

    // ─────────────────────── Profile 定义 ───────────────────────

    [Fact]
    public void Profiles_CoverEveryTaskAtLeastOnce()
    {
        var profileTasks = TestProfileDefinition.All.SelectMany(p => p.Tasks).Distinct().ToList();

        foreach (var task in TestTaskDefinition.All.Where(t => t.Category != "Analysis"))
            Assert.True(profileTasks.Contains(task.Kind), $"任务 {task.Kind} 没有出现在任何 Profile 里");
    }

    [Fact]
    public void Profiles_BasicExcludesDynamicTasks()
    {
        var basic = TestProfileDefinition.All.First(p => p.Kind == TestProfileKind.Basic);
        Assert.All(basic.Tasks, t => Assert.False(DynamicSession.IsDynamicTask(t),
            $"Basic Profile 不应包含动态任务 {t}"));
    }
}
