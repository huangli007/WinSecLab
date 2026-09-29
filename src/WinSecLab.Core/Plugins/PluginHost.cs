using System.Reflection;
using WinSecLab.Core.Models;
using WinSecLab.Core.Plugins.Builtin;

namespace WinSecLab.Core.Plugins;

/// <summary>计划中的一步：某个插件为某个任务执行一次。</summary>
public sealed class PluginExecution
{
    public required IWinSecLabPlugin Plugin { get; init; }
    public required TestTaskKind Task { get; init; }
    public ToolRole Role { get; init; } = ToolRole.Additive;
    /// <summary>该步骤是否被某个替代型工具顶替（被顶替的内置插件不会执行，仅记录在案）。</summary>
    public bool Substituted { get; init; }
}

public sealed class AnalysisPlan
{
    public List<PluginExecution> Steps { get; } = new();
    /// <summary>编排说明：谁替代了谁、谁因缺失被跳过 —— 直接进报告，让结论来源可追溯。</summary>
    public List<string> Notes { get; } = new();
    public List<PluginStatus> Plugins { get; } = new();

    public IEnumerable<PluginExecution> For(TestTaskKind task) => Steps.Where(s => s.Task == task);
}

/// <summary>
/// §17 插件宿主。三个职责：
///  1. 注册与探测（内置插件 + 外部工具适配器 + 外部程序集插件）；
///  2. 按"替代型 / 补充型"角色编排执行计划，避免同一结论被两个引擎重复计数；
///  3. 维持启用状态与加载错误清单，让 UI 能如实展示"谁没跑、为什么没跑"。
/// </summary>
public sealed class PluginHost
{
    private readonly List<IWinSecLabPlugin> _plugins = new();
    private readonly Dictionary<string, bool> _enabled = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _loadErrors = new();
    private readonly object _sync = new();

    /// <summary>任务执行顺序：静态 → 运行期 → 网络 → 关联 → 深度分析。</summary>
    public static IReadOnlyList<TestTaskKind> ExecutionOrder { get; } = new[]
    {
        TestTaskKind.PeAnalysis,
        TestTaskKind.DependencyScan,
        TestTaskKind.DigitalSignature,
        TestTaskKind.EntropyScan,
        TestTaskKind.DotNetAnalysis,
        TestTaskKind.StringsScan,
        TestTaskKind.YaraScan,
        TestTaskKind.ProcessMonitor,
        TestTaskKind.FileMonitor,
        TestTaskKind.RegistryMonitor,
        TestTaskKind.NetworkCapture,
        TestTaskKind.HttpProxy,
        TestTaskKind.TlsAnalysis,
        TestTaskKind.ToolCorrelation,
        TestTaskKind.DeepAnalysis,
    };

    public PluginHost(bool includeExternalAdapters = true)
    {
        RegisterBuiltins();
        if (includeExternalAdapters) RegisterExternalAdapters();
    }

    public IReadOnlyList<IWinSecLabPlugin> Plugins
    {
        get { lock (_sync) return _plugins.ToList(); }
    }

    public IReadOnlyList<string> LoadErrors
    {
        get { lock (_sync) return _loadErrors.ToList(); }
    }

    public IWinSecLabPlugin? Get(string id)
    {
        lock (_sync) return _plugins.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
    }

    public void Register(IWinSecLabPlugin plugin)
    {
        lock (_sync)
        {
            if (_plugins.Any(p => string.Equals(p.Id, plugin.Id, StringComparison.OrdinalIgnoreCase)))
            {
                _loadErrors.Add($"插件 Id 冲突，已忽略后注册者：{plugin.Id}（{plugin.GetType().FullName}）");
                return;
            }
            _plugins.Add(plugin);
            _enabled.TryAdd(plugin.Id, true);
        }
    }

    // ─────────────────────────────── 注册 ───────────────────────────────

    private void RegisterBuiltins()
    {
        // 静态分析
        Register(new PeAnalysisPlugin());
        Register(new DependencyPlugin());
        Register(new SignaturePlugin());
        Register(new EntropyPlugin());
        Register(new DotNetPlugin());
        Register(new StringsPlugin());
        Register(new BuiltinYaraPlugin());
        // 运行期
        Register(new ProcessMonitorPlugin());
        Register(new FileMonitorPlugin());
        Register(new RegistryMonitorPlugin());
        // 网络
        Register(new NetworkCapturePlugin());
        Register(new HttpProxyPlugin());
        // 关联与图谱（编排器保证它在动态阶段之后执行）
        Register(new ToolCorrelationPlugin());
    }

    private void RegisterExternalAdapters()
    {
        Register(new YaraToolAdapter());
        Register(new WiresharkToolAdapter());
        Register(new ProcmonToolAdapter());
        Register(new DependenciesToolAdapter());
        Register(new SigcheckToolAdapter());
        Register(new StringsToolAdapter());
        Register(new IlSpyToolAdapter());
        Register(new GhidraToolAdapter());
        Register(new X64DbgToolAdapter());
        Register(new ProcExpToolAdapter());
    }

    /// <summary>
    /// 加载外部程序集插件。目录由调用方给出（默认 <c>工作区/plugins</c>）。
    /// 注意：外部插件以完全信任方式在进程内运行 —— 这是本机自用工具，不做沙箱，
    /// 但必须在 UI 上明确告知用户"外部插件等同本机代码"。
    /// </summary>
    public int LoadExternalPlugins(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return 0;

        var loaded = 0;
        List<string> dlls;
        try
        {
            dlls = Directory.EnumerateFiles(directory, "*.dll", SearchOption.TopDirectoryOnly).ToList();
        }
        catch (Exception ex)
        {
            lock (_sync) _loadErrors.Add($"{directory}: 无法枚举插件目录 —— {ex.Message}");
            return 0;
        }

        foreach (var dll in dlls)
        {
            // Core 自身的副本不要重复加载
            var name = Path.GetFileName(dll);
            if (name.StartsWith("WinSecLab.", StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                var assembly = Assembly.LoadFrom(dll);
                Type[] types;
                try { types = assembly.GetTypes(); }
                catch (ReflectionTypeLoadException ex)
                {
                    types = ex.Types.Where(t => t is not null).Cast<Type>().ToArray();
                    lock (_sync)
                    {
                        foreach (var le in ex.LoaderExceptions.Where(e => e is not null).Take(3))
                            _loadErrors.Add($"{name}: 部分类型加载失败 —— {le!.Message}");
                    }
                }

                foreach (var type in types)
                {
                    if (type.IsAbstract || type.IsInterface) continue;
                    if (!typeof(IWinSecLabPlugin).IsAssignableFrom(type)) continue;
                    if (type.GetConstructor(Type.EmptyTypes) is null)
                    {
                        lock (_sync) _loadErrors.Add($"{name}: {type.Name} 缺少无参构造函数，无法实例化。");
                        continue;
                    }

                    try
                    {
                        var instance = (IWinSecLabPlugin)Activator.CreateInstance(type)!;
                        var before = Plugins.Count;
                        Register(instance);
                        if (Plugins.Count > before) loaded++;
                    }
                    catch (Exception ex)
                    {
                        lock (_sync) _loadErrors.Add($"{name}: 实例化 {type.Name} 失败 —— {ex.Message}");
                    }
                }
            }
            catch (BadImageFormatException)
            {
                // 非托管 DLL（很多工具目录里都有），静默忽略即可
            }
            catch (Exception ex)
            {
                lock (_sync) _loadErrors.Add($"{name}: 加载失败 —— {ex.GetType().Name}: {ex.Message}");
            }
        }

        return loaded;
    }

    public bool IsEnabled(string pluginId)
    {
        lock (_sync) return !_enabled.TryGetValue(pluginId, out var v) || v;
    }

    public void SetEnabled(string pluginId, bool enabled)
    {
        lock (_sync) _enabled[pluginId] = enabled;
    }

    // ─────────────────────────────── 探测 ───────────────────────────────

    /// <summary>探测全部插件的可用性。外部工具会触发一次真实探测（带缓存）。</summary>
    public List<PluginStatus> ProbeAll(bool includeDisabled = true)
    {
        var snapshot = Plugins;
        var statuses = new PluginStatus[snapshot.Count];

        System.Threading.Tasks.Parallel.For(0, snapshot.Count, i =>
        {
            statuses[i] = Probe(snapshot[i], includeDisabled);
        });

        return statuses.Where(s => s is not null).ToList();
    }

    private PluginStatus Probe(IWinSecLabPlugin plugin, bool includeDisabled)
    {
        var enabled = IsEnabled(plugin.Id);
        PluginProbeResult probe;
        try
        {
            probe = plugin.Detect();
        }
        catch (Exception ex)
        {
            probe = PluginProbeResult.Missing($"探测异常：{ex.GetType().Name}: {ex.Message}");
        }

        string installHint = "";
        string author = "", homepage = "";
        if (plugin is ExternalToolAdapterBase adapter)
        {
            installHint = adapter.Descriptor.InstallHint;
            author = adapter.Descriptor.Author;
            homepage = adapter.Descriptor.Homepage;
        }

        return new PluginStatus
        {
            Id = plugin.Id,
            Name = plugin.Name,
            Version = probe.Version ?? plugin.Version,
            Kind = plugin.Kind,
            Description = plugin.Description,
            Author = string.IsNullOrEmpty(author) ? "WinSecLab" : author,
            Homepage = homepage,
            Available = probe.Available,
            AvailabilityText = probe.Available
                ? probe.Message
                : (enabled ? probe.Message : "已禁用（用户设置）"),
            ExecutablePath = probe.ExecutablePath,
            Capabilities = plugin.Capabilities.Select(c => c.ToString()).ToList(),
            MissingDependencies = probe.MissingDependencies,
            InstallHint = installHint,
            Enabled = enabled,
            LastChecked = DateTime.Now,
        };
    }

    // ─────────────────────────────── 编排 ───────────────────────────────

    /// <summary>
    /// 生成执行计划。
    /// 规则：同一任务下，若有可用且启用的"替代型"外部工具 → 内置插件让位（记入 Notes）；
    /// "补充型"外部工具与内置插件并行执行，用于交叉验证。
    /// </summary>
    public AnalysisPlan BuildPlan(IEnumerable<TestTaskKind> tasks, AnalysisOptions options)
    {
        var plan = new AnalysisPlan();
        var wanted = new HashSet<TestTaskKind>(tasks);

        plan.Plugins.AddRange(ProbeAll());
        var statusById = plan.Plugins.ToDictionary(p => p.Id, p => p, StringComparer.OrdinalIgnoreCase);

        bool Usable(IWinSecLabPlugin p) =>
            IsEnabled(p.Id) && (!statusById.TryGetValue(p.Id, out var st) || st.Available);

        foreach (var task in ExecutionOrder.Where(wanted.Contains))
        {
            var all = Plugins.Where(p => p.Capabilities.Contains(task)).ToList();
            if (all.Count == 0)
            {
                plan.Notes.Add($"{task}：没有插件声明支持该任务，已跳过。");
                continue;
            }

            var builtins = all.Where(p => p.Kind == PluginKind.Builtin).ToList();
            var externalPlugins = all.Where(p => p.Kind != PluginKind.Builtin).ToList();

            var substitutive = externalPlugins
                .Where(p => p is ExternalToolAdapterBase a && a.Descriptor.Role == ToolRole.Substitutive)
                .ToList();
            var additive = externalPlugins
                .Where(p => p is not ExternalToolAdapterBase a || a.Descriptor.Role == ToolRole.Additive)
                .ToList();

            var usableSubstitutive = options.PreferExternalTools ? substitutive.Where(Usable).ToList() : new List<IWinSecLabPlugin>();

            if (usableSubstitutive.Count > 0)
            {
                var chosen = usableSubstitutive[0];
                plan.Steps.Add(new PluginExecution { Plugin = chosen, Task = task, Role = ToolRole.Substitutive });

                foreach (var b in builtins)
                    plan.Notes.Add($"{task}：由「{chosen.Name}」替代「{b.Name}」（外部工具已就绪且为替代型，避免同一结论重复计数）。");

                foreach (var extra in usableSubstitutive.Skip(1))
                    plan.Notes.Add($"{task}：「{extra.Name}」同样可用，但本次只选一个替代引擎（已选 {chosen.Name}）。");
            }
            else
            {
                foreach (var b in builtins.Where(Usable))
                    plan.Steps.Add(new PluginExecution { Plugin = b, Task = task, Role = ToolRole.Additive });

                if (substitutive.Count > 0 && options.PreferExternalTools)
                {
                    foreach (var s in substitutive)
                    {
                        var why = IsEnabled(s.Id) ? "未检测到或不可用" : "已被用户禁用";
                        plan.Notes.Add($"{task}：替代型工具「{s.Name}」{why}，改用内置引擎「{string.Join("、", builtins.Select(b => b.Name))}」。");
                    }
                }
                else if (substitutive.Count > 0)
                {
                    plan.Notes.Add($"{task}：已按配置关闭外部工具，使用内置引擎。");
                }
            }

            // 补充型：默认附加（这是交叉验证的价值所在）；
            // 但用户关闭外部工具时一条都不排 —— "关掉外部工具"必须意味着整个链路只用内置引擎，
            // 否则设置形同虚设，还会在报告里冒出一堆"已跳过"的噪声。
            var additiveCandidates = options.PreferExternalTools ? additive : new List<IWinSecLabPlugin>();

            foreach (var a in additiveCandidates.Where(Usable))
                plan.Steps.Add(new PluginExecution { Plugin = a, Task = task, Role = ToolRole.Additive });

            if (!options.PreferExternalTools && additive.Count > 0)
            {
                plan.Notes.Add($"{task}：已按配置关闭外部工具，「{string.Join("、", additive.Select(a => a.Name))}」不参与本次分析。");
            }

            foreach (var a in additive.Where(p => !Usable(p)))
            {
                var why = !IsEnabled(a.Id) ? "已被用户禁用" : "未检测到，已跳过";
                plan.Notes.Add($"{task}：补充型工具「{a.Name}」{why}。");
            }
        }

        return plan;
    }
}
