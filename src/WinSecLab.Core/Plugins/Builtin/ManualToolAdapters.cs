using System.Text;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Plugins.Builtin;

// ═══════════════════════════════════════════════════════════════════════════
//  Ghidra —— 反编译工作流（平台只管理工程与脚本，不自行反编译，§7）
// ═══════════════════════════════════════════════════════════════════════════

/// <summary>
/// Ghidra 适配器。两种模式：
///  1. 默认：准备工程目录 + 导出脚本 + 一行启动命令，人工点开 Ghidra 就能直接在"已导入目标"的状态下开工；
///  2. 可选：<c>EnableGhidraHeadless</c> 打开后跑 analyzeHeadless 自动导入分析并导出函数清单。
/// 之所以默认不自动跑：Ghidra 对中大型二进制要几分钟到几十分钟，让它在每次分析里"顺手跑一下"是反模式。
/// </summary>
public sealed class GhidraToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "ghidra";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var dir = ToolDirectory(context, "ghidra");
        var projectDir = Path.Combine(dir, "project");
        var scriptDir = Path.Combine(dir, "scripts");
        Directory.CreateDirectory(projectDir);
        Directory.CreateDirectory(scriptDir);

        var log = new List<string>();
        var artifacts = new List<string>();
        var evidence = new List<Evidence>();

        // 1) 导出脚本 —— 只依赖 Ghidra 稳定 API，避免版本升级就崩
        var scriptPath = Path.Combine(scriptDir, "WinSecLabExport.java");
        try
        {
            File.WriteAllText(scriptPath, ExportScriptSource, new UTF8Encoding(false));
            artifacts.Add(scriptPath);
            log.Add($"已写入 Ghidra 导出脚本：{scriptPath}");
        }
        catch (Exception ex)
        {
            return PluginRunResult.Fail($"写入 Ghidra 脚本失败：{ex.Message}");
        }

        var target = context.TargetPath;
        var projectName = "WinSecLab_" + context.Project.Id.Replace(':', '_').Replace('/', '_');
        var exportCsv = Path.Combine(dir, "functions.csv");

        // 2) 启动脚本：人工双击即可在已导入状态下打开 Ghidra
        var headless = Path.Combine(Path.GetDirectoryName(location.ExecutablePath!) ?? "", "analyzeHeadless.bat");
        var guiBat = Path.Combine(dir, "open-in-ghidra.cmd");
        var guiLines = new List<string>
        {
            "@echo off",
            "rem WinSecLab 生成的 Ghidra 工作流入口 —— 双击即可在已导入目标的状态下打开",
            $"rem 目标：{target}",
            $"cd /d \"{Path.GetDirectoryName(location.ExecutablePath!)}\"",
            $"call analyzeHeadless.bat \"{projectDir}\" {projectName} -import \"{target}\" -noanalysis",
            $"start \"\" \"{Path.Combine(Path.GetDirectoryName(location.ExecutablePath!) ?? "", "ghidraRun.bat")}\"",
            "echo.",
            "echo Ghidra 已启动。工程目录与目标已就绪，后续在 GUI 中人工完成反编译与函数标注。",
            "pause",
        };
        var guiScript = ToolArtifact.WriteText(dir, "open-in-ghidra.cmd", string.Join("\r\n", guiLines));
        if (guiScript is not null) artifacts.Add(guiScript);

        // 3) 可选的 headless 分析
        var ranHeadless = false;
        List<GhidraFunction> functions = new();

        if (context.Options.EnableGhidraHeadless && File.Exists(headless))
        {
            ranHeadless = true;
            var timeoutSec = Math.Max(60, context.Options.GhidraAnalysisSeconds);
            context.Progress(0.3, $"Ghidra headless 分析中（上限 {timeoutSec}s）");

            var run = await ProcessRunner.RunAsync(headless,
                $"\"{projectDir}\" {projectName} -import {ProcessRunner.Quote(target)} "
                + $"-scriptPath {ProcessRunner.Quote(scriptDir)} -postScript WinSecLabExport.java {ProcessRunner.Quote(exportCsv)} "
                + $"-analysisTimeoutPerFile {timeoutSec} -deleteProject",
                dir, timeoutMs: (timeoutSec + 120) * 1000, cancellationToken: context.CancellationToken, log: log.Add)
                .ConfigureAwait(false);

            var rawFile = ToolArtifact.WriteText(dir, "ghidra-headless.log", run.Combined);
            if (rawFile is not null) artifacts.Add(rawFile);

            if (File.Exists(exportCsv))
            {
                functions = ParseFunctionCsv(exportCsv);
                artifacts.Add(exportCsv);
            }

            evidence.Add(ToolEvidence(context, "ghidra", "Ghidra headless 分析结果",
                run.TimedOut
                    ? $"分析超过 {timeoutSec}s 被终止；已导出 {functions.Count} 个函数（不完整）。建议改用人工工作流继续。"
                    : $"分析完成，导出 {functions.Count} 个函数（退出码 {run.ExitCode}）。",
                new
                {
                    headless = true,
                    functionCount = functions.Count,
                    timedOut = run.TimedOut,
                    exitCode = run.ExitCode,
                    durationSeconds = Math.Round(run.Duration.TotalSeconds, 1),
                    exportCsv = File.Exists(exportCsv) ? exportCsv : null,
                    analysisTimeoutSeconds = timeoutSec,
                },
                "ghidra", "decompiler", "analysis"));
        }
        else if (context.Options.EnableGhidraHeadless && !File.Exists(headless))
        {
            evidence.Add(ToolEvidence(context, "ghidra", "Ghidra headless 不可用",
                $"已启用 headless 分析但未找到 analyzeHeadless.bat（期望位于 {Path.GetDirectoryName(location.ExecutablePath!)}），请确认 Ghidra 发行版完整解压。",
                new { expected = headless }, "ghidra", "warning"));
        }

        if (functions.Count > 0)
        {
            var suspiciousCandidates = functions
                .Where(f => f.Name.Contains("crypt", StringComparison.OrdinalIgnoreCase)
                         || f.Name.Contains("decrypt", StringComparison.OrdinalIgnoreCase)
                         || f.Name.Contains("inject", StringComparison.OrdinalIgnoreCase)
                         || f.Name.Contains("shell", StringComparison.OrdinalIgnoreCase)
                         || f.Name.Contains("hook", StringComparison.OrdinalIgnoreCase)
                         || f.Name.StartsWith("FUN_", StringComparison.Ordinal) && f.Size > 2000)
                .OrderByDescending(f => f.Size)
                .Take(80)
                .ToList();

            evidence.Add(ToolEvidence(context, "ghidra", "Ghidra 函数清单（人工分析入口）",
                $"共 {functions.Count} 个函数，其中 {functions.Count(f => f.Name.StartsWith("FUN_", StringComparison.Ordinal))} 个未命名（可能是刻意剥离符号）；"
                + $"挑出 {suspiciousCandidates.Count} 个建议优先看的函数（名称含敏感语义或体量偏大）",
                new
                {
                    totalFunctions = functions.Count,
                    unnamedFunctions = functions.Count(f => f.Name.StartsWith("FUN_", StringComparison.Ordinal)),
                    thunkFunctions = functions.Count(f => f.IsThunk),
                    externalFunctions = functions.Count(f => f.IsExternal),
                    priorityTargets = suspiciousCandidates,
                },
                "ghidra", "functions", "manual-analysis"));
        }

        // 4) 人工工作流的说明证据（无论是否跑 headless 都要给）
        var steps = new List<string>
        {
            $"[1] 双击 {guiScript ?? guiBat} 打开 Ghidra（工程 {projectName} 已导入目标）。",
            "[2] 对函数做批量分析：Analysis → Auto Analyze，关注 Crypto、File I/O、Network 类别。",
            "[3] 交叉核对：把本平台已识别的关注点（字符串命中、YARA 命中、导入表敏感 API）在 Ghidra 中定位到具体调用点。",
            "[4] 若需重新自动导出函数清单，勾选设置中的「启用 Ghidra headless 分析」后重跑本任务。",
        };

        evidence.Add(ToolEvidence(context, "ghidra", "Ghidra 工作流已就绪",
            $"工程目录：{projectDir}；导出脚本：{scriptPath}；启动脚本：{guiScript ?? guiBat}",
            new
            {
                projectDirectory = projectDir,
                projectName,
                scriptPath,
                launchScript = guiScript ?? guiBat,
                exportCsv = File.Exists(exportCsv) ? exportCsv : null,
                ranHeadless,
                steps,
                enginePath = location.ExecutablePath,
            },
            "ghidra", "workflow", "manual-analysis"));

        var result = PluginRunResult.Ok(
            ranHeadless
                ? $"Ghidra 工作流完成：headless 导出 {functions.Count} 个函数"
                : $"Ghidra 工作流已准备就绪（未自动分析，建议人工在 GUI 中深入；工程与脚本已生成）",
            evidence, null, artifacts);
        foreach (var l in log) result.Log.Add(l);
        return result;
    }

    internal sealed class GhidraFunction
    {
        public string Name { get; set; } = "";
        public string Entry { get; set; } = "";
        public long Size { get; set; }
        public bool IsThunk { get; set; }
        public bool IsExternal { get; set; }
    }

    internal static List<GhidraFunction> ParseFunctionCsv(string csvPath)
    {
        var list = new List<GhidraFunction>();
        try
        {
            foreach (var line in File.ReadLines(csvPath).Skip(1))
            {
                if (line.Length == 0) continue;
                var f = ProcmonCsvParser.SplitCsvLine(line);
                if (f.Count < 4) continue;
                list.Add(new GhidraFunction
                {
                    Name = f[0].Trim(),
                    Entry = f[1].Trim(),
                    Size = long.TryParse(f[2].Trim(), out var s) ? s : 0,
                    IsThunk = f.Count > 3 && bool.TryParse(f[3].Trim(), out var t) && t,
                    IsExternal = f.Count > 4 && bool.TryParse(f[4].Trim(), out var e) && e,
                });
            }
        }
        catch { }
        return list;
    }

    /// <summary>
    /// Ghidra Java 脚本源码。刻意只用 FunctionManager / Function 这类长期稳定的 API，
    /// 不碰反编译器内部类 —— 升级 Ghidra 不该让导出脚本失效。
    /// </summary>
    private const string ExportScriptSource = """
// WinSecLabExport.java —— 由 WinSecLab 自动生成，导出函数清单为 CSV。
// 用法（headless）：analyzeHeadless <projDir> <projName> -import <target> -postScript WinSecLabExport.java <outCsv>
// 用法（GUI）：Script Manager 中运行本脚本，参数填输出 CSV 路径。
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class WinSecLabExport extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("WinSecLabExport: 缺少输出文件路径参数。");
            return;
        }

        PrintWriter w = new PrintWriter(new FileWriter(args[0]));
        w.println("name,entry,size,thunk,external,bodySize");

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (it.hasNext()) {
            Function f = it.next();
            long entry = f.getEntryPoint() == null ? 0L : f.getEntryPoint().getOffset();
            long body = f.getBody() == null ? 0L : f.getBody().getNumAddresses();
            w.println(escape(f.getName()) + "," +
                      Long.toHexString(entry) + "," +
                      f.getBody().getNumAddresses() + "," +
                      f.isThunk() + "," +
                      f.isExternal() + "," +
                      body);
            count++;
            if (count % 2000 == 0) {
                println("WinSecLabExport: 已导出 " + count + " 个函数");
            }
        }
        w.close();
        println("WinSecLabExport: 完成，共 " + count + " 个函数 -> " + args[0]);
    }

    private String escape(String s) {
        if (s == null) {
            return "";
        }
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }
}
""";
}

// ═══════════════════════════════════════════════════════════════════════════
//  x64dbg —— 动态调试工作流
// ═══════════════════════════════════════════════════════════════════════════

/// <summary>
/// x64dbg 适配器。不做自动调试（那是"另一个产品"），只把开工需要的东西全部准备好：
/// 启动脚本、带断点建议的工作清单、以及本平台已识别的关注点作为调试目标。
/// </summary>
public sealed class X64DbgToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "x64dbg";

    protected override Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var dir = ToolDirectory(context, "x64dbg");
        var exe = location.ExecutablePath!;
        var is64 = Path.GetFileName(exe).StartsWith("x64", StringComparison.OrdinalIgnoreCase);

        var evidence = new List<Evidence>();
        var artifacts = new List<string>();
        var isDotNet = context.Result.DotNet is not null || (context.Result.Pe?.IsDotNet ?? false);

        // 1) 启动脚本
        var bat = new List<string>
        {
            "@echo off",
            "rem WinSecLab 生成的 x64dbg 调试入口",
            $"rem 目标：{context.TargetPath}",
            $"rem 平台识别架构：{(context.Result.Pe is null ? "未知（PE 未解析）" : context.Result.Pe.Architecture)}",
            $"start \"\" \"{exe}\" \"{context.TargetPath}\"",
            "echo x64dbg 已启动。断点建议见同目录 breakpoints.md。",
        };
        var batPath = ToolArtifact.WriteText(dir, "debug-target.cmd", string.Join("\r\n", bat));
        if (batPath is not null) artifacts.Add(batPath);

        // 2) 断点建议：从已采集事实推导，而不是泛泛的"下个断点看看"
        var breakpoints = new List<string>();
        if (isDotNet)
        {
            breakpoints.Add("托管程序集：先看 `clr.dll` 的 `JIT` 相关导出，或在 ILSpy 中定位可疑 IL 后再回来下断点。");
            breakpoints.Add("若已被 NativeAOT 编译，托管断点无效，改按原生二进制方式分析。");
        }

        var imports = context.Result.Pe?.Imports ?? new List<PeImportModule>();
        var sensitive = new[] { "CreateProcess", "ShellExecute", "WinExec", "LoadLibrary", "GetProcAddress",
                                "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
                                "SetWindowsHookEx", "RegSetValue", "CryptEncrypt", "InternetOpen", "WinHttpOpen",
                                "WSASocket", "send", "recv" };
        var hitImports = imports
            .SelectMany(m => m.Functions.Select(f => (ModuleName: m.ModuleName, Function: f.Name)))
            .Where(x => sensitive.Any(s => x.Function.Contains(s, StringComparison.OrdinalIgnoreCase)))
            .Select(x => $"{x.ModuleName}!{x.Function}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();

        if (hitImports.Count > 0)
        {
            breakpoints.Add($"建议在这些导入函数上下条件断点（命中时检查调用栈与参数）：{string.Join("、", hitImports.Take(12))}");
        }

        var suspiciousStrings = context.Result.Strings
            .Where(s => s.Category is "Url" or "Domain" or "Path" or "Command" or "Credential" or "Registry")
            .Select(s => s.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToList();
        if (suspiciousStrings.Count > 0)
        {
            breakpoints.Add($"可用这些字符串做内存搜索定位关键代码路径：{string.Join("、", suspiciousStrings.Take(8))}");
        }

        if (breakpoints.Count == 0)
            breakpoints.Add("尚未采集到足够的静态事实。建议先完成 PE 分析与字符串扫描，再回来下断点。");

        var bpMd = new StringBuilder();
        bpMd.AppendLine($"# x64dbg 调试建议 — {Path.GetFileName(context.TargetPath)}");
        bpMd.AppendLine();
        bpMd.AppendLine($"- 目标：`{context.TargetPath}`");
        bpMd.AppendLine($"- 调试器：{exe}（{(is64 ? "64 位" : "32 位")}）");
        bpMd.AppendLine($"- 架构（平台识别）：{context.Result.Pe?.Architecture ?? "未知"}");
        bpMd.AppendLine();
        bpMd.AppendLine("## 建议关注点");
        foreach (var b in breakpoints) bpMd.AppendLine($"- {b}");

        var bpPath = ToolArtifact.WriteText(dir, "breakpoints.md", bpMd.ToString());
        if (bpPath is not null) artifacts.Add(bpPath);

        evidence.Add(ToolEvidence(context, "x64dbg", "x64dbg 调试工作流已就绪",
            $"启动脚本：{batPath}；断点建议：{bpPath}（{breakpoints.Count} 条）",
            new
            {
                debugger = exe,
                is64BitDebugger = is64,
                launchScript = batPath,
                breakpointsFile = bpPath,
                breakpoints,
                suggestedImportBreakpoints = hitImports,
                suggestedStrings = suspiciousStrings,
            },
            "x64dbg", "workflow", "manual-analysis"));

        var run = PluginRunResult.Ok(
            $"x64dbg 工作流已准备：启动脚本 + {breakpoints.Count} 条断点建议（调试会话由人工进行）",
            evidence, null, artifacts);
        return Task.FromResult(run);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Process Explorer —— 运行期人工核对
// ═══════════════════════════════════════════════════════════════════════════

/// <summary>
/// Process Explorer 适配器。定位是「人工核对的旁证」：
/// 把本次会话观测到的 PID / 进程树 / 打开的文件句柄线索整理成核对清单，
/// 让分析员在 GUI 里几分钟内确认平台结论，而不是从零开始找进程。
/// </summary>
public sealed class ProcExpToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "procexp";

    protected override Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var dir = ToolDirectory(context, "procexp");
        var evidence = new List<Evidence>();
        var artifacts = new List<string>();

        var tree = context.Result.ProcessTree;
        var processes = context.Result.Events
            .Where(e => e.Type is MonitorEventType.ProcessStart or MonitorEventType.ChildProcess)
            .Select(e => new { e.ProcessId, e.ProcessName, e.ProcessPath })
            .Distinct()
            .Take(60)
            .ToList();

        var checklist = new List<string>();
        if (tree.Count > 0)
        {
            checklist.Add($"[1] 打开 Process Explorer，按 Ctrl+F 搜索目标进程 `{Path.GetFileName(context.TargetPath)}`，"
                          + $"确认其 PID 与平台的进程树一致（平台记录 {tree.Count} 个节点）。");
        }
        else
        {
            checklist.Add("[1] 本次没有动态会话记录，无法核对运行期状态。请先执行一次动态测试。");
        }

        if (processes.Count > 0)
        {
            checklist.Add($"[2] 逐个核对子进程（共 {processes.Count} 个）：选中进程 → View → Properties → Image 页签看完整路径与签名。");
            checklist.Add("[3] 对可疑子进程右键 → Check VirusTotal，快速确认是否为已知样本。");
        }

        checklist.Add("[4] 选中目标进程 → View → Lower Pane → Handles，按 Type 过滤 File / Key / Event，"
                      + "与平台的「进程打开的可疑文件/注册表」证据交叉验证。");
        checklist.Add("[5] View → Select Columns → Process Network，确认没有平台未捕获的出站连接。");

        var md = new StringBuilder();
        md.AppendLine($"# Process Explorer 人工核对清单 — {Path.GetFileName(context.TargetPath)}");
        md.AppendLine();
        md.AppendLine($"- 工具路径：`{location.ExecutablePath}`");
        md.AppendLine($"- 进程树节点数：{tree.Count}");
        md.AppendLine($"- 本会话进程事件：{processes.Count} 个");
        md.AppendLine();
        md.AppendLine("## 核对步骤");
        foreach (var c in checklist) md.AppendLine($"- {c}");

        if (processes.Count > 0)
        {
            md.AppendLine();
            md.AppendLine("## 需要核对的进程");
            md.AppendLine("| PID | 进程名 | 路径 |");
            md.AppendLine("|---|---|---|");
            foreach (var p in processes)
                md.AppendLine($"| {p.ProcessId} | {p.ProcessName} | {p.ProcessPath ?? "-"} |");
        }

        var mdPath = ToolArtifact.WriteText(dir, "verification-checklist.md", md.ToString());
        if (mdPath is not null) artifacts.Add(mdPath);

        evidence.Add(ToolEvidence(context, "procexp", "Process Explorer 核对清单",
            $"已生成 {checklist.Count} 步核对清单，覆盖 {processes.Count} 个进程 / 进程树 {tree.Count} 节点",
            new
            {
                toolPath = location.ExecutablePath,
                checklistFile = mdPath,
                processCount = processes.Count,
                processTreeNodes = tree.Count,
                checklist,
                processes,
            },
            "procexp", "manual-analysis", "verification"));

        var run = PluginRunResult.Ok(
            $"Process Explorer 核对清单已生成（{checklist.Count} 步，{processes.Count} 个进程）", evidence, null, artifacts);
        return Task.FromResult(run);
    }
}
