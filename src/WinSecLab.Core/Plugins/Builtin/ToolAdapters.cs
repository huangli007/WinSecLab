using System.Globalization;
using System.Text;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Plugins.Builtin;

/// <summary>把外部工具的原始输出落盘留档，返回产物路径。任何异常都不影响主流程。</summary>
internal static class ToolArtifact
{
    public static string? WriteText(string directory, string fileName, string content)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, fileName);
            File.WriteAllText(path, content, new UTF8Encoding(false));
            return path;
        }
        catch
        {
            return null;
        }
    }

    public static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Process Monitor —— 全系统文件/注册表/进程采集
// ═══════════════════════════════════════════════════════════════════════════

/// <summary>
/// Procmon 适配器。用它补内置监控的两个短板：
///  1. 内置 FileSystemWatcher 拿不到"是谁写的"（无 PID），Procmon 有；
///  2. 内置注册表监控靠 WMI 触发 + 快照差分，Procmon 能给出逐次操作与结果码。
/// 代价是需要管理员，且捕获的是全系统事件，因此要按目标目录/进程名做相关性过滤。
/// </summary>
public sealed class ProcmonToolAdapter : ExternalToolAdapterBase
{
    protected override string ToolId => "procmon";

    protected override async Task<PluginRunResult> RunAsync(PluginContext context, ToolLocation location)
    {
        var seconds = context.Options.ProcmonCaptureSeconds;
        if (seconds <= 0)
            return PluginRunResult.Skipped("Process Monitor 采集时长配置为 0（表示不启用），已跳过。");

        var exe = location.ExecutablePath!;
        var dir = ToolDirectory(context, "procmon");
        var pml = Path.Combine(dir, "capture.pml");
        var csv = Path.Combine(dir, "capture.csv");
        ToolArtifact.TryDelete(pml);
        ToolArtifact.TryDelete(csv);

        var log = new List<string> { $"Process Monitor：{exe}（{location.Source}）", $"计划采集 {seconds} 秒" };

        // 1) 后台启动采集（Procmon 不会自己退出，所以不能 await）
        var started = ProcessRunner.StartDetached(exe, $"/AcceptEula /Quiet /Minimized /BackingFile {ProcessRunner.Quote(pml)}",
            dir, log.Add);
        if (started is null)
            return PluginRunResult.Fail("Process Monitor 启动失败，请确认已接受 EULA 且当前账户具备管理员权限。");

        try
        {
            // 2) 等待采集窗口，期间响应取消
            for (var elapsed = 0; elapsed < seconds * 10; elapsed++)
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                context.Progress((double)elapsed / (seconds * 10), $"Process Monitor 采集中（{elapsed / 10.0:F0}/{seconds}s）");
                await Task.Delay(100, context.CancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            await StopCapture(exe, log).ConfigureAwait(false);
            throw;
        }

        // 3) 正常停止 —— 让 Procmon 把缓冲写盘，不能强杀
        await StopCapture(exe, log).ConfigureAwait(false);

        if (!File.Exists(pml))
            return PluginRunResult.Fail("Process Monitor 未生成 .pml 捕获文件，可能被安全软件拦截或缺少管理员权限。");

        // 4) 转 CSV
        context.Progress(0.85, "导出 Process Monitor 日志");
        var export = await ProcessRunner.RunAsync(exe, $"/OpenLog {ProcessRunner.Quote(pml)} /SaveAs {ProcessRunner.Quote(csv)}",
            dir, timeoutMs: 300_000, cancellationToken: context.CancellationToken, log: log.Add).ConfigureAwait(false);

        if (!File.Exists(csv))
        {
            return PluginRunResult.Fail(
                $"Process Monitor 日志导出失败（退出码 {export.ExitCode}）：{FirstLines(export.StdErr, 3)}");
        }

        // 5) 解析 + 相关性过滤
        context.Progress(0.92, "解析 Process Monitor 事件");
        var events = await Task.Run(() => ProcmonCsvParser.Parse(csv, context, log), context.CancellationToken)
            .ConfigureAwait(false);

        var artifacts = new List<string> { pml, csv };
        var rawOut = ToolArtifact.WriteText(dir, "capture-rawoutput.txt", export.Combined);
        if (rawOut is not null) artifacts.Add(rawOut);

        if (events.Count == 0)
        {
            return PluginRunResult.Ok(
                $"Process Monitor 采集完成（{seconds}s），共 {FileSizeText(csv)}，但没有匹配到与目标相关的操作。",
                new List<Evidence>
                {
                    ToolEvidence(context, "procmon", "Process Monitor 采集（无相关命中）",
                        $"全系统采集 {seconds} 秒，未发现与目标进程/目录相关的文件或注册表操作；"
                        + "说明目标在此期间没有触达这些资源，或目标未运行。",
                        new { seconds, pml, csv, artifacts }, "procmon", "dynamic"),
                }, null, artifacts);
        }

        context.Result.Events.AddRange(events);
        context.Database.SaveEvents(events);

        var fileEvents = events.Where(e => e.Type is MonitorEventType.FileCreate or MonitorEventType.FileWrite
            or MonitorEventType.FileDelete or MonitorEventType.FileRename).ToList();
        var regEvents = events.Where(e => e.Type is MonitorEventType.RegistryCreate or MonitorEventType.RegistrySet
            or MonitorEventType.RegistryDelete).ToList();
        var denied = events.Where(e => e.Result.Contains("DENIED", StringComparison.OrdinalIgnoreCase)
            || e.Result.Contains("ACCESS", StringComparison.OrdinalIgnoreCase)).ToList();

        var evidence = new List<Evidence>
        {
            ToolEvidence(context, "procmon", "Process Monitor 事件汇总",
                $"采集 {seconds}s：文件操作 {fileEvents.Count} 条、注册表操作 {regEvents.Count} 条、被拒绝的操作 {denied.Count} 条（PID 级归因）",
                new
                {
                    seconds,
                    totalEvents = events.Count,
                    fileEventCount = fileEvents.Count,
                    registryEventCount = regEvents.Count,
                    deniedCount = denied.Count,
                    captureFile = pml,
                    csvFile = csv,
                    enginePath = location.ExecutablePath,
                },
                "procmon", "dynamic"),
        };

        if (fileEvents.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "procmon", "Process Monitor 文件操作明细",
                string.Join("；", fileEvents.Take(10).Select(e => $"{e.ProcessName}({e.ProcessId}) {e.Operation} → {e.Target}")),
                fileEvents.Take(3000).ToList(), "procmon", "filesystem"));
        }

        if (regEvents.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "procmon", "Process Monitor 注册表操作明细",
                string.Join("；", regEvents.Take(10).Select(e => $"{e.ProcessName}({e.ProcessId}) {e.Operation} → {e.Target}")),
                regEvents.Take(3000).ToList(), "procmon", "registry"));
        }

        // 被拒绝的写操作是很有价值的信号：说明程序尝试越权访问
        if (denied.Count > 0)
        {
            evidence.Add(ToolEvidence(context, "procmon", "被系统拒绝的操作",
                $"共 {denied.Count} 条被拒绝（ACCESS DENIED），可能反映权限不足导致的异常降级行为",
                denied.Take(500).ToList(), "procmon", "denied", "permission"));
        }

        return PluginRunResult.Ok(
            $"Process Monitor 采集完成：{events.Count} 条相关事件（文件 {fileEvents.Count} / 注册表 {regEvents.Count}）",
            evidence, null, artifacts);
    }

    private static async Task StopCapture(string exe, List<string> log)
    {
        try
        {
            // /Terminate 会立即退出，因此这里可以正常 await
            await ProcessRunner.RunAsync(exe, "/Terminate", null, 30_000, CancellationToken.None, log.Add)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log.Add($"[停止采集时出错] {ex.Message}");
        }
    }

    private static string FirstLines(string text, int count) =>
        string.Join(" / ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim()).Where(l => l.Length > 0).Take(count));

    private static string FileSizeText(string path)
    {
        try
        {
            var len = new FileInfo(path).Length;
            return len < 1024 * 1024 ? $"{len / 1024.0:F0} KB" : $"{len / 1024.0 / 1024.0:F1} MB";
        }
        catch { return "未知大小"; }
    }
}

/// <summary>
/// Process Monitor CSV 解析。
/// Procmon 的 CSV 有几处坑：字段可能带引号且内含逗号、路径用 &lt; 分隔（"a &gt; b" 表示重命名）、
/// Detail 列在非注册表操作下是人读文本而非结构化数据。这里只做保守提取，宁可少判也不误判。
/// </summary>
internal static class ProcmonCsvParser
{
    public static List<MonitorEvent> Parse(string csvPath, PluginContext context, List<string> log)
    {
        var events = new List<MonitorEvent>();
        var targetName = SafeFileName(context.TargetPath);
        var targetDir = Path.GetDirectoryName(context.TargetPath) ?? "";
        var sessionId = context.Session?.SessionId ?? "procmon-" + DateTime.Now.ToString("HHmmss");

        long seq = 0;
        var total = 0;
        var skipped = 0;

        try
        {
            using var reader = new StreamReader(csvPath, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var header = reader.ReadLine();
            if (header is null) return events;

            var columns = SplitCsvLine(header);
            var idxTime = IndexOf(columns, "Time of Day");
            var idxProcess = IndexOf(columns, "Process Name");
            var idxPid = IndexOf(columns, "PID");
            var idxOperation = IndexOf(columns, "Operation");
            var idxPath = IndexOf(columns, "Path");
            var idxResult = IndexOf(columns, "Result");
            var idxDetail = IndexOf(columns, "Detail");

            if (idxOperation < 0 || idxPath < 0)
            {
                log.Add("[解析] CSV 表头不符合预期，已放弃解析（文件仍保留在 Artifacts 下可人工查看）。");
                return events;
            }

            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                total++;
                if (line.Length == 0) continue;

                var f = SplitCsvLine(line);
                if (f.Count <= Math.Max(idxOperation, idxPath)) { skipped++; continue; }

                var operation = f[idxOperation];
                var path = f[idxPath];
                if (operation.Length == 0 || path.Length == 0) { skipped++; continue; }

                var type = MapOperation(operation);
                if (type is null) continue;

                var processName = idxProcess >= 0 && f.Count > idxProcess ? f[idxProcess] : "";
                var pidText = idxPid >= 0 && f.Count > idxPid ? f[idxPid] : "";
                var result = idxResult >= 0 && f.Count > idxResult && f[idxResult].Length > 0 ? f[idxResult] : "SUCCESS";
                var detail = idxDetail >= 0 && f.Count > idxDetail ? f[idxDetail] : null;

                // 相关性：目标进程本身、或目标目录下的文件路径变化
                var related = (targetName.Length > 0 && processName.Contains(targetName, StringComparison.OrdinalIgnoreCase))
                              || (targetDir.Length > 0 && path.Contains(targetDir, StringComparison.OrdinalIgnoreCase));

                // 只保留相关事件 —— 全系统事件量太大，全存会让报告和 UI 失去焦点
                if (!related) continue;

                uint.TryParse(pidText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid);
                var normalizedPath = NormalizePath(path);

                events.Add(new MonitorEvent
                {
                    Sequence = ++seq,
                    ProjectId = context.Project.Id,
                    SessionId = sessionId,
                    Timestamp = ParseTime(idxTime >= 0 && f.Count > idxTime ? f[idxTime] : "") ?? DateTime.Now,
                    Type = type.Value,
                    ProcessId = pid,
                    ProcessName = processName,
                    Operation = operation,
                    Target = normalizedPath,
                    Detail = detail,
                    Result = result,
                    IsFromTargetTree = targetName.Length > 0 && processName.Contains(targetName, StringComparison.OrdinalIgnoreCase),
                    IsSuspicious = IsSuspicious(type.Value, normalizedPath),
                    SuspicionReason = IsSuspicious(type.Value, normalizedPath)
                        ? "Procmon 记录到该路径的可疑变更（可执行文件落地 / 用户可写目录 / 自启动位置）"
                        : null,
                    Source = "procmon",
                });
            }
        }
        catch (Exception ex)
        {
            log.Add($"[解析] Procmon CSV 解析中断：{ex.Message}");
        }

        log.Add($"[解析] Procmon 共 {total} 行，保留相关事件 {events.Count} 条，跳过 {skipped} 行");
        return events;
    }

    /// <summary>Procmon 的 "Path" 列在重命名场景下是 "旧路径 &gt; 新路径"，取目标侧。</summary>
    private static string NormalizePath(string path)
    {
        var idx = path.LastIndexOf('>');
        if (idx > 0 && idx + 1 < path.Length) return path[(idx + 1)..].Trim();
        return path.Trim();
    }

    private static MonitorEventType? MapOperation(string operation)
    {
        var op = operation.ToLowerInvariant();

        if (op.StartsWith("reg"))
        {
            if (op.Contains("setvalue")) return MonitorEventType.RegistrySet;
            if (op.Contains("createkey")) return MonitorEventType.RegistryCreate;
            if (op.Contains("deletevalue") || op.Contains("deletekey")) return MonitorEventType.RegistryDelete;
            return null; // RegQuery* / RegOpenKey 量太大且无变更语义，不纳入
        }
        if (op.StartsWith("process"))
        {
            if (op.Contains("create")) return MonitorEventType.ProcessStart;
            if (op.Contains("exit")) return MonitorEventType.ProcessStop;
            return null;
        }
        if (op.StartsWith("load image")) return MonitorEventType.DllLoad;
        if (op.StartsWith("createfile"))
            return operation.Contains("OpenReparsePoint", StringComparison.OrdinalIgnoreCase)
                ? MonitorEventType.FileAccess : MonitorEventType.FileCreate;
        if (op.StartsWith("writefile")) return MonitorEventType.FileWrite;
        if (op.StartsWith("setendoffileinformation") || op.StartsWith("setallocationinformation")) return MonitorEventType.FileWrite;
        if (op.StartsWith("setrenameinformation")) return MonitorEventType.FileRename;
        if (op.StartsWith("setdispositioninformation")) return MonitorEventType.FileDelete;
        if (op.StartsWith("querydirectory") || op.StartsWith("queryinformation")) return null;
        if (op.StartsWith("tcp") || op.StartsWith("udp"))
        {
            if (op.Contains("connect")) return MonitorEventType.NetworkConnect;
            if (op.Contains("disconnect")) return MonitorEventType.NetworkClose;
            return null;
        }

        return null;
    }

    private static bool IsSuspicious(MonitorEventType type, string path)
    {
        if (type is not (MonitorEventType.FileCreate or MonitorEventType.FileWrite or MonitorEventType.FileRename
            or MonitorEventType.DllLoad)) return false;

        var ext = Path.GetExtension(path);
        var executable = ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".bat", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase);

        if (!executable) return false;
        return PathSemantics.IsUserWritable(path) || path.Contains("Startup", StringComparison.OrdinalIgnoreCase);
    }

    private static DateTime? ParseTime(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var formats = new[] { "HH:mm:ss.ffffff", "HH:mm:ss.fff", "HH:mm:ss", @"h:mm:ss.ffffff tt", @"h:mm:ss tt" };
        if (DateTime.TryParseExact(text.Trim(), formats, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var t))
        {
            // Procmon 只给时分秒，补上今天的日期
            return DateTime.Today.Add(t.TimeOfDay);
        }
        return null;
    }

    private static int IndexOf(List<string> columns, string name)
    {
        for (var i = 0; i < columns.Count; i++)
            if (string.Equals(columns[i].Trim(), name, StringComparison.OrdinalIgnoreCase)) return i;
        return -1;
    }

    /// <summary>最小 RFC4180 拆分：支持双引号包裹与 "" 转义。</summary>
    internal static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQuotes = false;
                }
                else sb.Append(c);
            }
            else
            {
                if (c == '"') inQuotes = true;
                else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
                else sb.Append(c);
            }
        }
        fields.Add(sb.ToString());
        return fields;
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path) ?? ""; } catch { return ""; }
    }
}
