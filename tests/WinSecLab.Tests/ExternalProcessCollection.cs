namespace WinSecLab.Tests;

/// <summary>
/// 会启动**外部进程**的测试集合（Edge 无头打印、外部工具探测等）。
///
/// 为什么归入串行集合：xUnit 默认并行执行不同测试类。多个测试类各自启动 Edge / 外部工具时，
/// 会互相争抢 profile / 端口 / 文件句柄，导致用例卡到超时、并残留 msedge 拖住后续构建。
///
/// 归入本集合的测试类**彼此串行**，但仍可与其它纯计算测试并行。
/// 新增「会起进程」的测试类时，请给它加 <c>[Collection(ExternalProcess)]</c>。
///
/// 已归入本集合的类：PdfExportTests、CoreUtilTests、EtwParseTests、PipelineTests、
/// ToolVersionProbeTests、YaraTests —— 它们都会起子进程（Edge / 外部工具 / 被测程序）。
///
/// 注意：本机装了 360 + 火绒，会注入 DLL 到所有子进程，导致 testhost 偶发**原生崩溃**
/// （无失败用例，直接报"测试主机进程崩溃"，崩溃点随机）。这**不是**并行造成的，
/// 归一化到本集合也治不好——真正的稳定手段是跑 `./test.sh`（带 --blame-crash）。
/// </summary>
[CollectionDefinition(ExternalProcess.Name, DisableParallelization = true)]
public class ExternalProcess
{
    public const string Name = "ExternalProcess";
}
