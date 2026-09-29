using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Static;

/// <summary>
/// §3.2 自动识别模块。用多路独立信号打分，任一路命中都能给出可解释的依据，
/// 而不是黑箱判断 —— 每条信号连同权重一起进证据，人工可以复核。
/// </summary>
public sealed class AppTypeDetector
{
    public AppTypeDetection Detect(PeImageInfo pe, DotNetAssemblyInfo? dotNet, IReadOnlyList<StringHit> strings)
    {
        var detection = new AppTypeDetection();
        var scores = new Dictionary<AppRuntimeKind, int>();
        var stringLookup = BuildStringIndex(strings);
        var imports = pe.Imports.Select(m => m.ModuleName).ToList();
        var importFunctions = pe.Imports.SelectMany(m => m.Functions.Select(f => f.Name)).ToList();
        var sections = pe.Sections.Select(s => s.Name).ToList();
        var targetDir = Path.GetDirectoryName(pe.FilePath) ?? "";
        var siblingFiles = EnumerateSiblings(targetDir);

        void Hit(AppRuntimeKind kind, string signal, int weight, string detail)
        {
            scores[kind] = scores.GetValueOrDefault(kind) + weight;
            detection.Signals.Add(new DetectionSignal { Kind = signal, Detail = detail, Weight = weight });
        }

        // ---------------------------------------------------------- .NET / 托管
        if (pe.IsDotNet)
        {
            var managedSignal = dotNet is { IsDotNet: true };
            Hit(AppRuntimeKind.DotNet, "CLR 元数据", 6,
                $"PE 含 CLR 头（运行时 {pe.DotNetRuntimeVersion}），托管元数据{(managedSignal ? "已解析" : "不可读")}");
            if (managedSignal)
            {
                if (dotNet!.TargetFramework is { Length: > 0 } tf)
                    Hit(AppRuntimeKind.DotNet, "目标框架", 3, $"TargetFramework = {tf}");
                if (dotNet.ReferencedAssemblies.Any(r => r.Contains("PresentationFramework", StringComparison.OrdinalIgnoreCase)))
                    Hit(AppRuntimeKind.DotNet, "WPF", 2, "引用 PresentationFramework（WPF 桌面程序）");
                if (dotNet.ReferencedAssemblies.Any(r => r.Contains("System.Windows.Forms", StringComparison.OrdinalIgnoreCase)))
                    Hit(AppRuntimeKind.DotNet, "WinForms", 2, "引用 System.Windows.Forms");
                if (dotNet.ReferencedAssemblies.Any(r => r.Contains("Avalonia", StringComparison.OrdinalIgnoreCase)))
                    Hit(AppRuntimeKind.DotNet, "Avalonia", 2, "引用 Avalonia UI");
                if (dotNet.IsSingleFileBundle)
                    Hit(AppRuntimeKind.DotNet, "单文件打包", 2, "疑似 .NET 单文件 bundle，需先解包再反编译");
                if (dotNet.IsReadyToRun)
                    Hit(AppRuntimeKind.DotNet, "ReadyToRun", 1, "包含 ReadyToRun 原生镜像头");
            }
            if (pe.IsNativeAot)
                Hit(AppRuntimeKind.DotNet, "NativeAOT", 3, "CorFlags.NativeEntryPoint 置位，托管元数据可能不完整");
        }

        // ----------------------------------------------------------------- Qt
        var qtModules = imports.Where(m => m.StartsWith("Qt", StringComparison.OrdinalIgnoreCase) &&
                                            m.Contains("Core", StringComparison.OrdinalIgnoreCase)).ToList();
        var qtAny = imports.Where(m => m.StartsWith("Qt", StringComparison.OrdinalIgnoreCase) && m.Contains(".dll")).ToList();
        if (qtAny.Count > 0)
        {
            var major = qtAny.Any(m => m.StartsWith("Qt6", StringComparison.OrdinalIgnoreCase)) ? "Qt 6" : "Qt 5";
            Hit(AppRuntimeKind.Qt, "Qt 模块导入", 6, $"{major}：导入 {string.Join(", ", qtAny.Take(6))}");
            if (qtAny.Any(m => m.Contains("Widgets", StringComparison.OrdinalIgnoreCase)))
                Hit(AppRuntimeKind.Qt, "Qt Widgets", 2, "使用 Widgets 模块（传统桌面 UI）");
            if (qtAny.Any(m => m.Contains("Qml", StringComparison.OrdinalIgnoreCase) || m.Contains("Quick", StringComparison.OrdinalIgnoreCase)))
                Hit(AppRuntimeKind.Qt, "Qt Quick/QML", 2, "使用 QML 界面");
        }
        else if (siblingFiles.Any(f => f.StartsWith("Qt6", StringComparison.OrdinalIgnoreCase) || f.StartsWith("Qt5", StringComparison.OrdinalIgnoreCase)))
        {
            Hit(AppRuntimeKind.Qt, "同目录 Qt 运行库", 4, "同目录存在 Qt5/Qt6 运行库文件");
        }

        // ------------------------------------------------------------ Electron
        var electronSignals = new List<string>();
        if (siblingFiles.Contains("app.asar") || siblingFiles.Any(f => f.EndsWith(".asar", StringComparison.OrdinalIgnoreCase)))
            electronSignals.Add("存在 app.asar 打包");
        if (siblingFiles.Contains("icudtl.dat")) electronSignals.Add("存在 icudtl.dat");
        if (siblingFiles.Contains("v8_context_snapshot.bin")) electronSignals.Add("存在 v8_context_snapshot.bin");
        if (siblingFiles.Contains("ffmpeg.dll")) electronSignals.Add("存在 ffmpeg.dll");
        if (siblingFiles.Contains("libEGL.dll") && siblingFiles.Contains("libGLESv2.dll")) electronSignals.Add("存在 ANGLE 图形库");
        if (imports.Any(m => m.Contains("electron", StringComparison.OrdinalIgnoreCase))) electronSignals.Add("导入 Electron 模块");
        if (stringLookup.HasAny("electron", "chrome_100_percent.pak", "resources\\app.asar"))
            electronSignals.Add("字符串含 Electron / Chromium 资源名");
        if (electronSignals.Count > 0)
            Hit(AppRuntimeKind.Electron, "Electron 特征", electronSignals.Count * 2,
                string.Join("；", electronSignals));

        // --------------------------------------------------------------- Unity
        var unitySignals = new List<string>();
        if (siblingFiles.Contains("UnityPlayer.dll")) unitySignals.Add("同目录 UnityPlayer.dll");
        if (Directory.Exists(Path.Combine(targetDir, Path.GetFileNameWithoutExtension(pe.FileName) + "_Data")))
            unitySignals.Add($"{Path.GetFileNameWithoutExtension(pe.FileName)}_Data 数据目录");
        if (siblingFiles.Any(f => f.Equals("mono-2.0-bdwgc.dll", StringComparison.OrdinalIgnoreCase))) unitySignals.Add("Mono 运行时 DLL");
        if (stringLookup.HasAny("UnityPlayer", "UnityEngine", "il2cpp", "gameassembly.dll")) unitySignals.Add("字符串含 Unity 引擎符号");
        if (unitySignals.Count > 0)
            Hit(AppRuntimeKind.Unity, "Unity 特征", unitySignals.Count * 3, string.Join("；", unitySignals));

        // -------------------------------------------------------------- Unreal
        var unrealSignals = new List<string>();
        if (siblingFiles.Any(f => f.EndsWith(".pak", StringComparison.OrdinalIgnoreCase))) unrealSignals.Add("存在 .pak 资源包");
        if (siblingFiles.Any(f => f.Contains("UnrealEngine", StringComparison.OrdinalIgnoreCase))) unrealSignals.Add("UnrealEngine 运行库");
        if (stringLookup.HasAny("++UE4", "++UE5", "UnrealEngine", "/Script/Engine", "LogWindows"))
            unrealSignals.Add("字符串含 Unreal 版本标记 / 引擎脚本路径");
        if (Directory.Exists(Path.Combine(targetDir, "Engine"))) unrealSignals.Add("Engine 目录结构");
        if (unrealSignals.Count > 0)
            Hit(AppRuntimeKind.Unreal, "Unreal 特征", unrealSignals.Count * 3, string.Join("；", unrealSignals));

        // ------------------------------------------------------------------ Go
        var goSignals = new List<string>();
        if (sections.Any(s => s is ".gopclntab" or ".go.buildinfo" or ".go.buildid" or ".gosymtab")) goSignals.Add("存在 Go 专有节区");
        if (stringLookup.HasAny("runtime.goexit", "go1.", "runtime.morestack", "GOROOT=")) goSignals.Add("字符串含 Go 运行时符号");
        if (goSignals.Count > 0)
            Hit(AppRuntimeKind.Go, "Go 特征", goSignals.Count * 4, string.Join("；", goSignals));

        // ---------------------------------------------------------------- Rust
        var rustSignals = new List<string>();
        if (sections.Any(s => s.Contains("rustc", StringComparison.OrdinalIgnoreCase))) rustSignals.Add("存在 .rustc 节区");
        if (stringLookup.HasAny("rustc/", "cargo/", "core::panicking", "RUST_BACKTRACE", "library\\std"))
            rustSignals.Add("字符串含 Rust 标准库路径");
        if (rustSignals.Count > 0)
            Hit(AppRuntimeKind.Rust, "Rust 特征", rustSignals.Count * 4, string.Join("；", rustSignals));

        // ------------------------------------------------- Python 打包程序
        var pySignals = new List<string>();
        if (stringLookup.HasAny("_MEIPASS", "PYZ-00.pyz", "pyi-", "PyInstaller")) pySignals.Add("PyInstaller 特征字符串");
        if (siblingFiles.Any(f => f.StartsWith("python3", StringComparison.OrdinalIgnoreCase) && f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
            pySignals.Add("同目录 python3xx.dll");
        if (stringLookup.HasAny("Nuitka", "nuitka")) pySignals.Add("Nuitka 编译特征");
        if (siblingFiles.Any(f => f.Equals("python.exe", StringComparison.OrdinalIgnoreCase) ||
                                  f.Equals("pythonw.exe", StringComparison.OrdinalIgnoreCase)))
            pySignals.Add("同目录 python.exe");
        if (pySignals.Count > 0)
            Hit(AppRuntimeKind.PythonPackaged, "Python 打包特征", pySignals.Count * 3, string.Join("；", pySignals));

        // ---------------------------------------------------------------- Java
        var javaSignals = new List<string>();
        if (stringLookup.HasAny("java/lang/Object", "JNI_CreateJavaVM", "java.home", "sun.java.command"))
            javaSignals.Add("字符串含 JVM / Java 类路径");
        if (siblingFiles.Any(f => f.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase)) ||
            siblingFiles.Any(f => f.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)))
            javaSignals.Add("同目录 jvm.dll / jar 包");
        if (importFunctions.Any(f => f.Contains("JNI_", StringComparison.Ordinal)))
            javaSignals.Add("导入 JNI 接口函数");
        if (javaSignals.Count > 0)
            Hit(AppRuntimeKind.Java, "Java 特征", javaSignals.Count * 3, string.Join("；", javaSignals));

        // ------------------------------------------------------------ Node.js
        var nodeSignals = new List<string>();
        if (stringLookup.HasAny("NODE_SEA_BLOB", "node_modules", "process.binding", "NODE_OPTIONS"))
            nodeSignals.Add("字符串含 Node.js 运行时标记");
        if (sections.Any(s => s.Contains("nodedata", StringComparison.OrdinalIgnoreCase))) nodeSignals.Add("存在 Node 数据节区");
        if (nodeSignals.Count > 0)
            Hit(AppRuntimeKind.NodeJs, "Node.js 打包特征", nodeSignals.Count * 3, string.Join("；", nodeSignals));

        // -------------------------------------------------------------- Flutter
        var flutterSignals = new List<string>();
        if (siblingFiles.Contains("flutter_windows.dll")) flutterSignals.Add("同目录 flutter_windows.dll");
        if (Directory.Exists(Path.Combine(targetDir, "data")) &&
            File.Exists(Path.Combine(targetDir, "data", "app.so"))) flutterSignals.Add("data/app.so（AOT 快照）");
        if (flutterSignals.Count > 0)
            Hit(AppRuntimeKind.Flutter, "Flutter 特征", flutterSignals.Count * 4, string.Join("；", flutterSignals));

        // --------------------------------------------------------------- Delphi
        if (sections.Contains("CODE") && sections.Contains("DATA") &&
            importFunctions.Any(f => f.Contains("System", StringComparison.Ordinal) || f.Contains("@SysUtils")))
        {
            Hit(AppRuntimeKind.Delphi, "Delphi 节区", 5, "CODE / DATA 节区命名 + Delphi 运行时导入");
        }

        // ----------------------------------------------------- 原生 C/C++ 兜底
        if (scores.Count == 0 || (scores.Count == 1 && scores.ContainsKey(AppRuntimeKind.DotNet) && pe.IsNativeAot))
        {
            Hit(AppRuntimeKind.NativeCpp, "原生映像", 3,
                $"无托管 / 框架运行时特征，节区 {string.Join(" ", sections.Take(6))}");
        }

        var best = scores.OrderByDescending(kv => kv.Value).First();
        detection.Runtime = best.Key;
        var total = scores.Values.Sum();
        detection.ConfidencePercent = total > 0 ? Math.Clamp(best.Value * 100 / total, 10, 98) : 20;
        detection.DisplayName = Describe(best.Key);
        FillRecommendations(detection, pe, dotNet, siblingFiles);
        return detection;
    }

    private static void FillRecommendations(AppTypeDetection d, PeImageInfo pe, DotNetAssemblyInfo? dotNet,
        HashSet<string> siblings)
    {
        var analyzers = new List<string>();
        var tools = new List<string>();

        switch (d.Runtime)
        {
            case AppRuntimeKind.DotNet:
                d.RequiresManagedDecompiler = true;
                analyzers.Add(".NET Assembly Analyzer");
                analyzers.Add("Strings Scan");
                analyzers.Add("YARA");
                tools.Add("ILSpy（C# 源码级反编译）");
                tools.Add("dnSpyEx（可调试的托管反编译器）");
                if (dotNet?.IsSingleFileBundle == true)
                    tools.Add("单文件解包（ExtractBundle / dotnet-bundle-extract）后再反编译");
                if (dotNet?.IsNativeAot == true)
                    tools.Add("NativeAOT 场景改用 Ghidra / x64dbg 原生化分析");
                break;
            case AppRuntimeKind.Qt:
                FillQtRecommendations(analyzers, tools);
                break;
            case AppRuntimeKind.Electron:
                analyzers.Add("PE Analyzer");
                analyzers.Add("Strings Scan");
                tools.Add("asar 解包（npx asar extract）查看 JS 层逻辑");
                tools.Add("DevTools 远程调试 9222 端口（授权环境）");
                d.HasWebContent = true;
                break;
            case AppRuntimeKind.Unity:
                analyzers.Add("PE Analyzer");
                tools.Add("dnSpyEx（Assembly-CSharp.dll 反编译）");
                tools.Add("AssetStudio / UABEA（资源包解析）");
                d.IsGameEngine = true;
                break;
            case AppRuntimeKind.Unreal:
                analyzers.Add("PE Analyzer");
                tools.Add("Ghidra（C++ 原生逆向）");
                tools.Add("FModel / UE Viewer（.pak 资源解析）");
                d.IsGameEngine = true;
                break;
            case AppRuntimeKind.Go:
                analyzers.Add("PE Analyzer");
                analyzers.Add("Strings Scan");
                tools.Add("Ghidra + Go 符号恢复脚本");
                tools.Add("GoReSym / redress（恢复函数名与类型信息）");
                break;
            case AppRuntimeKind.Rust:
                analyzers.Add("PE Analyzer");
                tools.Add("Ghidra（Rust 名字修饰还原）");
                break;
            case AppRuntimeKind.PythonPackaged:
                analyzers.Add("PE Analyzer");
                analyzers.Add("Strings Scan");
                tools.Add("PyInstaller Extractor 解包（pyinstxtractor）");
                tools.Add("uncompyle6 / decompyle3 反编译 pyc");
                break;
            case AppRuntimeKind.Java:
                tools.Add("JD-GUI / CFR（jar 反编译）");
                tools.Add("Bytecode Viewer");
                break;
            case AppRuntimeKind.NodeJs:
                tools.Add("Node SEA 解包");
                break;
            case AppRuntimeKind.Flutter:
                tools.Add("flutter_blutter / Dart AOT 逆向工具");
                break;
            case AppRuntimeKind.Delphi:
                tools.Add("IDR（Interactive Delphi Reconstructor）");
                tools.Add("Ghidra");
                break;
            default:
                d.RequiresNativeDecompiler = true;
                analyzers.Add("PE Analyzer");
                analyzers.Add("Entropy Scan");
                tools.Add("Ghidra（反编译与调用图）");
                tools.Add("x64dbg（动态调试）");
                break;
        }

        if (pe.IsSigned == false) tools.Add("签名缺失，重点关注供应链与完整性");
        if (pe.Sections.Any(s => s.IsHighEntropy))
            tools.Add("存在高熵节区，先用 DIE / PEiD 识别壳再决定逆向路径");
        if (siblings.Any(s => s.EndsWith(".asar", StringComparison.OrdinalIgnoreCase)))
            tools.Add("asar 打包存在，前端逻辑可能可直接读取");

        d.RecommendedAnalyzers = analyzers.Distinct().ToList();
        d.RecommendedTools = tools.Distinct().ToList();

        static void FillQtRecommendations(List<string> a, List<string> t)
        {
            a.Add("PE Analyzer");
            a.Add("Strings Scan");
            t.Add("Ghidra（Qt 符号还原，注意 QMetaObject 元信息）");
            t.Add("Qt 资源文件（.qrc / rcc）提取");
            a.Add("Dependency Scan");
        }
    }

    private static string Describe(AppRuntimeKind kind) => kind switch
    {
        AppRuntimeKind.DotNet => "C# / .NET 托管应用",
        AppRuntimeKind.NativeCpp => "C / C++ 原生应用",
        AppRuntimeKind.Qt => "Qt 桌面应用",
        AppRuntimeKind.Electron => "Electron（Chromium + Node）应用",
        AppRuntimeKind.Unity => "Unity 引擎应用",
        AppRuntimeKind.Unreal => "Unreal Engine 应用",
        AppRuntimeKind.Go => "Go 编译的应用程序",
        AppRuntimeKind.Rust => "Rust 编译的应用程序",
        AppRuntimeKind.PythonPackaged => "Python 打包程序",
        AppRuntimeKind.Java => "Java 应用（含 JVM）",
        AppRuntimeKind.NodeJs => "Node.js 打包程序",
        AppRuntimeKind.Flutter => "Flutter 桌面应用",
        AppRuntimeKind.Delphi => "Delphi / C++Builder 应用",
        _ => "未识别",
    };

    private static HashSet<string> EnumerateSiblings(string directory)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory)) return set;
        try
        {
            foreach (var f in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
                set.Add(Path.GetFileName(f));
        }
        catch
        {
            // 目录不可读（权限 / 已卸载）
        }
        return set;
    }

    /// <summary>
    /// 把候选字符串拼成一个大写统一的小写 blob，用 IndexOf 做批量探测。
    /// 比 4 万条 × N 关键字的两层循环快一个数量级，内存上也有明确上限。
    /// </summary>
    private sealed class StringIndex
    {
        private const int MaxValues = 20_000;
        private const int MaxValueLength = 512;
        private readonly string _blob;

        public StringIndex(IEnumerable<string> values)
        {
            var builder = new System.Text.StringBuilder(2 << 20);
            var count = 0;
            foreach (var value in values)
            {
                if (count++ >= MaxValues) break;
                builder.Append(value.Length > MaxValueLength ? value[..MaxValueLength] : value);
                builder.Append('\n');
            }
            _blob = builder.ToString().ToLowerInvariant();
        }

        public bool HasAny(params string[] keywords)
        {
            foreach (var keyword in keywords)
            {
                if (_blob.Contains(keyword, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    private static StringIndex BuildStringIndex(IReadOnlyList<StringHit> hits)
    {
        // 只取可能承载框架标记的字符串，避免把 4 万条全量比对一遍
        var values = hits
            .Where(h => h.Category is "General" or "FilePath" or "Domain" or "URL" or "Command" or "Json")
            .Select(h => h.Value)
            .ToList();
        return new StringIndex(values);
    }
}
