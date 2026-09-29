# WinSecLab — Windows PC 应用综合安全测试平台

> 安全测试编排、证据采集、行为关联与报告平台。
> 不重复实现 Ghidra / x64dbg / Wireshark / YARA，而是把它们**接入**统一流程，同时保证**零外部依赖也能跑完核心链路**。

- 目标：把「导入 EXE → 静态检查 → 动态运行 → 监控行为 → 关联异常 → 生成报告」变成一条可重复、可追溯的流程
- 形态：WPF 桌面应用（主）+ `wsx` 命令行（同一引擎的另一个入口）
- 技术栈：.NET 10 + WPF + SQLite，纯 .NET 实现内置引擎

---

## 1. 快速开始

### 运行环境

| 项目 | 要求 |
|---|---|
| 操作系统 | Windows 10 / 11 |
| .NET | .NET 10 运行时（构建需 .NET 10 SDK） |
| 权限 | **标准用户即可**。需要 WMI 实时进程事件、抓包、Procmon 时再以管理员运行 |

### 启动

```
# 方式一：直接运行构建产物
src\WinSecLab.App\bin\Release\net10.0-windows10.0.19041.0\WinSecLab.exe

# 方式二：从源码启动
dotnet run --project src/WinSecLab.App -c Release
```

- 工作区默认在 `%USERPROFILE%\Documents\WinSecLab`，可用环境变量 `WINSECLAB_WORKSPACE` 覆盖
- 仓库里附带的 `.wsx-smoke` 目录是开发时的冒烟测试数据（含几个示例项目），**可以整个删掉**，不影响使用

### 命令行

```
wsx analyze <目标文件> [--profile FullSecurityAssessment] [--run-seconds 30] [--json]
wsx projects
wsx plugins
wsx doctor
wsx help
```

两条路径共用同一个 `AnalyzerPipeline`，**CLI 不是简化版实现**，结论与 GUI 完全一致。

---

## 2. 测试

```
dotnet test tests/WinSecLab.Tests/WinSecLab.Tests.csproj -c Release
```

**62 个用例全部通过**，覆盖四类回归点：

| 类别 | 防的是什么 |
|---|---|
| 工具层（熵 / 哈希 / 路径语义） | 基础判断被改坏——比如 `D:/Program Files` 曾被误判为用户可写 |
| YARA 引擎与规则解析 | 匹配语义（nocase / wide / N-of-them）、用户规则的 unsupported 语法静默丢弃 |
| 外部工具输出解析 | 第三方格式变化——Sigcheck / Procmon CSV、tshark 网卡列表、yara 输出 |
| 编排与存储 | 插件任务全覆盖、外部工具缺失回退、SQLite 建表与往返 |

测试用的是真实格式样例（含踩过坑的输入），新增规则或适配器时请照着补。

---

## 3. 核心流程（一个应用 = 一个项目）

```
导入 EXE/DLL/MSI → 建项目（自动复制样本 + 哈希留档 + 识别应用类型）
   → 勾选任务 / 选 Profile → 静态检查
   → 动态运行（启动目标，监控进程/文件/注册表/网络）
   → 规则引擎跨证据关联 → Findings + Security Graph
   → 生成 HTML / Markdown / JSON 报告
```

### 内置测试 Profile

| Profile | 内容 | 适用 |
|---|---|---|
| **Basic** | 仅静态：PE / 依赖 / 签名 / 字符串 / 熵 / YARA | 快速体检，不启动程序 |
| **Desktop Application** | Basic + 进程 / 文件 / 注册表 / 网络观测 | 桌面应用默认档 |
| **.NET Application** | Basic + 托管元数据 / 类型树 / 混淆迹象 | .NET 程序 |
| **Full Security Assessment** | 全部任务 + HTTP 代理 + 工具关联 + 深度分析工作流 | 一次性跑完 |

也可以在「测试执行」页逐项勾选自定义任务（共 15 个）。

---

## 4. 能力总览

### 内置引擎（零依赖，开箱即用）

| 能力 | 说明 |
|---|---|
| PE 解析 | 节区 / 导入导出（含前向导出）/ 资源树 / 延迟导入 / Rich Header / PDB 路径，SHA-256 / MD5 / SHA-1 / imphash |
| 数字签名 | WinVerifyTrust + 证书链 + PKCS#7 时间戳 + **同目录二进制签名普查** |
| 字符串提取 | ASCII / UTF-16 双通道，按 URL / 域名 / 路径 / 命令 / 凭据 / 安全 API 等 13 类分类 |
| 熵值分析 | 整体熵 + 逐节区熵，≥7.2 判定加壳 / 加密载荷 |
| .NET 分析 | 程序集标识 / 命名空间-类型-成员树 / 引用程序集 / 方法引用 / 混淆与 NativeAOT 识别 |
| 依赖解析 | 三级搜索定位实际 DLL，标出**从用户可写目录加载**的模块（DLL 劫持面） |
| 进程监控 | WMI 事件（管理员）+ 1 秒轮询双通道 + **ETW 内核进程事件**（管理员，内核级带准确父 PID），进程树归因 + 模块加载 diff |
| 文件监控 | FileSystemWatcher + 批量聚合 + 相关性过滤 + 限流 |
| 注册表监控 | WMI 触发 + 快照差分（覆盖 15 个常见持久化位置） |
| 网络观测 | `GetExtendedTcpTable/UdpTable`，**按 owning PID 精确归因** + DNS 缓存解析 |
| HTTP 代理 | 本地正向代理，明文 HTTP 完整解析（Chunked / gzip），HTTPS 隧道透传 + Repeater 重放 |
| YARA | 内置 20 条自研启发式规则；同一套规则可导出为标准 `.yar` 交给真正的 yara.exe 复跑 |
| 规则引擎 | 34 条内置规则，每条都带 CWE / OWASP / 影响 / 复现步骤 / 整改建议 |
| 安全图谱 | 同心圆分层（目标→模块→进程→网络→文件→注册表→发现），点击节点回溯证据 |

### 外部工具接入（可选，全部自动探测 + 降级）

| 工具 | 角色 | 接入方式 |
|---|---|---|
| YARA | 替代型 | 检测到 yara.exe 后接管 YARA 任务，结论可与内置引擎对照 |
| Process Monitor | 补充型 | 全系统采集 + CSV 解析，补齐 PID 级归因（内置 FSW 拿不到"谁写的"） |
| Wireshark / tshark | 补充型 | dumpcap 抓包 → 解析 DNS 查询与 **TLS SNI**（内置只能看连接表） |
| Dependencies | 补充型 | 依赖链交叉验证，暴露隐式加载 |
| Sigcheck | 补充型 | 签名结果交叉验证 |
| Sysinternals Strings | 补充型 | 字符串召回率对照 |
| ilspycmd | 补充型 | .NET 类型清单 + 可选反编译导出 |
| Ghidra | 深度分析 | 生成工程 / 导出脚本 / 启动命令；可选 headless 自动导出函数清单 |
| x64dbg | 深度分析 | 生成启动脚本 + 基于已采集事实的断点建议 |
| Process Explorer | 深度分析 | 生成人工核对清单（句柄 / 网络 / 子进程逐项对） |

**探测顺序**：显式配置 → 项目工具目录 → PATH → 默认安装目录/glob → 注册表（App Paths / 卸载项）。
未安装的工具**不会让任务失败**——对应任务由内置引擎兜底，并在报告与「插件与工具」页如实标注"已跳过 + 安装指引"。

### 外部程序集插件

把实现了 `IWinSecLabPlugin` 的 DLL 放进 `<工作区>\Plugins\` 即自动加载（会弹出与内置代码同等权限的提示）。`wsx plugins` 可查看加载情况与错误。

---

## 5. 关于报告

每次分析生成三份格式，位于 `项目目录\Reports\`：

- **HTML** — 自包含单文件（样式内联），双击浏览器打开；浏览器「打印 → 另存为 PDF」即可得 PDF
- **Markdown** — 适合贴进 Wiki / 禅道 / 仓库
- **JSON** — 结构化结果（findings / evidence / events），可接入 CI 做二次统计

报告章节：执行摘要 · 应用信息 · 测试环境 · 静态分析 · 动态行为 · 网络分析 · 文件系统 · 注册表 · 依赖关系 · 安全发现 · 证据附录 · 安全图谱 · 方法说明。

**每个发现都能回溯到原始证据**：规则只做"基于已采集证据的归纳"，不做猜测——这是 §25「证据优先 / 人工可验证」的落地。

---

## 6. 设计取舍（为什么这样做）

这些不是实现细节，而是"换一个团队接手也该遵守"的约束：

1. **样本复制与执行路径分离**
   导入时把样本复制进项目目录用于取证与哈希比对；但动态阶段**从原始安装位置启动程序**——
   把可执行文件搬到别的目录会改变 DLL 搜索路径、MUI 资源查找，很多程序会因此启动失败或行为失真，那样采集到的证据就不可信了。
   两者哈希不一致时，会改用项目内副本并明确警告。

2. **替代型 vs 补充型工具**
   替代型（如 YARA）就绪后接管任务，避免同一结论被两个引擎重复计数；
   补充型（如 Procmon / tshark）与内置引擎**并行**，用于交叉验证。

3. **监控必须比被监控对象更稳**
   所有定时器回调统一包了异常隔离——`Timer` 回调抛未处理异常会直接杀进程，
   一个畸形路径就能让整场分析崩掉是不可接受的。

4. **排除分析器自身的环境污染**
   沙箱 / EDR 常把代理 DLL 注入到所有子进程。平台会先记录自身进程的模块基线，
   被测进程里出现同样的模块时标记为"环境注入/继承"，不计入目标行为——否则会把环境噪声报成 DLL 劫持。

5. **路径可写性按"任意盘符"判断**
   多盘机器上程序装在 `D:\Program Files` 是常态，只认系统盘会把整类目录误判为用户可写。

6. **不吞错误**
   外部工具的 stderr、跳过原因、探测位置都会写进报告与界面——"已跳过"比"静默为空"诚实得多。

7. **每个任务必须有明确的执行者**
   任务清单里的每一项都要有插件认领，否则勾选/取消就是摆设 —— 「规则关联与图谱」由
   `builtin.correlation` 插件承担，编排器保证它排在动态阶段之后；因此**所有 Profile 都包含它**，
   取消勾选就意味着本次不生成发现项（界面会明确说明，而不是默默产出空报告）。

8. **破坏性动作显式确认**
   动态测试启动前会明确列出将要做的事（启动哪个程序、监控多久、会话结束会杀进程），需要用户确认。

---

## 7. 目录结构

```
WinSecLab/
├── WinSecLab.slnx
├── src/
│   ├── WinSecLab.Core/        # 引擎（静态/动态/网络/规则/报告/插件/存储），无 UI 依赖
│   │   ├── Engines/Static|Dynamic|Network|Rules|Analysis|Reports
│   │   ├── Plugins/           # 插件契约 + 内置插件 + 外部工具适配器
│   │   ├── Storage/           # SQLite 封装 + 工作区服务
│   │   └── Util/              # 哈希 / 熵 / 原生调用 / 安全定时器 / 进程快照
│   ├── WinSecLab.App/         # WPF 界面（10 个页面）
│   └── WinSecLab.Cli/         # wsx 命令行
└── tests/WinSecLab.Tests/
```

工作区布局：

```
<工作区>/
├── Projects/WS-YYYYMMDD-NNN_项目名/
│   ├── Target/                # 样本副本与依赖
│   ├── Static Analysis/ Dynamic Analysis/ Network/ ...
│   ├── Artifacts/             # 外部工具产物（pcap / csv / pml / 导出脚本）
│   ├── Rules/                 # 用户自定义 .yar
│   ├── Reports/               # HTML / MD / JSON
│   └── analysis.db            # SQLite（事件 / 证据 / 发现 / 会话）
├── Rules/  Plugins/  settings.json
```

---

## 8. 常用操作

| 想做的事 | 怎么做 |
|---|---|
| 新建项目 | 「项目」页拖入 EXE → 选 Profile → 创建项目 |
| 跑一次完整评估 | 「测试执行」页选 Full Security Assessment → 开始分析 |
| 只做静态体检 | 勾选 Profile 为 Basic，或勾掉所有动态任务 |
| 查看某个结论的依据 | 「安全发现」→ 选中条目 → 关联证据卡片 |
| 看程序到底访问了哪些域名 | 「动态行为」→ 网络连接 / DNS 观测（装了 tshark 还能看 TLS SNI） |
| 复用上次结果不重跑 | 「项目」页选中项目，其它页面会自动载入历史结果 |
| 重新生成报告 | 「报告」页 → 基于当前结果重新生成 |
| 加自己的 YARA 规则 | 把 `.yar` 放进 `<工作区>\Rules\`，下次分析自动加载 |
| 查环境是否就绪 | 「插件与工具」页，或命令行 `wsx doctor` |

---

## 9. UI 回归截图（开发用）

```
WinSecLab.exe --snapshot <输出目录> --snapshot-width 1480 --snapshot-height 900
```

会把 10 个页面渲染成 PNG 后自动退出（窗口移到屏幕外渲染，不依赖截屏权限），用于界面回归检查。

---

## 10. 授权与边界

- **仅限对已获授权的软件进行安全测试**。未获授权的测试可能违反法律与服务条款
- 平台不会做的事：不实现反编译器/调试器（走工作流适配）；不做 HTTPS 中间人解密；不修改被测程序的文件或注册表（监控全部只读）；不把结论包装成"确定恶意"，只给事实与可验证的推理

---

## 11. 构建与发布

```
# 全量构建（Core + App + CLI + Tests）
dotnet build WinSecLab.slnx -c Release

# 运行全部单元测试
dotnet test tests/WinSecLab.Tests/WinSecLab.Tests.csproj -c Release
```

**发布自包含单文件**（免 .NET 运行时，双击即跑，产物在 `dist/win-x64/`）：

```bash
# 桌面 GUI（WinSecLab.exe）
dotnet publish src/WinSecLab.App -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true -o dist/win-x64

# 命令行（wsx.exe）
dotnet publish src/WinSecLab.Cli -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true -o dist/win-x64
```

> ⚠️ App 与 CLI 都引用 Core，**必须串行发布**——并行发布会同时写 `WinSecLab.Core.dll`，
> 报 `CS2012 文件被占用`。若已冲突，先 `dotnet build-server shutdown` 再重试。

---

## 12. 外部工具真机验证清单

适配器代码对「未安装 → 降级」路径已验证；「已安装 → 接管/交叉验证」路径按下列清单逐项真机复验。
装好对应工具后，用 `wsx plugins` 确认探测到，再对样本跑一次分析核对输出：

| 工具 | 安装方式 | 验证要点 |
|---|---|---|
| ilspycmd | `dotnet tool install -g ilspycmd`（已真机验证 ✅） | 用任意 .NET 程序集，核对内置元数据 vs ilspy 类型清单数量级一致 |
| YARA | 下载 yara64.exe 到 `C:\Tools\YARA` | 内置 20 条规则导出后能被 yara.exe 复跑，命中数可对照 |
| Wireshark/tshark | 官方安装包（勾选 Npcap） | 抓包后「网络连接」页出现 DNS 域名与 TLS SNI（内置只有连接表） |
| Process Monitor | Sysinternals 解压到 `C:\Tools\Procmon` | 需管理员；事件带 PID 归因，与内置文件监控结果交叉验证 |
| Ghidra | 解压发行版到 `C:\Tools\ghidra`（需 JDK 21+） | headless 导出函数 CSV；GUI 工作流脚本能双击打开 |

验证三原则：① 探测到 ≠ 能跑通，务必看真实输出；② 外部工具结果与内置结果**应能对照**（数量级一致、无矛盾）；③ 降级路径要反向再验一次（卸载/禁用工具后回到内置引擎）。

---

*WinSecLab 0.1.0 · .NET 10 / WPF*
