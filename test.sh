#!/usr/bin/env bash
# 跑全量单元测试。
#
# 为什么不是简单的 `dotnet test`：
# 本机装了 360 + 火绒（可能还有沙箱/EDR），它们会注入 DLL 到所有子进程。
# 测试宿主 testhost.exe 在这种环境下会**偶发原生崩溃**——没有任何失败用例，
# 直接报「测试主机进程崩溃」，且崩溃点随机（有时 31 个、有时 113 个用例后）。
# 实测：加上 `--blame-crash`（附加崩溃转储工具）后进程行为改变，186 个用例稳定跑完。
# `--blame-hang-timeout` 再兜一层：万一某个用例真的卡住，180 秒后判定并继续，不会无限挂起。
#
# 若哪天真的崩了，诊断产物在 tests/WinSecLab.Tests/TestResults/<guid>/ 下（有 dump / Sequence.xml）。
set -euo pipefail

cd "$(dirname "$0")"

FILTER="${1:-}"

echo "== 关闭常驻构建进程（避免文件锁） =="
dotnet build-server shutdown >/dev/null 2>&1 || true

ARGS=(tests/WinSecLab.Tests/WinSecLab.Tests.csproj --nologo
      --blame-crash --blame-hang-timeout 180s)

if [ -n "$FILTER" ]; then
  echo "== 过滤：$FILTER =="
  dotnet test "${ARGS[@]}" --filter "FullyQualifiedName~$FILTER"
else
  echo "== 全量测试 =="
  dotnet test "${ARGS[@]}"
fi
