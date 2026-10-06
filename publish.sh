#!/usr/bin/env bash
# 发布自包含单文件（免 .NET 运行时，双击即跑）到 dist/win-x64/。
#
# 为什么写成脚本：App 与 CLI 都引用 Core，**并行发布会同时写 WinSecLab.Core.dll 报 CS2012**，
# 必须串行，且最好先关掉 MSBuild 常驻进程。手工敲容易漏掉一步，结果拿到的是上一次的旧产物。
set -euo pipefail

cd "$(dirname "$0")"

OUT="dist/win-x64"
FLAGS=(-c Release -r win-x64 --self-contained true
       -p:PublishSingleFile=true
       -p:IncludeNativeLibrariesForSelfExtract=true
       -p:EnableCompressionInSingleFile=true)

echo "== 关闭常驻构建进程（避免文件锁） =="
dotnet build-server shutdown >/dev/null 2>&1 || true

echo "== 清理 $OUT =="
rm -rf "$OUT"
mkdir -p "$OUT"

echo "== 发布 GUI（WinSecLab.exe） =="
dotnet publish src/WinSecLab.App "${FLAGS[@]}" -o "$OUT"

echo "== 发布 CLI（wsx.exe） =="
dotnet publish src/WinSecLab.Cli "${FLAGS[@]}" -o "$OUT"

echo
echo "== 产物 =="
ls -lh "$OUT"/*.exe

echo
echo "== 冒烟：wsx doctor =="
"$OUT/wsx.exe" doctor 2>&1 | tail -5 || true
