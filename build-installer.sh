#!/usr/bin/env bash
# 打包 WinSecLab 安装包（Inno Setup）。
#
# 前置：先跑 `bash publish.sh` 生成 dist/win-x64/ 下的自包含单文件。
# 产物：dist/installer/WinSecLab-Setup-<版本>.exe
#
# 为什么写成脚本：
#  1) ISCC.exe 的安装路径因人而异（本机在 %LOCALAPPDATA%\Programs\Inno Setup 6\），
#     脚本里自动探测，不写死。
#  2) 中文语言包 Inno 不自带，随仓库放在 installer/ChineseSimplified.isl，
#     脚本确保它同时存在于 Inno 的 Languages 目录（编译期能找到）。
set -euo pipefail

cd "$(dirname "$0")"

# ── 1. 探测 ISCC.exe ──
find_iscc() {
  for p in \
    "$LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe" \
    "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" \
    "/c/Program Files/Inno Setup 6/ISCC.exe" \
    "$LOCALAPPDATA/Programs/InnoSetup/ISCC.exe" \
    ; do
    if [ -f "$p" ]; then echo "$p"; return 0; fi
  done
  return 1
}

ISCC="$(find_iscc || true)"
if [ -z "$ISCC" ]; then
  echo "错误：未找到 Inno Setup 编译器（ISCC.exe）。" >&2
  echo "安装方式（任选其一）：" >&2
  echo "  winget install --id JRSoftware.InnoSetup" >&2
  echo "  或从 https://jrsoftware.org/isdl.php 下载安装" >&2
  exit 1
fi
echo "== 使用编译器：$ISCC =="

# ── 2. 确保中文语言包就位 ──
ISCC_DIR="$(dirname "$ISCC")"
if [ -d "$ISCC_DIR/Languages" ] && [ ! -f "$ISCC_DIR/Languages/ChineseSimplified.isl" ]; then
  echo "== 安装中文语言包到 Inno Languages 目录 =="
  cp installer/ChineseSimplified.isl "$ISCC_DIR/Languages/ChineseSimplified.isl" || true
fi

# ── 3. 检查发布产物是否存在 ──
if [ ! -f dist/win-x64/WinSecLab.exe ]; then
  echo "错误：未找到 dist/win-x64/WinSecLab.exe，请先跑 bash publish.sh" >&2
  exit 1
fi

# ── 4. 编译 ──
echo "== 编译安装包 =="
"$ISCC" installer/WinSecLab.iss

echo
echo "== 产物 =="
ls -la dist/installer/*.exe
