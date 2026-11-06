#!/usr/bin/env bash
# =========================================================
# wander-github-pull · 推送前安全护栏
# 确认敏感文件（运行时数据 / 数据库 / 证书私钥 / 主配置 / 部署包 / 二进制）
# 未进入 git 跟踪或暂存区。命中即返回非零，调用方应中止提交/推送。
#
# 用法（在仓库根目录执行）：
#   bash .qoder/skills/wander-github-pull/scripts/guard.sh
# 退出码：0=干净可推送；1=发现敏感文件（禁止推送）；2=非 git 仓库
# =========================================================
set -uo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "guard: 当前目录不是 git 仓库，请先 cd 到仓库根目录。"
  exit 2
fi

# 敏感路径 / 文件匹配（扩展正则）。与仓库 .gitignore 的排除意图保持一致。
PATTERN='(^|/)data/|(^|/)dist/|(^|/)config\.json$|\.db($|-)|\.sqlite|\.key$|\.crt$|\.cer$|\.pem$|\.p12$|\.pfx$|(^|/)easm-platform$'

tracked_hits=$(git ls-files | grep -E "$PATTERN" || true)
staged_hits=$(git diff --cached --name-only | grep -E "$PATTERN" || true)
hits="${tracked_hits}
${staged_hits}"
hits=$(printf '%s\n' "$hits" | sed '/^$/d' | sort -u)

if [ -n "$hits" ]; then
  echo "!!! guard: 发现敏感文件被 git 跟踪/暂存，禁止提交与推送："
  printf '%s\n' "$hits" | sed 's/^/  - /'
  echo ""
  echo "修复步骤："
  echo "  1) 从索引移除（保留本地文件）：git rm --cached <上述每个文件>"
  echo "  2) 确认 .gitignore 已覆盖对应路径（data/、config.json、dist/、*.db、*.key 等）"
  echo "  3) 重新 git add -A 后再次运行本脚本，直到输出 OK"
  echo "  注意：若敏感文件曾进入历史提交，需用 git filter-repo / BFG 清理历史并轮换密钥。"
  exit 1
fi

echo "guard: OK — 未发现敏感文件（data/、dist/、config.json、数据库、证书私钥、二进制均未进入跟踪/暂存）。"
exit 0
