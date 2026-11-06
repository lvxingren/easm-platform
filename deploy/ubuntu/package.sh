#!/usr/bin/env bash
#
# 灵瞰 · 资产测绘管理平台（EASM）—— 成品打包脚本（在开发机执行）
#
# 作用：交叉编译 Linux 二进制 + 收集部署所需文件到成品目录 dist/，并打成 tar.gz，
#       实现「一次上传」：scp 该 tar.gz 到服务器 → 解压 → sudo bash install.sh。
# 开发机可为任意平台（用 Go 交叉编译产出 Linux 二进制）；部署目标仅 Linux（systemd + apt）。
#
# 用法：
#   bash deploy/ubuntu/package.sh                 # 默认 amd64
#   ARCH=arm64 bash deploy/ubuntu/package.sh       # ARM64 服务器
#   VERSION=v1.0.0 bash deploy/ubuntu/package.sh   # 自定义版本标签
#
set -euo pipefail

ARCH="${ARCH:-amd64}"                 # 目标服务器架构：amd64 / arm64
VERSION="${VERSION:-$(date +%Y%m%d)}" # 版本标签（用于产物文件名）

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST="$PROJECT_ROOT/dist"
STAGE_NAME="easm-platform-linux-${ARCH}-${VERSION}"
STAGE="$DIST/$STAGE_NAME"

log() { echo -e "\n\033[1;32m==> $*\033[0m"; }

command -v go >/dev/null 2>&1 || { echo "错误：未找到 go，请先安装 Go（版本要求见 go.mod）。" >&2; exit 1; }
case "$ARCH" in amd64|arm64) ;; *) echo "错误：ARCH 仅支持 amd64 / arm64，当前为 $ARCH" >&2; exit 1 ;; esac

cd "$PROJECT_ROOT"

log "清理并创建成品目录：$STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"

log "交叉编译 Linux/${ARCH} 二进制（CGO 关闭，纯 Go 依赖，静态可移植；注入版本号 ${VERSION}）"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w -X easm-platform/internal/buildinfo.Version=${VERSION}" -o "$STAGE/easm-platform" .

log "收集部署文件"
cp config.json                "$STAGE/config.json"
cp README.md                  "$STAGE/README.md"
cp deploy/ubuntu/install.sh   "$STAGE/install.sh"
cp deploy/ubuntu/easm.service "$STAGE/easm.service"
chmod +x "$STAGE/install.sh" "$STAGE/easm-platform"

cat > "$STAGE/DEPLOY.txt" <<EOF
灵瞰 · 资产测绘管理平台（EASM）—— Linux 部署包（${ARCH} / ${VERSION}）
生成时间：$(date '+%Y-%F %T')

【一次上传部署】
  1) 本机成品包：dist/${STAGE_NAME}.tar.gz
  2) 上传：      scp dist/${STAGE_NAME}.tar.gz user@SERVER:/tmp/
  3) 解压：      ssh user@SERVER
                 mkdir -p /tmp/easm && tar -xzf /tmp/${STAGE_NAME}.tar.gz -C /tmp/easm --strip-components=1
  4) 安装：      cd /tmp/easm && sudo bash install.sh
                 （包内已含预编译二进制，install.sh 会直接使用，服务器无需安装 Go）
  5) 访问：      https://<服务器IP>:8443   或   http://<服务器IP>:8000

【说明】
  - 仅支持 Linux（systemd + apt）；naabu 由 install.sh 下载官方 Linux 预编译版并 setcap。
  - config.json 可在安装前修改监听地址 / HTTP·HTTPS 开关 / naabu 路径 / 管理员密码。
  - 首次以 HTTPS 启动会自动生成约 100 年有效期的自签名证书到 data/certs/；也可登录后在
    「系统管理 → 系统设置 → 网络与证书」上传正式证书（热生效，无需重启）。
  - 监听地址 / HTTP·HTTPS 开关改动需重启服务：sudo systemctl restart easm。
EOF

log "打包 tar.gz"
TARBALL="${STAGE_NAME}.tar.gz"
tar -czf "$DIST/$TARBALL" -C "$DIST" "$STAGE_NAME"

log "完成"
echo "成品目录 : $STAGE"
echo "上传包   : $DIST/$TARBALL"
echo "包内文件 :"
tar -tzf "$DIST/$TARBALL" | sed 's/^/  /'
echo
echo "一次上传部署示例："
echo "  scp \"$DIST/$TARBALL\" user@SERVER:/tmp/"
echo "  ssh user@SERVER 'mkdir -p /tmp/easm && tar -xzf /tmp/$TARBALL -C /tmp/easm --strip-components=1 && cd /tmp/easm && sudo bash install.sh'"
