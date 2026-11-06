#!/usr/bin/env bash
#
# 灵瞰 · 外部攻击面管理平台（EASM）—— Linux 一键部署脚本
# 仅支持基于 systemd + apt 的 Linux 发行版（amd64 / arm64）；本脚本不含任何交叉编译步骤。
#
# 推荐部署流程（本机打包 → 上传 → 服务器安装）：
#   1) 本机编译二进制：            go build -o easm-platform .
#   2) 上传到服务器同一目录：       easm-platform、config.json、deploy/ubuntu/
#   3) 服务器执行：                 sudo bash deploy/ubuntu/install.sh
#   脚本优先使用上传的预编译二进制；若未上传二进制，则回退为「检查/安装 Go 并从源码编译」。
#
# 保留能力：Go 检查/安装、naabu 预编译下载、config.json 修正、systemd 注册、开机自启、
#           HTTP + HTTPS 双探活、后续操作指引。
#
# 可用环境变量覆盖默认值，例如：
#   APP_DIR=/srv/easm LISTEN=127.0.0.1:8000 HTTPS_LISTEN=127.0.0.1:8443 sudo -E bash deploy/ubuntu/install.sh
#
set -euo pipefail

# ===== 仅 Linux 守卫 =====
if [ "$(uname -s)" != "Linux" ]; then
  echo "错误：本部署脚本仅支持 Linux（Ubuntu 24.04 及同类发行版），当前系统为 $(uname -s)。" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "错误：未检测到 systemd（systemctl）。本脚本依赖 systemd 管理服务。" >&2
  exit 1
fi

# ===== 可配置变量 =====
APP_DIR="${APP_DIR:-/opt/easm}"                     # 部署目录
LISTEN="${LISTEN:-0.0.0.0:8000}"                     # HTTP 监听地址（测试环境默认对所有网卡开放，注意安全）
HTTPS_LISTEN="${HTTPS_LISTEN:-0.0.0.0:8443}"         # HTTPS 监听地址（首次启动自动生成约 100 年自签名证书）
NAABU_PATH="${NAABU_PATH:-/usr/local/bin/naabu}"     # naabu 固定绝对路径，避免守护进程 PATH 问题
NAABU_VERSION="${NAABU_VERSION:-2.7.0}"              # naabu 预编译二进制版本（直接下载，免编译）
GO_MIN_VERSION="${GO_MIN_VERSION:-1.27}"             # go.mod 要求 go 1.27.0（仅源码编译回退路径需要）
GO_INSTALL_VERSION="${GO_INSTALL_VERSION:-1.27.0}"   # 联网获取最新版失败时的回退版本
SERVICE_NAME="${SERVICE_NAME:-easm}"                 # systemd 服务名

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORT="${LISTEN##*:}"
HTTPS_PORT="${HTTPS_LISTEN##*:}"

# 预编译二进制查找顺序：脚本目录 → 项目根 → 当前工作目录
PREBUILT=""
for cand in "$SCRIPT_DIR/easm-platform" "$PROJECT_ROOT/easm-platform" "$PWD/easm-platform"; do
  if [ -f "$cand" ]; then PREBUILT="$cand"; break; fi
done

log() { echo -e "\n\033[1;32m==> $*\033[0m"; }

# ===== [1/6] 系统依赖（下载/解压/授权所需的最小集合）=====
log "[1/6] 安装系统依赖 (curl / unzip / libcap2-bin / ca-certificates)"
sudo apt-get update -y
sudo apt-get install -y curl unzip libcap2-bin ca-certificates

# ===== [2/6] naabu（官方 Linux 预编译二进制，免编译）=====
log "[2/6] 安装 naabu v${NAABU_VERSION} (Linux 预编译二进制)"
if [ -x "$NAABU_PATH" ]; then
  log "已存在 ${NAABU_PATH}，跳过下载（如需重装请先删除该文件）"
else
  case "$(dpkg --print-architecture)" in
    arm64) naabu_arch="arm64" ;;
    *)     naabu_arch="amd64" ;;
  esac
  url="https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${naabu_arch}.zip"
  log "下载 ${url}"
  curl -fsSL "$url" -o /tmp/naabu.zip
  unzip -o /tmp/naabu.zip -d /tmp/naabu
  sudo cp /tmp/naabu/naabu "$NAABU_PATH"
  sudo chmod +x "$NAABU_PATH"
  rm -rf /tmp/naabu /tmp/naabu.zip
fi
# 授予抓包能力：非 root 也能做 SYN 扫描（免 sudo）
sudo setcap cap_net_raw+ep "$NAABU_PATH" || log "setcap 失败，可忽略（服务以 root 运行）"
log "naabu 版本："
"$NAABU_PATH" -version || true

# ===== [3/6] 平台二进制：优先上传的预编译产物，否则服务器端 Go 编译 =====
log "[3/6] 准备平台二进制"
sudo mkdir -p "$APP_DIR/data"
if [ -n "$PREBUILT" ]; then
  log "使用上传的预编译二进制：$PREBUILT"
  sudo cp "$PREBUILT" "$APP_DIR/easm-platform"
  sudo chmod +x "$APP_DIR/easm-platform"
else
  log "未发现上传的二进制，回退为服务器端 Go 编译（将检查/安装 Go）"
  sudo apt-get install -y build-essential git
  export PATH="/usr/local/go/bin:$PATH"
  need_install_go=1
  if command -v go >/dev/null 2>&1; then
    cur="$(go version | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p')"
    if [ -n "$cur" ] && [ "$(printf '%s\n' "$GO_MIN_VERSION" "$cur" | sort -V | head -n1)" = "$GO_MIN_VERSION" ]; then
      log "已检测到 Go ${cur}，满足要求，跳过安装"
      need_install_go=0
    fi
  fi
  if [ "$need_install_go" = "1" ]; then
    # Ubuntu 24.04 apt 自带 Go 版本过低(1.22)，改用官方 tar 包
    ver="$(curl -fsSL 'https://go.dev/dl/?mode=json' 2>/dev/null | grep -oE '"version": ?"go[0-9.]+"' | head -n1 | sed -E 's/.*"go([0-9.]+)"/\1/' || true)"
    ver="${ver:-$GO_INSTALL_VERSION}"
    arch="$(dpkg --print-architecture)"   # amd64 / arm64
    log "下载并安装 Go ${ver} (${arch})"
    curl -fL "https://go.dev/dl/go${ver}.linux-${arch}.tar.gz" -o /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
    hash -r || true
    go version
  fi
  if [ ! -f "$PROJECT_ROOT/main.go" ]; then
    echo "错误：既未上传预编译二进制，也未在 $PROJECT_ROOT 找到源码（main.go），无法继续。" >&2
    echo "      请先在本机执行 'go build -o easm-platform .' 并把二进制上传到脚本同级目录。" >&2
    exit 1
  fi
  cd "$PROJECT_ROOT"
  go build -o easm-platform .
  sudo cp easm-platform "$APP_DIR/easm-platform"
  sudo chmod +x "$APP_DIR/easm-platform"
fi

# ===== [4/6] config.json 部署与修正 =====
log "[4/6] 部署并修正 config.json"
if [ ! -f "$APP_DIR/config.json" ]; then
  for c in "$SCRIPT_DIR/config.json" "$PROJECT_ROOT/config.json" "$PWD/config.json"; do
    if [ -f "$c" ]; then sudo cp "$c" "$APP_DIR/config.json"; log "已从 $c 复制 config.json"; break; fi
  done
fi
if [ ! -f "$APP_DIR/config.json" ]; then
  echo "错误：未找到 config.json（请将上传的 config.json 放到 $APP_DIR 或脚本同级目录）。" >&2
  exit 1
fi
# 修正部署副本：naabu 绝对路径 + HTTP/HTTPS 监听地址（不改动仓库源文件）
sudo sed -i "s#\"naabu_path\": \"naabu\"#\"naabu_path\": \"$NAABU_PATH\"#" "$APP_DIR/config.json"
sudo sed -i "s#\"listen\": \"127.0.0.1:8000\"#\"listen\": \"$LISTEN\"#" "$APP_DIR/config.json"
sudo sed -i "s#\"https_listen\": \"127.0.0.1:8443\"#\"https_listen\": \"$HTTPS_LISTEN\"#" "$APP_DIR/config.json"

# ===== [5/6] systemd 服务（注册 + 开机自启 + 启动）=====
log "[5/6] 安装并启动 systemd 服务 (${SERVICE_NAME})"
sudo cp "$SCRIPT_DIR/easm.service" "/etc/systemd/system/${SERVICE_NAME}.service"
sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
sudo systemctl restart "${SERVICE_NAME}"

# ===== [6/6] 双探活验证（HTTP + HTTPS）=====
log "[6/6] 验证服务状态（HTTP + HTTPS）"
sleep 2
sudo systemctl --no-pager --full status "${SERVICE_NAME}" | head -n 12 || true
echo
curl -s  -o /dev/null -w "本地探活: HTTP  %{http_code}\n" "http://127.0.0.1:${PORT}/login" || true
curl -sk -o /dev/null -w "本地探活: HTTPS %{http_code}\n" "https://127.0.0.1:${HTTPS_PORT}/login" || true

cat <<EOF

========================================================
 部署完成（Linux / systemd）
 - 访问地址 : https://<本机IP>:${HTTPS_PORT}  （或明文 http://<本机IP>:${PORT}）
 - TLS 证书 : ${APP_DIR}/data/certs/  （首次启动自动生成约 100 年自签名证书；浏览器提示不安全属正常）
 - 默认账号 : admin / admin123  （请尽快登录后改密，或修改 ${APP_DIR}/config.json 的 password 后重启）
 - 部署目录 : ${APP_DIR}
 - 运行日志 : ${APP_DIR}/data/easm.log ；页面「系统管理 → 运行日志」可分级检索
 - 服务管理 : sudo systemctl {start|stop|restart|status} ${SERVICE_NAME}
 - naabu    : ${NAABU_PATH}

 首次初始化：
   1) 浏览器登录 → 资产台账 → 导入待监控 IP
   2) 扫描任务 → 新建/运行一次（定时默认不启用，需要时在任务里手动勾选）
   3) 白名单 → 「生成基线」把现有暴露面全部入白
   4) 系统设置 → 填飞书 Webhook → 发送测试消息

 安全提醒：测试环境默认监听 ${LISTEN} / ${HTTPS_LISTEN}。如需限制访问：
   sudo ufw allow OpenSSH && sudo ufw enable
   或重新执行： LISTEN=127.0.0.1:${PORT} HTTPS_LISTEN=127.0.0.1:${HTTPS_PORT} sudo -E bash deploy/ubuntu/install.sh  走 SSH 隧道
========================================================
EOF
