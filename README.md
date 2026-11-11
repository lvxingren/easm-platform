# 灵瞰 · 资产测绘管理平台

基于 Go + SQLite + 内嵌 Web UI 的资产测绘管理（EASM）平台，采用侧边栏式安全控制台设计。核心流程：
**资产台账（IP/网段/范围 + 标签）→ 扫描任务（全部/标签/手工，支持定时）→ 端口扫描（naabu，带容错）→ 聚合暴露面 → 白名单比对 → 风险处置闭环 → 飞书推送**，并内置多账号 RBAC 与操作审计。

设计参考 ARL 灯塔的资产库、任务编排、持续监控、组合检索、数据导出与风险闭环思路；当前版本聚焦**已知且获授权 IP 资产的端口暴露面管理**，不包含 ARL 的域名爆破、站点指纹识别或 PoC 漏洞验证能力，不应将其描述为完整 ARL 替代品。

> 合规提示：只应对台账内自有/已授权资产进行扫描。
> 系统名称可在 `config.json` 的 `app_name` 配置（默认「灵瞰 · 资产测绘管理平台」）；首个管理员账号取自 `config.json` 的 `admin`，之后统一在「系统管理-账号」维护。

---

## 一、环境依赖

| 依赖 | 说明 |
|------|------|
| Go 1.27+ | 编译运行本平台 |
| **naabu** | 实际执行端口扫描的引擎（ProjectDiscovery 出品），**必须单独安装** |
| fscan（可选） | 多工具并行扫描引擎（端口+高危 PoC 漏洞），新建任务时可选 fscan/混合引擎 |
| Subfinder（可选） | 子域名爆破工具，配置后增强域名资产子域枚举 |

平台本身不含扫描能力，所有端口扫描都通过调用外部 `naabu` 命令完成。**启动扫描前会校验配置并自检 naabu**；路径、权限、目标或参数异常会返回明确原因，同时在「执行记录」中保留失败记录。

---

## 二、安装 naabu（macOS）

任选其一：

### 方式一：Go 安装（推荐，跨平台一致）

```bash
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

安装后二进制位于 `$(go env GOPATH)/bin`（通常是 `~/go/bin`）。请确保该目录已加入 `PATH`：

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
source ~/.zshrc
```

### 方式二：Homebrew

```bash
brew install naabu
```

### 验证

```bash
which naabu      # 应输出 naabu 的绝对路径
naabu -version   # 应输出版本号
```

若 `naabu` 不在 `PATH` 中，可在平台「系统设置 → 扫描器路径」里填写绝对路径（例如 `/Users/你的用户名/go/bin/naabu`），保存后点击「检测 naabu」验证。

### 关于扫描权限

平台默认使用 CONNECT 扫描，无需 root。SYN 扫描需要 root 或给 naabu 授予 `CAP_NET_RAW`；权限不足时 naabu 自身会**静默降级为 CONNECT**（不会报错退出），平台会读取其 stderr 识别该降级并在执行事件中记录警告、同时把执行快照的 UDP 标记纠正为未启用，可改用 CONNECT，不需要用 root 运行整个 Web 平台。

---

## 三、编译与运行

> 首次克隆后仓库不含 `config.json`（已被 `.gitignore` 排除以防泄露密钥），请先执行 `cp config.example.json config.json` 再按需修改。

```bash
# 编译
go build -o easm-platform .

# 运行（默认读取 ./config.json）
sudo ./easm-platform

# 或指定配置文件
sudo ./easm-platform /path/to/config.json
```

启动后默认同时监听 HTTP `http://127.0.0.1:8000` 与 HTTPS `https://127.0.0.1:8443`（地址见 `config.json` 的 `listen` / `https_listen`）。

首次初始化账号默认为 `admin` / `admin123`（以首次启动时的 `config.json` 为准）。**登录后请立即通过右上角「改密」修改；后续账号与密码统一在 Web 中维护，修改 `config.json` 不会覆盖已有账号。**

### 版本与发布

- 查看二进制版本：`./easm-platform -version`。发布构建通过 `-ldflags "-X easm-platform/internal/buildinfo.Version=vX.Y.Z"` 注入版本号；`deploy/ubuntu/package.sh` 已自动注入 `VERSION`，页面侧栏与启动日志也会显示当前版本。
- 发布新版本（逐步更新）：`VERSION=v1.0.1 ARCH=amd64 bash deploy/ubuntu/package.sh` 产出 `dist/easm-platform-linux-amd64-v1.0.1.tar.gz` → `git tag -a v1.0.1 -m "..." && git push origin v1.0.1` → 在 GitHub Releases 基于该 tag 上传二进制包。
- **二进制不入库**：`dist/` 与根 `/easm-platform` 已在 `.gitignore` 排除，二进制只随 GitHub Release 分发，避免仓库膨胀。

### HTTPS 与证书（默认启用）

平台默认同时监听 HTTP（`listen`）与 HTTPS（`https_listen`）。首次启用 HTTPS 时，若 `tls_cert` / `tls_key` 不存在，会**自动生成一张有效期约 100 年的自签名证书**并写入 `data/certs/`，之后复用——无需在打包或部署时手工准备证书。证书 SAN 默认包含 `localhost`、`127.0.0.1`、`::1`，可用 `tls_hosts` 追加对外域名或 IP。

- **只用 HTTPS**：把 `http_enabled` 设为 `false`（`listen` 的明文端口将不再监听）。
- **使用正式 CA 证书**：把证书/私钥放到 `tls_cert` / `tls_key` 指定路径；文件已存在时不会被自动生成覆盖。
- **页面配置与证书上传**：登录后进入「系统管理 → 系统设置 → 网络与证书」，可开关 HTTP/HTTPS、修改监听地址与自签名 SAN 主机（保存到 `config.json`，**监听与开关需重启服务生效**），并可直接上传正式证书与私钥（选择文件或粘贴 PEM，系统校验两者匹配后写入，**热生效、无需重启**）；页面同时展示当前证书主体、有效期、剩余天数与 SAN。
- **浏览器提示不安全**：自签名证书会有此警告，属正常现象；内网可将 `data/certs/server.crt` 导入「受信任的根证书颁发机构」，或直接选择继续访问。
- **TLS 握手噪音已降噪**：公网暴露时，浏览器/扫描器不信任自签名证书会触发 `http: TLS handshake error ... remote error: tls: unknown certificate` 等握手失败。这类**客户端原因**（`remote error`、不信任证书、协议不符、扫描半开连接）的错误已降为 info 级，不再刷 error 日志、不污染「只看报错」；服务端真正的证书/私钥错误仍按 error 记录。要彻底消除客户端不信任，请上传受信任 CA 证书（热生效），或让客户端导入 `data/certs/server.crt`，或用防火墙/安全组限制 HTTPS 端口的公网暴露。
- 私钥文件权限自动收紧为 `0600`；`data/certs/` 随部署目录持久化，迁移时请一并保留或重新生成。

---

## 四、配置项（config.json）

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `app_name` | `灵瞰 · 资产测绘管理平台` | 页面与启动日志中的系统名称 |
| `listen` | `127.0.0.1:8000` | HTTP 监听地址 |
| `http_enabled` | `true` | 是否启用明文 HTTP；设为 `false` 可只保留 HTTPS |
| `https_enabled` | `false`（仓库 `config.json` 预置 `true`） | 是否启用 HTTPS 监听 |
| `https_listen` | `127.0.0.1:8443` | HTTPS 监听地址 |
| `tls_cert` / `tls_key` | `data/certs/server.crt` / `data/certs/server.key` | TLS 证书与私钥路径；不存在时首次启动自动生成约 100 年自签名证书 |
| `tls_hosts` | `["localhost","127.0.0.1"]` | 自签名证书附加的 SAN（域名 / IP） |
| `db_path` | `data/easm.db` | SQLite 数据库路径 |
| `log_level` | `warn` | stderr 最低输出级别（info/warn/error）；仅控制控制台输出，「运行日志」页环形缓冲始终全量；可在「系统设置→异常排查」热生效 |
| `naabu_path` | `naabu` | naabu 可执行文件路径，可为绝对路径 |
| `naabu_rate` | `3000` | 发包速率（包/秒，单进程），影响扫描耗时；2C4G 推荐 3000 |
| `realert_days` | `7` | 同一暴露面重复告警的间隔天数 |
| `alert_out_of_scope` | `true` | 台账外 IP 是否也告警 |
| `feishu.webhook` / `feishu.secret` | 空 | 飞书机器人 Webhook 与加签密钥 |
| `admin.user` / `admin.password` | `admin` / `admin123` | 仅用于 users 表为空时创建首个管理员 |

以上基础配置也可在「系统设置」页面在线修改并持久化到数据库。「系统设置」按 **网络监听 / TLS 证书 / 通知与告警 / naabu 参数（含资源监测）/ AI 分析 / 异常排查** 拆分为独立面板，顶部胶囊导航可锚点跳转，**各类单独保存、互不覆盖**（后端按提交字段部分更新）。页面另提供 CONNECT/SYN、响应等待时间、内部并发线程、扫描并发度（并行 naabu 批次数）、排除端口、指定网卡、TCP 二次验证及任务总超时；每项均附作用说明和格式校验，保存后立即生效。**飞书加签密钥与 AI Token 等敏感项不回显明文**：输入框始终为空，已配置时占位提示「已配置，留空则不修改」，填写新值即轮换。 CONNECT 无需特殊权限；SYN 需要 root 或 `CAP_NET_RAW`。响应等待过短可能漏报，重试、并发和 TCP 二次验证会增加耗时或资源消耗。

「系统设置 → naabu 资源监测」默认开启，每 5 秒采样当前 naabu 进程的 CPU 和 RSS 内存。默认 CPU 阈值为 90%、内存阈值为 1024 MiB，任一指标持续 30 秒超阈值才告警；CPU 的 100% 表示占满一个逻辑核。资源监测只记录执行事件、日志并发送飞书通知，**不会自动暂停或终止任务**；未配置飞书 Webhook 时不影响扫描。

---

## 五、扫描耗时估算

单次扫描把所有台账 IP 写入一个列表交给 naabu 一次性并发执行，`naabu_rate` 为**全局共享**的发包速率。单个 IP 的理论耗时：

```
耗时 ≈ (端口数 × 每端口探测次数) / rate + 启动开销
```

以 `rate=2000` 为例估算单个 IP（默认已调优为 3000，实际更快）：

| 模式 | 端口数 | 理论最快 | 实际预估 |
|------|--------|----------|----------|
| 常用端口 top-1000 | 1000 | ~0.5 秒 | 约 1~10 秒 |
| 全端口 1-65535 | 65535 | ~33 秒 | 约 30 秒 ~ 2 分钟 |

实际耗时受 naabu 重试（`naabu_retries`，默认 2，被防火墙丢包的端口会重试）、响应等待、扫描方式等因素影响。**任务总超时 `scan_timeout_min` 默认 0=不限制**，任务跑到完成、不会中途被强制终止（符合使用习惯）；如需保护可在「系统设置」填写上限分钟数。想加速可在「系统设置」调高 `naabu_rate`，或优先使用 top 模式。

为提供真实目标进度，平台按每批最多 20 个目标规格切分，并按**扫描并发度**（`scan_concurrency`，默认 6，可在系统设置调整，1=串行）**并行调用多个 naabu 进程**扫不同批次，总发包吞吐≈并发度×`naabu_rate`；每批结束后更新已处理、待处理和异常目标数。仅当设置了超时上限时，任务总超时才对有效扫描时间合并计算（**暂停时长不计入**）；默认不限制则跑到完成。提高并发度可显著提速，但会增加 CPU/内存/网络占用，需按服务器与目标网络承受能力调整。

**性能调优（提高资源占用）**：默认 `scan_concurrency=6`、`naabu_workers=100`、`naabu_rate=5000`、平台总速率预算 30000/s、`scan_timeout_min=0`（不限制），以充分利用 CPU 与内存、加快出结果且不中途截断。存量库启动时会自动把仍等于旧默认值（3/25/2000、4/50/3000、超时 60）的参数升级到该推荐值，用户手动自定义的值不受影响。如仍嫌慢可在「系统设置」继续上调并发度/线程/速率（注意 FD 与网络承受力）。出现问题时执行详情与「运行日志」始终保留完整异常与 stderr，便于排查。

---

## 六、功能一览

- **资产台账**：粘贴 / CSV / TXT / XLSX 导入，支持 **单 IP / CIDR 网段 / IP 范围 / 域名**四种类型，自动去重、去 BOM；返回合法、新增、非法跳过数量及非法样例，不再静默丢弃。资产含**维护人员（owner）**与**安全设备标识（security_device）**可选字段，旧存量默认留空、不影响扫描与告警。导入与**手动添加单条**均为按钮触发模态面板，导入回显明细（新增/跳过/非法示例）；CSV/XLSX 可按「目标, 维护人员, 安全设备」列头批量带入维护信息。列表新增「维护人员」「安全设备」两列并支持关键词检索，行内「编辑」可改维护人员/安全设备/标签、「删除」独立于批量栏；**复选框 + 全选 + 批量修改标签**（追加/覆盖/清空）与**批量删除**；支持「已打/未打标签」快捷筛选与 **CSV 导出（含新字段）**；格式说明与样例下载收敛到「帮助 / 模板」按钮。
- **暴露面资产**：跨扫描按 `IP + 端口 + 协议` 聚合，展示首次/最近发现、出现次数、白名单和告警状态；支持 IP/服务、端口、协议查询与 **CSV 导出**，可下钻最近扫描和相关告警；非只读账号支持勾选**批量加白**、**批量修改关联资产标签**与行内一键加白。聚合视图表示历史探明结果，不等同于实时在线状态。
- **扫描任务**：支持**全部台账 / 按标签动态圈选 / 手工目标**三种范围；扫描模式支持常用端口 top-1000 / 全端口 1-65535 / **自定义端口**（`22,80,8000-9000`，新建表单实时校验非法端口并附 Top1000 说明）；可即席运行、保存复用或挂每日/每周计划；手工目标可选择加入台账；列表与新建/编辑分页，全局单任务串行。手动和定时执行共用进度统计，任务页显示已处理、待处理、异常目标、当前批次和百分比。管理员和操作员可暂停、恢复或终止当前执行；Linux/macOS 通过进程组信号实际控制 naabu，暂停仍占用全局扫描锁，终止会停止整个进程组及后续批次。其他平台可终止当前进程，但暂停/恢复会明确提示不支持。任务列表「上次运行」列可点击直达对应执行详情。
- **执行记录**：独立页面保留每次已接受执行的任务，不再只显示最近 50 条；支持按任务、运行、暂停、完成、部分完成、终止、失败状态、全端口/常用端口和关键词筛选。每次执行名称自动追加扫描模式与执行时间，避免同名定时任务的历史记录混淆；删除任务定义不删除历史执行。
- **扫描容错**：naabu 带 `-retries` 重试、有效扫描**超时保护**（防卡死占用锁）、**标准输出/错误输出捕获**；即使进程异常或超时，已解析结果仍保留并标为「部分完成」，但不基于不完整结果生成告警。用户或平台终止后状态为「已终止」，保留终止前结果和真实进度，**已基于已入库结果完成白名单比对与风险告警，结果可能因提前终止而不完整**；服务正常退出也会清理当前 naabu 进程。**容量预检小批量豁免**：≤500 条目标规格的常规扫描，即使最坏情况估算超过任务超时也放行执行（仅告警），运行时超时仍会保护；智能拆分批次计算已纳入 naabu 重试轮数，避免子任务因低估耗时而再次被拒。**状态自愈**：服务重启时自动把残留的运行中/暂停执行修正为已终止（进程已随重启消失），已入库结果保留，但本次重启无法执行白名单比对与告警生成，请等待下次扫描完成或手工触发；`run()` 对 panic 做 recover 并修正状态，执行详情页对悬空状态提供「重新同步状态」按钮。
- **执行详情**：展示目标规格数、开始/结束时间、目标处理进度、当前/最近批次命令、开放端口、资源当前值/峰值、执行事件及完整异常。naabu 标准输出逐行解析，结果达到 50 条或约 500ms 即入库，批次结束再从原始输出文件去重补齐；页面每 2 秒按游标追加新结果并更新状态，无需等待任务结束或整页刷新；暂停/恢复/终止为独立醒目按钮（终止为危险色）。路径/权限/架构/自检超时、目标解析、文件读写、数据库保存、进程退出和任务总超时均说明失败阶段与处理建议。
- **扫描结果**：独立页面按单次执行展示开放端口，保留执行名称、模式和时间来源；支持全端口/常用端口、执行 ID、任务、IP/服务及端口查询与 **CSV 导出**，不再混淆不同任务或不同扫描模式的结果。
- **白名单**：单条添加 + **批量导入**（文本行 IP + 多端口逗号分隔，兼容空格/冒号/范围/tcp-udp；或上传 **Excel/CSV 模板**，列：IP/网段 + 端口 + 服务 + 备注）；支持单 IP / CIDR / 通配。**操作按钮化分区**：「单条添加 / 批量导入 / 生成基线 / 帮助说明」各自独立按钮与面板，互不混杂；附**白名单使用说明文档页**；支持关键词检索与 CSV 导出。条目含**业务归属**字段，可按业务筛选；单条添加与基线生成均可填写业务归属；备注在添加/导入/行内编辑三个环节均可维护。
- **风险处置闭环**：白名单比对、范围内外判断、按 `realert_days` 重复提醒；同一端口复用一条告警，支持待处理、跟进中、已解决、已忽略、处理人和处理说明。已解决后再次发现会自动重开，已忽略不再提醒；行内与批量均可一键加白，支持筛选和 CSV 导出。告警页支持**批量处置**：勾选多条后统一改为跟进中/已解决/已忽略/重新打开（解决、忽略需填统一说明），或一键**批量加白并忽略**；批量操作同样记录处理人与审计流水。告警页还可**按选中告警批量修改关联资产标签**（按 IP 匹配台账，网段/范围或范围外 IP 自动跳过并回显匹配数）。
- **基线生成**：「生成基线」先弹出**预览面板**，展示最近一次完成扫描中尚未加白的开放端口（最多 2000 条），可逐条取消勾选并批量填写业务归属，确认后写入白名单（`owner=baseline`）。
- **资源监测告警**：记录 naabu CPU/RSS 当前值与历史峰值，持续超阈值在执行详情展示事件并写入运行日志；持续高占用期间不重复记录，恢复后再次持续超阈值可重新告警。资源事件独立保存，不与端口风险告警混用，也不再单独推送飞书，而是并入任务结束的唯一一条汇总。
- **飞书通知**：Webhook + HMAC-SHA256 加签推送。**每次扫描任务结束只发送一条汇总消息**（执行状态、目标进度、执行耗时、资源峰值与触发次数、新增风险告警清单），扫描过程中不再逐条推送；未配置 Webhook 时仅保留页面事件与日志，不视为失败。设置页支持测试发送。推送走 HTTPS 并强制 HTTP/1.1 短连接（规避部分中间设备对 HTTP/2 的连接重置），网络层失败（如 `connection reset by peer`）自动重试最多 3 次：**首次尝试走系统 DNS，重试阶段改用公共 DNS（Cloudflare/Google DoH）重新解析域名**，绕过本地 DNS 解析异常（如解析到与部署地不匹配的节点）；业务错误（如签名非法）不重试；Webhook 地址仅允许飞书官方域名（open.feishu.cn / larksuite / larkoffice）。若持续报连接重置，请检查本机到 `open.feishu.cn` 的 DNS 解析（如解析到非飞书网段建议更换 DNS）与出网链路。
- **运行日志**：管理员专属「运行日志」页，采用**进程内环形缓冲**（默认保留最近 3000 条，重启后清空），把扫描、naabu、飞书、数据库等模块的标准日志按 `info/warn/error` 分级；支持**只看报错**、级别筛选与关键词检索，并可每 3 秒实时追加。日志同时照常输出到 stderr，便于 systemd/journalctl 查看。
- **网络流量 / 安全日志分析（AI 溯源）**：导入 CFW 防火墙 / ECS 云主机日志（CSV/JSON/TXT/XLSX，自动识别 `src_ip`/`dst_ip`/端口/协议/动作/时间等中英文列头），聚合资产间通信关系；通过 **OpenAI 兼容接口**调用 AI 还原网络拓扑、识别异常通信（高危端口 / 可疑外联 / 横向移动）并给出溯源路径，结果以结构化 JSON + 可读报告双形式返回。`/analysis` 列表 + `/analysis/{id}` 详情：上传文件清单、AI 调用状态（异步轮询）、拓扑摘要、**内嵌 SVG 交互式拓扑图**、通信关系表、异常高亮、溯源步骤列表，并可一键将结果 IP 加白或创建告警处置单。未配置 AI 端点时用**内置规则降级**分析（离线可用）。AI 端点/Token/模型/超时/温度在「系统设置 → AI 分析」配置并支持连通性测试；请求走 HTTPS、Token 不落日志，原始文件保留于 `data/uploads` 供复核。
- **账号与权限（RBAC）**：多账号管理，角色 **管理员 / 操作员 / 只读**；密码 PBKDF2-SHA256 加盐哈希；管理员可增删改账号、重置密码、启停；防止删除/降级最后一个管理员；任意用户可改本人密码；停用、删除或调整角色后，已有会话立即按最新账号状态生效。只读账号可查看实时结果和事件，但不能暂停、恢复或终止执行，也不能批量处置告警。运行日志、账号管理、操作审计与系统设置仅管理员可见。
- **操作审计**：记录所有登录与写操作（用户/角色/操作/对象/来源 IP/时间），管理员可按关键词与用户名筛选检索并 CSV 导出。
- **全新 UI**：左侧边栏安全控制台布局、概览卡片、状态徽章、Toast 通知、空状态（含引导文案与操作按钮）、响应式；系统名可配置。**顶栏展示「领域 + 模块」两级大标题**（领域如 资产/扫描/防护/风险/分析/系统管理），侧边栏导航按同样七领域分组；各页筛选/操作/批量面板均带小标题分区。**默认浅色主题**（白底、浅灰分区、蓝色主色、柔和阴影，对标 Ant Design Pro / Vercel Dashboard 风格），顶栏「◐ 主题」可一键切换深浅色并记忆到本地，两套配色统一走 CSS 变量。仪表盘未处理告警卡可点击直达告警页。
- **自检**：扫描前校验全部 naabu 参数并实际执行 `-version`；「系统设置」页也可手动检测，路径不存在、无执行权限、二进制异常或自检超时都会返回完整原因。
- **定时调度**：每个任务独立配置每日/每周计划；修正到期跳过问题，同一周期只执行一次，运行中冲突会等待后续轮询重试，停机后仅补跑当前日/周已经到期的计划。
- **旧库兼容**：启动时自动补充任务目标类型、标签、**资产域名/维护人员/安全设备**、扫描进度、资源指标和告警处置字段，并创建执行事件表与流量分析（analysis/analysis_files/analysis_edges）表；所有可空文本列读取统一 COALESCE 兜底，兼容旧任务及旧告警中的 NULL 时间。升级前仍建议备份 `data/easm.db`。

---

## 六-b、多工具引擎（fscan）与域名扫描（可选）

> 合规提示：fscan 漏洞 PoC 与子域爆破仅应对自有/已授权资产使用；默认不启用，不影响现有 naabu 任务。

### 安装 fscan / Subfinder

```bash
# fscan（shadow1ng/fscan，Release 下载对应架构二进制）
# https://github.com/shadow1ng/fscan/releases
curl -fsSL -o /usr/local/bin/fscan <对应架构 fscan 二进制 URL> && chmod +x /usr/local/bin/fscan

# Subfinder（ProjectDiscovery，可选）
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

安装后在「系统设置 → fscan / 域名」填写 `fscan_path` / `subfinder_path`（绝对路径），保存即生效；fscan 自检执行 `-h`。平台按 fscan 1.8.x 参数调用：`-hf` 目标文件（`-h` 只接受单个主机/网段）、`-nobr` 关闭爆破，纯端口模式追加 `-nopoc -noredis` 关闭 PoC 与 Redis 检测。其他版本如参数不兼容，执行记录会完整显示 fscan 原始报错。未安装时选择 naabu 引擎的任务完全不受影响。

### 使用示例

1. **fscan 扫描（三模式）**：新建任务 → 扫描引擎选 `fscan · 纯端口扫描`（默认，轻量，不启用 PoC）、`fscan · 漏洞检测`（SmbGhost/Struts2/Log4j/Shiro/WebLogic 等高危 PoC）或 `fscan · 混合模式`（端口+漏洞）。系统设置「fscan / 域名」可设默认模式（默认纯端口）。自定义端口格式同 naabu（`22,80,443 或 8000-9000`），实时校验 1-65535；留空则 fscan 默认全端口 1-65535。结果端口复用暴露面入库，漏洞明细存 `scan_vulns`；任务结束飞书汇总追加「端口发现：共 N + 样本」，漏洞模式再追加「漏洞发现：高危 X 中危 Y + 样本」。
2. **fscan 自动拆分**：目标数超过拆分阈值（默认每批 50，可配）或容量超时时，自动按批拆分串行执行子任务（复用 `runSplitTask`/`runSubTask`）；子扫描名沿用主任务格式（如 `全台账·常用端口 · fscan-纯端口 · … [自动拆分] · 子任务 1/3`），task_id 关联主任务，完成后 `CopySubScanResults`/`CopySubScanVulns` 聚合到主扫描并统一 `AfterScan` 告警。纯端口容量按 1-2 分钟/目标÷线程数估算，≤500 规格享小批量豁免。
3. **域名扫描**：资产台账导入 `domain` 类型（单域名/`*.example.com`）；在「fscan / 域名」开启「启用域名衍生 IP 扫描」后，平台用 `net.Resolver`（失败回退 Google DoH）递归解析 A/AAAA，结合 `data/subdomains.txt` 种子（可选 Subfinder）枚举子域，衍生 IP 以 `source=domain_resolver` 入台账并自动纳入 naabu 扫描。手工目标或台账中的域名本身不依赖此开关即可直接扫描：naabu 原生解析域名（默认首个 IPv4 + 首个 IPv6）；fscan 由平台在扫描前解析全部 IPv4（fscan 不支持 IPv6），并写入 `domain_map` 供域名详情与暴露面域名列关联；解析失败的域名会记录执行事件，本次终态不会虚报 done。
4. **暴露面域名列**：暴露面资产页新增「域名」列（IP:Port → domain），并支持 `domain=` 参数按域名反向检索所有开放端口；同一主域不同子域的相同端口按「主域+端口」合并计数，避免重复告警。

### 终止后继续扫描未完成节点（增量续扫）

每次执行会按目标规格记录处理状态（`scan_target_status`：未开始/扫描中/已完成/失败）。任务被终止（手动或平台）后，执行详情页新增「目标处理状态」面板，明确区分哪些节点已完成、哪些尚未开始或正在扫描中，并提供「继续扫描未完成节点」按钮：

- 管理员/操作员可从该次终止的执行直接发起增量续扫，只扫未完成（未开始/扫描中/失败）的目标，**保留已完成结果，不重复劳动**。
- 续扫生成一条新执行（`resume_of` 指向父执行），复用现有 naabu/fscan 路径与容量预检；父执行结果与状态不变，两者并集覆盖全部目标。
- 旧执行（无按规格状态记录）不显示续扫入口；运行中/暂停中的执行拒绝续扫。

### UDP 端口扫描

此前平台只下发 TCP（`-top-ports`/`-p -`/CONNECT），而 naabu 的 UDP 端口必须以 `-p u:端口` 显式指定且依赖 SYN/root，故 UDP 从未被扫描。现已支持：

- 「系统设置 → naabu 参数」勾选「同时扫描 UDP 常用端口」，并可自定义 `udp_ports`（默认 DNS/DHCP/NTP/NetBIOS/SNMP/IPsec/syslog/SSDP/mDNS/memcached 等）。
- 启用后自动改用 SYN 并在 TCP 之外同批扫描 UDP：full=`1-65535,u:…`、custom=`自定义,u:…`、top=显式 top-1000 TCP+`u:…`（`-top-ports` 与 `-p` 互斥）。
- UDP 需 root/CAP_NET_RAW；权限不足时 naabu 会自行降级为 CONNECT（UDP 探测被丢弃但进程仍正常退出），平台通过 stderr 识别后写入执行事件/日志「已自动降级为 CONNECT」，并纠正 `scans.udp_enabled=0`，不会静默丢失。
- 「仅 UDP」任务在无原始套接字权限时不会退回 TCP 常用端口扫描（避免扫出用户未授权的 TCP 结果）：本批直接跳过不启动 naabu，执行终态为 `failed` 并提示授权后重试。
- 为保证降级可被识别，SYN/UDP 模式下不再向 naabu 追加 `-silent`（CONNECT 模式仍追加），naabu 的模式自述日志仅写入 stderr，不影响结果解析。
- 结果按 `protocol=udp` 入库，暴露面/白名单/告警均支持 UDP 协议维度。

### 任务级 UDP 开关 / 白名单自动匹配 / 资产分页

- **任务级 UDP**：新建/编辑任务表单在「扫描引擎」旁新增「启用 UDP 端口扫描」开关（默认关闭，新建时以全局 `scan_udp` 为默认值，可单独覆盖）。勾选后本次任务 settings 快照 `scan_udp=1`（强制 SYN+UDP），执行详情显示「已启用 UDP 端口扫描」（`scans.udp_enabled` 可追溯）；未勾选为纯 TCP，不追加 `-p u:`。仅 naabu 引擎生效。
- **白名单自动匹配**：批量导入面板新增「自动匹配已识别端口」复选框。勾选后纯 IP 行自动查询 `scan_results` 历史开放端口并生成白名单条目（`source=auto_match`，列表标 `auto` 徽章）；手动 IP+端口 行记 `source=manual`；回显区分两类数量。自动匹配仅对台账内单 IP 生效，CIDR/范围/范围外跳过并提示。
- **资产分页**：台账筛选栏右侧新增每页 20/50/100 下拉（默认 20），选择持久化到 localStorage；后端 `GET /api/assets` 接收 `page_size`（上限 100）与 `page`，返回记录+总条数+总页数；分页导航显示「共 N 条 · 每页 X 条 · 第 a/b 页」并支持跳转；导出 CSV 不受分页限制。

### 导航分域 / 审计筛选 / 资产分类 / 日志级别

- **导航分域色条**：安全运营分组项（暴露面/告警/扫描结果/白名单/流量分析）加 `.nav-item.sec-op` 主色左条；账号/审计/日志/设置归入底部「系统管理」区加 `.nav-item.sys-admin` 灰色左条；折叠/高亮交互不变。
- **审计筛选**：操作审计页新增「对象类型」下拉（登录/导入资产/删除资产/创建任务/启动扫描/暂停/恢复/终止/加白/批量处置/改密/账号管理/系统设置/其他）+ 起止日期，支持「操作人+类型+时间」组合查询；「对象」列 IP 跳转暴露面、`#扫描ID` 跳转执行详情；导出 CSV 保留全字段。
- **资产分类与服务标记**：台账类型列用彩色 pill 区分 IP/CIDR/Range/Domain；域名行内展示历史服务指纹标签（HTTP/SSH/DNS 等）与安全设备（security_device）；域名详情页（/assets/domain/{domain}）含「关联端口」子面板（domain_map 衍生 IP 开放端口）与一键加白所有衍生 IP 端口。
- **日志级别**：`config.json.log_level` 默认 `warn`；`info` 级仅在设为 info 时输出 stderr；环形缓冲始终全量，运行日志页分级检索不受影响；设置页热生效。

### 资产全局去重与网络不可达告警

- **全局去重**：导入（CSV/XLSX/TXT/粘贴）与手动添加统一经规格归一化后去重：未掩码 CIDR（`10.0.0.5/24`）与掩码形态（`10.0.0.0/24`）、大小写/尾点域名、IPv4 映射 IPv6、范围两端空白均视为同一资产，自动合并不重复入库（`targets.ip` UNIQUE 约束兼并发安全）。导入结果明确回显「新增数量 / 跳过重复数量 / 非法数量与示例」；重复导入时本批标签并入已有资产而非覆盖。存量旧库启动时一次性归一化合并（保留最早一条，标签并入、维护信息补齐）。
- **网络不可达告警**：独立于端口暴露告警的新告警类型（`kind=unreachable`）：
  - 扫描过程中 naabu 报告的 DNS 解析失败逐条记录（同扫描幂等），收尾自动生成告警；即使执行因解析失败被标记为 partial 也照常检测。
  - 可选连通性探测：「系统设置 → 通知与告警」勾选「启用连通性探测」后，扫描收尾对台账中零结果的单 IP 补做 TCP 80/443 连接测试（最多 500 个、并发 8、总预算 90 秒）；超时/网络不可达才告警，连接拒绝视为主机在线不告警。默认关闭，不影响现有扫描耗时。
  - 告警内容含目标资产、失败原因（DNS 解析失败/连接超时/网络不可达）、发生时间与排查建议；复用 `realert_days` 间隔提醒、已解决再次失败自动重开、已忽略不再提醒。
  - 「风险告警」页新增类型筛选（全部/端口风险/网络不可达）与「网络不可达」标签；导出 CSV 含类型/失败原因/排查建议列；飞书结束汇总追加独立的「网络不可达」段落。
  - 不可达告警不适用端口加白：行内/处置页不展示加白按钮，API 单条拒绝、批量自动跳过。
  - 自动拆分任务同样支持：子扫描（含失败子任务）的不可达明细聚合到主扫描后统一生成告警。

### 白名单 Excel/CSV 模板导入与备注维护

- **模板列**：`IP/网段`、`端口`、`服务`、`备注` 四列（一行一条规则）。首行表头按列名自动识别（中英文候选名均可），删掉表头则按模板列序解析；需区分 UDP 或补充维护信息时自行加表头列 `协议`（tcp/udp/*）、`负责人`、`业务` 即可。模板可在导入面板下载：`/api/sample/whitelist.xlsx`、`/api/sample/whitelist.csv`。
- **端口列写法**：`22,80,443`、`1000-2000`、`*` 与 IP 列内写 `1.2.3.4:3306` 都支持；端口列留空并勾选「自动匹配已识别端口」，则取该台账内单 IP 的历史开放端口逐条入白（行内备注仍会写入自动匹配条目）。
- **两步式导入（预览 → 确认）**：页面导入先调 `POST /api/whitelist/import/preview` 只解析不写库，返回可逐条勾选的候选清单（自动匹配已展开为具体端口，已存在的规则标 `exists` 并默认不勾选）；确认后调 `POST /api/whitelist/import/apply` 只写入勾选行，写入前逐条重新校验（规则合法性、备注 ≤2000 字节、单次 ≤5000 条）并再次跳过库内重复。脚本对接可继续用一步式的 `POST /api/whitelist/import`（去重与容错规则相同）。
- **逐行容错与去重**：非法 IP/端口、非法协议、端口留空且未勾选自动匹配的行被跳过并逐条回显原因，不阻断整批入库；同批中 IP+端口+协议 完全相同的规则只入一条，与库中已有规则完全相同的条目也会跳过（提示「已在白名单」），因此线下维护的整表可反复导入。文本框与上传文件可同时提交，结果合并。
- **备注全流程**：单条添加可填备注；表格逐行备注优先，未填时用导入面板的「批量备注」兜底；列表行内「备注」按钮可直接编辑任意来源（导入/自动匹配/基线/告警加白）条目，只改备注不动匹配规则，留空即清除，均写审计流水。

### 容量与兼容

- fscan 容量按「目标数 × 单目标 5-10 分钟 / 内部线程数」估算，500 IP 默认线程下约 37 分钟，不会被误拒；≤500 规格另有小批量豁免。
- 漏洞/域名映射均为附加表（`scan_vulns`/`domain_map`），不改动 `scan_results` 与 naabu 现有流程，旧任务/旧库完全兼容。

### TLS 握手噪音统计

「运行日志」页新增「TLS 握手噪音统计」面板：展示当日/近 7 天被降级的客户端 TLS 握手失败次数与来源 /24 网段 Top 列表（IP 仅保留前 3 段掩码），帮助判断是否为持续扫描攻击；该类噪音记 info、不进入 warn/error 筛选。

---

## 七、人员日常使用流程

### 管理员：首次初始化

1. 配置并检测 naabu，确认扫描速率、重试和超时时间。
2. 立即修改本人密码，在「账号管理」中创建运营人员（`operator`）和只读人员（`viewer`），不要多人共用管理员。
3. 检查定时任务是否符合业务窗口；不需要的计划应编辑关闭，避免默认任务自动运行。
4. 配置飞书后先发送测试消息，再到「操作审计」复核关键变更。

### 运营人员：资产到风险闭环

1. 在「资产台账」导入已授权 IP，按业务/环境添加标签；若有非法跳过项，根据提示修正后重新导入，重复资产会自动去重。
2. 在「扫描任务」选择**按资产标签圈选**，先使用常用端口验证范围，再按需要配置全端口和定时计划。
3. 运行后自动进入「执行详情」，查看已处理/待处理目标、当前批次和实时追加的端口结果；需要时可暂停、恢复或确认终止当前 naabu 进程，并在事件时间线查看操作与资源告警。也可从左侧「执行记录」查看全部历史，在「扫描结果」按全端口/常用端口、执行 ID、资产或端口筛选，在「暴露面资产」跨任务检索、导出和回溯最近发现记录。
4. 初次扫描结果需逐条确认后再生成白名单基线，避免把违规端口一次性全部放行。
5. 在「风险告警」中处置：正在排查选「跟进中」；端口已关闭选「已解决」并填写工单；确认业务放行使用「加入白名单」。已解决端口再次被发现会自动重开。

### 只读人员：查询与报表

可查看资产、暴露面、任务、扫描、实时结果、执行事件、白名单和告警，并导出暴露面/告警 CSV；不能导入、启动任务、控制扫描进程、处置告警或访问系统管理页面。

> 角色权限：管理员拥有全部权限；操作员拥有日常资产与风险运营权限，但不能管理账号、审计和系统设置；只读账号仅查询和导出。

---

## 八、Ubuntu 24.04 本地测试环境部署

仓库提供打包脚本 [`deploy/ubuntu/package.sh`](deploy/ubuntu/package.sh)、安装脚本 [`deploy/ubuntu/install.sh`](deploy/ubuntu/install.sh) 与 systemd 单元 [`deploy/ubuntu/easm.service`](deploy/ubuntu/easm.service)，**仅支持 Linux（systemd + apt）**。

### 方式零：本机打包成品，一次上传（推荐）

在开发机（任意平台）交叉编译并打包，产物为成品目录 + 一个 tar.gz，**只需上传一次**：

```bash
# 默认 amd64；ARM64 服务器改用 ARCH=arm64
bash deploy/ubuntu/package.sh
# 产物：dist/easm-platform-linux-amd64-<日期>.tar.gz
# 内含 Linux 静态二进制 + config.json + install.sh + easm.service + README.md + DEPLOY.txt

# 一次上传并在服务器安装
scp dist/easm-platform-linux-amd64-*.tar.gz user@SERVER:/tmp/
ssh user@SERVER 'mkdir -p /tmp/easm && tar -xzf /tmp/easm-platform-linux-amd64-*.tar.gz -C /tmp/easm --strip-components=1 && cd /tmp/easm && sudo bash install.sh'
```

`install.sh` 检测到同级目录已有预编译 `easm-platform` 二进制时会**直接使用、跳过服务器编译**（服务器无需安装 Go）。

### 方式一：服务器端编译安装（备选）

把源码放到 Ubuntu 24.04 后，在项目根目录执行；未上传预编译二进制时，脚本会检查/安装 Go 并从源码编译：

```bash
bash deploy/ubuntu/install.sh
```

脚本依次完成：**安装最小系统依赖**（`curl`/`unzip`/`libcap2-bin`）→ **下载 naabu 官方 Linux 预编译二进制并 `setcap` 授权**（免编译）→ 平台二进制（上传优先，否则回退 Go 编译）→ 部署到 `/opt/easm` 并修正 `config.json`（naabu 绝对路径、HTTP/HTTPS 监听）→ 注册并启动 systemd 服务（开机自启 + 崩溃重启）→ **HTTP + HTTPS 双探活**并打印初始化指引。

可用环境变量覆盖默认值：

```bash
# 例如：改部署目录，且只监听本机走 SSH 隧道
APP_DIR=/srv/easm LISTEN=127.0.0.1:8000 bash deploy/ubuntu/install.sh
```

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `APP_DIR` | `/opt/easm` | 部署目录 |
| `LISTEN` | `0.0.0.0:8000` | 监听地址，测试环境默认对所有网卡开放 |
| `NAABU_PATH` | `/usr/local/bin/naabu` | naabu 固定绝对路径 |
| `SERVICE_NAME` | `easm` | systemd 服务名 |

### 方式二：手动安装基础组件

```bash
# 1) 系统依赖（unzip 解压 naabu 包，libcap2-bin 提供 setcap，build-essential 供编译本平台）
sudo apt-get update
sudo apt-get install -y curl git unzip build-essential libcap2-bin ca-certificates

# 2) Go 1.27+（Ubuntu 24.04 apt 自带 1.22 版本过低，改用官方 tar 包；仅用于编译本平台）
arch=$(dpkg --print-architecture)          # amd64 / arm64
curl -fL "https://go.dev/dl/go1.27.0.linux-${arch}.tar.gz" -o /tmp/go.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh
go version                                  # 确认 >= 1.27

# 3) naabu —— 直接下载官方预编译二进制，免编译
#    amd64 用下面的 URL；arm64 把 linux_amd64 换成 linux_arm64
curl -fsSL https://github.com/projectdiscovery/naabu/releases/download/v2.7.0/naabu_2.7.0_linux_amd64.zip -o /tmp/naabu.zip
unzip -o /tmp/naabu.zip -d /tmp/naabu
sudo cp /tmp/naabu/naabu /usr/local/bin/ && sudo chmod +x /usr/local/bin/naabu
sudo setcap cap_net_raw+ep /usr/local/bin/naabu    # 授予抓包能力，非 root 也能 SYN 扫描（免 sudo）
naabu -version
```

> `setcap cap_net_raw+ep` 后，naabu 无需 root/sudo 即可发 SYN 包，普通用户在命令行直接跑扫描也行；systemd 服务同样可降权到非 root（见 `deploy/ubuntu/easm.service` 注释）。换版本/架构到 [naabu releases](https://github.com/projectdiscovery/naabu/releases) 找对应的 `naabu_<版本>_linux_<架构>.zip`。

### 编译与安装服务

```bash
# 编译
cd /path/to/easm-platform
go build -o easm-platform .

# 部署到 /opt/easm
sudo mkdir -p /opt/easm/data
sudo cp easm-platform config.json /opt/easm/
sudo sed -i 's#"naabu_path": "naabu"#"naabu_path": "/usr/local/bin/naabu"#' /opt/easm/config.json

# 安装 systemd 服务
sudo cp deploy/ubuntu/easm.service /etc/systemd/system/easm.service
sudo systemctl daemon-reload
sudo systemctl enable --now easm
sudo systemctl status easm
tail -f /opt/easm/data/easm.log
```

### 关键说明

- **工作目录**：systemd 单元里 `WorkingDirectory=/opt/easm` 必须正确，因为 `config.json`、`data/easm.db`、`data/scan_<执行ID>/batch_*.out` 都是相对路径。
- **抓包权限**：脚本已对 naabu 执行 `setcap cap_net_raw+ep`，**非 root 也能 SYN 扫描**；systemd 单元默认仍用 `User=root`（测试环境最省事），如需降权按单元文件注释改为专用用户即可。
- **首次初始化**：登录改密并建运营账号 → 台账导入 IP 和标签 → 常用端口验证扫描 → 在暴露面复核结果 → 谨慎生成白名单基线 → 配置飞书并测试。
- **安全提醒**：测试部署默认监听 `0.0.0.0:8000` 且初始账号为 `admin/admin123`，请立即通过页面改密；如需限制访问执行 `sudo ufw allow OpenSSH && sudo ufw enable`，或把 `LISTEN` 设为 `127.0.0.1:8000` 走 SSH 隧道。
- **升级**：重新 `go build` 覆盖 `/opt/easm/easm-platform` 后 `sudo systemctl restart easm` 即可，数据库与配置不受影响。


