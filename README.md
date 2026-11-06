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

平台默认使用 CONNECT 扫描，无需 root。SYN 扫描需要 root 或给 naabu 授予 `CAP_NET_RAW`；权限不足时会在执行详情中显示 naabu 的错误输出，可改用 CONNECT，不需要用 root 运行整个 Web 平台。

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
| `naabu_path` | `naabu` | naabu 可执行文件路径，可为绝对路径 |
| `naabu_rate` | `2000` | 发包速率（包/秒），影响扫描耗时 |
| `realert_days` | `7` | 同一暴露面重复告警的间隔天数 |
| `alert_out_of_scope` | `true` | 台账外 IP 是否也告警 |
| `feishu.webhook` / `feishu.secret` | 空 | 飞书机器人 Webhook 与加签密钥 |
| `admin.user` / `admin.password` | `admin` / `admin123` | 仅用于 users 表为空时创建首个管理员 |

以上基础配置也可在「系统设置」页面在线修改并持久化到数据库。「系统设置」按 **网络监听 / TLS 证书 / 通知与告警 / naabu 参数（含资源监测）/ AI 分析 / 异常排查** 拆分为独立面板，顶部胶囊导航可锚点跳转，**各类单独保存、互不覆盖**（后端按提交字段部分更新）。页面另提供 CONNECT/SYN、响应等待时间、内部并发线程、扫描并发度（并行 naabu 批次数）、排除端口、指定网卡、TCP 二次验证及任务总超时；每项均附作用说明和格式校验，保存后立即生效。 CONNECT 无需特殊权限；SYN 需要 root 或 `CAP_NET_RAW`。响应等待过短可能漏报，重试、并发和 TCP 二次验证会增加耗时或资源消耗。

「系统设置 → naabu 资源监测」默认开启，每 5 秒采样当前 naabu 进程的 CPU 和 RSS 内存。默认 CPU 阈值为 90%、内存阈值为 1024 MiB，任一指标持续 30 秒超阈值才告警；CPU 的 100% 表示占满一个逻辑核。资源监测只记录执行事件、日志并发送飞书通知，**不会自动暂停或终止任务**；未配置飞书 Webhook 时不影响扫描。

---

## 五、扫描耗时估算

单次扫描把所有台账 IP 写入一个列表交给 naabu 一次性并发执行，`naabu_rate` 为**全局共享**的发包速率。单个 IP 的理论耗时：

```
耗时 ≈ (端口数 × 每端口探测次数) / rate + 启动开销
```

以默认 `rate=2000` 估算单个 IP：

| 模式 | 端口数 | 理论最快 | 实际预估 |
|------|--------|----------|----------|
| 常用端口 top-1000 | 1000 | ~0.5 秒 | 约 1~10 秒 |
| 全端口 1-65535 | 65535 | ~33 秒 | 约 30 秒 ~ 2 分钟 |

实际耗时受 naabu 重试（`naabu_retries`，默认 2，被防火墙丢包的端口会重试）、有效扫描总超时（`scan_timeout_min`，默认 60 分钟）、响应等待、扫描方式等因素影响。想加速可在「系统设置」调高 `naabu_rate`，或优先使用 top 模式。

为提供真实目标进度，平台按每批最多 20 个目标规格切分，并按**扫描并发度**（`scan_concurrency`，默认 3，可在系统设置调整，1=串行）**并行调用多个 naabu 进程**扫不同批次，总发包吞吐≈并发度×`naabu_rate`；每批结束后更新已处理、待处理和异常目标数。任务总超时对所有批次的有效扫描时间合并计算，不是每批单独计时，**暂停时长不计入超时**（暂停会冻结全部并行进程）。提高并发度可显著提速，但会增加 CPU/内存/网络占用，需按服务器与目标网络承受能力调整。

---

## 六、功能一览

- **资产台账**：粘贴 / CSV / TXT / XLSX 导入，支持 **单 IP / CIDR 网段 / IP 范围 / 域名**四种类型，自动去重、去 BOM；返回合法、新增、非法跳过数量及非法样例，不再静默丢弃。资产含**维护人员（owner）**与**安全设备标识（security_device）**可选字段，旧存量默认留空、不影响扫描与告警。导入与**手动添加单条**均为按钮触发模态面板，导入回显明细（新增/跳过/非法示例）；CSV/XLSX 可按「目标, 维护人员, 安全设备」列头批量带入维护信息。列表新增「维护人员」「安全设备」两列并支持关键词检索，行内「编辑」可改维护人员/安全设备/标签、「删除」独立于批量栏；**复选框 + 全选 + 批量修改标签**（追加/覆盖/清空）与**批量删除**；支持「已打/未打标签」快捷筛选与 **CSV 导出（含新字段）**；格式说明与样例下载收敛到「帮助 / 模板」按钮。
- **暴露面资产**：跨扫描按 `IP + 端口 + 协议` 聚合，展示首次/最近发现、出现次数、白名单和告警状态；支持 IP/服务、端口、协议查询与 **CSV 导出**，可下钻最近扫描和相关告警；非只读账号支持勾选**批量加白**、**批量修改关联资产标签**与行内一键加白。聚合视图表示历史探明结果，不等同于实时在线状态。
- **扫描任务**：支持**全部台账 / 按标签动态圈选 / 手工目标**三种范围；扫描模式支持常用端口 top-1000 / 全端口 1-65535 / **自定义端口**（`22,80,8000-9000`，新建表单实时校验非法端口并附 Top1000 说明）；可即席运行、保存复用或挂每日/每周计划；手工目标可选择加入台账；列表与新建/编辑分页，全局单任务串行。手动和定时执行共用进度统计，任务页显示已处理、待处理、异常目标、当前批次和百分比。管理员和操作员可暂停、恢复或终止当前执行；Linux/macOS 通过进程组信号实际控制 naabu，暂停仍占用全局扫描锁，终止会停止整个进程组及后续批次。其他平台可终止当前进程，但暂停/恢复会明确提示不支持。任务列表「上次运行」列可点击直达对应执行详情。
- **执行记录**：独立页面保留每次已接受执行的任务，不再只显示最近 50 条；支持按任务、运行、暂停、完成、部分完成、终止、失败状态、全端口/常用端口和关键词筛选。每次执行名称自动追加扫描模式与执行时间，避免同名定时任务的历史记录混淆；删除任务定义不删除历史执行。
- **扫描容错**：naabu 带 `-retries` 重试、有效扫描**超时保护**（防卡死占用锁）、**标准输出/错误输出捕获**；即使进程异常或超时，已解析结果仍保留并标为「部分完成」，但不基于不完整结果生成告警。用户或平台终止后状态为「已终止」，保留终止前结果和真实进度，不执行白名单比对及端口风险告警；服务正常退出也会清理当前 naabu 进程。**状态自愈**：服务重启时自动把残留的运行中/暂停执行修正为已终止（进程已随重启消失），`run()` 对 panic 做 recover 并修正状态，执行详情页对悬空状态提供「重新同步状态」按钮。
- **执行详情**：展示目标规格数、开始/结束时间、目标处理进度、当前/最近批次命令、开放端口、资源当前值/峰值、执行事件及完整异常。naabu 标准输出逐行解析，结果达到 50 条或约 500ms 即入库，批次结束再从原始输出文件去重补齐；页面每 2 秒按游标追加新结果并更新状态，无需等待任务结束或整页刷新；暂停/恢复/终止为独立醒目按钮（终止为危险色）。路径/权限/架构/自检超时、目标解析、文件读写、数据库保存、进程退出和任务总超时均说明失败阶段与处理建议。
- **扫描结果**：独立页面按单次执行展示开放端口，保留执行名称、模式和时间来源；支持全端口/常用端口、执行 ID、任务、IP/服务及端口查询与 **CSV 导出**，不再混淆不同任务或不同扫描模式的结果。
- **白名单**：单条添加 + **批量导入**（IP + 多端口逗号分隔，兼容空格/冒号/范围/tcp-udp）；支持单 IP / CIDR / 通配。**操作按钮化分区**：「单条添加 / 批量导入 / 生成基线 / 帮助说明」各自独立按钮与面板，互不混杂；附**白名单使用说明文档页**；支持关键词检索与 CSV 导出。条目含**业务归属**字段，可按业务筛选；单条添加与基线生成均可填写业务归属。
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


