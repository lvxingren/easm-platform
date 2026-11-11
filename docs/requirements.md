# 灵瞰 EASM 平台 — 需求清单与完成度核对

> 本文档依据仓库当前实际实现（路由表、handler、模板与存储层）逐项核对生成，作为历史需求与完成度的唯一核对清单。
> 已实现功能标注来源文件；待完善项附描述与建议优先级（P0/P1/P2），用于指导后续迭代排期。
> 生成基线：`go build ./...`、`go vet ./...` 全部通过（最近一次核对）。

---

## 〇、仓库上传状态梳理

> 远端为 **GitHub**（非 GitLab）：`git@github.com:lvxingren/easm-platform.git`，主分支 `main`，提交格式 `type(scope,...): 中文摘要`。`data/`、`config.json`、`dist/`、数据库与证书私钥由 .gitignore 与推送护栏排除。

| 层级 | 内容 | 状态 |
|------|------|------|
| 已上传 origin/main（7 个提交，至 `c3d234a`） | 初始化仓库 + 推送护栏技能；v1.0.0/v1.0.1 版本化发布；扫描批次并行（scan_concurrency）+ SQLITE_BUSY 修复；容量预算与后处理流式化；容量预检自动拆分降级 | 远端可见 |
| 本地已提交未推送（`cff1cd0`） | fscan 三模式引擎（纯端口/漏洞/混合）+ 超阈值自动拆分聚合；终止后增量续扫（resume_of）；域名资产解析（DoH/Subfinder）；TLS 握手噪音治理；默认取消任务超时与并发参数上调；侧边栏层级重组折叠 | 待推送 |
| 本地未提交（19 处修改 + 9 个新文件） | UDP 端口扫描（全局 + 任务级开关）；白名单自动匹配已识别端口；资产台账分页；域名详情页与资产分类标记；审计对象类型/日期组合筛选；导航分域色条；log_level 日志级别热生效 | 待提交并推送 |

---

## 一、已实现功能清单（按模块）

### 1. 资产台账

| 功能 | 说明 | 来源 |
|------|------|------|
| 批量导入 | 粘贴 / CSV / TXT / XLSX，支持单 IP / CIDR / 范围 / 域名，自动去重、去 BOM，回显新增/跳过/非法样例 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go)、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) |
| 全局去重增强（本轮新增） | 导入/手动添加统一经 `NormalizeTargetSpec` 归一化：等价 CIDR（未掩码→掩码对齐）、大小写/尾点域名、IPv4 映射 IPv6、范围去空白均视为同一资产；批内重复+库内已存在合并计入「跳过数量」回显；`targets.ip` UNIQUE 约束兼并发安全；启动时存量旧库一次性归一化合并（标签并入、维护信息补齐、保留最早一条） | [store_target_norm.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store_target_norm.go)、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) `ImportAssetsDetailed` |
| 手动添加单条 | 维护人员、安全设备、标签可选字段；重复资产提示不重复添加 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 行内编辑 / 删除 | 编辑不改动 IP/域名主标识，删除独立于批量栏 | 同上 |
| 批量操作 | 全选 + 批量修改标签（覆盖/追加/清空）+ 批量删除（本轮新增） | 同上 |
| 检索与导出 | 关键词（IP/域名/标签/来源/维护人员/安全设备）、标签与「已打/未打标签」筛选；CSV 导出含全部字段 | 同上 |
| 样例文件 | CSV / XLSX / TXT 样例下载，格式说明收敛到「帮助 / 模板」按钮 | 同上 |
| 分页浏览（本轮新增） | 每页 20/50/100 可选（默认 20，localStorage 持久化）；后端 `GET /api/assets` 支持 `page`/`page_size`（上限 100）返回记录+总条数+总页数；导航可跳转；导出 CSV 不受分页限制 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go)、[assets.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/assets.html) |
| 资产分类与服务标记（本轮新增） | 类型列彩色 pill 区分 IP/CIDR/Range/Domain；域名行内展示历史服务指纹（HTTP/SSH/DNS 等）与安全设备；域名详情页 `/assets/domain/{domain}` 含关联端口子面板（domain_map 衍生 IP 开放端口）与一键加白所有衍生 IP 端口 | [domain_detail.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/domain_detail.html)、[web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) |

### 2. 扫描任务

| 功能 | 说明 | 来源 |
|------|------|------|
| 三种任务范围 | 全部台账 / 按标签动态圈选 / 手工目标（可选加入台账） | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 自定义端口模式 | 扫描模式支持 top-1000 / 全端口 / **自定义端口**（`22,80,8000-9000`）；表单实时校验 + 后端 `ValidatePortList`，naabu 拼 `-p`；`scan_tasks.custom_ports` 旧库 ALTER 兼容 | [scanner.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner.go)、[task_form.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/task_form.html)、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) |
| 定时计划 | 每任务独立每日/每周计划，到期跳过修正、同周期只执行一次、停机补跑 | [scheduler.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scheduler/scheduler.go) |
| 任务列表定位 | 「上次运行」列可点击直达对应执行详情（本轮优化） | [tasks.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/tasks.html) |
| 全局串行 | 单任务串行执行，运行中冲突等待后续轮询重试 | [scheduler.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scheduler/scheduler.go) |
| 任务级 UDP 开关（本轮新增） | 任务表单「启用 UDP 端口扫描」开关（默认取全局 `scan_udp`，可单独覆盖）；勾选后 settings 快照 `scan_udp=1` 强制 SYN+UDP，`scans.udp_enabled` 可追溯；未勾选为纯 TCP；仅 naabu 引擎生效 | [task_form.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/task_form.html)、[scanner.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner.go)、[scanner_udp.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner_udp.go) |

### 3. 端口扫描与执行详情

| 功能 | 说明 | 来源 |
|------|------|------|
| 扫描引擎 | naabu / fscan 双引擎调用、`-retries` 重试、标准输出/错误捕获、分批（每批 ≤20 目标）；默认不设任务超时（`scan_timeout_min=0`），存量旧默认值自动迁移 | [scanner.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner.go)、[execution.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/execution.go)、[config.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/config/config.go) |
| fscan 多模式引擎 | 纯端口 / 漏洞检测 / 混合三模式，自定义端口校验，超容量阈值自动拆分并聚合子扫描结果与漏洞明细 | [fscan.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/fscan.go) |
| UDP 端口扫描（本轮新增） | 设置页「同时扫描 UDP 常用端口」+ 自定义 `udp_ports`（DNS/DHCP/NTP/SNMP 等）；启用后自动切 SYN 并以 `-p u:` 同批扫描；需 root/CAP_NET_RAW，权限不足自动降级仅 TCP 并在事件/日志明确提示；结果按 `protocol=udp` 入库 | [scanner_udp.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner_udp.go)、[settings.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/settings.html) |
| 增量续扫 | 终止后按目标四态处理状态一键续扫（`POST /api/scans/{id}/resume`），`resume_of` 关联父执行，保留已完成结果；旧执行无入口，运行中/暂停中拒绝续扫 | [scanner_resume.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner_resume.go)、[store_target_status.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store_target_status.go) |
| 域名资产解析 | net.Resolver + DoH 回退 + Subfinder/种子子域，衍生 IP 入台账并纳入扫描 | [engine_dns.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/engine/engine_dns.go)、[scanner_domain.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner_domain.go) |
| 实时详情页 | 每 2 秒按游标增量追加新结果与事件，无需整页刷新 | [handlers_scan_live.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_scan_live.go) |
| 进程控制 | 暂停/恢复/终止（Linux/macOS 进程组信号），按钮醒目化（本轮优化） | [control.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/control.go)、[scan_detail.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/scan_detail.html) |
| 并行批次执行 | 按 `scan_concurrency`（默认 3，1=串行）并行运行多个 naabu 进程扫不同批次，总吞吐≈并发度×rate；共享去重集/进度计数加锁，暂停/终止作用于全部并行进程；SQLite 走 DSN `_pragma` 保证每连接 busy_timeout 以支撑并发写 | [execution.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/execution.go)、[control.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/control.go)、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) |
| 资源指标与事件 | CPU/RSS 每 5 秒采样、当前值/峰值/阈值告警、执行事件时间线 | [resource.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/resource.go) |
| 执行记录 | 独立页面保留全部已接受执行，按状态/模式/任务/关键词筛选 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 状态自愈 | 启动修正残留 running/paused 为 stopped（`HealStaleScans`）、`run()` panic recover 修正、详情页「重新同步状态」按钮（`ForceStopScanIfActive` 幂等） | [main.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/main.go)、[execution.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/execution.go)、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go)、[scan_detail.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/scan_detail.html) |

### 4. 暴露面聚合

| 功能 | 说明 | 来源 |
|------|------|------|
| 跨扫描聚合 | 按 IP + 端口 + 协议聚合，展示首次/最近发现、出现次数、白名单与告警状态 | [store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go)、[handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 多维度筛选 | IP/服务关键词 + 端口 + 协议（tcp/udp）；新增域名列与 `domain=` 反查（本轮新增） | 同上 |
| CSV 导出 | 含白名单与告警状态列，公式注入防护（前导 `=+-@` 加 `'`）+ BOM | 同上 |
| 批量操作（本轮新增） | 勾选批量加白、批量修改关联资产标签、行内一键加白 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go)、[exposure.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/exposure.html) |

### 5. 白名单管理

| 功能 | 说明 | 来源 |
|------|------|------|
| 分区按钮化 | 单条添加 / 批量导入 / 生成基线 / 帮助说明各自独立按钮与面板 | [whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) |
| 批量导入 | IP + 多端口逗号分隔，兼容空格/冒号/范围/tcp-udp；支持单 IP / CIDR / 通配 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 基线生成 | 一键把最近一次完成扫描结果全部加入白名单 | 同上 |
| 检索与导出 | 前端关键词检索（本轮新增）+ CSV 导出（本轮新增） | [whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) |
| 说明文档页 | 白名单使用说明独立页面 | [whitelist_help.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist_help.html) |
| 业务归属字段 | 条目含 `business` 字段（旧库 ALTER 兼容），列表新增「业务」列并支持按业务筛选；单条添加与基线均可填写 | [store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go)、[whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) |
| 基线预览 | 「生成基线」先预览最近完成扫描中尚未加白的端口（≤2000 条），可逐条勾选 + 批量填业务归属，确认后写入（owner=baseline） | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go)、[whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) |
| 自动匹配已识别端口（本轮新增） | 批量导入勾选后，台账内单 IP 自动查询 `scan_results` 历史开放端口生成条目（`source=auto_match`，列表 auto 徽章）；手动 IP+端口 行记 `source=manual`，回显区分两类数量；CIDR/范围/台账外跳过并提示 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go)、[store_udp_whitelist.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store_udp_whitelist.go)、[whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) |
| 备注全流程可维护（本轮新增） | 单条添加可填备注；批量导入新增「批量备注」字段（兜底应用到本批未填备注的条目，含自动匹配）；列表行内「备注」按钮直接编辑任意来源条目（导入/基线/告警加白），只改备注不动匹配规则，留空即清除，保存后同步检索文本并写审计；`POST /api/whitelist/{id}/remark`（operator/admin，≤2000 字节） | [web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) `apiUpdateWhitelistRemark`、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) `UpdateWhitelistRemark`、[whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) |
| Excel/CSV 模板导入（本轮新增） | 批量导入可上传表格文件，模板列 **IP/网段 + 端口 + 服务 + 备注**（可选加列 协议/负责人/业务）：首行表头按列名自动识别，删掉表头则按模板列序解析；端口列支持 `22,80,443`/`1000-2000`/`*`/留空（留空 + 勾选自动匹配 = 取该 IP 已识别端口，行内备注仍写入）；逐行容错（非法 IP/端口/协议、批内规则重复均跳过并回显原因，不阻断整批）；与库内已有规则（IP+端口+协议）完全相同的条目跳过并提示「已在白名单」（`store.WhitelistRuleKey`/`WhitelistRuleSet`，整表可反复导入）；行内备注优先于批量备注；文本框与文件可同时提交；模板可下载 `/api/sample/whitelist.xlsx`、`/api/sample/whitelist.csv` | [whitelist_import.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/whitelist_import.go) `identifyWhitelistColumns`/`parseWhitelistTable`/`dedupeWLEntries`/`dedupeAgainstRules`、[web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) `apiImportWhitelist`、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) `WhitelistRuleSet`、[handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) `apiSample`、[whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html)、[whitelist_help.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist_help.html) |
| 两步式预览导入（本轮新增） | 页面导入拆为「解析预览 → 确认导入」：`POST /api/whitelist/import/preview` 只解析不写库，返回逐条可勾选的候选清单（自动匹配已展开为具体端口、`exists` 标记库内已有规则并默认不勾选、附跳过原因与 `truncated` 展示上限提示）；`POST /api/whitelist/import/apply` 只写入勾选行，写入前逐条重新校验（`engine.ValidateEntry`、备注 ≤2000 字节、单次 ≤5000 条）并再做一轮库内同规则去重（客户端数据不可信）；一步式 `POST /api/whitelist/import` 保留给脚本对接，三者共用 `buildWhitelistImportPlan` 解析链 | [whitelist_import.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/whitelist_import.go) `buildWhitelistImportPlan`/`apiWhitelistImportPreview`/`apiWhitelistImportApply`、[whitelist.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/whitelist.html) `previewWlImport`/`applyWlImport` |

### 6. 风险告警处置

| 功能 | 说明 | 来源 |
|------|------|------|
| 告警生成 | 白名单比对、范围内外判断、`realert_days` 重复提醒、解决后重开、忽略不再提醒；每次扫描收尾自动执行（done/stopped），拆分任务先聚合子扫描结果再对主扫描比对 | [engine.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/engine/engine.go) |
| 网络不可达告警（本轮新增） | 独立于端口告警（`alerts.kind=unreachable`）：naabu 报告的 DNS 解析失败逐条落 `scan_unreachable` 明细（同扫描幂等）；可选连通性探测（设置 `unreachable_probe=1`，对台账零结果单 IP 补做 TCP 80/443 测试，≤500 个/90 秒预算，连接拒绝视为可达）；不受 partial/failed 终态门禁；告警含目标/原因/发生时间/排查建议，复用 realert 间隔、resolved 重开、ignored 屏蔽；告警页「网络不可达」类型筛选/处置/导出（含原因与建议列）；不适用端口加白（单条拒绝、批量自动跳过）；拆分任务聚合含失败子任务的不可达明细 | [engine_unreachable.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/engine/engine_unreachable.go)、[store_unreachable.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store_unreachable.go)、[alerts.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/alerts.html) |
| 批量处置 | 勾选多条统一改为跟进中/已解决/已忽略/重新打开，解决与忽略需填统一说明 | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 一键加白 | 行内单条加白（本轮新增）+ 批量加白并忽略 + 暴露面批量加白 | 同上、[alerts.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/alerts.html) |
| 关联资产标签 | 按选中告警 IP 批量修改台账资产标签（匹配数回显） | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 筛选与导出 | 状态/关键词筛选 + CSV 导出 | 同上 |

### 7. 飞书通知

| 功能 | 说明 | 来源 |
|------|------|------|
| 推送通道 | Webhook + HMAC-SHA256 加签，设置页支持测试发送；HTTPS 强制 HTTP/1.1 短连接、网络层错误自动重试（最多 3 次，重试阶段切换公共 DNS/DoH 重新解析域名）、Webhook 主机限飞书官方域名 | [feishu.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/notify/feishu.go) |
| 结束汇总 | 每次任务结束仅发送一条汇总：状态、目标进度、资源峰值与触发次数、新增风险告警清单、端口/漏洞发现统计、耗时；本轮新增「网络不可达」独立段落（总数+有界样本+原因） | [engine.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/engine/engine.go) |

### 8. 账号 / 审计 / 日志

| 功能 | 说明 | 来源 |
|------|------|------|
| RBAC | 管理员 / 操作员 / 只读三级；PBKDF2-SHA256 密码；防删最后管理员；停用/删改即时生效 | [handlers_admin.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_admin.go)、[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) |
| 操作审计 | 登录与全部写操作落库（用户/角色/操作/对象/详情/来源 IP）；关键词+用户名筛选 + CSV 导出（仅管理员）；本轮新增「对象类型」下拉（登录/导入资产/创建任务/启动扫描/加白/批量处置等 14 类）+ 起止日期组合查询，「对象」列 IP 跳转暴露面、`#扫描ID` 跳转执行详情 | [store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go)、[handlers_admin.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_admin.go)、[audit.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/audit.html) |
| 运行日志 | 进程内环形缓冲（默认 3000 条），按 info/warn/error 分级、级别筛选、关键词检索、只看报错、每 3 秒实时追加；TLS 握手噪音降级治理 + 噪音统计面板 | [handlers_logs.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_logs.go)、[applog.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/applog/applog.go)、[tlsnoise.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/applog/tlsnoise.go) |
| 日志级别控制（本轮新增） | `config.json.log_level` 默认 `warn`，仅控制 stderr 最低输出级别；环形缓冲始终全量，页面分级检索不受影响；设置页「异常排查」热生效 | [config.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/config/config.go)、[applog.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/applog/applog.go)、[settings.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/settings.html) |

### 9. AI 溯源分析

| 功能 | 说明 | 来源 |
|------|------|------|
| 日志导入 | CFW 防火墙 / ECS 云主机日志（CSV/JSON/TXT/XLSX），自动识别中英文列头 | [logparse.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/logparse/logparse.go) |
| 分析引擎 | OpenAI 兼容接口，未配置时内置规则降级（离线可用） | [ai.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/ai/ai.go) |
| 报告渲染 | 拓扑摘要、内嵌 SVG 交互拓扑图、异常通信高亮、溯源路径步骤、通信关系表、结果 IP 加白/创建告警联动 | [handlers_analysis.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_analysis.go)、[analysis.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/analysis_detail.html) |

### 10. 网络、安全与部署

| 功能 | 说明 | 来源 |
|------|------|------|
| 网络配置 | HTTP/HTTPS 双监听、自签名证书自动生成与在线上传热生效、SAN 配置 | [handlers_network.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_network.go)、[cert.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/cert/cert.go) |
| 导出防护 | 全部 CSV 导出统一防公式注入 + BOM | [handlers_ext.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/handlers_ext.go) |
| 部署 | Ubuntu systemd 打包/安装脚本，预编译二进制免服务器编译 | [deploy/ubuntu](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/deploy/ubuntu) |
| 旧库兼容 | 启动自动迁移补列、可空列 COALESCE 兜底 | [store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go) |

### 11. Web UI 布局与交互

| 功能 | 说明 | 来源 |
|------|------|------|
| 顶栏两级大标题 | 每个页面顶栏展示「领域 eyebrow + 模块大标题」，领域由导航高亮项派生（概览/资产/扫描/防护/风险/分析/系统管理） | [web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) `sectionOf`、[base.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/base.html) |
| 侧边栏领域分组 | 导航按 概览/资产/扫描/防护/风险/分析/系统管理 七领域分组，与顶栏 eyebrow 一致；支持层级折叠（cff1cd0）；本轮新增分域色条：安全运营项主色左条（`.sec-op`）、系统管理项灰色左条（`.sys-admin`） | [base.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/base.html)、[style.css](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/static/style.css) |
| 面板小标题分组 | 各页筛选/操作/批量面板均带 `.panel-title` 小标题（检索与筛选、批量操作、白名单操作等），表格上方有 `.section-head` 标明记录数 | 全部列表模板（[assets.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/assets.html) 等） |
| 系统设置分模块 | 设置页拆分为 网络监听 / TLS 证书 / 通知与告警 / naabu 参数（含资源监测）/ AI 分析 / 异常排查 六个独立面板，各带独立表单与保存按钮，顶部胶囊分类跳转 | [settings.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/settings.html) |
| 设置按类别部分保存 | `/api/settings` 按提交字段部分更新，各类别独立保存互不覆盖（SaveSettings 只写提交的键） | [web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) `apiSaveSettings` |
| 空状态引导按钮 | 资产/白名单/分析/任务/仪表盘空状态含引导文案与操作按钮（角色安全，viewer 不见写操作按钮） | 各列表模板 |
| 双主题与响应式 | 深浅双主题（CSS 变量）、≤560/≤900/≤1200/≥1600/≥2000 断点、汉堡抽屉导航、prefers-reduced-motion 与 backdrop-filter 降级 | [style.css](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/static/style.css)、[base.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/base.html) |

---

## 二、待完善 / 待增强清单（附优先级）

### P0 — 影响大规模使用或数据可用性，建议优先排期

1. ~~**资产台账分页缺失**~~ ✅ 本轮已完成：后端分页（page/page_size，上限 100）+ 前端分页控件与 localStorage 持久化，导出 CSV 不受分页限制。
2. **风险告警分页缺失** — 告警列表同样一次性渲染，长期运营后告警量增长会明显卡顿。建议：按状态/关键词分页，默认仅加载待处理。
3. **运行日志重启即丢失且不可导出** — 环形缓冲仅在进程内存，服务重启即清空，无法追溯历史故障。建议：落盘轮转（如 `data/logs/` 按天/按大小）+ 页面导出按钮。
4. **多副本部署不支持（session 存内存）** — 登录会话保存在进程内存，负载均衡/多实例下登录态不共享、重启全员掉线。建议：会话迁移到 SQLite/Redis，或至少在文档中明确单实例约束并支持配置外部会话存储。

### P1 — 显著影响体验或运营效率

5. **仪表盘无趋势图表与自动刷新** — 首页为静态概览卡片（告警卡已可点击跳转告警页，本轮优化）。建议：新增最近 7/30 天暴露面与告警趋势图 + 定时自动刷新。
6. **审计页无分页** — 本轮已补齐关键词/用户名筛选检索与 CSV 导出，但页面仍一次性渲染 2000 条。建议：前端分页或虚拟滚动。
7. **白名单无有效期与命中统计** — 本轮已补业务归属字段与按业务筛选，但条目仍无法到期自动失效、也无「被命中多少次」统计，长期维护困难。建议：增加有效期字段（到期自动停用）与命中计数展示。
8. **暴露面 / 扫描结果页无分页** — 聚合视图固定 limit 1000、结果页一次性渲染。建议：分页或虚拟滚动 + 「加载更多」。

### P2 — 增强项，视业务节奏排期

9. **飞书模板不可自定义且仅单渠道** — 汇总文案固定、仅支持一个机器人 Webhook。建议：模板变量（状态/进度/峰值/清单可定制）+ 多 Webhook 按告警级别路由。
10. **登录安全加固** — 无失败次数锁定、验证码或 MFA，公网暴露时存在爆破风险。建议：连续失败锁定 + 可选验证码/MFA。
11. **审计日志无保留策略** — audit_log 无限增长。建议：按保留天数/条数定期归档清理策略（清理本身也写审计）。
12. **数据库备份无自动化** — 单文件 SQLite 依赖手工备份。建议：定时备份或 WAL 模式 + 快照脚本，纳入部署文档。
13. **告警通知渠道单一** — 除飞书外无邮件/企业微信/钉钉等通道。建议：抽象通知接口，多渠道按告警级别路由。
14. **设置页 naabu 参数与资源监测共用一个表单**（P2）— 资源监测字段与 naabu 扫描参数同属一个保存单元（受 `NaabuSettings.Validate` 整体校验约束，拆分需先抽出资源字段独立校验）。建议：抽出资源监测独立校验，使其成为完全独立的保存面板。
15. **顶栏领域标签为静态派生**（P2）— 领域由 `sectionOf(active)` 硬编码映射，新增页面需同步维护。建议：将领域映射下沉到路由注册表或页面元数据，避免遗漏。
16. **空状态操作按钮覆盖不全**（P2）— 已覆盖资产/白名单/分析/任务/仪表盘，暴露面与告警空状态仍仅文案。建议：补充引导按钮（如「去运行扫描」「调整筛选」）。
17. **无全局面包屑导航**（P2）— 顶栏为「领域+标题」两级，未提供可点击面包屑回溯。建议：详情页（执行详情/告警处置/分析详情）增加面包屑链路。

---

## 三、UI/UX 体验优化专项（用户故事与验收标准）

> 本节记录本轮「Web UI 布局与视觉层级优化」的用户故事与验收标准，作为后续回归核对依据。

### 3.1 全局大标题与领域层级

- **用户故事**：作为运营人员，我在任意页面都能在顶栏看到当前所属领域与模块名，以便快速定位自己处于哪个功能区。
- **验收标准**：
  - 顶栏左侧展示两级标题：上方小字领域标签（带强调色方块），下方模块大标题。
  - 领域映射：仪表盘→概览；资产台账/暴露面→资产；扫描任务/执行记录/扫描结果→扫描；白名单→防护；风险告警→风险；流量分析→分析；账号/审计/日志/设置→系统管理。
  - 侧边栏导航分组与顶栏领域一致。
  - 来源：[web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) `sectionOf`、[base.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/base.html) `.page-heading`/`.page-eyebrow`。

### 3.2 页面内小标题分组

- **用户故事**：作为管理员，我希望每个功能区（筛选、批量操作、单条添加等）都有清晰小标题，避免按钮堆砌。
- **验收标准**：
  - 所有筛选/操作面板顶部有 `.panel-title` 小标题；表格上方有 `.section-head` 标明记录数。
  - 白名单页「单条添加 / 批量导入 / 生成基线 / 帮助说明」按钮分组清晰。
  - 批量操作栏独立于筛选栏，且带「批量操作」小标题。

### 3.3 系统设置分模块

- **用户故事**：作为管理员，我希望系统设置按类别分面板、每类独立保存，避免一处改动影响全部配置。
- **验收标准**：
  - 设置页含 网络监听 / TLS 证书 / 通知与告警 / naabu 参数（含资源监测）/ AI 分析 / 异常排查 六个独立面板。
  - 顶部胶囊导航可锚点跳转，跳转不被 sticky 顶栏遮挡（`scroll-margin-top`）。
  - 每个可编辑面板有独立「保存」按钮与结果提示框。
  - 提交某一类只更新该类，其余类别原值不变（后端按字段部分更新，空提交返回 400）。
  - 来源：[settings.html](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/templates/settings.html)、[web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go) `apiSaveSettings`。

### 3.4 按钮与操作分区

- **用户故事**：作为操作员，我希望导入/导出/加白/处置等按钮按功能归类，互不混杂。
- **验收标准**：操作按钮归入 `.btn-group` 或独立面板；筛选栏（查询/重置/导出）与写操作栏（添加/导入/批量）分区呈现。

### 3.5 空状态与确认提示

- **用户故事**：作为新用户，数据为空时我希望看到引导文案与下一步操作按钮；执行危险操作前希望有确认。
- **验收标准**：
  - 数据为空时展示 `.empty` 引导文案 + 操作按钮（角色安全，viewer 不见写操作按钮）。
  - 删除/终止/批量处置/生成基线等关键操作前有 `confirm` 确认。

### 3.6 响应式适配

- **用户故事**：作为用户，我在手机、平板与大屏上都能正常使用，侧边栏可折叠，表格不溢出。
- **验收标准**：
  - ≤560px 单列卡片、紧凑顶栏；≤900px 侧边栏抽屉化 + 汉堡按钮 + 遮罩；≥1600px/≥2000px 内容区与卡片按比例扩展。
  - 表格 `.table-wrap` 横向滚动不溢出；双主题切换正常；遵循 prefers-reduced-motion 与 backdrop-filter 降级。

---

## 四、核对结论

- 核心链路（资产 → 扫描 → 暴露面 → 白名单 → 告警处置 → 飞书 → AI 溯源）全部贯通，RBAC 与审计覆盖全部变更类操作。
- 「整体功能与体验优化」落地项：告警行内一键加白、暴露面批量加白/批量改标签/行内加白、资产批量删除、扫描结果/白名单/审计三处 CSV 导出、审计页筛选检索、白名单页检索、扫描控制按钮醒目化、任务列表直达执行详情、仪表盘告警卡可点、飞书汇总增加耗时字段。
- 「Web UI 布局与视觉层级优化」落地项：顶栏领域+模块两级大标题、侧边栏七领域分组、各页面板小标题分组、系统设置拆分为六个独立面板并按类别部分保存、空状态引导按钮、分类跳转胶囊导航。
- 「功能增强与体验优化」落地项：各列表页导出当前筛选（补 results 导出按钮）、搜索框视觉美化、批量删除空选择提示透传后端错误、白名单业务归属字段+基线预览面板、执行状态启动自愈+panic recover+手动重新同步、自定义端口扫描、架构升级评估文档（docs/architecture-upgrade.md）。
- 「fscan 多模式与续扫」落地项（cff1cd0，待推送）：fscan 三模式引擎与超阈值自动拆分聚合、终止后增量续扫、域名资产解析入台账、TLS 噪音治理、默认无超时与并发参数上调。
- 「本轮新增」落地项（未提交）：UDP 端口扫描（全局+任务级，权限不足降级提示）、白名单自动匹配已识别端口、资产台账分页、域名详情页与资产分类服务标记、审计对象类型/日期组合筛选与对象跳转、导航分域色条、log_level 热生效。
- 「三项优化」落地项（本轮，未提交）：① 资产全局去重增强（规格归一化+批内/库内合并+跳过数回显+存量迁移，覆盖 IP/CIDR/Range/Domain）；② 聚合/白名单/realert 链路回归核对通过并新增测试（三维匹配、间隔抑制、resolved 重开、ignored 屏蔽）；③ 网络不可达告警（DNS 失败采集+可选连通性探测+独立类型筛选/处置/导出+飞书独立段落+加白防护）。新增测试：store 3 个、engine 5 个、web 2 个，全量 `go test ./...` 通过。
- 「白名单备注与模板导入」落地项（本轮，未提交）：备注覆盖「添加 → 导入 → 行内编辑」全流程（`POST /api/whitelist/{id}/remark`，只改备注不动匹配规则）；批量导入新增 Excel/CSV 模板（IP/网段 + 端口 + 服务 + 备注，可选 协议/负责人/业务 列），表头名自动识别、无表头按模板列序，非法行逐行跳过并回显原因，批内与库内同规则去重（整表可反复导入），模板可下载；导入交互改为两步式「解析预览 → 确认导入」，预览不写库、自动匹配在预览阶段就展开成可勾选的具体端口，确认时对客户端数据逐条重校验。新增测试：web 5 个（备注/Excel 模板/协议列与自动匹配/无表头 CSV + 模板回灌/预览与确认导入），全量 `go test ./...` 通过。
- 当前无 P0 阻塞性缺陷；P0 剩余项聚焦告警分页、日志落盘与多实例会话，建议在数据量接近万级前启动。
- 上传待办：本地 `cff1cd0` 与本轮未提交改动需经 wander-github-pull 护栏提交并推送至 origin/main（远端为 GitHub）。
