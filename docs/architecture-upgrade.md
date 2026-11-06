# 灵瞰 EASM 平台 — 架构升级评估

> 本文档评估当前架构（SQLite + 内存 session + go:embed 模板 + 单进程扫描）对本轮 6 项功能需求的支撑能力，并给出分阶段升级方案（含迁移计划、向后兼容与风险评估）。
> 结论先行：**本轮 6 项需求均可在现有架构内实现，无需破坏性重构**；架构升级（分页、session 外置、日志落盘、可选 PostgreSQL）作为后续独立任务，按数据规模与可用性需求分阶段触发。
> 生成基线：`go build ./...`、`go test ./...`、`go vet ./...` 全部通过。

---

## 一、当前架构概述

| 层 | 选型 | 关键特征 |
|----|------|----------|
| 存储 | SQLite（`modernc.org/sqlite`，纯 Go 无 CGO） | 单文件 `data/easm.db`；轻量迁移用 `ALTER TABLE ADD COLUMN DEFAULT`；可空列读取统一 `COALESCE` 兜底 |
| 会话 | 进程内 `map[sid]session`（12h 过期） | 每次请求回查 users 表，停用/删改即时生效；**不落库、不支持多副本、重启掉线** |
| 前端 | `go:embed` 内嵌 html/template + 静态资源 | 编译期打包，改模板需重建重启；侧边栏控制台 + 双主题 CSS 变量 |
| 扫描 | 单进程 `Runner` + 全局互斥锁 | 全局同时只跑一个扫描；分批（每批 ≤20 目标）调用外部 `naabu`；进程组信号控制暂停/恢复/终止 |
| 通知 | 飞书 Webhook（HTTP/1.1 短连接 + DoH 兜底重试） | 任务结束单条汇总 |

来源：[store.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/store/store.go)、[web.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/web/web.go)、[scanner.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/scanner/scanner.go)、[applog.go](file:///Users/Admin/Desktop/soft/fenxi/lxr/easm-platform/internal/applog/applog.go)。

---

## 二、本轮 6 项需求与现有架构的适配性

| 需求 | 是否需架构升级 | 实现方式 | 结论 |
|------|----------------|----------|------|
| ① 各列表页导出当前筛选 | 否 | 复用既有 `writeCSVDownload`（BOM + 公式注入防护），补 results 页导出按钮 | SQLite 只读查询即可，导出量不受页面上限限制 |
| ② 查询框视觉美化 | 否 | 纯 CSS（药丸圆角 + 内联 SVG 放大镜 + 聚焦 ring + 暗色适配） | 与数据层无关 |
| ③ 批量删除空选择提示 | 否 | 前端透传后端 `res.json.error`，去除硬编码文案 | 纯前端修复 |
| ④ 白名单 business 字段 + 基线预览 | 否 | `whitelist` 表 `ALTER ADD COLUMN business`；预览走只读接口（`LatestDoneScan`+`ResultsByScan`+`WhitelistStatus`） | SQLite 补列向后兼容；预览为只读聚合，无需新存储 |
| ⑤ 执行状态自愈 | 否 | 启动时 `HealStaleScans()` 幂等 UPDATE + `run()` panic recover + 详情页手动 resync | 单进程重启后内存无活动进程，残留 running/paused 必然悬空，一条 UPDATE 即可修正 |
| ⑥ 自定义端口扫描 | 否 | `scan_tasks` 表 `ALTER ADD COLUMN custom_ports`；`naabu -p <ports>`；复用端口格式校验 | naabu 原生支持 `-p` 逗号/范围，仅透传字符串 |

**评估结论**：6 项需求全部落在「新增可空列（ALTER 兼容）+ 新增只读接口 + 前端交互 + 幂等状态修正」范围内，未触及存储引擎、会话机制或部署模型，现有架构完全支撑。

---

## 三、现有架构瓶颈（规模 / 可用性）

以下为**当前架构在更大规模或高可用场景下**的固有瓶颈，非本轮需求引入：

1. **列表页一次性渲染、无分页**（P1）— 资产/告警/暴露面/结果/审计均全量或按上限一次性渲染（资产无上限、告警 500、暴露面 1000、结果/审计 2000）。万级数据时页面卡顿、内存峰值高。
2. **内存 session 不支持多副本**（P2）— 会话存进程内存，负载均衡/多实例下登录态不共享，重启全员掉线。
3. **运行日志重启即丢失、不可导出**（P1）— `applog` 进程内环形缓冲（约 3000 条），无法追溯历史故障。
4. **单进程全局扫描锁**（P2）— 全局串行，无法水平扩展扫描吞吐；适合中小规模授权资产盘点。
5. **SQLite 单写者**（P2+）— 高并发写存在锁竞争；当前写频率低（扫描批次入库 + 偶发配置/处置），可接受。
6. **导出全内存构造 CSV**（P2）— `writeCSVDownload` 先在内存拼 `[][]string` 再写出，超大数据量内存峰值高。

---

## 四、分阶段升级方案（迁移 / 兼容 / 风险）

### 阶段一：单体增强（P1，低风险，建议数据量接近万级前启动）

- **列表分页**：store 侧成对补 `COUNT(*)` 与 `LIMIT/OFFSET` 查询方法；handler 读 `page`/`page_size` 并回传总数；模板 `filter-bar` 追加分页控件。
  - 迁移：无 schema 变更。兼容：`page_size` 缺省取较大值时行为等同现状。风险：**低**（注意「有 limit 无页码」与总数不显示的成对切口）。
- **运行日志落盘轮转 + 导出**：`applog` 增加 `data/logs/` 按天/按大小轮转的落盘 sink，页面加导出按钮；内存环形缓冲保留用于实时 tail。
  - 迁移：新增目录，无 schema 变更。兼容：stderr 输出不变。风险：**低**。
- **导出流式化**：`csv.Writer` 直接写 `http.ResponseWriter`（配合 `Flush`），替代内存 `[][]string`。
  - 兼容：保留公式注入前缀转义与 BOM。风险：**低**。

### 阶段二：多副本就绪（P2，中风险，确有高可用需求时启动）

- **session 外置**：抽象 `SessionStore` 接口，提供内存实现（默认）与 Redis/SQLite 实现；部署多副本时切换。
  - 迁移：接口化后默认仍内存，零行为变化；切 Redis 需引入依赖与运维。兼容：cookie 名 `easm_sid` 与语义不变。风险：**中**（新增外部依赖）。
- **扫描调度**：若需水平扩展扫描，全局互斥锁须改为分布式锁（Redis/DB 行锁）+ 任务队列。
  - 风险：**高**。建议**保持单扫描节点**，通过多只读副本 + 共享外置 session 承载读流量，扫描仍单点串行。

### 阶段三：数据层升级（P2+，可选，数据量百万级或多写者时）

- **SQLite → PostgreSQL**：仅当数据量达百万级或需并发多写者时评估。
  - 迁移：store 层 SQL 方言适配（UPSERT、类型、`COALESCE` 语义基本一致）+ 数据迁移脚本；建议以配置/构建标签驱动，保留 SQLite 作单机默认后端。兼容：schema 逻辑模型不变。风险：**高**（方言差异 + 运维复杂度）。

---

## 五、本次迭代的架构影响声明

- 本轮仅新增**可空列**（`whitelist.business`、`scan_tasks.custom_ports`，均 `ALTER TABLE ADD COLUMN DEFAULT ''`，旧库自动兼容）、**只读接口**（`/api/baseline/preview`、`/results/export` 按钮）、**幂等状态修正**（`HealStaleScans`/`ForceStopScanIfActive`）与前端交互。
- **未改动**存储引擎、session 机制、部署模型与扫描并发模型；未引入任何新的第三方依赖。
- 所有新增可空文本列的读取均经 `COALESCE(col,'')` 兜底，符合既有旧库兼容约定。

---

## 六、建议优先级与触发条件

| 升级项 | 优先级 | 触发条件 |
|--------|--------|----------|
| 列表分页 | P1 | 资产/告警数据量接近万级前 |
| 运行日志落盘 + 导出 | P1 | 需要故障追溯 / 合规留存时 |
| 导出流式化 | P2 | 单次导出达十万级记录时 |
| session 外置（Redis） | P2 | 确有多副本 / 高可用部署需求时 |
| PostgreSQL | P2+ | 数据量百万级或需并发多写者时 |

> 本次迭代优先实现 6 项功能，架构升级按上表触发条件作为后续独立任务推进。
