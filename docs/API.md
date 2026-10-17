# API 摘要

API 前缀为 `/api`，请求及响应使用 JSON。除健康检查外，管理员接口需要 `Authorization: Bearer <SCAN_ADMIN_TOKEN>`。错误响应为 `{"error":"原因"}`。

## 管理接口

| 方法与路径 | 用途 |
|---|---|
| `GET /api/health` | 控制面及数据库健康 |
| `POST /api/runs` | 创建扫描任务 |
| `GET /api/runs?summary=true` | 列表摘要，仅含前 2 条输入和真实 `input_count` |
| `GET /api/runs/{id}` | 完整任务与原始输入 |
| `POST /api/runs/{id}/pause` | 暂停 |
| `POST /api/runs/{id}/resume` | 恢复 |
| `POST /api/runs/{id}/cancel` | 取消，保留已收到的结果 |
| `GET /api/runs/{id}/results` | 目标分页、筛选与统计 |
| `GET /api/runs/{id}/ports?target=...` | 单目标开放端口和关联 HTTP |
| `GET /api/runs/{id}/http?status=responded` | HTTP 端点；支持 `responded` / `no_response` / `all` |
| `GET /api/observations/{id}` | 完整已存储的观测与报文 |
| `GET /api/runs/{id}/findings` | PoC 结果；`status=matched/not_matched/error/all`、`purpose=discovery/verification/check`、`severity`、`q`、分页 |
| `GET /api/library` | 可执行规则列表；`kind=http/port/poc`、`purpose=discovery/verification/check`、`q`、`enabled`、`engine`、`source_id`、分页 |
| `GET /api/library/{id}` | 完整规则定义 |
| `POST /api/library` | 创建规则 |
| `PUT /api/library/{id}` | 修改规则，必须携带 `expected_revision` |
| `PATCH /api/library/{id}` | 启停，提交 `enabled` 与 `expected_revision` |
| `DELETE /api/library/{id}?expected_revision=N` | 持久删除内置或自定义规则 |
| `POST /api/library/delete` | 原子批量删除，`items:[{id,expected_revision}]`，返回 `deleted_count` |
| `GET /api/library/products` | 可绑定产品名称，返回 `{items:[string]}` |
| `POST /api/library/import` | 原子导入 JSON / Nuclei YAML，默认禁用 |
| `GET /api/library/sources` | 固定官方源状态、版本、统计和排除样例 |
| `POST /api/library/sources/{id}/update` | 后台检查并原子更新一个官方源 |
| `GET /api/library/sources/{id}/license` | 来源许可证全文和成功版本 |
| `GET /api/library/sources/{id}/catalog` | 上游原库分页；支持 `revision/kind/purpose/engine/enabled/runtime/q` |
| `GET /api/library/sources/{id}/catalog/{ruleID}` | 上游完整 Rule、原始模板和 metadata |
| `GET /api/library/sources/{id}/files` | revision 文件分页，返回 path / SHA-256 / size / is_template |
| `GET /api/library/sources/{id}/files/raw?path=...` | 原始文件字节；可带 `revision` |
| `GET /api/library/sources/{id}/export` | 流式导出 revision ZIP；可带 `revision` |
| `GET /api/library/export?kind=http` | 导出完整规则 JSON；支持与列表相同的 `purpose` 等筛选 |
| `GET /api/workers` | Worker、指标和当前任务 |
| `GET /api/worker-pool` | 节点池状态及配置版本 |
| `PATCH /api/worker-pool` | 设置目标数量、启停池，需提供 `expected_generation` |
| `GET /api/cloud/aliyun` | 脱敏云配置 |
| `POST /api/cloud/aliyun/verify` | 验证云凭据和相关查询能力 |
| `PUT /api/cloud/aliyun` | 验证并加密保存配置 |
| `POST /api/worker-pool/setup-cloud` | 准备云网络 |
| `GET /api/cloud/aliyun/instances` | 云实例状态与历史 |

创建任务示例（文档保留地址仅用于说明格式，替换为实际授权目标）：

```json
{
  "name": "example-discovery",
  "targets": ["192.0.2.10", "192.0.2.0/28", "example.com"],
  "modes": ["port", "http"],
  "poc_enabled": false
}
```

列表使用 `limit`、`offset` 分页。结果按当前执行版本计算，旧 attempt 的观测不会混入本次覆盖统计。`task_total` 是内部执行步骤数，派生指纹任务后会增加；目标完成进度使用 `target_done / target_count`。

## Agent 协议

Agent 以引导令牌调用 `POST /api/workers/register`，获得独立会话令牌。随后通过 heartbeat、claim、renew、batches、complete、release 接口工作。

新版 Agent 在 claim 中提交 `use_rule_sets:true`。HTTP / service 任务返回 `rules_ref`，Agent 使用 Worker bearer token 调用 `GET /api/tasks/{id}/rules?worker_id=...&session_id=...&attempt_no=N` 下载冻结规则；控制面校验当前 lease、worker、session 和 attempt。

支持完整 Wapp 的 Agent 还提交 `supports_httpx_cff:true`。含 HTTPx 指纹的新 run 标记 `requires_httpx_cff`；未同时声明 rules_ref 和 HTTPx capability 的旧 Agent 不能领取该 run 的 HTTP task，但仍可领取其他任务类型。这样不会把 `httpx-cff` 规则交给不认识该 engine 的旧节点。

`request_id` 保证认领重试幂等；`attempt_no` 隔离旧执行；`batch_seq` 和内容校验防止重复批次污染数据。任务在完成结果排空、批次确认和完成确认后才算完成。

租约 120 秒、发包许可 60 秒，Agent 每 15 秒续约。心跳与续约可携带停止动作；无有效许可不能继续发包。详细请求结构以 `internal/control` 和 `internal/agent` 的类型及处理器为准。

观测中的服务 Banner 或 HTTP 报文可以包含 NUL 字符。控制面在 JSONB 查询索引中以 `␀` 显示，另以 BYTEA 保存含该字符的完整回传观测；`GET /api/observations/{id}` 返回原始字段值。批次幂等校验仍使用原始内容，显示相同的不同报文不会被误认为同一批次。

## 规则与 PoC 数据

创建任务可设置 `poc_enabled:true`（必须包含 HTTP 模式）及 `poc_rule_ids:["poc-security-txt"]`。省略或空数组表示按端点指纹自动筛选已启用的产品型 PoC；默认 `poc_enabled:false` 不创建 PoC 任务。创建时保存 HTTP / 端口 / 所选 PoC 的规则快照。

规则更新采用 `expected_revision` 乐观并发控制，冲突返回 409；详情和列表都有 `revision`。列表包含精简的 `match_summary`；完整定义从详情或导出接口获取。导入提交 `{ "format": "json" | "nuclei", "content": "原始文件内容" }`，JSON 一次最多 10,000 条。Nuclei 导入可增加 `execution_profile:"http-basic-v1"`，保存原始 YAML 字节并执行受支持的静态 HTTP 子集；省略该字段或传 `legacy` 保持旧版规范化导入。只有 `/api/library/import` 的请求体上限为 32 MiB，以容纳完整 Wapp 导出包经过外层 JSON 字符串转义后的膨胀；其他 JSON API 仍为 8 MiB。导出包可携带 `licenses` / `notices` 备份元数据。

执行型原始规则的 `nuclei` metadata 含 `template_id`、`execution_profile:"http-basic-v1"`、`content_sha256`、`request_count` 和原始 `info` / `classification`。平台规则 ID 与模板 ID 分开；导入、导出及 Agent 临时文件都保留原文字节。此类规则必须是 `poc`、`purpose:"check"`、有 `applies_to` 产品绑定且 `catalog_only:false`。Agent 认领时声明 `supports_nuclei_http_original:true`；旧 Agent 不会领取新格式任务。

PoC 观测包含 `rule_id`、`rule_name`、`rule_revision`、`engine`、`severity`、`finding_status`、`evidence` 和 `purpose`；原始 YAML 执行另含 `template_id`、`execution_profile`、`content_sha256`。详情包含 `request_raw`、`response_raw`、`error`、`truncated`。verification 另含只读的 CVE / 类别 / 证据等级 / source pin metadata，以及按定义顺序排列的 `checks:[{request_raw,response_raw}]`。分类和 metadata 由控制面从冻结任务规则写入，不信任 Worker 自行上报。

`finding_status` 为 `matched`、`not_matched` 或 `error`。`findings` 接口返回 `{items,total,summary:{matched,not_matched,error,verification_matched,check_matched,discovery_matched}}`，只统计当前执行版本；`purpose` 可筛选列表。Run 的 `finding_count` 保持为全部 matched 的兼容总数，另有 `verification_finding_count`、`check_match_count`、`discovery_match_count` 和 `poc_checked_count`。

规则含 `applies_to:[产品名]`，多个产品为 OR 精确归一匹配；空绑定仅在任务显式选择该规则时执行。新快照持久化 `poc_policy:"fingerprint"` 及 `explicit_poc_rule_ids`，旧快照兼容历史行为。findings 列表和观测详情包含 `matched_products`、`trigger_reason`（`http_technology`、`service_product`、`explicit_unbound_rule` 或历史策略）。

规则列表响应的 `purpose_counts` 给出 PoC discovery / verification / check 数量。HTTPx 规则的详情含单个 Wapp app 的原始 `fingerprint`；任务 rules_ref 只传执行所需字段。导出支持 `kind`、`purpose`、`q`、`enabled`、`engine`、`source_id`、`ids`（最多 1000 个）组合。

`catalog` 响应为 `{items,total,revision,converter_version}`。目录摘要含 `upstream`、`capabilities`、`default_disabled_reason`、`runtime_reason`、`catalog_only` 和 `execution_available`；Nuclei 原始条目的 `execution_available` 为 false。若索引 metadata 含 PostgreSQL JSONB 不能保存的 NUL，摘要和详情增加 `catalog_sanitized_fields`，并用可见的 `␀` 展示索引值。

完整详情的 `template` 会按 Upstream revision / path 从 BYTEA 恢复，不取自 JSONB 索引副本。files 响应为 `{items:[{path,sha256,size,is_template}],total,revision}`；raw 响应带 `X-Content-SHA256`。raw 和 ZIP 始终返回未修改的源文件字节；ZIP 包含 `.shen-source-manifest.json`，不经过 JSON 导入端点。

Wapp source 更新会发布到可执行 `rule_library`；Nuclei source 更新只发布到独立 catalog/files，不修改当前 907 条 PoC。catalog-only Rule 不能通过 CRUD 或 JSON 导入混入可执行规则库。
