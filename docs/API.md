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
| `GET /api/runs/{id}/findings` | PoC 结果；`status=matched/not_matched/error/all`、`severity`、`q`、分页 |
| `GET /api/library` | 规则列表；`kind=http/port/poc`、`q`、`enabled`、`engine`、`source_id`、分页 |
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
| `GET /api/library/export?kind=http` | 导出完整规则 JSON |
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

新版 Agent 在 claim 中提交 `use_rule_sets:true`。HTTP / service 任务返回 `rules_ref`，Agent 使用 Worker bearer token 调用 `GET /api/tasks/{id}/rules?worker_id=...&session_id=...&attempt_no=N` 下载冻结的精简规则；控制面校验当前 lease、worker、session 和 attempt。旧 Agent 不提交该字段时仍收到 gzip 内联规则。部署时必须先升级控制面，再升级使用引用协议的 Agent。

`request_id` 保证认领重试幂等；`attempt_no` 隔离旧执行；`batch_seq` 和内容校验防止重复批次污染数据。任务在完成结果排空、批次确认和完成确认后才算完成。

租约 120 秒、发包许可 60 秒，Agent 每 15 秒续约。心跳与续约可携带停止动作；无有效许可不能继续发包。详细请求结构以 `internal/control` 和 `internal/agent` 的类型及处理器为准。

## 规则与 PoC 数据

创建任务可设置 `poc_enabled:true`（必须包含 HTTP 模式）及 `poc_rule_ids:["poc-security-txt"]`。省略或空数组表示按端点指纹自动筛选已启用的产品型 PoC；默认 `poc_enabled:false` 不创建 PoC 任务。创建时保存 HTTP / 端口 / 所选 PoC 的规则快照。

规则更新采用 `expected_revision` 乐观并发控制，冲突返回 409；详情和列表都有 `revision`。列表包含精简的 `match_summary`；完整定义从详情或导出接口获取。导入提交 `{ "format": "json" | "nuclei", "content": "原始文件内容" }`，JSON 一次最多 10,000 条，请求体上限 8 MiB。JSON 采用导出的 `{ "items": [Rule] }` 格式，并可携带 `licenses` / `notices` 备份元数据。

PoC 观测包含 `rule_id`、`rule_name`、`rule_revision`、`engine`、`severity`、`finding_status`、`evidence`；详情包含 `request_raw`、`response_raw`、`error`、`truncated`。`finding_status` 为 `matched`、`not_matched` 或 `error`。`findings` 接口返回 `{items,total,summary:{matched,not_matched,error}}`，只统计当前执行版本。任务的 `finding_count` 仅计命中，`poc_checked_count` 计全部检查结果。模板格式和执行边界见 [规则库说明](RULE_LIBRARY.md)。

规则含 `applies_to:[产品名]`，多个产品为 OR 精确归一匹配；空绑定仅在任务显式选择该规则时执行。新快照持久化 `poc_policy:"fingerprint"` 及 `explicit_poc_rule_ids`，旧快照兼容历史行为。findings 列表和观测详情包含 `matched_products`、`trigger_reason`（`http_technology`、`service_product`、`explicit_unbound_rule` 或历史策略）。

导出支持 `kind`、`q`、`enabled`、`engine`、`ids`（逗号分隔，最多 1000 个）组合，返回完整定义且不分页。批量删除采用相同版本条件，任一不存在或冲突都不删除；删除的规则不会进入列表、产品候选、导出或新任务快照。同 ID 导入可恢复删除项并增加版本，恢复项仍默认禁用。
