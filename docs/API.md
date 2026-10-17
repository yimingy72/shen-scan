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
  "modes": ["port", "http"]
}
```

列表使用 `limit`、`offset` 分页。结果按当前执行版本计算，旧 attempt 的观测不会混入本次覆盖统计。`task_total` 是内部执行步骤数，派生指纹任务后会增加；目标完成进度使用 `target_done / target_count`。

## Agent 协议

Agent 以引导令牌调用 `POST /api/workers/register`，获得独立会话令牌。随后通过 heartbeat、claim、renew、batches、complete、release 接口工作。

`request_id` 保证认领重试幂等；`attempt_no` 隔离旧执行；`batch_seq` 和内容校验防止重复批次污染数据。任务在完成结果排空、批次确认和完成确认后才算完成。

租约 120 秒、发包许可 60 秒，Agent 每 15 秒续约。心跳与续约可携带停止动作；无有效许可不能继续发包。详细请求结构以 `internal/control` 和 `internal/agent` 的类型及处理器为准。
