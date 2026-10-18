# API 摘要

API 前缀为 `/api`，请求及响应使用 JSON。除健康检查外，管理员接口需要 `Authorization: Bearer <SCAN_ADMIN_TOKEN>`。错误响应为 `{"error":"原因"}`。

## 管理接口

| 方法与路径 | 用途 |
|---|---|
| `GET /api/health` | 控制面及数据库健康 |
| `GET /api/scheduler/status` | HTTP共享许可额度、阶段队列和未来批次调优信息 |
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
| `GET /api/library/fingerprint-bundles` | fingers默认包、源版本和实际加载统计 |
| `GET /api/library/fingerprint-bundles/{digest}` | 下载固定摘要的完整被动执行包 |
| `POST /api/library/sources/{id}/update` | 后台检查并原子更新一个官方源 |
| `GET /api/library/sources/{id}/license` | 来源许可证全文和成功版本 |
| `GET /api/library/sources/{id}/catalog` | 上游原库分页；支持 `revision/kind/purpose/engine/enabled/runtime/q` |
| `GET /api/library/sources/{id}/catalog/{ruleID}` | 上游完整 Rule、原始模板和 metadata |
| `GET /api/library/sources/{id}/files` | revision 文件分页，返回 path / SHA-256 / size / is_template |
| `GET /api/library/sources/{id}/files/raw?path=...` | 原始文件字节；可带 `revision` |
| `GET /api/library/sources/{id}/export` | 流式导出 revision ZIP；可带 `revision` |
| `GET /api/library/export?kind=http` | 导出完整规则 JSON；支持与列表相同的 `purpose` 等筛选 |
| `GET /api/workers` | Worker、指标、当前任务及 `maintenance/session_id` |
| `POST /api/workers/{id}/maintenance` | 独立维护开关，阻止新认领，不停止当前任务或变更云容量 |
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

列表使用 `limit`、`offset` 分页。完整端口覆盖按被接受的完成版本计算。P1新增独立的阳性端口凭证及Nuclei逐模板凭证：在有效执行中确认收到的这些证据可跨attempt保留；它们不替代完整端口区间覆盖。目标结果增加 `port_coverage`，端口列表增加 `port_observation_id/positive_port_receipt_id`，端口观测详情的 `positive_port_receipt` 包含来源task、attempt、batch和完整摘要。`task_total` 是内部执行批次数，派生任务后会增加；目标完成进度使用 `target_done / target_count`。

## Worker 维护

管理员调用 `POST /api/workers/{id}/maintenance`，请求 `{"enabled":true,"expected_session_id":"当前会话"}`。开启时 session 可省略；提供但不匹配则返回409。关闭必须提交 `{"enabled":false,"expected_session_id":"当前会话"}`；缺少会话返回400，重注册导致会话变化时返回409，避免错误恢复节点。会话来自 Worker 列表或开启维护响应。

成功响应为 `{"worker_id":"...","session_id":"...","maintenance":true,"active_tasks":0}`。开关与 claim 使用同一 Worker advisory lock；开启响应前已提交的认领计入 active_tasks，开启后不再创建执行或启动额度。active_tasks 保守计入所有 leased 任务及 active/suspect/revoking 配额对应任务，不把过期租约当作已停证明。维护期间同一 request_id 的有效历史认领仍可重放，已有执行可以续租、回传和完成。开启后使用不同 request_id 的认领返回200和 `task:null`，原因 `worker_maintenance`。

维护标志在重注册和心跳后保留；它不更改 ready/running/draining/offline 状态、池 enabled/desired_workers 或 drain_reason。滚动升级先开启维护并等待 active_tasks 为0，再停止本机服务、安装并启动新 Agent，读取新 session_id 后关闭维护。不要用停用池或减少期望数量实现维护；这些仍属于云回收操作。

首次引入执行配额版本前，须在旧控制面以认领锁阻止新认领，等待所有 leased 任务自然完成，停止旧控制面后再次确认 leased 为0，再启动新控制面迁移。迁移不会为旧活跃任务伪造配额或停止证明。target_quotas保留独立的任务和实例/会话身份，删除run/task不会级联删除未知停止额度；仍需对应instance/session的真实停止证据释放。

## Agent 协议

Agent 以引导令牌调用 `POST /api/workers/register`，获得独立会话令牌。随后通过 heartbeat、claim、renew、batches、complete、release 接口工作。

P2心跳响应增加`prefer_service`及`preference_ttl_seconds`（默认20秒），仅提示有空闲服务槽的Agent先尝试服务工作；不授予执行、连接或发包额度。旧Agent忽略新字段；新Agent对提示设本地有效期，失败或过期后恢复原顺序。`GET /api/scheduler/status`增加`service_pressure`，包括候选/采样数、窗口截断、队龄、成本样本和优先状态，不能将其估计当作完成倒计时。

Worker数值metrics增加`tools_processes`、`tools_rss_mib`、`peak_tools_rss_mib`，以及`masscan/nmap/httpx/web_probe/fingerprint/nuclei`各自的`*_processes`和`*_rss_mib`；还包括`connection_slots_used/connection_slots_limit`、`upload_queued_bytes`、`admission_paused`（0/1）。RSS仅统计直接受控进程，未知或不支持的指标缺省。详见[P2执行资源](P2_EXECUTION.md)。

新版 Agent 在 claim 中必须声明 `supports_confirmed_stop:true`，表示执行器及其子进程退出后才发送 `release.stopped:true`。缺少该字段或为false的旧 Agent不能取得任何新执行或启动额度，认领返回200和 `{"task":null,"blocked_reason":"agent_upgrade_required"}`，仍可心跳和重放有效历史认领。新 Agent另提交 `use_rule_sets:true`。HTTP / service 任务返回 `rules_ref`，Agent 使用 Worker bearer token 调用 `GET /api/tasks/{id}/rules?worker_id=...&session_id=...&attempt_no=N` 下载冻结规则；控制面校验当前 lease、worker、session 和 attempt。

支持完整 Wapp 的 Agent 还提交 `supports_httpx_cff:true`。含 HTTPx 指纹的新 run 标记 `requires_httpx_cff`；未同时声明 rules_ref 和 HTTPx capability 的旧 Agent 不能领取该 run 的 HTTP task；已声明停止确认能力时，其他任务类型继续按各自能力过滤。这样不会把 `httpx-cff` 规则交给不认识该 engine 的旧节点。

`request_id` 保证认领重试幂等；`attempt_no` 隔离旧执行；`batch_seq` 和内容校验防止重复批次污染数据。任务在完成结果排空、批次确认和完成确认后才算完成。

P1新增 `supports_http_request_budget:true`，HTTP/PoC认领及历史claim重放均需该能力；端口与服务仍按已有能力过滤。兼容原始模板合批另需 `supports_nuclei_http_batch:true`，Agent实际检查Nuclei3.11.1和必要参数后才声明。批次payload的 `nuclei_batch_profile` 为 `nuclei-3.11.1-single-http-batch-v1`，最多4条同入口、单请求单matcher模板。任务存储保留原清单，认领响应只含无独立完成凭证的规则；已全部封账时可返回空rules，Agent无需再发送探测，仍须完成最终确认。合批不改变规则匹配范围或PoC默认关闭策略。

`POST /api/tasks/{id}/http-permit` 使用Worker会话令牌，请求：

```json
{"worker_id":"...","session_id":"...","attempt_no":1,"request_id":"1","connect_ip":"192.0.2.1","host":"example.test","port":443}
```

`request_id` 是每个执行内串行递增的十进制编号。成功或等待均返回200，字段为 `granted/server_time/valid_until/retry_after_ms/rate_rps/cluster_rps/burst`。发放许可的有效期至多500ms，重放不延长；等待期间在事务外重试。失败、过期、执行取消、session变化或额度冻结时不得写出HTTP请求。许可按实际连接IP归并，默认10/IP/s和250/集群/s，表示协作式请求准入速率，不等同网络到达的精确滑动窗口RPS。维护及回收排空状态中的现有有效执行继续受租约约束。

外部被动库任务另带 `fingerprint_bundle_schema`；Agent通过 `GET /api/tasks/{id}/fingerprint-bundle?worker_id=...&session_id=...&attempt_no=N` 下载该执行对应的固定包并校验SHA。管理员更新默认库不会改写已有任务的包身份。

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

## 有限 Web enrichment 协议

新建 run 内部快照增加 `web_enrichment_profile:"bounded-enrichment-v1"`，初始及服务派生的 HTTP payload 继承该值。原 `web_profile:"bounded-passive-v1"` 保留；createRun 请求不新增 profile 开关。旧 run 缺字段时不自动开启重定向或补采。

Agent claim 增加 `web_enrichment_profile` 字符串。payload 非空时必须精确匹配，普通认领及同 request_id 重放均检查；不匹配返回 `task:null`，不改变原执行身份或额度。payload 字段为空时，新旧 Agent 继续经过原有能力检查。Agent 只有从实际 helper capability 得到 `enrichment_profile:"bounded-enrichment-v1"` 才声明该能力。

HTTP collection 规则使用已有规则库接口，列表摘要、详情、执行 rules_ref 和 JSON 导入导出均包含：

```json
{
  "collection": {
    "path": "/readme.html",
    "products": ["WordPress"],
    "source_rule_id": "poc-wordpress-readme",
    "source_rule_revision": 1
  }
}
```

该对象只适用于 native、info、discovery 的 HTTP 产品指纹，执行固定为静态同源路径 GET；产品绑定为 1–16 个。来源字段可同时省略，提供来源 ID 时版本必须为正整数。主页面匹配不会直接执行 collection 条件。先匹配主页面候选产品，再对选中规则对应的独立响应做确认；同 URL 多条规则共用响应。创建/修改、启停、删除及默认禁用的导入行为沿用现有接口，后续库变更不修改已冻结 run。

新 profile 最多跟随 3 跳严格同源重定向、使用 8 次逻辑 collect、额外请求 2 个不同补采 URL，最多保留 64 条候选规则。所有阶段共用入口的 90 秒父截止；重定向、图标、失败尝试和补采均占共用预算。PoC 仍须 `poc_enabled:true`，collection 响应不会生成独立 HTTP 任务或 PoC finding。

Agent→helper JSONL 请求增加 `enrichment_profile`、`step`（`entry` / `supplement`）和 `max_requests`。结果增加 `input_url`、`enrichment_profile`、`redirects[]`；每个 redirect 含 `from_url/to_url/status_code/outcome/attempt_index`，其中索引从 0 开始绑定源 attempt。被阻止的跨源目的地只能作为停止原因出现在证据中。enriched `attempts` 包含图标尝试，其数量等于 helper 的 `requests`，图标对应 attempts 尾部。

新 profile 的 token 化 loopback `/admit` 请求带逻辑序号：

```json
{"id":"<ITEM_ID>","url":"https://example.test/start","wait":true,"request_seq":1}
```

这不是公开控制面接口。序号范围为 1–8，同 item/序号只能对应同 URL；等待或 TLS 后刷新仍调用共享 HTTP 许可，但不重复扣逻辑 collect 预算。每条补采拥有独立 item ID，仅允许对应精确 URL 的一次逻辑 GET，主采集和补采共用总预算。公开 `http-permit` 的 request_id、有效期及协作式准入语义不变。

HTTP observation 的 `evidence` 仍为 JSON 字符串，enrichment 增加 `requests_budget_used`、`supplement_plan`、`supplements[]` 和 `storage`。supplement 含 `url/rule_ids/outcome/response/matches/rule_results/error/reused/storage`，各 rule result 含 `rule_id/rule_revision/outcome`。规则结论包括 matched/not_matched、partial/error，以及因预算、数量或不完整复用而 skipped 的状态；它们不属于 findings。

主 observation 保留原 `work_key` / Target，URL 可为合法同源最终路径。成功结果必须带绑定原 InputURL 的主 Probe 证据；明确的 setup 失败允许无 URL，但仍校验工作身份并记 partial。补采 response 正文最多保留 32 KiB 原字节（JSON base64），标明 complete/prefix；主 Probe 正文为 hash_only。新 profile 按完整 JSON 大小收敛，省略和截断有标志；仍无法放入 2 MiB 批次的单条 observation 按不可重试错误处理。详见 [Web enrichment 执行边界](WEB_ENRICHMENT.md)。
