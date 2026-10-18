# 有限 Web 重定向与产品补采

新建 run 的 HTTP 执行增加 `web_enrichment_profile: "bounded-enrichment-v1"`。它在原有 `web_profile: "bounded-passive-v1"` 上增加有限重定向和候选产品确认；主采集、httpx/Wappalyzer 被动匹配及 fingers 被动匹配继续使用已有执行器。补采结果属于 HTTP 指纹证据，不是漏洞结论。

## 执行范围与预算

| 项目 | 当前边界 |
|---|---|
| 重定向 | 仅处理 301/302/303/307/308，最多实际跟随 3 跳 |
| 同源 | 每跳 scheme、精确主机名及有效端口相同；connect IP 固定，Host/SNI 保持分配身份 |
| 请求总预算 | 每入口最多 8 次逻辑 collect，覆盖主请求、失败尝试、既有同端口协议确认、重定向、图标及补采 |
| 图标 | 沿用最多 2 个同源图标的边界，占用同一请求预算 |
| 独立补采 | 最多额外请求 2 个不同 URL；相同 URL 的多条规则共用响应，失败尝试也占补采机会 |
| 候选规则 | 按规则 ID 稳定排序，最多保留 64 条，记录被省略数量 |
| 总截止 | 入口开始执行后共用一个 90 秒父 context，补采只取得剩余时间 |
| 单次网络阶段 | 最多 8 秒；请求准入排队与持有目标连接的网络阶段分开 |

严格同源不允许通过重定向切换 HTTP/HTTPS、主机别名或端口。相对 Location 按当前响应 URL 解析，fragment 从请求目标移除；含用户信息、无效/过长 Location、跨源目的地、循环、跳数或预算耗尽均停止跟随并记原因。被阻止的目的地只出现在 trace 中，不成为已发送请求。隐式 URL 的既有 HTTP/HTTPS 同端口确认仍可使用，但不是跨源重定向授权。

8 次计数表示逻辑采集尝试，不是成功响应数、许可调用数或目标实测到达 RPS。helper 在 collect 开始前分配 `request_seq`；相同 item ID、序号及 URL 的准入等待或 TLS 后许可刷新复用这次逻辑操作。刷新仍须重新取得有效共享许可，不会获得额外 collect 机会。失败或尚未真正写出 HTTP 的采集也可能消耗预算。

同一入口的 DNS、准入等待、主采集、被动匹配和补采共享父截止时间，不为每条规则重新分配 90 秒。入口执行前等待 Agent 本地槽位仍受任务自身的取消和执行截止约束。

## 候选产品与补采规则

Agent 先从主响应完成原有被动识别，再用已识别产品名与 `collection.products` 做归一后的精确绑定。没有候选产品就不补采。规则计划只生成一次，补采识别出的产品不会递归扩展本轮计划，也不会遍历 PoC 库猜测路径。

规则必须是启用的 `kind: "http"`、`engine: "native"`、`severity: "info"` 产品发现规则。`collection` 指定一个静态同源路径，执行方法固定 GET；匹配条件保存在该 HTTP 规则的 `definition.matchers` 中。collection 规则不参与主页面的普通 `Match`，只有选中并取得相应独立响应后才执行产品确认。

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

`products` 为 1–16 个产品绑定。自定义规则可以不设置来源；设置 `source_rule_id` 时必须同时提供正整数 `source_rule_revision`。来源只说明确认定义的出处，不授权执行对应 PoC。

当前手工选择的六条内置 HTTP 确认规则如下。它们各自保留来源规则 ID/版本，不是对所有低危或 discovery PoC 做自动转换。

| HTTP 规则 ID | 产品 | 固定确认路径 |
|---|---|---|
| `http-collect-wordpress-readme` | WordPress | `/readme.html` |
| `http-collect-joomla-version-manifest` | Joomla | `/administrator/manifests/files/joomla.xml` |
| `http-collect-gitlab-health` | GitLab | `/-/health` |
| `http-collect-gitea-version-api` | Gitea | `/api/v1/version` |
| `http-collect-swagger-ui-interface` | Swagger UI | `/swagger-ui/index.html` |
| `http-collect-django-admin-login` | Django | `/admin/login/` |

补采 URL 从最终主响应的同源根路径解析，不把主页面重定向后的目录当作额外的路径前缀。每条独立补采只有一次 GET，不跟随重定向、不切换协议、不再采集图标。完整且无错误的主响应或图标响应可以复用；已经尝试过但缺少完整正文的 URL 记录 `skipped_incomplete_reuse`，不重新请求。

同 URL 的各规则分别记录 ID、版本及匹配结论。部分正文或错误响应不能证明匹配或不匹配，记录为 partial/error；预算和数量上限分别记录 `skipped_budget`、`skipped_limit`。补采失败不改写已取得的主响应状态，也不撤回已有产品识别。

## 规则管理和快照隔离

规则库列表摘要、详情、执行规则下载及 JSON 导入导出均保留完整 `collection` 小对象。创建/修改、启停和持久删除使用已有规则库接口及 `expected_revision` 并发控制；JSON 导入默认禁用。通过禁用或删除对应 HTTP collection 规则，可控制后续新 run 的补采计划。原 PoC 条目仍独立存在，修改其启停状态不等于修改已建立的 HTTP 确认规则。

创建 run 时冻结完整规则和版本，以及 `web_enrichment_profile`。初始 HTTP task 与端口→服务派生的 HTTP task 都读取该 run 的快照。之后更新、禁用或删除规则只影响后续快照，不改写已经创建的 run。createRun 请求没有单独的 enrichment profile 开关；当前由控制面为新 run 设置。

旧 run 缺少该快照字段时，派生 HTTP task 也保持字段为空。新 Agent 执行此类任务仍采用旧路径：保留已有被动采集、协议确认和图标逻辑，不跟随重定向、不执行 collection。安装新 helper 或新增规则不会自动为旧任务开启补采。

新任务认领要求 Agent 的 `web_enrichment_profile` 与 payload 非空值精确相等，历史 request_id 重放也做同样检查；能力不匹配不会下发新执行。原 HTTP 预算、规则集、指纹包 schema 等能力检查继续生效。发布时先更新控制面，再升级空闲 Worker 的 Agent/helper，并通过实际 helper capability 声明新能力。

## 结果身份、PoC 与证据

主 HTTP observation 的 URL 可以是有效同源链的最终路径，但 `work_key` 和源目标保持原分配身份。新 profile 的成功结果须包含主 Probe 证据，InputURL 必须对应原入口；控制面核对主响应、重定向来源、同源范围及固定 connect IP。明确的 DNS/helper 等 pre-probe 失败可带空 URL，但必须绑定分配工作，只能封账为 partial。

补采保存在同一个 observation 的 `evidence` JSON 字符串中，不派生额外 HTTP task，不生成独立的 PoC finding。只有 run 显式设置 `poc_enabled:true` 时，已有产品/规则策略才会选择 PoC，并保留原分配入口；重定向或补采路径不会成为新的 PoC 入口。产品或版本确认本身不能当作漏洞结论。

证据主要字段为：

- `probe.input_url`、`probe.enrichment_profile`、最终 `probe.response`、`probe.attempts`、`probe.icons` 和 `probe.requests`；enriched attempts 包含图标尝试，图标位于其尾部。
- `probe.redirects[]` 的 `from_url/to_url/status_code/outcome/attempt_index`；索引从 0 开始，绑定产生跳转的实际 attempt。
- `requests_budget_used` 为主采集与补采共用预算的计数；`supplement_plan` 给出候选、选中、省略数和截断标志。
- `supplements[]` 的 URL、规则 ID、各版本结论、匹配产品、错误、复用标志及有界响应。

主正文采集上限为 2 MiB，图标为 256 KiB；传给被动匹配器的是实际有界正文，持久化主 Probe 正文为 `hash_only`。补采正文最多保存 32 KiB 原字节，JSON 的字节字段使用 base64；完整小正文标 `body_storage: "complete"`，前缀或部分正文标 `prefix`，同时保留摘要和采集完整性。补采 request/header 原文各最多 16 KiB，另有截断标志，TLS 详细证据沿用主 Probe。

新 profile 还按实际 JSON 编码后的 observation 大小做存储收敛，为 2 MiB 上传批次保留封装余量。必要时移除重复头部、部分补采证据、部分产品或详细匹配结构；`storage.headers_omitted/omitted_supplements/omitted_technologies` 记录相应省略，不能据缩减结果声称完整保留全部发现。收敛不再有进展时直接返回，由公共 emit 上限以不可重试错误拒绝仍超大的单条记录，避免无限循环。完整采集与完整存储是两个不同状态。

该功能不包含浏览器渲染、页面爬行、站点遍历、通用主动模板执行或容量基准承诺。HTTP 请求仍走现有按 connect IP 归并的共享许可，其协作式准入语义不变。
