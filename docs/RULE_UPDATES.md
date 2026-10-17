# 官方规则源更新

SHEN 支持从两个固定官方仓库一键更新规则：

- `wappalyzer` → `projectdiscovery/wappalyzergo`
- `nuclei-templates` → `projectdiscovery/nuclei-templates`

不能输入任意 URL，也不会切换第三方镜像。规则源更新是管理员主动操作；控制面启动、Worker 启动和普通扫描都不会自动访问 GitHub。

## 更新流程

1. 控制面从 `api.github.com` 读取官方仓库最新 commit SHA。
2. 若 SHA 和转换器版本均未变化，直接记录本次检查为无变化，不重复下载归档。
3. 否则从同仓库的 `codeload.github.com` 固定 SHA 地址下载归档。
4. 校验 HTTPS 跳转范围、压缩与展开大小、文件数量、tar 路径和文件类型。
5. 读取仓库根 `LICENSE.md`，要求为完整 MIT 许可；保存许可全文、SHA 和归档内容摘要。
6. 转换全部候选，记录 accepted、skipped、排除原因和有限样例。
7. 在一个 PostgreSQL 事务中发布。任何下载、许可、解析、校验或写入错误都保留上一成功版本。

当前转换与只读策略版本为 `ConverterVersion=3`。该版本与上游 SHA 一起决定是否需要重新下载转换；v3 增加了按路径和逐文件 SHA 审核的 native verification。以后筛选或审核语义变化时必须提升版本。

压缩归档上限 128 MiB，展开上限 256 MiB；更新总预算 10 分钟。GET 连接错误最多重试 3 次，拨号、TLS 和响应头等待均有界；HTTP 4xx（包括 API 限额 403）、坏许可、坏 tar 和转换错误不会盲目重试。

GitHub 匿名 API 限额不足时，可在控制面进程环境中设置 `GITHUB_TOKEN`。该 token 只作为 `api.github.com` 的 Authorization header，不发送到 codeload、Worker 或 UI，也不写入 source 状态。

## 状态与统计

规则源状态为：

- `idle`：尚未成功更新；
- `updating`：后台更新进行中；同源重复点击返回当前状态，不启动第二份下载；
- `ready`：最近检查或发布成功；
- `failed`：最近更新失败，`error` 包含简短原因。

两个源互不阻塞，可并行更新。进程重启时遗留的 `updating` 会标为失败，可重新点击。`updated_at` 表示最近检查时间；`revision` 和 `digest` 表示最近成功发布的上游版本。

`stats` 字段含义：

| 字段 | 含义 |
|---|---|
| `total` | 本次转换器看到的上游候选总数 |
| `accepted` | 通过当前安全模型的规则数 |
| `skipped` | 产品或模板级排除总数 |
| `reasons` | 排除原因及数量 |
| `added` | 本次新增 |
| `updated` | 本次按上游更新 |
| `unchanged` | 内容未变化 |
| `preserved` | 因本地编辑、删除或 ID 冲突而保留 |
| `retired` | 上游已移除或不再合规，因而停用 |

Nuclei 的 `review_required` 表示某个 reviewed verification 的上游文件 SHA 已变化，不能继续沿用旧审核结论。它属于 `skipped` 原因；更新仍可发布其余有效规则，旧的未本地改写 verification 会被停用并计入 `retired`。

发布要求 `total = accepted + skipped`，且 accepted 不能为零。空目录、统计不完整或全部不兼容会使整次更新失败，不会清空现有规则。

## 本地修改保护

来源规则保留稳定 `source_id` 和上游规范内容摘要。后续更新遵循：

- 用户禁用状态不被重新开启；
- 用户编辑过的完整规则不被上游覆盖；
- 软删除规则不复活；
- 自定义规则占用同 ID 时保留自定义规则；
- 上游移除且没有本地改写的规则停用，而非物理删除；
- reviewed verification 的 source pin 变化时不自动接受新模板；未改写的旧条目停用，等待重新审核；
- 删除项通过同 ID JSON 导入恢复后视为本地修改。

任务继续使用创建时冻结的规则快照。规则源更新不会改变正在运行或历史任务的匹配定义。

## 导入、导出与许可

JSON 导入一次最多 10,000 条，请求体上限 8 MiB，整批校验和写入；任一规则失败则全部不写入。导入规则默认禁用。勾选 ID 导出和批量删除仍最多 1,000 条；按筛选导出不受页面分页限制。

导出的 JSON 包含适用规则、source SHA、MIT 许可全文和 bootstrap 第三方声明，因此可以作为规则与许可备份。许可证也可通过管理员接口读取：

```text
GET /api/library/sources/{id}/license
→ {"license":"MIT","license_text":"...","revision":"<commit>"}
```

## Control 与 Agent 升级顺序

先升级控制面，再升级 Agent。新版 Agent 在 claim 中发送 `use_rule_sets:true`；控制面返回很小的 `rules_ref`，Agent 再用当前租约身份下载对应 run / task type 的冻结执行规则。旧 Agent 不发送该标记，控制面继续内联精简规则并用 gzip 传输。reviewed verification 还要求新 Agent 按请求回传 `checks`，由新 Control 从冻结规则写入分类并重验完整证据；升级完成前不要启用这批规则。

引用规则集具有以下边界：

- ref 固定为 `run_id:http` 或 `run_id:service`；service 下载返回 port 规则；
- 下载必须携带 Worker bearer token，并匹配当前 leased task、worker、session、attempt 和有效 lease；
- Agent 对最近 8 份规则集做不可变 LRU 缓存，同一 ref 并发下载会合并；
- 首次下载超时 30 秒，解压后上限 16 MiB；下载后逐条校验；
- HTTP claim 不再传输未使用的 PoC 规则；PoC 任务自身仍携带冻结的单条规则。

当前验证快照中，旧内联 HTTP claim 为约 2.90 MB JSON、394 KB gzip；引用 claim 最大约 463 B。12 个同 run HTTP 任务只下载一次规则集。该容量数据用于说明当前边界，不替代未来上游增长后的重新测量。

本地端到端验收还确认：同 SHA 快速检查约 1.05 秒；产品已识别时可派发并命中转换后的 `nt-3cx-phone-management-panel`，未知产品不会产生 PoC 请求。这些是固定环境的功能证据，不是公网延迟或吞吐承诺。

## PoC 调度边界

PoC 默认关闭，必须在任务中显式开启。产品型规则仅在同源 HTTP 端点识别到精确规范化产品后派发；匹配只处理大小写、空白、下划线 / 连字符和少量明确别名，不做模糊子串或厂商猜测。没有产品绑定的规则只在任务中手选该 ID 时执行。

自动来源 PoC 分为 `discovery` 和 `verification`。常规 Nuclei discovery 仍受静态同源 GET / HEAD、无 query / traversal、安全路径、请求数和 matcher 上限约束；面板、登录页、健康接口或产品版本页命中只是产品确认或暴露信息，不应直接表述为漏洞。

verification 是窄化的审核例外：只接受内置注册表中的精确定义，原模板必须匹配固定 upstream path 与文件 SHA，随后转换为 native probe / control 请求。原始 Nuclei YAML 不交给 Agent，模板中的 RCE、OAST、敏感文件读取等其他分支不会执行。source hash 变化会记录 `review_required` 并停用未本地改写的旧规则。完整边界见 [只读漏洞验证](READONLY_VERIFICATION.md)。
