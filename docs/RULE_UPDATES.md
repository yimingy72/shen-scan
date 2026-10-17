# 官方规则源更新

SHEN 支持管理员从两个固定官方仓库一键跟随最新 HEAD：

- `wappalyzer` → `projectdiscovery/wappalyzergo`
- `nuclei-templates` → `projectdiscovery/nuclei-templates`

不能输入任意 URL，也不会切换第三方镜像。控制面启动、Worker 启动和普通扫描不会自动访问 GitHub。

## 下载与原子发布

1. 控制面从 `api.github.com` 读取最新 commit。
2. commit 与 ConverterVersion 均未变化时，只记录检查成功，不重复下载。
3. 否则从固定仓库的 `codeload.github.com` 按该 commit 下载归档。
4. 校验 HTTPS 跳转、压缩和展开大小、文件数、tar 路径、普通文件类型及 MIT 许可。
5. 转换 Wapp app 或建立 Nuclei 原始目录，保存 revision、文件 SHA-256、归档摘要、完整许可证和统计。
6. 在一个 PostgreSQL 事务中发布；任何下载、解析、校验或写入失败都保留上一成功版本。

当前为 `ConverterVersion=4`。版本变化会使相同 commit 重新转换。本版本的两条发布路径不同：

- Wappalyzer 的 7,642 个原始 app 进入 HTTP 执行库，供 HTTPx v1.12.0 被动识别。
- Nuclei 的 14,075 条可解析规则和全部原始文件进入独立 source catalog / files，不进入执行库。

压缩归档上限 128 MiB，展开上限 256 MiB，更新总预算 10 分钟。GET 连接错误最多重试 3 次；HTTP 4xx、坏许可、坏 tar 和转换错误不盲目重试。可选 `GITHUB_TOKEN` 只发送给 `api.github.com`，不会进入 codeload、Worker、UI 或 source 状态。

## 状态与统计

状态为 `idle`、`updating`、`ready` 或 `failed`。同源重复点击不会启动第二个并发更新；两个不同 source 可以并行。进程重启会把遗留的 `updating` 标为失败，允许重试。

`updated_at` 是最近检查时间；`revision` 和 `digest` 是最近成功发布版本。`stats` 包含：

| 字段 | Wapp 执行库 | Nuclei 上游原库 |
|---|---|---|
| `total` / `accepted` / `skipped` | app 总数、有效规则和排除项 | YAML 总数、目录规则和非模板 / 无效项 |
| `added` / `updated` / `unchanged` | 与当前执行库来源内容比较 | 与上一 catalog revision 比较 |
| `preserved` | 因用户编辑、删除、启停 override 或 ID 冲突保留 | 不适用；catalog 按 revision 不可变保存 |
| `retired` | 上游移除且未本地改写的规则会在执行库停用 | 仅表示目录版本差异，不会停用任何 PoC 执行规则 |

发布要求 `total = accepted + skipped` 且至少有可用规则。空目录或统计不完整会使整次更新失败。

## 两个数据面的边界

### Wapp 执行库

Wapp 规则遵循现有本地修改保护：用户禁用不会被重新开启，编辑和软删除不被覆盖，自定义同 ID 冲突保留本地规则。上游默认 Enabled 会应用于新规则；后续只有在用户没有设置 enabled override 时才随上游变化。规则更新只影响之后创建的任务，已有任务继续使用冻结快照。

### Nuclei 上游原库

从官方源同步的 Nuclei 规则以 `catalog_only` 保存，初始 `enabled:false` 并带运行能力原因；原库条目可查看或导出，但不会自动进入执行快照。需要执行时，管理员可通过 `POST /api/library/import` 使用 `execution_profile:"http-basic-v1"` 导入受支持的原始 YAML，导入后仍需显式启用、绑定产品并在任务中开启 PoC。

Nuclei 源更新不会写入、覆盖、退役或重新启用当前执行库中的 PoC；也不会把全量目录自动转为执行规则。`http-basic-v1` 只覆盖静态 GET / HEAD 子集，DSL、extractor、raw、payload、fuzz、race、flow、重定向和其他协议仍不执行。

## 原库 API 与导出

管理员可以读取当前或历史 revision：

```text
GET /api/library/sources/{id}/catalog
GET /api/library/sources/{id}/catalog/{ruleID}
GET /api/library/sources/{id}/files
GET /api/library/sources/{id}/files/raw?path=...
GET /api/library/sources/{id}/export
GET /api/library/sources/{id}/license
```

ZIP 导出是流式响应，包含该 revision 的原始模板、辅助文件、许可证和 `.shen-source-manifest.json`。现有执行库 JSON 导入仍最多 10,000 条；仅 import 端点请求体放宽到 32 MiB，以便完整 Wapp JSON 导出包可以整包恢复。其他 JSON API 仍为 8 MiB，勾选导出和批量删除仍最多 1,000 个 ID。

## Control、Agent 与 HTTPx 升级顺序

先升级 Control，使其识别 HTTPx capability，再升级 Agent 并安装 HTTPx，最后更新 Wapp source 和创建新任务。新 Agent 在 claim 中同时提交：

```json
{"use_rule_sets":true,"supports_httpx_cff":true}
```

包含 HTTPx 指纹的 run 会记录 `requires_httpx_cff`。未同时声明上述能力的旧 Agent 不会领取该 run 的 HTTP task，但仍可领取 port、service 或旧 PoC task，避免静默漏识别或把新规则交给旧执行器。

HTTP / service 规则仍通过 `rules_ref` 下载：Worker bearer 必须匹配当前 leased task、session、attempt 和有效 lease；Agent 对最近 8 份规则集做 LRU 缓存，同一 ref 并发下载合并。HTTP claim 不携带 PoC 库。Wapp 7,642 个 app 只在首次下载冻结规则集后重建一次启用 CFF，不在每个 task claim 中重复传输。

HTTPx 运行参数、固定二进制和本地 fixture 结果见 [HTTPx 引擎说明](../deploy/httpx/README.md)。PoC 默认关闭和按产品指纹派发的策略保持不变。
