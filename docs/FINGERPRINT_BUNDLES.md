# Web 被动指纹库更新

在「指纹库 → 被动库」中更新 fingers 数据。平台读取 chainreactors/fingers 的最新提交，并从该提交下载 Fingers、FingerprintHub、EHole 和 aliases 四个固定文件。下载、解压、解析和实际引擎检查全部成功后，才原子替换新任务的默认包；失败保留旧包。SDK 不随数据更新，当前固定为 `e870395e898422e43e271ec08f47ff2ccb4003ee`，必须使用 `passive_only` 构建。

## 识别范围与统计

这是对已采集 HTTP 响应的被动匹配，不额外运行通用主动模板。FingerprintHub 当前只接纳能够正确表达的单个根路径 GET 正向规则，且只用于真实根路径、无 query 的响应；路径探测、主动规则和不支持的表达式分别计数。界面按引擎显示加载/总数，aliases 单列，不将别名计入规则数量，也不承诺上游所有规则均可执行。

2026-10-18 对上述提交的实际加载结果：

| 数据 | 总条目 | 加载 | 主动排除 | 不支持 | 编译失败 |
|---|---:|---:|---:|---:|---:|
| Fingers | 8,727 | 7,884 | 51 | 792 | 0 |
| FingerprintHub | 3,139 | 2,875 | 7 | 257 | 0 |
| EHole | 958 | 911 | 0 | 47 | 0 |
| aliases | 39 | 39 | 0 | 0 | 0 |

共11,670条可加载规则、39条别名。数量随源版本变化。来源混合，保留上游原文及声明，不给所有规则统一标注MIT许可。

## 任务、Worker 与包

- 创建任务时固定包SHA-256和schema，派生HTTP任务继承；更新不改变已创建任务。历史内置包任务仍使用原来的嵌入数据。
- 包包含原始数据、有效子集、逐文件摘要及拒绝原因。已发布包不可修改/删除；可下载原库ZIP和执行包。
- Agent声明 `fingerprint_bundle_schema` 能力；旧Agent不认领外部包任务。包下载校验task、worker、session、attempt及有效租约，按任务读取固定包，不接受任意下载地址。
- Agent校验摘要及大小后缓存一个包，切换时停止旧matcher并使用新包启动常驻helper。损坏或不匹配会报错，不静默换成当前默认库。
- HTTP响应和匹配结果携带实际包身份。PoC仍默认关闭、任务中显式开启并按识别产品选择；此次不扩展Nuclei执行范围。

## 部署

`deploy/build-release.sh` 同时输出Agent包及 `tools/fingerprint-worker`。控制服务器须安装该checker到 `scan-server` 同级的 `tools/fingerprint-worker`，或设置绝对路径 `FINGERPRINT_CHECKER_BINARY`。只装Agent端helper无法让控制面完成更新检查。每次checker调用最长120秒；stdout上限96MiB，stderr仅保留最后16KiB，不因正常日志量终止有效更新。

先部署Control与checker，再在Worker维护模式下等已有任务排空后分批升级Agent。使用当前session解除维护。全部可用Worker具备新能力后更新被动库；否则新包HTTP任务等待兼容节点，不降级执行。

发布包自动迁移 `fingerprint_bundles` 和默认引用表。升级前备份数据库、运行配置和云凭据加密密钥。恢复旧控制面时保留新表数据，新包任务仍需兼容Agent。

## 必要验证

已覆盖实际helper生成/检查、固定来源下载边界、错误包保留默认值、历史包不可变、A/B任务快照、过期执行和错误session下载拒绝、旧Agent兼容性、真实helper切换缓存包，以及完整上游库的一键更新。页面截图和完整HTTP请求响应保存在私有验证目录，避免将部署凭据或业务目标推送到公有仓库。
