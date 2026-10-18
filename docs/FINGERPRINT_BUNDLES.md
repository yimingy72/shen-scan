# 完整 HTTP 指纹规则包

当前新任务使用 `web-full-v2` 和 `shen-fingerprint-bundle-v2 / full-http-v1`。在「指纹库 → 来源与更新」执行一键更新，或导入此前导出的完整 v2 执行包。更新下载上游原文后使用实际引擎编译，成功后原子发布；不能编译的记录使更新失败，不再静默过滤。

| 原始资源 | 已装载记录 |
|---|---:|
| Fingers HTTP | 8,727 |
| FingerprintHub Web | 3,139 |
| EHole | 958 |
| Goby | 7,085 |
| 产品别名（不计指纹） | 39 |

固定资源提交：`e870395e898422e43e271ec08f47ff2ccb4003ee`。HTTP 目录共 **19,909** 条原始记录；同名、同内容的上游记录保留其原始 JSON pointer，不能用产品名覆盖。favicon 来自原 Fingers/EHole/FPHub 条件，不伪造额外资源文件。数量是装载记录数，不是独立产品数、实际请求数或识别准确率。

统一 HTTP 目录同时列出 Wappalyzer 规则和此合集，支持来源、引擎、主动/响应/图标/标题筛选及原文查看。来源管理的 fingers 条目以完整包更新、导入和导出；单条原文可以导出，但不在页面上改写为平台 native。Wappalyzer/自定义执行规则保留原有编辑、启停、删除、导入导出。历史任务继续使用各自的不可变快照。

## 执行语义

- httpx 使用官方完整 Runner 做采集；WappalyzerGo 对响应进行匹配。JS/DOM 可在任务中单独开启，由系统 Chrome 提供运行时证据；未选择或无法求值的条件分别记录，不能把全量同步解释为全量执行支持。
- fingers 保留原生被动和主动 matcher，两者可独立选择。开启主动后，未知页面同样进入主动发现，已知产品只提高优先级。
- title 使用真实标题；favicon 与页面头/正文分别取证，保留组合条件，同 hash 的多个产品均参与匹配。
- 安全 GET/HEAD 缓存键包含方法、完整 URL/query、连接 IP、Host、SNI、headers 和入口身份。有 body/Cookie/Auth、状态链或 Set-Cookie/private/no-store 响应不共享缓存。
- Goby 已证明的 `rdp` 单词内部子串误报保留为候选，需独立证据才进入产品 PoC 路由。
- 以完整 finger/template 作为完成单元，绑定原始路径/pointer、ID、内容摘要和冻结 manifest。中断的状态链有界重跑，已接受进度不因换 attempt 丢失。
- 每段最多 1,024 个请求许可、约 45 秒主动执行；入口总上限 16,384、绝对 20 分钟、最多 32 段。失联未知消耗不退还，达到限制明确 partial，不冒充完整未命中。

当前 fingers 合集的 HTTP 资源需要页面、headers、TLS 和关联 icon，不含依赖 JS/DOM 执行的 matcher；Wapp 的浏览器条件由独立可选通道处理。后续源若新增不支持语义，实际编译/能力检查必须拒绝不完整更新。

## 发布与兼容

构建命令 `deploy/build-web-helpers.sh` 不使用 `passive_only`。本地依赖 override 保留源码、原始资源和说明，可重复构建；不要改 Go 模块缓存。Control 只将新 profile 派给对应 Agent/helper 能力；原 v1 包和旧 embedded 路径保留旧执行范围。Manifest 在发布时计算一次，领取只读取摘要，不在每个入口重复解包全库。

HTTP 原始包下载：`GET /api/library/fingerprint-bundles/{digest}`；完整导入：`POST /api/library/fingerprint-bundles/import`。统一目录为 `GET /api/library/http-fingerprints`，原文详情为 `GET /api/library/http-fingerprints/{unit_key}`，均需要管理员权限。

原始资源和各来源声明保留，不把执行引擎许可证当作所有数据集统一许可证。补丁说明见 `third_party/httpx/SHEN_PATCHES.md` 和 `cmd/fingerprint-worker/third_party/`。
