# 指纹规则来源、许可与筛选记录

核对日期：2026-10-17。SHEN 的规则库由两部分组成：随项目发布的 bootstrap 规则，以及管理员按需更新的固定官方源。所有数量都对应某个上游 commit SHA；上游变化或转换策略升级后，数量会变化。

## 当前官方源

| Source ID | 固定官方仓库 | 许可证 | 当前验证快照 |
|---|---|---|---|
| `wappalyzer` | [`projectdiscovery/wappalyzergo`](https://github.com/projectdiscovery/wappalyzergo) | MIT | 7,642 个产品中接受 4,437 条 HTTP 规则，排除 3,205 个产品 |
| `nuclei-templates` | [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) | MIT | 14,119 个模板中接受 864 条只读 PoC，排除 13,255 个模板；含 11 条 reviewed verification |

控制面先从 GitHub API 读取最新 commit，再从固定 SHA 的 `codeload.github.com` 地址下载归档。它校验归档边界、根目录、文件数量和大小，并要求仓库根 MIT 许可证；完整许可文本随 source 状态持久化，可在工作台查看。可选 `GITHUB_TOKEN` 只用于 `api.github.com` 的限额认证，不会发送给 codeload、Worker 或浏览器。

同一 SHA 且转换器版本未变化时，只检查 HEAD，不重复下载归档。当前策略版本为 `ConverterVersion=3`；v3 增加了 Nuclei 文件 source pin 审核与 native verification 转换。以后转换器或只读策略升级会增加内部版本，即使 commit 相同也会重新转换。更新流程、失败保护和 API 见 [规则源更新](RULE_UPDATES.md)。

## Wappalyzer 转换范围

转换器只保留当前一次 HTTP 响应可以完整表达的被动信号：

- 专用响应头、Cookie 名称、HTML、meta 和静态脚本路径；
- 可以安全转换为 Go RE2 的 word / regex 条件；
- 有明确产品归属、不会把普通页面元素当作产品证据的信号。

以下能力明确排除，不做低保真降级：

- JavaScript 运行时变量、渲染后 DOM、CSS selector 运行结果；
- favicon hash、主动请求、额外路径和协议握手；
- 无法完整表达的 `requires`、`excludes`、`implies` 和置信度关系；
- 无效正则、弱通用 token 及与扫描任务无关的产品条目。

主统计中的 `skipped` 是产品级排除，满足 `total = accepted + skipped`。信号级损失单独记录，不重复计入产品级排除。规则 ID 使用稳定的 `wa-` 前缀和产品名摘要；更新同一产品时保留本地启停选择。

## 当前库规模

当前完成验证的数据库快照为：

- HTTP：4,588 条，其中当前 bootstrap 151 条、Wappalyzer 转换规则 4,437 条；新增项是供 verification 派发使用的 XWiki 强被动指纹；
- Port：22 条 bootstrap 产品规则；
- PoC：907 条，其中 43 条 bootstrap discovery、853 条 Nuclei discovery 和 11 条 Nuclei reviewed verification。

这些不是代码承诺的固定常量。工作台显示的 source revision、digest、accepted / skipped 和规则库实际计数才是当前部署的权威状态。

## Bootstrap 的历史来源

一键更新出现前，SHEN 根据公开资料人工维护了 150 条 HTTP、22 条 port 和 43 条只读 PoC。HTTP bootstrap 中 85 条是对 MIT `wappalyzergo` 信号的人工改写，另有产品专用强信号；许可声明保留在 [THIRD_PARTY_NOTICES.md](../internal/rulelib/THIRD_PARTY_NOTICES.md)。当前代码又增加了 XWiki 强被动指纹，因此随项目发布的 HTTP 规则为 151 条。历史“150 / 22 / 43”不代表当前自动更新后的完整库。

早期调研同时核对了 [`hanc00l/nemo_go`](https://github.com/hanc00l/nemo_go) v3.2.1（commit `55506cc9fb7cbba329f7ca04dbf7308ee5e5f681`）：它组合 HTTPX、ChainReactor fingers、FingerprintHub 和 fingerprintx。`httpx.go` 收集 header / body / title / status 后交给静态匹配器；`fingerprinthub.go` 实现 favicon、word、regex 和 AND / OR / negative；`fingerprintx.go` 则启动外部主动协议探测器。研究快照中的 `web_fingerprint_v4.json` 有 3,154 个条目、3,552 个 matcher（2,910 word、382 regex、260 favicon），这些统计只描述 Nemo vendored 数据，不是 SHEN 当前规则数。

该研究解释了产品关联和主动协议探测的差异，但当前自动 source 不从 Nemo、ChainReactor 或 FingerprintHub 下载内容：

- Nemo 为 Apache-2.0，仅用于核对架构和调用语义；
- ChainReactor fingers / templates 与 FingerprintHub 当时未发现可满足本项目再分发要求的明确仓库根许可证，因此不复制；
- fingerprintx 是主动协议握手，不可等价转换为已有 Banner 上的静态 matcher；
- HTTPX 负责采集响应，不是本次规则数据源。

当时核对的 ChainReactor fingers 版本为 `48ba7446b94b`；Nemo 与 fingerprintx 分别采用 Apache-2.0，HTTPX 采用 MIT。ChainReactor templates / fingers 与 FingerprintHub 原始规则没有作为当前自动源，其许可证与执行语义也不会由一键更新流程继承。

Port 规则仍以 Agent 实际协议解析结果为前提；仅增加字符串规则不会获得 fingerprintx 的主动握手能力，也不会按默认端口猜产品。

## 本地修改与来源归属

来源规则记录 `source_id`、上游规范内容摘要和 source revision。再次更新时：

- 用户的禁用状态继续保留；
- 已编辑、删除或与本地自定义 ID 冲突的规则不被覆盖；
- 上游移除且没有本地改写的规则会被停用并计为 retired；
- reviewed verification 的原文件 hash 变化会记为 `review_required`；未改写的旧条目停用，不执行变化后的模板；
- 更新失败不会发布部分规则，也不会替换上一次成功版本。

导出的 JSON 包含相关上游 SHA、MIT 许可全文和 bootstrap 第三方声明，可直接作为规则与许可备份。手工导入恢复后视为本地修改，不再由上游静默覆盖。

Reviewed verification 不参与 bootstrap seed，只能在 `nuclei-templates` 更新中以受管来源规则接入。固定 commit、逐文件 SHA、执行证据和结果限制见 [只读漏洞验证](READONLY_VERIFICATION.md)。
