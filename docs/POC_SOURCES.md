# 只读 PoC 来源与筛选记录

核对日期：2026-10-17。SHEN 的 PoC 库包含随项目发布的 bootstrap，以及从固定官方 [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) commit 转换的规则。控制面只发布通过静态只读策略的子集；不会把整个上游模板目录交给 Worker 任意执行。

## 当前官方快照

当前验证快照共读取 14,119 个上游模板，接受 864 条，排除 13,255 条。接受规则中：

- 458 条带明确 `applies_to` 产品绑定，只在同源端点已识别对应产品后派发；其中 11 条为 reviewed verification；
- 406 条没有可靠产品绑定，只能由用户在创建任务时明确选中；
- 常规转换规则使用 `nt-` 前缀的稳定 ID；reviewed verification 使用 `nv-` 前缀。两类都保留来源路径、source revision 和规范内容摘要。

这些数字对应当时的 commit SHA，并非长期固定数量。最新 SHA、accepted / skipped、排除原因和样例以工作台的规则源状态为准。

## 只读静态子集

常规 discovery 自动转换只接受能安全表达为以下模型的 HTTP 模板：

- 同源静态 GET / HEAD；
- 最多 3 个固定路径、8 个 word / regex / status matcher；
- 无 query、payload、动态变量、重定向或外部回连；
- 响应匹配可以由当前原生执行器或受限 Nuclei 进程完整复现；
- 仓库根 MIT 许可证验证通过。

以下类别明确排除并计入拒绝原因：POST 等写操作、raw / DSL / flow / workflow、code、headless、网络或 DNS 模板、payload / fuzz、Interactsh / OAST、认证爆破、默认口令、文件读取、配置或会话泄露、SQL 注入、RCE、上传，以及包含目录穿越或编码利用载荷的路径。解析失败、未知执行字段和无法安全确定语义的模板也不会降级导入。

11 条 reviewed verification 是封闭审核例外，不代表放开上述类别。转换器只在官方相对路径和原文件 SHA-256 与代码内注册表一致时，输出审核后的 native probe / control 定义；原 YAML 不执行。当前包括 9 条固定 `.invalid` 哨兵的开放重定向行为验证，以及 2 条只读取固定非敏感 `/etc/os-release` 的越界读取验证。原模板中的 RCE、OAST、敏感文件或其他分支不会进入执行定义。

若上游文件 hash 变化，该项记为 `review_required`，不会沿用旧审核。来源发布会停用未被用户改写的旧规则并计入 retired，等待重新审阅；11 条规则也不会由 bootstrap seed 插入，只通过 `nuclei-templates` 一键更新作为受管来源规则进入库。

全部模板变得不兼容时，更新会失败并保留旧库，而不是把现有规则批量退役。正常更新中，单条上游规则被移除或不再合规时，未被本地改写的对应规则会停用并计为 retired。

## 结果不等于漏洞清单

853 条 discovery 接受项只检查产品特有的面板、登录页、版本页、健康接口或公开元数据。这类 `info` / `low` 命中用于确认产品表面或暴露状态，不代表存在可利用漏洞。11 条 verification 则要求 probe、阴性 control 和控制面原始报文重验；其 matched 表示观察到审核定义中的行为，仍不单靠响应确定产品版本或漏洞根因。

执行结果严格区分：

- `matched`：完整请求后满足规则条件；
- `not_matched`：完整请求后条件不满足；
- `error`：超时、连接失败、响应不完整、引擎缺失或输出无效，不能推断目标安全。

PoC 默认关闭。用户必须为任务显式开启；未知产品不会自动遍历产品型 PoC。产品名称仅进行大小写、空白、下划线 / 连字符和少量明确别名的精确规范化匹配，不做模糊子串或厂商猜测。没有绑定的规则即使启用，也只有在任务中明确选中 ID 才执行。

## Bootstrap 与 Nemo 历史调研

一键更新出现前，项目维护了 43 条 bootstrap PoC，其中 36 条是在固定公开资料基础上独立编写的单路径只读检查，另有 7 条早期规则。这个“43”是 bootstrap 历史数量，不是当前完整 PoC 库数量。

早期研究核对了 Nemo v3 的真实接入方式：它加载官方 `nuclei-templates`、团队 `some_nuclei_templates`，并通过 `poc_map` 把产品指纹关联到模板。该研究促成了 `applies_to` 的设计，但当前自动 source 只使用 ProjectDiscovery 官方仓库：

| 历史参考 | 固定提交 | 许可证 | 当前用途 |
|---|---|---|---|
| [`hanc00l/nemo_go`](https://github.com/hanc00l/nemo_go) | `0fda1b0d9f28fb57c1e37495ad3ed793dbb85274` | Apache-2.0 | 核对 Nuclei 调用与模板目录接入 |
| [`hanc00l/some_nuclei_templates`](https://github.com/hanc00l/some_nuclei_templates) | `3b56f388784377db5246fd7b1b1f0b160a69d666` | Apache-2.0 | 只做排除范围调研，不同步 |
| [`hanc00l/poc_map`](https://github.com/hanc00l/poc_map) | `acfdd0bf89bdff78c08a1ca17ad9a52f0baf9af1` | Apache-2.0 | 参考产品到模板的关联原则，不同步 |

`some_nuclei_templates` 中常见的 SQL 注入、RCE、上传、认证绕过、任意文件读取以及配置 / 会话泄露模板均不符合本项目边界，没有复制或自动同步。

## 许可与可复现性

官方 `nuclei-templates` 使用 MIT。更新时控制面验证仓库根许可证、记录 commit SHA 与归档内容摘要，并持久化完整许可文本。规则导出包同时携带相关 SHA、MIT 全文和第三方声明；重新导入时这些元数据不会被当作可执行字段。

固定 Nuclei 引擎的下载、校验和许可证见 [引擎部署说明](../deploy/nuclei/README.md)；11 条审核项、逐文件 source pin 和结果边界见 [只读漏洞验证](READONLY_VERIFICATION.md)；一键更新流程见 [规则源更新](RULE_UPDATES.md)。
