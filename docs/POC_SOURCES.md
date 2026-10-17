# PoC 执行库与 Nuclei 上游原库

核对日期：2026-10-17。SHEN 当前的 PoC 执行库和 `nuclei-templates` 上游原库是两个独立数据面。

## 当前可执行 PoC

当前执行库保持 **907 条**：

- 原有 896 条 discovery，用于页面、面板、版本、健康接口、公开元数据等发现检查；
- 11 条 native verification，使用固定 probe / control 和完整请求响应证据验证具体行为。

这 907 条规则继续使用现有 native 与受限 Nuclei 执行路径。任务默认 `poc_enabled:false`；用户必须显式开启 HTTP 任务的 PoC 阶段。产品型规则仍按同源端点的真实技术指纹精确匹配，显式选择也不绕过产品绑定；空绑定通用规则只能手选。任务创建时冻结规则，来源更新不改变运行中或历史任务。

Nuclei 上游原库更新**不会**新增、覆盖、退役或重新启用这 907 条规则。原库中出现相同 template ID、CVE 或路径也不建立自动执行关系。

## Nuclei 全量原始目录

当前官方 revision `17f5725dc10ced09f464dd2d255c19957aad51e7` 包含：

- 14,119 个 YAML；
- 14,075 条可解析 catalog rule；
- 377 个非模板 / 辅助 Files，其中含 44 个非模板 YAML；
- 模板正文落入 files 后，当前 revision 约 14,452 个文件条目。

目录规则保留原始 YAML 字节和上游签名注释，不做规范化重写；同时提取 template ID、protocols、capabilities、info、classification、请求数估计、来源 revision / path / SHA-256。所有条目初始禁用并标为 catalog-only；DoS、破坏性、fuzz、爆破、默认口令、credential stuffing、password spray 等额外显示默认关闭原因。

这些字段用于浏览、筛选、风险判断和以后迁移，不表示当前 Agent 能执行模板。工作台“上游原库”只提供查看原文和下载；完整 ZIP 带 MIT 许可证和逐文件 SHA-256 manifest。

## 原始 YAML 执行子集

[原始 Nuclei YAML 兼容性适配方案](NUCLEI_MIGRATION_PLAN.md) 定义的 `http-basic-v1` 已实现。导入时保留原始字节并由官方 Nuclei v3.11.1 执行，支持 GET / HEAD、最多 3 个静态同源请求及 word / regex / status matcher。原始规则必须显式绑定产品，PoC 仍默认关闭并只在任务显式开启后按指纹派发。

以下能力仍不在执行范围：

- 直接把 14,075 条上游目录批量转为执行规则；
- 执行 DSL、extractor、动态变量、raw、payload、fuzz、race、workflow / flow、重定向、code、headless、OAST、DNS 或其他协议；
- 从 `technologies` / `exposed-panels` 模板派生主动 HTTP 发现；
- 将 catalog enabled 状态解释为任务运行许可。

原库同步仍不改变执行库；只有单独导入、通过兼容性检查并启用产品绑定的规则才会进入任务快照。

## 结果语义

discovery 命中通常只确认产品表面或暴露状态，不等于漏洞。verification `matched` 表示正向 probe 和阴性 control 共同满足冻结规则定义；关联 CVE 仍不替代版本归因和影响面分析。

`not_matched` 只表示本次固定检查未满足条件，不表示目标已修复；`error` 表示执行或证据不完整，不能推断安全状态。11 条 native verification 的请求、负对照和限制见 [只读漏洞验证](READONLY_VERIFICATION.md)。

## 来源与许可

官方 `projectdiscovery/nuclei-templates` 使用 MIT。控制面跟随最新 HEAD，记录实际 commit 和文件 hash，用于追溯和数据一致性；这不是人工 source pin 或模板执行白名单。完整许可文本随 source 状态及 ZIP 导出提供。

早期 Nemo、`some_nuclei_templates` 和 `poc_map` 调研只用于理解产品关联，不是当前自动数据源。固定官方源、目录 API 和失败保护见 [规则来源](RULE_SOURCES.md) 与 [规则源更新](RULE_UPDATES.md)。
