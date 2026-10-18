# 指纹规则与上游原库来源

核对日期：2026-10-17。SHEN 从两个固定的 ProjectDiscovery 官方仓库跟随最新 HEAD，同步时记录实际 commit、文件 SHA-256、归档摘要和 MIT 许可证全文。revision 和 hash 用于来源追溯、更新幂等及任务快照一致性，不是人工批准列表，也不会把 Nuclei 原始模板自动变成可执行规则。

| Source ID | 固定官方仓库 | 当前快照 | 发布位置 |
|---|---|---|---|
| `wappalyzer` | [`projectdiscovery/wappalyzergo`](https://github.com/projectdiscovery/wappalyzergo)，MIT | 7,642 个完整 app | 进入 HTTP 执行库，由 HTTPx v1.12.0 被动识别 |
| `nuclei-templates` | [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates)，MIT | revision `17f5725dc10ced09f464dd2d255c19957aad51e7`；14,119 个 YAML 中形成 14,075 条目录规则；377 个 Files 中含 44 个非模板 YAML | 只进入独立“上游原库”，不进入执行库 |

Nuclei 的有效目录规则保留原始 YAML 字节，不规范化、重写或替换上游签名；SHA-256 按原文件计算。44 个无法作为模板解析的 YAML 仍包含在 377 个 Files 中。控制面把目录规则的模板正文和这 377 个非模板 / 辅助文件按路径保存，当前快照在文件表约为 14,452 项，实际数量以 source revision 的 files API 为准。

原文件以 PostgreSQL BYTEA 保存，是原文和导出的权威数据。catalog JSONB 只保存不含 Template 的索引副本；metadata 字符串或键中的 NUL 会递归显示为 `␀`，并在 `catalog_sanitized_fields` 记录位置。规则详情再从 BYTEA 恢复原始 Template，因此索引兼容处理不会改变源字节或 SHA。

## Wappalyzer 与 HTTPx

Wappalyzer 转换不再把上游 app 降级成少量 Go word / regex。每个 app 的原始 JSON 存入 `Rule.Fingerprint`，所有已启用 app 在任务创建时冻结；Agent 使用 HTTPx v1.12.0 的 `-cff` 生成本任务的被动识别集合。

HTTPx 的 `-cff` 会叠加自身 embedded fingerprints，因此 Agent 只接纳当前冻结快照中启用产品的输出。禁用 app 不会因为 HTTPx 内置库仍存在而重新出现。旧 native HTTP 规则继续支持自定义规则和历史任务快照，并可与 HTTPx 使用同一份响应证据。

当前完整 Wapp app 为 7,642 条，加上 157 条 bootstrap HTTP 规则，更新后的 HTTP 执行库预计为 **7,799 条**；最终数量以 live 数据库列表为准。Port 规则仍为 22 条。Wapp 更新继续保留用户的禁用、删除和编辑状态；新上游默认启停策略仅在没有本地 override 时生效。

HTTPx 安装、固定版本和运行参数见 [HTTPx 引擎说明](../deploy/httpx/README.md)。本地普通 HTTP / HTTPS fixture 覆盖了默认端口、同 origin 多 URL、漏结果检测及失败协议回退；3 个端点在验证环境中约 2.0 秒完成。Mac 小型 fixture 的观测最大 RSS 为 216 MiB；这些数据用于说明当前测试边界，不是大规模容量承诺。

## Nuclei 上游原库

Nuclei HEAD 同步后的所有可解析模板都写入独立 source catalog，并统一带有：

- 原始 template ID、protocols、capabilities、info、classification 和请求数估计；
- `Upstream{source_id,revision,path,sha256}` 来源信息；
- 目录条目使用 `catalog_only:true`、`enabled:false` 初始状态，并保留运行能力原因；需要执行时单独走 `http-basic-v1` 导入；
- 对 DoS、破坏性、fuzz、爆破、默认口令或密码喷洒等模板的额外默认关闭原因。

“上游原库”支持分页、筛选、查看完整 YAML、读取任意原始文件和下载整个 revision 的 ZIP。ZIP 包含路径、大小和 SHA-256 manifest。目录的 enabled 值是管理元数据，不代表具备运行能力；catalog-only 条目不会进入任务快照或派发给现有 Agent。

全量原库已同步，但不会自动生成可执行规则；`http-basic-v1` 仅支持经过检查的静态 HTTP 子集，不能把“14,075 条模板可同步”表述成“14,075 条模板可执行”。原始目录中的 DSL、extractor、raw、payload、fuzz、race、flow、重定向和其他协议仍不在执行范围。

现有 PoC 执行库保持 **907 条**：原有 896 条 discovery 加 11 条 native verification。Nuclei 原库更新不会新增、覆盖、退役或重新启用这 907 条规则；历史任务仍使用其创建时冻结的规则数据。

## Bootstrap 与历史调研

一键更新出现前，项目维护了 150 条 HTTP、22 条 port 和 43 条 PoC；当前又补充 1 条 XWiki 强被动 HTTP 指纹。HTTP bootstrap 中 85 条是对 MIT `wappalyzergo` 信号的早期人工改写。它们现在主要用于旧快照兼容和明确的 native 补充，不代表完整 Wapp 数据量。

早期还核对了 [`hanc00l/nemo_go`](https://github.com/hanc00l/nemo_go)、`some_nuclei_templates` 和 `poc_map`，用于理解产品关联和调用方式。当前自动 source 不从 Nemo、ChainReactor、FingerprintHub 或团队模板仓库同步规则；这些历史调研不会改变两个固定官方 source 的许可和执行边界。

## 更新与许可

控制面只访问固定 GitHub API、codeload 仓库和 commit，不接受任意 URL。下载后校验归档边界、文件路径、大小和 MIT 许可，并在一个数据库事务中发布；失败保留上一成功版本。同一 HEAD 且 ConverterVersion 未变化时不重复下载，当前转换版本为 **4**。

完整 MIT 文本可在工作台查看，也随规则或上游原库导出。更新、失败保护和 API 见 [规则源更新](RULE_UPDATES.md)，PoC 执行库边界见 [PoC 来源](POC_SOURCES.md)。

## HTTP 产品补采

新增 6 条 `collection` HTTP 规则，只在已识别产品匹配后请求固定路径。支持现有编辑、禁用、删除、JSON 导入/导出与任务快照；不是将整个 PoC 库作为 HTTP 规则执行。新任务使用 Web helper + WappalyzerGo/fingers，旧 CLI 说明仅适用于历史兼容路径。预算、数据模型和证据详见 [Web 补采](WEB_ENRICHMENT.md)。
