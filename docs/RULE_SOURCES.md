# 指纹规则来源、许可与筛选记录

核对日期：2026-10-17。本文记录 SHEN 公共版规则库扩充所依据的上游、实际执行语义、许可判断和排除范围。研究过程只读取公开仓库源码和本地响应夹具，没有探测任何外部目标。

## Nemo v3 实际调用链

- 核对版本：[`hanc00l/nemo_go` v3.2.1](https://github.com/hanc00l/nemo_go/tree/v3.2.1)，commit `55506cc9fb7cbba329f7ca04dbf7308ee5e5f681`，仓库根许可证为 Apache-2.0。
- `v3/go.mod` 固定 `github.com/chainreactors/fingers` 为 `v1.0.1-0.20240730173434-48ba7446b94b`。
- `v3/pkg/task/fingerprint/httpx.go` 调用外部 HTTPX 收集 header/body/title/status 等响应信息，再把同一响应交给 ChainReactor fingers 和 Nemo 自带的 FingerprintHub 匹配器。FingerprintHub 数据文件 `web_fingerprint_v4.json` 有 3,154 个条目、3,552 个 matcher（2,910 word、382 regex、260 favicon）。
- `v3/pkg/task/fingerprint/fingerprinthub.go` 只实现 favicon、word、regex，matcher 内支持 AND/OR、negative 和大小写；HTTP definition 与 matcher 集合之间采用 OR。SHEN 没有 favicon 输入，因此 favicon 规则不能等价转换。
- `v3/pkg/task/fingerprint/fingerprintx.go` 把目标交给外部 fingerprintx 可执行文件并解析 JSON；这不是“已有 banner 上做字符串匹配”。fingerprintx 自身采用 Apache-2.0，但其主动协议握手不能在不改 Agent 探测器的前提下移植到当前 port matcher。
- HTTPX 项目采用 MIT，负责采集而非提供本次转入的产品规则。

## 许可结论

| 来源 | 固定版本 | 许可判断 | 本次使用 |
|---|---|---|---|
| hanc00l/nemo_go | v3.2.1 / `55506cc` | Apache-2.0 | 仅核对架构、依赖和匹配语义 |
| chainreactors/fingers | `48ba7446` | 仓库根未发现明确 LICENSE | 不复制代码或规则 |
| chainreactors/templates | 2026-10-17 所见 master | 仓库根未发现明确 LICENSE | 不复制规则 |
| 0x727/FingerprintHub | Nemo README 指向的公开仓库 | 仓库根未发现明确 LICENSE | 不复制规则；仅统计 Nemo vendored 数据的能力范围 |
| projectdiscovery/httpx | Nemo bundling 版本未标明 | MIT | 仅确认采集字段，不复制规则 |
| praetorian-inc/fingerprintx | Nemo bundling 版本未标明 | Apache-2.0 | 未移植；主动协议语义不兼容 |
| projectdiscovery/wappalyzergo | v0.3.5 / `10c7df1e2b381046fad03dccb3bec3280052df99` | MIT | 选取并改写 85 个可精确表达的被动信号 |

`wappalyzergo` 明确说明其指纹数据来自 `enthec/webappanalyzer` 与 `HTTPArchive/wappalyzer`。本次固定到上述 commit，保留 `Source` 字段，并按当前 matcher 模型重写为 Go RE2 可编译的 header/body/title 规则，没有把其 3.7 MiB 数据文件直接打包进项目。

完整 MIT 许可证与版权声明见 [THIRD_PARTY_NOTICES.md](../internal/rulelib/THIRD_PARTY_NOTICES.md)。

## 转换准则

只转换以下可由当前一次 HTTP 响应完整表达的信号：

- 专用响应头、`Set-Cookie` 名称、Server/X-Powered-By 产品 token；
- 静态 HTML 中的强 generator meta、产品专用 DOM 属性、脚本/样式资源路径；
- 产品专用标题与第二个独立资源/DOM 信号的 AND 组合；
- 能由 Go RE2 表达的正则和明确版本捕获组。

以下语义全部排除，没有静默降级：

- favicon 的 mmh3/md5/hash；
- JavaScript 运行时全局变量、渲染后 DOM、CSS selector 运行时结果；
- 主动 `send_data`、额外路径探测、协议握手；
- `requires`、`excludes`、`implies`、confidence 分数、复杂 DSL；
- 只有默认端口、泛化标题、裸产品名称、单个通用 cookie/header 的弱规则；
- 无明确再分发许可证的 ChainReactor templates 和 FingerprintHub 原始规则。

`wappalyzergo` 当前包含 7,642 个产品。这里不是无损转换器：只人工选择 85 个常见 CMS、框架和中间件产品。其余 7,557 个没有导入，原因包括类别与任务无关、需要上述不支持语义、信号过弱、与已有规则重复，或尚未做正反样本审查。

## 最终覆盖

- HTTP：150 个稳定 builtin ID，其中原有 54 个，新增 96 个不同产品规则；新增规则中 85 个来自 MIT `wappalyzergo` 的人工改写，11 个是为 SHEN 常见产品/PoC 绑定编写的强被动信号。
- Port：22 个产品规则，数量未增加。当前协议解析器只可靠产出这些产品；仅增加规则无法获得 fingerprintx 的主动握手结果，硬加会退化为按端口猜测。
- PoC：43 个 builtin（原有 7 个、新增 36 个）。`AppliesTo` 只对真实产品名称做 OR 精确规范化匹配；空绑定保持手动选择。通配 `* / all / any / http / https / web` 被校验拒绝。

新增覆盖包括 Adobe AEM、Magento、PrestaShop、Shopware、OpenCart、Discuz! X、Typecho、DedeCMS、ThinkPHP、Craft CMS、October CMS、Umbraco、Moodle、Liferay、Confluence、Jira、CakePHP、CodeIgniter、Symfony、Yii、Rails、FastAPI、SvelteKit、Astro、Qwik、Blazor、Varnish、Traffic Server、APISIX、JBoss、WebSphere、GlassFish、Keycloak、Airflow、Solr、Flink、NiFi、Nacos、Druid、Hadoop YARN 等。规则按产品合并多个 header/body 分支，不把同一产品的不同 header 计成多个产品规则。
