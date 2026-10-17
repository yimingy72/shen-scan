# 只读 PoC 扩展来源与筛选记录

研究日期：2026-10-17。本文固定记录研究时使用的提交，避免把会持续变化的上游 `main` 当成可复现版本。

## Nemo v3 的实际接入方式

Nemo v3 在 [`pkg/task/pocscan/nuclei.go`](https://github.com/hanc00l/nemo_go/blob/0fda1b0d9f28fb57c1e37495ad3ed793dbb85274/v3/pkg/task/pocscan/nuclei.go) 中遍历并加载两个目录：`thirdparty/nuclei/nuclei-templates` 和 `thirdparty/nuclei/some_nuclei_templates`。运行时把选择结果交给 Nuclei `-t`，使用 JSONL 输出。该代码把两个模板库作为资源名声明，但没有在执行代码中固定仓库提交。因此，本次研究单独固定以下快照：

| 来源 | 固定提交 | 许可证 | 在 Nemo/poc_map 中的作用 |
|---|---|---|---|
| [hanc00l/nemo_go](https://github.com/hanc00l/nemo_go) | `0fda1b0d9f28fb57c1e37495ad3ed793dbb85274` | Apache-2.0 | v3 的真实 Nuclei 调用与两套模板目录接入 |
| [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | `e07ef2152c4ef4ced8367f879d36c65017c9a5db` | MIT | 官方社区模板与常见产品端点参考 |
| [hanc00l/some_nuclei_templates](https://github.com/hanc00l/some_nuclei_templates) | `3b56f388784377db5246fd7b1b1f0b160a69d666` | Apache-2.0 | Nemo 加载的团队模板目录 |
| [hanc00l/poc_map](https://github.com/hanc00l/poc_map) | `acfdd0bf89bdff78c08a1ca17ad9a52f0baf9af1` | Apache-2.0 | 指纹名称到模板来源与路径的映射依据 |

`poc_map` 明确区分 `nuclei-template`、`some_nuclei_templates` 和私有模板三种来源，并用 `fingerprint[]` 将已识别产品关联到 PoC。本项目的 `Rule.applies_to` 采用同一原则，但只做规范化后的产品精确匹配，不使用模糊子串或通配符。

## 纳入标准

新增的 36 条规则覆盖 36 个产品：`info` 20 条、`low` 14 条、`medium` 2 条。所有规则均满足：

- 仅一个静态同源 `GET`，无 query、payload、变量、重定向、OAST、爆破或写操作。
- `applies_to` 非空，只会在产品已经被识别后参与调度。
- 同时匹配 HTTP 状态与产品特有内容；通用 HTML 200、单独 `OK` 或单独 JSON 字段不算命中。
- `info` 只表示产品特有的公开健康、登录或客户端清单；名称和描述不声称漏洞。
- `low` 表示无需认证即可读取管理、状态、集群或运行信息的暴露。
- `medium` 仅用于可直接确认的调试/设置界面暴露：Werkzeug console、phpMyAdmin setup。
- 不依据版本 banner 推断 CVE，也不读取配置文件、密钥、会话、用户记录、数据库内容或任意文件。

覆盖范围：Jenkins、Elasticsearch、Kibana、RabbitMQ Management、Vault、Grafana、Prometheus、Harbor、SonarQube、Portainer、Apache Airflow、Solr、Druid、Flink、Hadoop、NiFi、Nacos、Traefik、Envoy、nginx、OpenResty、Werkzeug、Microsoft IIS、Django、phpMyAdmin、Swagger UI、Gitea、GitLab、MediaWiki、Joomla、Drupal、Gatsby、Angular、ASP.NET、Apache Tomcat、Microsoft SharePoint。

二次最小化复核删除了 Consul 和 Nomad 的 `/v1/agent/self`，因为完整响应包含运行配置；同时将 Harbor `systeminfo`、Solr `system`、Envoy `server_info` 分别替换为只返回最小健康状态的 `/api/v2.0/ping`、`/solr/admin/info/health`、`/ready`。Jenkins 改用只描述匿名请求身份的 `/whoAmI/api/json`，不再请求会列出 jobs/views 的根 API；Apache `/server-status` 可能包含客户端与请求路径，因此删除。GitLab 使用官方文档明确的 `/-/health` 与 `GitLab OK` 响应；`/-/readiness` 通常返回 JSON 检查结果，且可能在使用 `all=1` 时包含依赖服务状态，因此没有纳入。参见 [GitLab Health check 官方文档](https://docs.gitlab.com/administration/monitoring/health_check/)。

## 未纳入的上游内容

`some_nuclei_templates` 当前主要包含 SQL 注入、RCE、文件上传、OAST、任意文件读取、认证绕过以及会话/配置泄露模板，例如上传类模板、`jumpserver-session-unauth.yaml`、`ruijie-switch-configuration-leak.yaml`。这些模板即使使用 GET，也会读取用户会话、设备配置或其他敏感数据；其余模板需要 POST、动态参数、延时判断、回连或写入。它们均不符合本项目只读静态子集，未复制也未改写为内置规则。

官方 `nuclei-templates` 中的 default-login、文件读取、SQL/RCE、上传、DAST、headless、code、workflow 和 interactsh 模板同样排除。健康接口若只返回通用 `200/OK`，也没有作为漏洞规则加入；只有已关联产品且响应包含产品特有结构时，才作为 `info` 发现项保留。

## 许可证处理

新增 Go 规则是针对公开产品端点独立编写的静态请求和最小匹配器，没有逐字复制完整 YAML 模板、说明或利用 payload。文件中的 `Source` 字段和本文保留了研究来源、固定提交和许可证。

如果后续直接分发上游 YAML 或逐字复制其较大部分，需要同时保留对应许可文本和版权声明：ProjectDiscovery 模板使用 MIT；Nemo、`poc_map`、`some_nuclei_templates` 使用 Apache-2.0，后者还要求修改文件带有显著修改说明，并在存在 NOTICE 时保留 NOTICE。当前扩展没有引入需要随二进制打包的第三方模板文件。
