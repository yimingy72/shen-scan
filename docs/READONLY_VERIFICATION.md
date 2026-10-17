# 只读漏洞验证

SHEN 将 PoC 规则分为两种用途：

- `discovery`：发现检查。确认面板、版本页、健康接口或其他产品特征；旧规则未写 `purpose` 时也按 discovery 处理。
- `verification`：漏洞验证。只允许进入代码内审阅注册表的固定 native 定义，必须包含 CVE、类别、证据等级和上游 source pin。

产品面板或版本命中不会自动升级为漏洞。当前执行库包含 **896 条 discovery** 和 **11 条 native verification**，合计 **907 条 PoC**。

## 授权和派发

PoC 默认关闭，创建任务时仍须显式设置 `poc_enabled:true`，并包含 HTTP 模式。verification 不增加另一套权限开关；它与 discovery 一样只使用任务创建时冻结的规则快照。

11 条 verification 都有非空 `applies_to`。即使用户明确选择某条规则，也必须由该同源 HTTP 端点的真实技术指纹，或同目标、同 IP、同端口的服务产品，精确规范化命中绑定产品后才能派发。匹配不做模糊子串或厂商猜测。HTTP 重定向不会自动把新域名加入 PoC 范围。

## 历史来源与当前更新边界

11 条 native 定义保留了当时参考的官方 [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) 路径、commit 和文件 SHA-256：

| Source ID | 历史来源 commit | 许可证 | 当前用途 |
|---|---|---|---|
| `nuclei-templates` | `17f5725dc10ced09f464dd2d255c19957aad51e7` | MIT | provenance、结果说明和任务数据一致性 |

这些 source pin 是现有规则的历史来源记录，不是最新 HEAD 的人工批准机制。Agent 执行的是已经冻结的 native probe / control 定义，不执行对应原始 YAML，也不会执行 YAML 中的其他分支。

新的 Nuclei HEAD 同步只写入独立“上游原库”。它不会创建、更新、退役或重新启用这 11 条 verification，也不会把原始模板交给现有执行器。当前 ConverterVersion 4 只负责原库目录与文件追溯。

原库中的 revision / hash 随 HEAD 更新，仅表示内容来自哪个版本。上游文件变化会产生新的 catalog revision，不会修改现有 verification。原始 Nuclei 执行器迁移尚未完成。

## 执行和证据闭环

每条 verification 使用 2–3 个按顺序执行的静态 GET 请求，并同时包含 `probe` 和 `control`。开放重定向只观察响应状态和 `Location`，不跟随跳转，也不会连接固定的 `shen-verify.invalid` 哨兵主机。文件读取只请求固定非敏感的 `/etc/os-release`，不读取账户、密钥、配置、会话或业务文件，也不尝试命令执行。

Agent 为每个请求回传一组完整的 `checks[].request_raw` 和 `checks[].response_raw`。verification 只有在以下条件全部满足时才能记录为 `matched`：

1. check 数量与冻结规则的请求数量相同，顺序一致，且整体证据未截断、没有执行错误；
2. 每个请求的方法、精确 URI、指定 Header、空请求体和同源 host 都与任务规则一致；
3. 控制面重新解析每个原始 HTTP 请求与响应，并重新运行各请求 matcher；
4. 控制面再次运行完整 native 规则，正向 probe 和阴性 control 共同满足差分条件。

观测中的 `purpose`、CVE 和 verification metadata 由控制面从冻结任务规则写入，不接受 Worker 自行上报的分类升级。缺项、乱序、越出同源、原始报文不完整、响应截断或阴性对照失败都会使 `matched` 上报被拒绝。

## 当前审核项

下面的“验证方式”描述网络上实际执行的只读行为。“限制”说明结果能证明什么；关联 CVE 不表示平台仅凭响应就确定了产品版本或漏洞根因。

| CVE / 产品 | 验证方式 | 阴性对照 | 限制 |
|---|---|---|---|
| CVE-2018-11784 / Apache Tomcat | 请求 `//shen-verify.invalid`，要求重定向响应的 `Location` 指向固定 `.invalid` 哨兵 | `/shen-verify.invalid` 不得产生相同外部重定向 | 证明该端点呈现对应重定向行为；反向代理或 URL 规范化也可能影响响应，不能单靠响应判定 Tomcat 版本根因 |
| CVE-2018-14574 / Django | 请求 `//shen-verify.invalid`，要求固定哨兵重定向 | `/shen-verify.invalid` 不得产生相同外部重定向 | 证明行为，不根据 Server、页面或关联 CVE 推断 Django 版本 |
| CVE-2021-29622 / Prometheus | 请求 `/new/newhttp://shen-verify.invalid`，检查固定哨兵重定向 | `/new/__shen_control` 不得产生相同外部重定向 | 只覆盖该固定路径行为，不枚举其他路由或跟随跳转 |
| CVE-2022-28923 / Caddy | 请求固定双编码反斜线 / 路径载荷，检查固定哨兵重定向 | `/__shen_control/` 不得产生相同外部重定向 | 代理层解码和规范化会影响结果；不据此单独确定 Caddy 版本 |
| CVE-2020-11529 / Grav | 请求固定双编码 URL 载荷，检查固定哨兵重定向 | `/__shen_control/` 不得产生相同外部重定向 | 只验证响应差分，不测试认证、写操作或其他 Grav 路由 |
| CVE-2024-57241 / DedeCMS | 向固定 `plus/download.php` 查询参数提供编码后的 `.invalid` URL，检查重定向 | 同一端点使用编码后的本地 control 值，不得产生哨兵重定向 | 查询和值均固定；不构造任意外部目标，不跟随跳转 |
| CVE-2023-32068 / XWiki | 向固定登录路径的 `xredirect` 提供 `//shen-verify.invalid`，检查重定向 | `xredirect=/__shen_control` 不得产生相同外部重定向 | 先要求 XWiki 强被动指纹；结果说明端点行为，不独立证明版本或部署根因 |
| CVE-2025-54793 / Astro | 请求 `//shen-verify.invalid/en/`，检查固定哨兵重定向 | `/shen-verify.invalid/en/` 不得产生相同外部重定向 | 仅覆盖固定 locale 路径；代理或路由配置可能改变行为 |
| CVE-2025-4123 / Grafana | 请求固定编码的 `/public/` 路径载荷，检查固定哨兵重定向 | `/public/__shen_control` 不得产生相同外部重定向 | 不推断 Grafana 版本；代理重写或自定义 public 路径可能改变结果 |
| CVE-2021-43798 / Grafana | 通过固定插件路径读取 `/etc/os-release`，要求同时出现发行版 `NAME` 与 `ID` 特征 | 直接请求 `/etc/os-release` 和穿越到固定不存在文件，两者都不得出现该证据 | 只验证固定非敏感文件的路径越界读取；不读取配置、凭据或其他敏感文件 |
| CVE-2021-41773 / Apache HTTP Server | 通过固定 `/icons/` 编码路径读取 `/etc/os-release`，要求同时出现发行版 `NAME` 与 `ID` 特征 | 直接请求 `/etc/os-release` 和穿越到固定不存在文件，两者都不得出现该证据 | 只验证固定非敏感文件的路径越界读取；不尝试 RCE、CGI 或敏感文件读取 |

每条规则还固定了上游相对路径和文件 SHA-256：

| CVE | 上游路径 | 文件 SHA-256 |
|---|---|---|
| CVE-2018-11784 | `http/cves/2018/CVE-2018-11784.yaml` | `3e0ad45800d75b4bcaa0bf7f1e0fb5b168e356e3d850bea995ef85087665b05d` |
| CVE-2018-14574 | `http/cves/2018/CVE-2018-14574.yaml` | `a5d2eb3dc03879e79bbeece03981f2cc193aef57e96a27b7d6c4ccbaaa600bb7` |
| CVE-2021-29622 | `http/cves/2021/CVE-2021-29622.yaml` | `e94334b34941a80784eac44e84c3a8e606794e66700b7700ea188503a17a113e` |
| CVE-2022-28923 | `http/cves/2022/CVE-2022-28923.yaml` | `33b4de95a47c3097be06cfe0234e34b046c5f079bc97ead6cb32c09b0f336b27` |
| CVE-2020-11529 | `http/cves/2020/CVE-2020-11529.yaml` | `c8a990d3a6ed859504f449134f8af158d9bfa3c724f5528471facbc2e02b3cc5` |
| CVE-2024-57241 | `http/cves/2024/CVE-2024-57241.yaml` | `7dc7e6b43a13d47656490bfffdd9d4b6e6f569f91f6923f66866138028006b9e` |
| CVE-2023-32068 | `http/cves/2023/CVE-2023-32068.yaml` | `c657286ca7af98f76323399f61c1d2c5c1d5925d0b0c1041ee879ba925b2d22e` |
| CVE-2025-54793 | `http/cves/2025/CVE-2025-54793.yaml` | `9c00be602bdeb7b43678523af2b6a13847feaac63f72ffbb0a4695b32708acf1` |
| CVE-2025-4123 | `http/cves/2025/CVE-2025-4123.yaml` | `70e5abd7529ffee1792a7917782ce5c3db7680466b6265414c1b6ddaa386cf8b` |
| CVE-2021-43798 | `http/cves/2021/CVE-2021-43798.yaml` | `9086c36be285c9206f6ec3013db9b212e9fa798b8bba97494037f0d6df9e9d7b` |
| CVE-2021-41773 | `http/cves/2021/CVE-2021-41773.yaml` | `7f5d21b935a782395d1e7471fbad9140f02601e0b2f4eff30e80355ceb8fd630` |

## 结果语义和验证状态

- verification `matched` 表示完整差分请求在该端点呈现了注册表定义的行为。界面应表述为“行为验证”，不应把关联 CVE 写成已经完成版本归因、影响面分析或可利用性扩展。
- `not_matched` 只表示本次固定请求和对照没有同时满足定义。它可能受到路由、认证、WAF、反向代理或运行配置影响，**不表示目标已修复**。
- `error` 表示请求、响应或证据链不完整，不能推断安全状态。
- discovery 命中仍只表示发现检查条件成立；面板、版本页或产品特征不能计为 verification 漏洞命中。

当前 11 条规则均已通过 Agent 合成正向 / 阴性夹具。控制面证据防伪测试及本地 Control → Agent → 合成 HTTP 目标的两类端到端验证已通过：正例 2 条、反例 2 条，未知产品未派发，默认关闭任务检查数为 0。未执行外部扫描，也未完成真实漏洞软件与修复版本的对照，因此不声称已经在 11 种真实漏洞实例上完成验证。

部署时必须先升级 Control，再升级 Agent。新 Control 能识别冻结规则中的 verification metadata 并重验 `checks`；新 Agent 才会逐请求回传完整证据。版本未同时满足时，不应启用这批 verification。
