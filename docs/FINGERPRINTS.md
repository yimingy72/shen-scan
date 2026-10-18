# HTTP 与服务指纹依据

当前 bootstrap 包含 **157 条 HTTP 规则（151 条原有规则 + 6 条按产品补采）、22 条端口规则和 43 条 PoC**。记录的 Wapp source 为 7,642 个完整 app；与当前 bootstrap 合计理论值为 7,799，实际数量取决于 source 更新和本地编辑。完整执行规则以任务冻结快照为准。

新任务由 Web helper 采集响应并运行 WappalyzerGo，Agent 继续用同一响应运行 fingers 与 native 被动规则；识别到产品后，按冻结 HTTP collection 规则有限补采。补采使用独立响应匹配，不拼接正文。六项规则、同源跳转和预算见 [Web 补采](WEB_ENRICHMENT.md)。服务产品规则仍只依据真实协议与 Banner，不从端口号猜测。

## HTTP 规则

| 技术 | 匹配条件 | 版本来源 |
|---|---|---|
| WordPress、Drupal、Joomla、Ghost、MediaWiki、TYPO3 CMS、Hugo | `meta[name=generator]` 或 `X-Generator` 的值以产品名开头；WordPress 还接受真实资源 URL 中的 `/wp-content/` 或 `/wp-includes/` | generator 产品名后的版本令牌 |
| Next.js | `script#\_\_NEXT_DATA\_\_` 或 `X-Powered-By: Next.js` | 不推测 |
| Nuxt、Gatsby | 对应应用根元素 `#__nuxt`、`#___gatsby` | 不推测 |
| Angular | 元素的 `ng-version` 属性 | 属性值 |
| PHP、ASP.NET | `X-Powered-By`；ASP.NET 也接受 `X-AspNet-Version` | Header 中明确给出的版本 |
| Express | `X-Powered-By: Express` | 不推测 |
| Laravel | 名为 `laravel_session` 的响应 Cookie | 不推测 |
| Django | 响应同时出现 `csrftoken` Cookie 和 `csrfmiddlewaretoken` HTML 字段 | 不推测 |

规则按 Header、HTML 元素和 Cookie 的结构匹配，避免在普通正文中搜索单个产品词。比如介绍 `wp-content/` 或 `__NEXT_DATA__` 的文章不会被识别为 WordPress 或 Next.js；单独出现 `csrftoken` 也不会判断为 Django。

## 服务规则

- SSH 按 [RFC 4253 第 4.2 节](https://www.rfc-editor.org/rfc/rfc4253#section-4.2) 拆分 `protoversion` 和 `softwareversion`。`SSH-2.0-OpenSSH_9.6p1` 的产品为 OpenSSH、版本为 `9.6p1`；`2.0` 是协议版本，不再写进产品版本。
- HTTP Banner 从 `Server` Header 中拆分常见服务器的显式版本，包括 nginx、Apache HTTP Server、Microsoft IIS、Caddy、OpenResty、lighttpd、Gunicorn、Uvicorn 和 Werkzeug。未知 Server 值保留原文，不猜版本。
- SMTP、FTP 先要求合法的 `220` 状态行及协议/产品标识，再提取 Postfix、Exim、vsftpd、ProFTPD 或 FileZilla Server 的显式版本。普通正文包含 `smtp` 或 `ftp` 不构成命中。
- MySQL 要求完整的 protocol 10 初始握手包头，并从 NUL 结尾的 server version 字段读取版本；MariaDB 只在该字段明确含 `MariaDB` 时区分。
- Redis 只接受 `PING` 的 `+PONG`、`-NOAUTH` 或明确提到 `PING` 的 `-NOPERM` 响应；memcached 只接受 `VERSION <version>`。普通 `-ERR` 不作为 Redis 证据。
- 没有 Banner、TLS 握手或上述命令响应依据时，服务、产品和版本均留空；端口号本身不作为识别结果。

## 来源与许可

规则条件根据下列项目文档、协议文档或项目自身仓库所描述的公开输出重新编写：

- [WordPress `wp-content` 配置文档](https://developer.wordpress.org/apis/wp-config-php/#moving-wp-content-folder)
- [Next.js `__NEXT_DATA__` 文档](https://nextjs.org/docs/messages/large-page-data)
- [Drupal generator 说明](https://www.drupal.org/project/drupal/issues/275092)
- Joomla、Ghost 和 TYPO3 的 generator 规则仅接受相应项目名；核对来源为项目自身仓库：[Joomla CMS](https://github.com/joomla/joomla-cms)、[Ghost](https://github.com/TryGhost/Ghost)、[TYPO3](https://github.com/TYPO3/typo3)
- [MediaWiki generator 输出](https://www.mediawiki.org/wiki/Topic:Vzur7g62k9hsxymp) 与 [Hugo generator 输出](https://gohugo.io/functions/hugo/generator/)
- [Nuxt 部署文档中的 `#__nuxt`](https://github.com/nuxt/nuxt/blob/main/docs/1.getting-started/16.deployment.md)
- [Gatsby 项目中的 `#___gatsby` 示例](https://github.com/gatsbyjs/gatsby/issues/22908)
- Angular 版本规则只读取框架写入 DOM 的 `ng-version` 属性；实现核对来源为 [Angular 项目仓库](https://github.com/angular/angular)
- [Django CSRF Cookie 与字段](https://docs.djangoproject.com/en/5.2/ref/csrf/)、[Express `X-Powered-By`](https://expressjs.com/en/4x/api.html#app.settings.table) 和 [ASP.NET 版本 Header](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/aspnet/development/cannot-use-session-state-server)
- [PHP `X-Powered-By` 说明](https://www.php.net/security.hiding.php)；Laravel 的 `laravel_session` 只作为旧版/显式配置仍使用该专用名称时的信号，不把任意 `*_session` Cookie 当成 Laravel
- [MySQL protocol 10 handshake](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)
- [Redis PING 命令](https://redis.io/docs/latest/commands/ping/) 与 [memcached 文本协议](https://github.com/memcached/memcached/blob/master/doc/protocol.txt)
- [SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253#section-4.2)、[SMTP](https://www.rfc-editor.org/rfc/rfc5321) 和 [FTP](https://www.rfc-editor.org/rfc/rfc959) 协议文档

Bootstrap 中 85 个被动信号是早期对 MIT `projectdiscovery/wappalyzergo` 的人工改写，并保留 [许可证与归属](../internal/rulelib/THIRD_PARTY_NOTICES.md)。现在 Wapp source 还保存全部原始 app JSON，并交给 HTTPx 的正式 CFF 语义处理；native 规则继续用于自定义和旧快照补充。未从无明确许可证的 FingerprintHub 或 ChainReactor 复制规则。

## 调度边界

新任务冻结 `bounded-enrichment-v1`，使用 Web helper 和常驻 fingers；最多跟随 3 次同源跳转，并共享 8 次逻辑采集、最多 2 个补采 URL 和 90 秒父截止时间。跨 scheme、host 或有效端口不跟随。没有新 profile 的历史快照保持原行为；旧 HTTPx CLI / native 路径继续兼容，不会自动增加网络动作。连接预算和 helper 进程复用见 [P2 执行资源](P2_EXECUTION.md)。

## 匹配质量

禁用的 HTTP / 端口规则不会参与新任务匹配。空响应不识别技术；正文截断或读取失败时不据此断言某个正文标记不存在。同产品的多条规则合并显示，保留明确版本。Drupal 不把任意 X-Generator 当作依据，phpMyAdmin 不根据正文的单个产品词命中。

基础协议解析仍用于确认 HTTP、SSH、SMTP 等协议；端口产品匹配由任务快照控制。PoC 的请求和结论单列，不混入普通端口产品汇总。

完整来源与覆盖列表见 [规则来源记录](RULE_SOURCES.md)。端口库仍为 22 个可靠产品；当前 Agent 没有 fingerprintx 的全部主动协议握手，单纯新增端口规则不能获得这些能力。
