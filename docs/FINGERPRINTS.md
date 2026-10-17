# HTTP 与服务指纹依据

当前随项目发布的 bootstrap 包含 151 条 HTTP 规则、22 条端口规则和 43 条 PoC。Wapp source 更新加入 7,642 个完整 app，由 HTTPx v1.12.0 被动识别；本轮更新后已验证 HTTP 执行库为 7,793 条，后续数量随上游更新与本地修改变化。下面列举 native bootstrap 的主要依据，完整执行规则以任务创建时的冻结快照为准。

HTTP 指纹只使用本次 HTTP 探测响应，不为识别 CMS、框架或版本增加请求。HTTPx 使用完整 Wapp CFF 识别后，Agent 只保留冻结快照中启用的产品，并继续用同一响应运行 native 补充规则。服务指纹优先读取连接已经返回的首段 Banner；6379 和 11211 端口分别发送一次无副作用的 `PING` 和 `version` 命令。

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

含 httpx-cff 的 HTTP 任务使用每任务批量 CLI，默认最多 2 个 HTTPx 进程、每进程 8 线程。每次协议尝试的请求超时不超过 12 秒；显式 URL 保持输入协议，端口派生且未指定 URL 的端点在首选协议无响应时批量尝试另一协议，整个任务仍受统一执行截止时间约束。本轮 HTTPx 不自动跟随重定向，保留响应中的 Location，跳转目标需要单独作为已授权输入。旧的纯 native 快照保留此前 2 端点并发和共享 12 秒协议回退预算。服务任务仍受 Agent 端点并发约束，控制面仍为开放端口派生 HTTP 候选。

## 匹配质量

禁用的 HTTP / 端口规则不会参与新任务匹配。空响应不识别技术；正文截断或读取失败时不据此断言某个正文标记不存在。同产品的多条规则合并显示，保留明确版本。Drupal 不把任意 X-Generator 当作依据，phpMyAdmin 不根据正文的单个产品词命中。

基础协议解析仍用于确认 HTTP、SSH、SMTP 等协议；端口产品匹配由任务快照控制。PoC 的请求和结论单列，不混入普通端口产品汇总。

完整来源与覆盖列表见 [规则来源记录](RULE_SOURCES.md)。端口库仍为 22 个可靠产品；当前 Agent 没有 fingerprintx 的全部主动协议握手，单纯新增端口规则不能获得这些能力。
