# HTTP 与服务指纹依据

当前内置 54 条 HTTP 规则、22 条端口规则，另有 7 条显式启用的只读 PoC。工作台的“指纹库”展示实际规则、启用状态和版本，可编辑、复制及导入导出；接口和格式见 [规则库说明](RULE_LIBRARY.md)。下面列举主要识别依据，完整规则以 `internal/rulelib/builtins.go` 和库内定义为准。任务使用创建时的规则快照。

HTTP 指纹只使用既有响应，不为识别 CMS、框架或版本增加请求。服务指纹优先读取连接已经返回的首段 Banner；6379 和 11211 端口分别发送一次无副作用的 `PING` 和 `version` 命令，并且只在响应符合协议时确认 Redis 或 memcached。HTTP 正文仍受现有 1 MiB 上限约束，服务响应仍受现有 4096 字节上限和单端点 5 秒总时限约束。

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

内置规则没有复制 Wappalyzer、Nuclei templates、WhatWeb 等第三方规则库；匹配表达式和测试样本为本项目编写。Nuclei 执行引擎单独遵循 MIT 许可，随 Worker 发布包保留许可证；导入规则的版权和许可由其来源决定。

## 调度边界

HTTP 任务内部最多并行 2 个端点；未指定 URL 时，首个协议的首字节及正文读取最多使用单端点 12 秒总预算的一半，HTTP 与 HTTPS 协议尝试共享总截止时间，给回退协议保留实际执行时间。收到有效 HTTP 状态后，即使响应体超时也保留该次响应证据，不再用另一协议覆盖；显式 URL 仍可使用完整的单端点预算。服务任务每任务最多 8 个端点并发，并受 Agent 默认 16 个全局端点槽约束。当前控制面仍会为每个开放端口派生 HTTP 候选，指纹层不改变这项调度策略。

## 匹配质量

禁用的 HTTP / 端口规则不会参与新任务匹配。空响应不识别技术；正文截断或读取失败时不据此断言某个正文标记不存在。同产品的多条规则合并显示，保留明确版本。Drupal 不把任意 X-Generator 当作依据，phpMyAdmin 不根据正文的单个产品词命中。

基础协议解析仍用于确认 HTTP、SSH、SMTP 等协议；端口产品匹配由任务快照控制。PoC 的请求和结论单列，不混入普通端口产品汇总。
