# HTTPx 引擎

当前新任务走 `web-full-v2`：完整官方 Runner + fingers HTTP 被动/主动执行。构建和能力边界见 [Web helpers](../WEB_HELPERS.md)、[当前实现](../../docs/HTTP_FINGERPRINT_FULL_IMPLEMENTATION.md)。以下 CLI 及 v0.5 说明仅用于旧快照兼容。

Worker使用官方HTTPx v1.12.0 / Linux amd64，二进制包SHA256为 `9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76`。下载脚本核对归档，release再次核对二进制，MIT许可证随包发布。这是软件发布完整性校验，不是模板审批或规则更新版本锁定。

```sh
deploy/httpx/download.sh
CONTROL_CA_FILE=/path/to/public-ca.crt deploy/build-release.sh
```

安装到 `/usr/local/bin/httpx`；手动 Worker 可设置 `HTTPX_BINARY`。每个含 HTTPx 指纹的 HTTP 任务批量启动一次工具，默认最多 2 个并发进程、每进程 8 线程；`HTTPX_MAX_PROCESSES` 上限为 2，`HTTPX_THREADS` 上限为 16。规则来自任务开始时已启用的 Wappalyzer 原始 app 快照。HTTPx 的 `-cff` 会与其内置库叠加，因此 Agent 还会过滤不在启用名单的识别结果。

旧的纯native任务快照仍兼容原执行路径。新HTTPx任务需要同时声明rules_ref和HTTPx能力的Agent。Agent 保留输入中的默认端口和同 origin 多 URL，核对每个请求目标都有结果；首选协议失败时按任务范围回退另一协议。

真实 v1.12.0 二进制在本地普通 HTTP / HTTPS fixture 上完成了 3 endpoint 验证，包含显式 HTTP/HTTPS、同站点多 URL、识别、批次完整性、禁用过滤和漏结果校验，耗时约 2.0 秒。Mac 小型 fixture 的最大观测 RSS 为 216 MiB；完整 7,642 app 的本地普通网页探测最大观测 RSS 为 231,342,080 字节（约 220.6 MiB）。这些数据不代表云环境或大规模目标容量，未开展外部扫描或云压测。

来源：[官方发布](https://github.com/projectdiscovery/httpx/releases/tag/v1.12.0)。

## P0 v0.5 执行适配

新增 `web-probe-worker` 与常驻 `fingerprint-worker`，Agent在前者可执行时采用新路径。可分别用 `WEB_PROBE_BINARY`、`FINGERPRINT_WORKER_BINARY` 指定路径；`WEB_PROBE_BINARY=disabled` 仅用于旧路径兼容。新节点发布应同时安装两个helper，否则Web采集后的被动匹配会明确记为不完整。

```sh
# 需要 Go 1.26 或更新版本；工具依赖留在各自子 module。
deploy/build-web-helpers.sh
```

采集helper复用 **httpx v1.12.0 的请求构造/标题 SDK + WappalyzerGo v0.2.96**，使用标准库受控传输层收发请求。它没有调用 `httpx.Do`：该版本没有导出可替换传输层，直接执行无法满足独立的在线编码读取/解压上限。不要把这一实现表述为完整httpx runner等价。WappalyzerGo直接加载本次CFF快照，不合并其默认库；输入和输出摘要均核对。

每入口90秒、每请求最多8秒、总请求最多8次，正文编码读取和解码均不超过2 MiB；仅识别首页响应，至多补取两个同origin图标，各256 KiB。不跟随重定向、不解析页面脚本、不加载跨站图标、不调用通用主动规则、不调用AI。跨站图标本期跳过；不是推定其已获得授权。协议尝试和favicon请求共享同一入口预算。HTTP Host、TLS SNI沿用目标域名，TCP连接使用Agent已验证并固定的IP；证书来自该HTTP请求实际TLS连接。

`fingerprint-worker`基于fingers `e870395e8984`，旧版曾使用 `-tags passive_only`；当前发布必须使用不带此 tag 的 `deploy/build-web-helpers.sh`。只启用fingers、FingerprintHub、EHole及独立favicon匹配，不重复启用Wappalyzer；每引擎合并前保存实际命中来源。本期嵌入规则库，单实例常驻、串行输入、截止后杀进程并按需重建。摘要同时覆盖库资源、alias与profile，`--bundle`显示当前摘要；Agent收到的`fingerprint_bundle`必须匹配，不能静默换库。旧版不支持的 nginx `(?x)` 表达式已在当前原生 matcher 中通过兼容处理，全量装载结果见当前验证报告。

正文或图标达到限制时标为partial；不把不完整内容交给可能含negative/hash语义的通用matcher。图标失败不抹掉首页成功。IPC传递完整的有界正文、图标字节与TLS证书；上传保留原有192KiB响应/32KiB正文预览，并保存正文和图标摘要、时间、连接IP、TLS来源、匹配依据。`bounded-excerpt-v1`明确表示**大响应持久化为预览，不是完整报文归档**；压缩响应展示为规范化的解码报文，原始响应头留在证据对象。

必要验证为本地HTTP/TLS夹具：Host/SNI与固定IP、实际证书、gzip膨胀限制、跨站图标拒绝、不跟随跳转、CFF摘要拒绝、部分正文不派生产品，以及Agent通过真实helper二进制完成两个入口的采集与被动匹配。未在生产或云节点执行本轮探测。
