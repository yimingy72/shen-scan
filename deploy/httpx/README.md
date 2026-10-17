# HTTPx 引擎

Worker使用官方HTTPx v1.12.0 / Linux amd64，二进制包SHA256为 `9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76`。下载脚本核对归档，release再次核对二进制，MIT许可证随包发布。这是软件发布完整性校验，不是模板审批或规则更新版本锁定。

```sh
deploy/httpx/download.sh
CONTROL_CA_FILE=/path/to/public-ca.crt deploy/build-release.sh
```

安装到 `/usr/local/bin/httpx`；手动 Worker 可设置 `HTTPX_BINARY`。每个含 HTTPx 指纹的 HTTP 任务批量启动一次工具，默认最多 2 个并发进程、每进程 8 线程；`HTTPX_MAX_PROCESSES` 上限为 2，`HTTPX_THREADS` 上限为 16。规则来自任务开始时已启用的 Wappalyzer 原始 app 快照。HTTPx 的 `-cff` 会与其内置库叠加，因此 Agent 还会过滤不在启用名单的识别结果。

旧的纯native任务快照仍兼容原执行路径。新HTTPx任务需要同时声明rules_ref和HTTPx能力的Agent。Agent 保留输入中的默认端口和同 origin 多 URL，核对每个请求目标都有结果；首选协议失败时按任务范围回退另一协议。

真实 v1.12.0 二进制在本地普通 HTTP / HTTPS fixture 上完成了 3 endpoint 验证，包含显式 HTTP/HTTPS、同站点多 URL、识别、批次完整性、禁用过滤和漏结果校验，耗时约 2.0 秒。Mac 小型 fixture 的最大观测 RSS 为 216 MiB；完整 7,642 app 的本地普通网页探测最大观测 RSS 为 231,342,080 字节（约 220.6 MiB）。这些数据不代表云环境或大规模目标容量，未开展外部扫描或云压测。

来源：[官方发布](https://github.com/projectdiscovery/httpx/releases/tag/v1.12.0)。
