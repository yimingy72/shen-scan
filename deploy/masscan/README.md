# Masscan 1.3.2 接收修复构建

目标环境为 Ubuntu 22.04 Linux amd64。构建脚本固定并校验官方 `1.3.2` 源码，在临时目录应用唯一补丁并运行上游 selftest。产物固定写入：

- `bin/masscan/masscan`
- `bin/masscan/masscan.sha256`
- `bin/masscan/masscan-source-1.3.2-scan-platform.tar.gz`
- `bin/masscan/masscan-source-1.3.2-scan-platform.tar.gz.sha256`

传统构建：

```sh
sudo apt-get update
sudo apt-get install -y build-essential ca-certificates curl patch libpcap0.8
./deploy/masscan/build.sh
```

在 Ubuntu 22.04 amd64 容器中构建：

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD:/workspace" -w /workspace ubuntu:22.04 \
  bash -lc 'apt-get update && apt-get install -y build-essential ca-certificates curl patch libpcap0.8 && ./deploy/masscan/build.sh'
```

源码缓存默认位于项目内 `.cache/masscan-source/`，不会把上游整仓提交到主仓。可用 `MASSCAN_SOURCE_CACHE` 和 `MASSCAN_OUTPUT_DIR` 覆盖缓存与输出位置。构建默认使用 2 个并行 job；需要调整时设置正整数 `MASSCAN_BUILD_JOBS`。

运行时退出日志格式为：

```text
scan_capture: received=N dropped=N if_dropped=N
```

统计在 receive thread 退出 capture 循环后、adapter handle 关闭前读取。Ubuntu 的 live capture 应返回统计；不支持时明确记录 `scan_capture: unavailable`。
