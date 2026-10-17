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

Linux live capture 使用非阻塞读取：缓存读空后最多等待 100 ms 的可读事件，再检查接收线程退出标志；接口没有任何入站报文也能结束。等待只发生在缓存为空时，不对已收到报文逐包休眠。`pcap_setnonblock()` 失败会拒绝初始化，不能静默退回可能永久阻塞的读取。

列表输出（`-oL`）在每条完整记录后立即刷新；写入或刷新失败以非零状态退出。下游可在扫描仍运行时逐行读取开放端口，不需要等待进程结束。
