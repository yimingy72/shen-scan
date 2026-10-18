# Masscan 对应源码与许可

本目录的补丁以 Masscan 官方 `1.3.2` 标签为唯一上游基线：

- 仓库：<https://github.com/robertdavidgraham/masscan>
- 标签：`1.3.2`
- 提交：`06902c40d1494881c17b7968ef530e1d6bbd320c`
- 官方源码：<https://github.com/robertdavidgraham/masscan/archive/06902c40d1494881c17b7968ef530e1d6bbd320c.tar.gz>
- 官方源码 SHA-256：`00bb562686bc765b76b7c02d161d311ff60bc845fa0dfde0ad5b602b6ebcbf3d`

`masscan-1.3.2-recv-buffer.patch` 是完整修改：接收 snaplen 为 2048 字节，`pcap_activate()` 前请求 32 MiB capture buffer，并在 live pcap handle 仍有效时记录退出统计。Linux live handle 激活后强制启用非阻塞读取；每次读空后使用最多 100 ms 的 poll 等待可读事件（不可轮询的 handle 或轮询错误退避 1 ms），使零入站报文时也能重新检查接收线程退出标志，不依赖背景流量唤醒。只在读空时等待，不对已缓存的报文逐包延时；离线文件及 PF_RING 路径保持原行为。列表输出（`-oL`）每条完整记录写入后检查流错误并立即刷新；写入/刷新失败明确以非零状态退出，避免流式派生只能等进程结束。接收与输出修复不改变扫描速率、源端口或防火墙。无状态 TCP 清理 RST 仅在通过 cookie 校验和去重、且最终状态为开放端口时发送；不再回复闭端口 RST，也不回复同时含 SYN-ACK 与 RST 的异常组合，保留正常开放连接的收尾。SYN 枚举、端口覆盖、输出与发包预算算法保持不变。

补丁 SHA-256：`cec73f9531390ec3e8804f6add30d31e3456ee719b566c78011a500a29df27d2`。

上游采用 GNU Affero General Public License version 3。`LICENSE.masscan` 是上游许可证声明；构建脚本还会取得 GNU 发布的完整 AGPLv3 文本并校验 SHA-256 `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`。生成的对应源码包包含官方源码压缩包、补丁、许可证、来源说明和构建脚本，可独立重建二进制。

手工复现：

```sh
sha256sum -c <<'EOF'
00bb562686bc765b76b7c02d161d311ff60bc845fa0dfde0ad5b602b6ebcbf3d  masscan-06902c40d1494881c17b7968ef530e1d6bbd320c.tar.gz
EOF
tar -xzf masscan-06902c40d1494881c17b7968ef530e1d6bbd320c.tar.gz
cd masscan-06902c40d1494881c17b7968ef530e1d6bbd320c
patch -p1 < ../masscan-1.3.2-recv-buffer.patch
make CC=gcc GITVER=1.3.2-scan-platform
bin/masscan --selftest
```
