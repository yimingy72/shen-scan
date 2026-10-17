# Masscan 对应源码与许可

本目录的补丁以 Masscan 官方 `1.3.2` 标签为唯一上游基线：

- 仓库：<https://github.com/robertdavidgraham/masscan>
- 标签：`1.3.2`
- 提交：`06902c40d1494881c17b7968ef530e1d6bbd320c`
- 官方源码：<https://github.com/robertdavidgraham/masscan/archive/06902c40d1494881c17b7968ef530e1d6bbd320c.tar.gz>
- 官方源码 SHA-256：`00bb562686bc765b76b7c02d161d311ff60bc845fa0dfde0ad5b602b6ebcbf3d`

`masscan-1.3.2-recv-buffer.patch` 是完整修改：接收 snaplen 为 2048 字节，`pcap_activate()` 前请求 32 MiB capture buffer，并在 live pcap handle 仍有效时记录退出统计。它不改变扫描速率、源端口、防火墙或 RST 行为。

补丁 SHA-256：`07e3388ca58add877cdafdc441f18c1fb6efe1d42d108171a97f589e34f970e1`。

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
