# Masscan 有效 SYN 吞吐：公开微测证据子集

本目录整理已经完成的本地隔离微测；导出时未运行新测试、截图或云操作。合成资产均标记为 **未利用**，见 [assets.json](assets.json)。它是主报告的证据附件，截图由根在真实测试平台/验证接口页面补齐后合并；本附件不单独宣称已满足完整成果报告的截图要求。

## 结果与范围

`--rate 5000 --wait 2 --seed 42 -p1-12000`；真实 Linux TCP 目标仅监听 8080。在 Docker Linux amd64（arm64 宿主机模拟执行）内使用独立 veth/netns，容器 `--network none`。使用未分配源 IP，避免宿主机内核 RST 干扰。

| 已执行情形 | SYN / 唯一目标端口 | 发向关闭端口的扫描器 RST | 开放 8080 清理 RST | 有效 SYN/s（首末 SYN 间隔） | 8080 结果 |
|---|---:|---:|---:|---:|---|
| 原版平台二进制 | 12000 / 12000 | 11999 | 1 | 2507.2785 | 正确识别 |
| 最终 `statusOpen` 候选 | 12000 / 12000 | 0 | 1 | 5042.3849 | 正确识别 |
| 原版 + `--noreset`（诊断） | 12000 / 12000 | 0 | 0 | 5026.7530 | 正确识别；目标 SYN-ACK 共 3 次 |
| 静默地址接收端（诊断） | 12000 / 12000 | 0 | 0 | 5023.1652 | 没有目标地址，不作开放识别声明 |

所有上述扫描均覆盖 1–12000，每端口恰好一个 SYN；独立抓包和 Masscan capture 统计均无丢包。约 5k 的短窗口观测含有限样本/批处理抖动，配置上限未提高。静默情形通过移除目标地址实现，**不是**“防火墙 DROP 且同时保留开放监听”的新测试。精确计数、时间和原始输出见 [micro-summary.json](summaries/micro-summary.json)。

组合旗标回归发送一个校验和正确、ACK 等于原 SYN 序号加一的 `SYN+ACK+RST (0x16)`：原版回一个 RST，最终候选不回 RST；两者均不记录开放端口，独立抓包无丢包。[mixed-summary.json](summaries/mixed-summary.json) 包含每帧完整十六进制及 cookie/校验和断言结果。

## 原因与最小候选

固定上游提交 `06902c40d1494881c17b7968ef530e1d6bbd320c` 的 `main.c:1010–1063` 同时处理 SYN-ACK 与 RST，在 cookie 校验、去重和状态记录之后，无状态模式会对两者均排队发送 RST。`stack-queue.c` 将排队包计入同一发送 PPS，发送循环先排空队列再发新的 SYN。这是 **RST → RST 开销**，不能把额外包都称作 SYN 重传。Agent 主扫描命令未传 `--retries`。

最终候选仅将清理条件收紧为 `tcpcon == NULL && !masscan->is_noreset && status == PortStatus_Open`。它保留开放端口清理、SYN 全覆盖、cookie/去重、同一 PPS 和原有接收/输出边界。`--noreset` 会连开放清理也关闭，因此只作为诊断对照。[源码片段](references/source-evidence.log) 保留上游行号，不含整个源码树。

## 制品身份：不要改写微测历史

| 身份 | SHA-256 |
|---|---|
| 微测原版二进制 | `6882bfaafb68e98974aba5159056867563652dfd0188be82f06bf2e380830ab9` |
| 最终受测 `statusOpen` 候选二进制 | `afc20e66f99e13f4c65a7a7acc52b51d9f51b3798c3f7ac296abc6121ba39f7d` |
| **微测当时**对应源码包 | `36362eb485e77e9489cfded88599c3f9d26fa9d2f8a428436635d4956ae976b8` |
| 根后续仅更新说明的对应源码包 | `162ae4a3f5c933d74048864fbe37492ce48c485fdd443cbaa5cc1d077f45a349` |

后两个包只在 `README.md` 与 `SOURCE.md` 不同；上游源码、扫描补丁、构建脚本和许可证逐项相同。这是既有归档的只读成员比对，不是新的执行测试。后续说明包不是当时微测使用的源码包；不能覆盖原历史身份。完整身份、核心成员摘要见 [artifact-provenance.json](summaries/artifact-provenance.json)。本附件不复制扫描二进制、海量源码或完整源码包；主交付另提供 AGPL 对应源码和许可证。

## 旧 DROP 与 R4 RST 的差异

旧 1000 IP fixture 默认 DROP 除 80/8080/2222 外的初始 SYN；R4 目标未配置这种过滤，关闭端口由内核返回 RST。4 IP 下单 SYN 模型 `262140/5000+15 = 67.428s`，旧实测中位数 `68.4824815s`；额外 RST 模型 `262140*2/5000+15 = 119.856s`，R4 baseline 为 `120.3482195s`。3 IP 同模型为 `93.642s`，R4 candidate 为 `93.961981s`。

这是不同目标响应分布的解释，不是全场景速度保证；R4 聚合接口计数还包含下游工具流量，包型归因依据本地 PCAP。旧 5 个配置 Worker 与 6 个历史 ID 不代表 6 个同时执行的 Worker。[历史引用和规则片段](references/target-model-excerpts.txt)、[精确聚合比较](references/existing-data-comparison.json)、[旧任务选取汇总](references/old1000-selected-aggregate.json) 保留来源；选取汇总明确省略了真实云实例/任务标识。

## 完整证据与复现

- `pcap/*.pcap`：六份完整、未裁剪的原始 Ethernet/IP/TCP 抓包；逐文件 SHA 在清单中。
- [complete-representative-frames.txt](complete-representative-frames.txt)：原版、候选、诊断情形的完整代表帧；组合旗标完整帧见 `mixed-summary.json`。
- `logs/`：完整终端命令/输出、各情形 stderr/stdout/list/time/capture 记录及候选构建记录。只将随机构建目录标签归一化为 `BUILD_DIR`，没有删减报文或关键输出；容器通用路径 `/shen/...` 保留原记录含义，不含个人绝对路径或凭据。
- `reproduce/`：小型本地 fixture、原已执行流程的路径可移植导出脚本，以及离线 PCAP 分析脚本；**这些导出脚本没有在整理期间重新执行**。原始执行命令在 `logs/*terminal.log`。

复现仅应在一次性、无外部网络的 Linux amd64 容器中进行。准备含 `cc`、`iproute2`、`libpcap`、`time`、`timeout` 的本地工具镜像，并通过校验后的独立路径提供两个 Masscan 二进制；本附件不下载或运行任何工具。

```sh
# 当前目录为本证据包；MASSCAN_TOOLS_DIR 下有 original/masscan、candidate/masscan。
# LOCAL_LINUX_TOOLBOX_IMAGE 是已准备的本地 Linux amd64 工具镜像。
docker run --rm --pull never --platform linux/amd64 --network none --privileged \
  -v "$PWD:/evidence" -v "$MASSCAN_TOOLS_DIR:/tools:ro" \
  -e MASSCAN_ORIGINAL=/tools/original/masscan \
  -e MASSCAN_CANDIDATE=/tools/candidate/masscan \
  "$LOCAL_LINUX_TOOLBOX_IMAGE" sh /evidence/reproduce/run-micro.sh
# 同参数分别执行 run-candidate.sh、run-mixed.sh。
```

运行脚本将结果写入 `reproduced-run/`，不会覆盖本包历史 PCAP。离线分析脚本默认读取历史 `pcap/` 和 `logs/`，只写新的 `summaries/reproduced-*.json`；本次导出未执行它们。微测不是完整 65535 端口云压测，也未测量云端发布后的加速比。

HTTP 对本原始 SYN/RST 微测不适用，不编造 HTTP。根的主报告另合并实际 Control/目标 HTTP 请求响应及真实页面截图。未启动本地 HTML 服务，也未尝试绕过此前截图策略拒绝。`screenshots/` 待根补充主报告证据，当前目录没有新截图。

Masscan 源码片段和最小补丁来源于上述固定上游及本地候选；保留 [上游许可证声明](references/LICENSE.masscan) 与 [AGPLv3 文本](references/AGPL-3.0.txt)。完整对应源码随主交付提供，本附件不替代它。
