# Linux libpcap 发送错误：本地证据子集

仅整理已经执行的原版假成功、最终8次候选持续失败/恢复，以及正常coldVXLAN65535端口用例；本次整理没有运行新测试、云/API、部署或截图。所有资产为自建、**未利用**。

| 既有用例 | Masscan退出 | 源/目标观察SYN | 结论 |
|---|---:|---:|---|
| 原版持续ENOBUFS，256调用均被拒绝 | 0 | 0 / 0 | 原版错误传播缺陷可导致CLI假成功 |
| 最终候选持续ENOBUFS，8次调用/7重试 | 1 | 0 / 0 | 非零失败，保留errno105/pcaperr/计数 |
| 最终候选连续40msEAGAIN | 0 | 256 / 256 | 6次失败后第7次同包恢复，每端口一次、8080识别 |
| 最终候选正常freshVXLAN，10000PPS | 0 | 65535 / 65535 | 1–65535各一次、8080识别，两端observer drops0 |

配置重试为最多8次调用，1/2/4/8/16/32/64ms请求退避，总计127ms；实际墙钟另含调用和调度。只重试EINTR/EAGAIN/ENOBUFS；其他/未知错误或耗尽立即exit1。协议、范围、索引和配置PPS未改，Linux live-libpcap之外未作通过声明。

`pcap/*.pcap.gz` 是完整双端PCAP的无损压缩，解压后SHA及原始长度在 `pcap-index.json`；没有裁剪报文。正常双端抓包用于独立确认，保留两端并非重复运行。4次旧候选的PCAP/二进制不复制，只保留用于原版假成功的v1注入源码版本说明；最终身份均指8次候选。

受测ELF `2ee12f51003d127996b49c98771d118d713a9fc5d16ff623de864e1ac9bb0c3d` 不变。微测时源码包 `c644521abff78949a8d511d80237e97d1e33af6f142080268895cc0318cebf8f`；后续README/SOURCE和build检查断言更新后的来源包 `88fd72494c8b98488b9984e902bf26758de413e4e2f75c7e85a6bd19193d1c73`。上游tar和精确代码补丁一致，ELF未因此重编译，不能回写历史包身份。`2691677`整包身份只表示后续构建，不等于R4/R5曾测此包，制品身份本身不代替验收；R6的100IP预检和1000IP主case已另行独立通过，在主报告分列。

`phase=rx_shutdown` 是接收线程退出快照，不是最终所有发送调用总数；成功sendpacket也不是远端送达证明。微测当时Agent非零退出路径仅源码核对；随后独立真实Agent→Control链路验证了8次持久ENOBUFS非零→release200、无complete且覆盖unconfirmed，见[机器摘要](../summaries/send-chain.json)及[15组完整HTTP索引](../http-index.json)。未保留direct manifest SQL快照，不作数据库补证。R5缺口原因仍未知，本修复和本地成功不能证明R5已修复。

完整日志、命令和现有小型复现工具在 `logs/`、`reproduce/`。复现仅用于已有Linuxamd64工具镜像的 `--network none` 私有环境；脚本保留历史容器 `/shen/...` 路径以对应原日志，可按自有工作目录修改。注入库仅明确加载到Masscan子进程，限定私有接口/地址SYN；不得放入发布包、全局环境或其他进程。本附件不复制ELF/注入.so/海量源码归档。

这是rawTCP证据，没有HTTP，不编造HTTP或用合成画面代替真实截图。对实际Control/目标的HTTP见R5独立证据。
