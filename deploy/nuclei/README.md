# 固定 Nuclei 引擎

Worker 使用官方 **Nuclei v3.11.1 / Linux amd64**，作为独立进程执行任务固定的只读 HTTP 模板。只安装引擎，不同步整个模板库。

```sh
deploy/nuclei/download.sh
CONTROL_CA_FILE=/path/to/public-ca.crt deploy/build-release.sh
```

下载脚本缓存官方 ZIP，核对固定 SHA-256 后提取引擎及 MIT 许可证。构建脚本再次核对二进制摘要、Linux amd64 架构和许可证；bootstrap 安装到 `/usr/local/bin/nuclei`。手动 Worker 可设置 `NUCLEI_BINARY=/path/to/nuclei`。

| 项目 | 值 |
|---|---|
| 版本 | v3.11.1 |
| 归档 | `nuclei_3.11.1_linux_amd64.zip` |
| 归档 SHA-256 | `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6` |
| 二进制 SHA-256 | `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251` |
| 许可 | MIT；本目录 `LICENSE.md`，发布包 `licenses/LICENSE.nuclei` |

来源：[官方发布](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1)、[固定版本许可证](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/LICENSE.md)。升级版本时同时核对归档摘要、CLI 兼容性、HTTP/HTTPS 命中与未命中输出，再更新固定值；不要把下载地址改为未固定的 latest。

平台支持的模板范围、请求限制和结果语义见 [指纹库说明](../../docs/RULE_LIBRARY.md)。内置规则由本项目编写，没有复制第三方模板仓库。
