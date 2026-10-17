# 部署说明

## 控制面

控制面由一个 Go 进程和 PostgreSQL 组成。前端构建后由 Go 静态托管；`deploy/compose.yaml` 仅启动数据库，不包含控制面或 Worker。

| 变量 | 说明 |
|---|---|
| `DATABASE_URL` | PostgreSQL 连接字符串 |
| `SCAN_ADMIN_TOKEN` | 管理 API / 工作台令牌 |
| `SCAN_JOIN_TOKEN` | Worker 注册引导令牌，须与管理员令牌不同 |
| `SCAN_LISTEN_ADDR` | 监听地址；本地示例为 `127.0.0.1:8080` |
| `SCAN_STATIC_DIR` | 前端构建目录，默认 `web/dist` |
| `SCAN_DOWNLOAD_DIR` | Agent 包和对应扫描器源码的下载目录 |
| `SCAN_TLS_CERT` / `SCAN_TLS_KEY` | HTTPS 证书及私钥，必须同时设置 |
| `SCAN_CONTROL_PUBLIC_URL` | 云 Worker 能访问的 HTTPS 地址 |
| `SCAN_CONTROL_CA_FILE` | 用于 Worker 初始化信任的公开 CA 文件 |
| `SCAN_CREDENTIAL_KEY_FILE` | 云凭据加密密钥文件；默认 `data/cloud-credentials.key` |
| `SCAN_CLOUD_PROVIDER` | `manual` 或 `aliyun` |

参考 `deploy/scan-platform.service` 部署时，创建独立 `scanplatform` 用户，将程序放入 `/opt/scan-platform/scan-server`，环境文件放入 `/opt/scan-platform/runtime.env`，并确保该用户可读证书和静态文件、可写 `data/`。环境文件、凭据密钥及 TLS 私钥应限制权限。不要用示例令牌暴露服务。

在已有服务器部署时选择独立目录和端口。数据库端口默认仅绑定回环地址。若使用反向代理，需要将 `/api/`、前端静态文件和 `/downloads/` 正确转发；公开下载目录内只放可发布的包与源码。

## 阿里云

首次启用需要设置 `SCAN_CLOUD_PROVIDER=aliyun`、控制面 HTTPS 和下载包参数。AK/SK 可以在工作台保存，也兼容从环境变量提供：

```dotenv
ALIBABA_CLOUD_ACCESS_KEY_ID=
ALIBABA_CLOUD_ACCESS_KEY_SECRET=
ALIBABA_CLOUD_SECURITY_TOKEN=
SCAN_ALI_REGION=cn-hangzhou
SCAN_ALI_ZONE_ID=cn-hangzhou-h
SCAN_POOL_ID=shen-scan
SCAN_AGENT_PACKAGE_URL=https://scan.example.com/downloads/scan-agent-linux-amd64.tar.gz
SCAN_AGENT_PACKAGE_SHA256=填写真实的64位SHA256
```

界面保存的加密凭据优先于环境凭据。地域 / 可用区改变时需重新准备或绑定网络。`SCAN_POOL_ID` 用于资源归属识别，同一账号内不同部署使用不同值。

可选环境配置：`SCAN_ALI_IMAGE_ID`、`SCAN_ALI_INSTANCE_TYPES`、`SCAN_ALI_VSWITCH_IDS`、`SCAN_ALI_SECURITY_GROUP_ID`、`SCAN_ALI_MIN_MEMORY_GIB`、`SCAN_ALI_PUBLIC_BANDWIDTH_MBIT`、`SCAN_ALI_PRICE_LIMIT`。实例候选规格必须在目标可用区可用；内存默认最低 2 GiB，公网出带宽默认 10 Mbit/s，使用按流量计费。

自动准备网络只创建或复用该平台管理的网络资源，不会启动 Worker。点击启动后才申请抢占式实例。启动和停止应通过平台完成，避免数据库记录与云资源状态脱节。

## 构建与发布 Agent

1. 在 Linux amd64 环境构建固定 Masscan，见 [构建说明](../deploy/masscan/README.md)。
2. 运行 `deploy/nuclei/download.sh` 下载并校验固定 Nuclei v3.11.1；运行 `deploy/httpx/download.sh` 下载并校验 HTTPx v1.12.0。详见 [Nuclei 引擎](../deploy/nuclei/README.md) 和 [HTTPx 引擎](../deploy/httpx/README.md)。
3. 准备公开 CA 文件；仓库不携带任何现有部署证书。执行 `CONTROL_CA_FILE=/path/to/public-ca.crt deploy/build-release.sh`。
4. 发布生成的 `bin/release/scan-agent-linux-amd64.tar.gz`，将输出 SHA-256 填入配置。
5. 同时发布 `bin/masscan/masscan-source-1.3.2-scan-platform.tar.gz`，保留对应许可证。

发布包包含 Agent、Masscan、Nuclei、HTTPx、web-probe-worker、fingerprint-worker、公开 CA，以及第三方声明和 Masscan 对应源码。bootstrap 安装系统 Nmap 与 probes 数据；两个 helper 使用独立 Go module 构建。cloud-init 下载并校验固定包，安装必要依赖并启动 Agent。包不应包含 AK/SK 或管理员令牌；Worker 只获得注册所需的引导配置。

更新 Agent 包地址和哈希影响后续新建实例。现有节点通过维护状态分批升级：

1. 先上传并校验新包、预装工具依赖，再为目标 Worker 开启维护；维护只阻止新认领，不更改节点池状态或缩容。
2. 等维护接口返回 `active_tasks=0` 后停止 Agent，确认服务及其进程组退出，备份并替换文件。
3. 重启 Agent，验证新版本、session、工具能力及心跳；用当前 `session_id` 关闭维护后继续下一批。建议先1台，再每批2台。
4. 保留包与旧二进制用于回滚。不能用停止节点池或 `draining` 充当升级维护，前者会释放实例。

从旧控制面迁移P0时，先阻止旧Worker认领并等已有执行自然结束；停旧服务后再次确认 `leased=0`，再启动新版迁移。新控制面只给声明 `supports_confirmed_stop` 的Agent新增执行，旧Agent仍可心跳和处理合法历史回放。不要把缺失停发确认解释为已经停止。

维护接口：`POST /api/workers/{id}/maintenance`，请求 `{"enabled":true,"expected_session_id":"当前session"}`；关闭维护必须带当前session。响应包含 `maintenance` 和保守的 `active_tasks`。Worker页面提供维护/恢复调度按钮。自动滚动编排仍由发布流程完成，不会因为上传包就自动重启所有节点。

## 调整扫描策略

- `SCAN_PORT_RATE_PPS`：控制面创建新任务的发包预算，支持 1000–20000，默认 5000。
- `SCAN_PORT_SHARD_MAX`：候选片宽，支持 1–16，默认 4；平台会根据执行时间预算收缩片宽。
- `AGENT_MAX_TASKS`：Agent 总任务数，默认 17，预留端口执行槽。
- `AGENT_ENDPOINT_CONCURRENCY`：Agent 全局端点并发，默认 16。
- `HTTPX_BINARY`：HTTPx 路径，默认从 PATH 查找 `httpx`。
- `HTTPX_MAX_PROCESSES` / `HTTPX_THREADS`：HTTPx 默认最多 2 个进程、每进程 8 线程；进程上限 2，线程上限 16。
- `SCAN_MASSCAN_MAX_RATE_PPS`：Agent 接受的最大速率，默认及绝对上限 20000。

Agent 参数需要配置在 Worker 环境中，不是控制面 `.env` 的通用转发参数。调低 Agent 速率上限时，也要同步控制面的新任务速率；超过 Agent 上限的任务会明确失败。修改控制面环境变量后重启服务，只影响随后创建的任务，已创建任务保留自己的 payload。

提高 PPS 需同时核对实际出带宽、捕获丢包和结果回传能力，不能只放大一个数字。默认没有提高到实验高值。

## 备份与停止

备份 PostgreSQL、云凭据加密密钥和部署配置；只备份数据库而丢失密钥，会导致保存的云凭据无法恢复。运行环境文件和密钥不应进入 Git。

停止节点池后等待排空，并检查云端实例已经释放。仅停止控制面或 Agent 进程不等价于停止 ECS 计费。网络资源可保留供下次复用；删除云账号或卸载程序不会自动清理所有云资源。

## 指纹库与 Nuclei 升级

fingers被动库的一键更新需要控制面checker。将发布目录的 `tools/fingerprint-worker` 安装到 `scan-server` 同级 `tools/`（可执行权限0755），或设置 `FINGERPRINT_CHECKER_BINARY`。先升级Control/checker，再维护、排空并分批升级Agent，最后更新库。外部包schema不兼容的Worker不会收到对应HTTP任务。完整步骤见[被动指纹库](FINGERPRINT_BUNDLES.md)。

控制面启动时迁移执行库、上游 catalog / files 和任务规则快照；内置规则按 ID 首次插入，不覆盖管理员编辑或禁用状态。升级前备份数据库及运行配置。启动控制面不会自动开启处于停止状态的节点池。

推荐顺序为：先升级 Control，再升级 Agent 并安装 HTTPx，最后更新 Wapp source 和创建新任务。新版 Agent 在 claim 中声明 rules_ref 与 HTTPx capability；含 Wapp CFF 的 HTTP task 不会分配给旧 Agent。旧 Agent 仍可处理不要求 HTTPx 的历史快照和其他任务类型。不要在 Control 已升级而 Agent / HTTPx 尚未就绪的间隙启动新的 Wapp HTTP 任务。

手动 Worker 的 `NUCLEI_BINARY` 可指定引擎路径，默认从 PATH 查找 `nuclei`。云发布包安装到 `/usr/local/bin/nuclei`。缺失引擎或执行失败会记录“检测错误”，不会当作未命中。新版 Agent 认领时会检查二进制及原始 YAML 所需参数，并上报 `supports_nuclei_http_original`；旧 Agent 不会领取 `http-basic-v1` 任务。滚动升级时先停止创建新格式任务，等空闲 Worker 分批替换，再恢复派发。每 Worker 最多一个 PoC 任务；Nuclei 不使用用户 HOME、云账号、外部回连或自动模板下载。

手动 Worker 的 `HTTPX_BINARY` 可指定 HTTPx 路径，云发布包安装到 `/usr/local/bin/httpx`。缺少 HTTPx 的新任务会 retryable release，不把规则记成永久失败。Nuclei 全量上游原库不会打包进任务，也不会由当前 Nuclei 二进制执行。

规则修改只影响随后创建的任务；已有任务继续使用快照。旧版历史任务没有快照时保留原识别逻辑，且不会被追溯追加 PoC。

扩库升级增加 `rule_library.deleted_at` 和 `seed_version`。补种只添加新 ID；旧内置 PoC 首次回填绑定时保留用户对启用状态和匹配定义的修改，增加规则版本。已删除的内置规则不复活。重新导入删除项会恢复为默认禁用的自定义规则；旧任务的已冻结规则不受影响。
