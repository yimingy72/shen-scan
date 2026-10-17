# 指纹库与只读 PoC

工作台“指纹库”分为 HTTP 指纹、端口指纹和 PoC 库。当前内置 **150 条 HTTP、22 条端口、43 条 PoC**。HTTP 指纹利用扫描已有响应识别 CMS、框架、Web 服务器和应用；端口指纹利用协议解析和 Banner 识别服务、产品及明确版本。两者不因增补规则而改变 TCP 全端口范围。

![PoC 库：规则、请求范围、引擎和启用状态](images/rule-library.png)

## 管理与执行

列表支持搜索、启停、编辑、复制、JSON 导出与导入。内置及自定义规则都可以编辑、禁用和删除；删除使用持久标记，重启或补种不会复活。可以先导出备份，之后用同 ID 重新导入恢复，恢复后默认禁用且版本递增。每次修改递增版本，冲突编辑返回 409。导入为原子操作，一次最多 1000 条（请求体上限 8 MiB），校验失败全部不写入；成功导入的规则默认禁用。

创建任务时，平台保存当时启用的 HTTP / 端口规则及选择的 PoC 规则。修改、禁用或删除库内规则只影响之后创建的任务，已有任务继续使用其快照。界面显示的规则版本与观测记录对应。

**PoC / Nuclei 默认关闭。** 创建任务选择 HTTP 指纹后，可以显式勾选“PoC / Nuclei · 只读检查”。不选择具体规则时，在已启用且有 `applies_to` 绑定的规则中按指纹自动筛选；也可选取子集，产品型规则仍须命中绑定。没有识别结果时不派发产品型 PoC。`applies_to` 为空的通用规则（如 security.txt、Git HEAD）仅在任务中明确选中该 ID 时执行。只对本任务完成 HTTP 探测后发现的同源端点执行；同一任务、同一 origin、同一规则版本跨 URL 路径只执行一次。不追溯执行历史任务，不因跨源重定向自动扩展范围。

产品绑定取 HTTP 技术指纹及同目标、同 IP、同端口的服务产品；服务识别晚到时补派，其他端口的产品不参与匹配。结果详情显示触发依据与匹配产品。旧任务保留创建时的调度策略。

列表支持勾选跨页规则后批量导出和删除（最多 1000 条）；“导出筛选结果”导出当前条件的全部结果，不限当前页。版本冲突时整批删除失败，不会删一半。

每 Worker 最多执行一个 PoC。原生检查总超时 60 秒，单请求 8 秒；Nuclei 总超时 90 秒，进程请求速率 3/秒、并发 1。每条规则最多 3 个请求、8 个匹配器。任务取消、租约失效和实例回收继续沿用 Agent 的停止及重派机制。

## 结果语义

| 结果 | 含义 |
|---|---|
| 命中 `matched` | 完整执行后满足规则条件；需结合规则级别和证据判断 |
| 未命中 `not_matched` | 完整执行且响应不满足匹配条件 |
| 检测错误 `error` | 超时、连接失败、响应不完整、缺少引擎、输出无效等，不能推断目标安全 |

信息级检查如 security.txt、登录页或健康端点命中，不等同于确认漏洞。Git HEAD 暴露检查只读取固定路径并确认引用格式，不下载仓库、不提取凭据。结果包含规则 ID / 版本、引擎、级别、依据及请求响应；报文超过采集上限会标记 `truncated`。平台有界采集，不承诺保存任意大小的完整响应。

## 原生 JSON 规则

从界面导出的 `{ "items": [...] }` 可以直接导入；以下示例识别已有响应中的明确 Header。字段枚举及约束以 `internal/rulelib/types.go`、`validate.go` 为准。

```json
{
  "items": [{
    "id": "http-example-server",
    "kind": "http",
    "name": "Example server",
    "engine": "native",
    "severity": "info",
    "enabled": false,
    "tags": ["server"],
    "source": "custom",
    "definition": {
      "product": "Example",
      "condition": "and",
      "matchers": [{
        "part": "header",
        "type": "word",
        "words": ["Server: Example"],
        "condition": "or"
      }]
    }
  }]
}
```

`kind` 为 `http`、`port` 或 `poc`。HTTP 可匹配 `body/header/title/status`；端口可匹配 `banner/service/product`。`type` 为 `word/regex/status`，组合使用 `and/or`；支持 `negative` 和 `case_sensitive`。`version_regex` 配合 `version_part` 从明确输出中提取版本，不按端口号推测。

PoC 顶层增加 `"applies_to": ["WordPress"]` 等绑定字段；名称经大小写、空白及明确别名归一后精确匹配，多个产品为 OR，禁止 `* / all / http` 等通配。

原生 PoC 的 `definition.requests` 写入静态 `method`、`path`、可选 `headers` 和 `matchers`，例如：

```json
{
  "condition": "and",
  "requests": [{
    "method": "GET",
    "path": "/.well-known/security.txt",
    "condition": "and",
    "matchers": [
      {"part": "status", "type": "status", "status": [200]},
      {"part": "body", "type": "word", "words": ["Contact:"]}
    ]
  }]
}
```

新增和导入规则都经过控制面校验，Agent 执行前再校验。响应失败或截断时不会根据“缺少正文标记”作负向推断。

## Nuclei YAML

Nuclei 使用真实的 **v3.11.1 引擎**，仅开放受限 HTTP 子集；不是任意模板执行入口。导入使用“导入 → Nuclei YAML”。以下模板可用于自有测试站点：

```yaml
id: custom-security-policy
info:
  name: Published security policy
  author: local
  severity: info
  tags: discovery,read-only
http:
  - method: GET
    path:
      - '{{BaseURL}}/.well-known/security.txt'
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ['Contact:']
```

支持静态同源 `{{BaseURL}}` / `{{RootURL}}` 路径、GET / HEAD、word / regex / status 匹配器。模板 ID 与库内规则 ID 一致。`info.metadata.product` 可为产品名或名称数组，导入时映射到 `applies_to`；缺失时保留手动选择，不从泛化 tags 猜测绑定。关联指纹也可在编辑界面单独设置。编辑模板后重新解析规范化定义，不能通过修改 metadata 绕过执行校验。

不接受 POST 等写入请求、查询参数、目录穿越、编码载荷、动态变量、raw 请求、DSL、workflow、flow、code、headless、网络/DNS 模板、payload、外部回连及重定向。YAML 别名和未知执行字段会被拒绝。当前也不支持直接整库同步官方 `nuclei-templates`。

Nuclei 使用隔离临时目录、清理过的环境变量和目标范围代理，关闭自动模板下载、云认证、Interactsh、重定向及 HTTP 探活。HTTP 代理核对方法、主机、端口及路径；HTTPS CONNECT 固定目标主机和端口，TLS 内路径由预先校验的静态模板限定。地址仍由 Agent 的受保护目标校验处理。进程异常或缺少有效匹配事件记录为检测错误。

Nuclei 下载与校验见 [固定引擎部署](../deploy/nuclei/README.md)，API 见 [接口说明](API.md)。CLI 参数来源为 [ProjectDiscovery 官方运行说明](https://docs.projectdiscovery.io/opensource/nuclei/running)。

来源、许可证与为何没有直接导入整个 Nemo 库见 [规则来源](RULE_SOURCES.md) 和 [只读 PoC 筛选](POC_SOURCES.md)。
