# HTTP 扫描选项、JS/DOM 与首页截图

## 任务选项

创建 HTTP 任务时，`web_scan_options` 独立选择四种能力。基础 httpx 采集始终保留。

| 选项 | 默认 | 执行内容 |
|---|---|---|
| `passive` | 开 | WappalyzerGo、fingers 对已采集响应的指纹匹配 |
| `active` | 开 | fingers 原始主动规则；未被动识别的目标也可执行 |
| `js_dom` | 关 | 系统 Chrome 执行页面，采集 Wapp JS 属性和 DOM 条件 |
| `screenshot` | 关 | 使用 httpx 截图实现保存入口页面首屏，在 HTTP 列表显示缩略图 |

四项均关闭是有效的“仅基础采集”；端口扫描仍为 TCP 1–65535，包含服务识别。未选择 HTTP 时不附加这些选项。任务创建时冻结策略，新选项不会追改旧任务。新任务只分配给声明选项能力的 Agent，避免旧 Agent 忽略开关。

```json
{
  "name": "HTTP 页面巡检",
  "targets": ["http://192.0.2.10/"],
  "modes": ["http"],
  "poc_enabled": false,
  "web_scan_options": {
    "passive": true,
    "active": true,
    "js_dom": false,
    "screenshot": true
  }
}
```

被动指纹是复用已采集证据匹配，不代表零网络请求；基础采集仍会请求入口、跟随允许的重定向和采集图标。主动关闭后不再执行 fingers 主动路径。单独开启截图不会执行 Wapp 的 JS/DOM 指纹规则；为了渲染页面，浏览器本身仍执行页面 JavaScript。

## 执行与性能

```text
httpx 基础采集 → 按选择执行被动 / 主动指纹 → HTTP 结果先入库展示
                                             ↓ 可选浏览器子任务
                                一次页面加载：JS/DOM + 截图
                                             ↓
                                补全同一入口结果、派生产品 PoC
```

浏览器任务使用单独并发槽，每 Worker 最多一个；CPU、可用内存、连接预算和上传积压参与准入。默认任务不启动浏览器。浏览器进程有界复用，每个入口独立上下文；空闲 60 秒回收 Chrome 进程，保留小型 helper 与编译规则缓存。正常 HTTP 采集无需等待全批浏览器任务结束。

截图接入现有 httpx v1.12.0 SDK：将原 `takeScreenshotAndGetBody` 提取为 `ScreenshotWithBodyFromPage`，CLI 原调用点与平台适配器共用同一段截图实现。这对应 `-screenshot -system-chrome` 的截图与系统浏览器用途，不是额外启动一次 httpx CLI，也不再为截图重新打开第二个页面。平台负责固定连接身份、网络准入、生命周期和尺寸限制。

截图保存入口最终页面的首屏；完整 URL 的路径不会被改写为 `/`。PNG 和尺寸都有上限，页面资源也受请求额度和时间限制。仅 JS/DOM 模式不为截图加载额外图像；截图模式允许受限页面图像/CSS/字体。无法取得的资源、超时与无效上游规则单独记录，不能把未执行条件记为未命中。

Chrome 采用专用非 root 用户并保留沙箱；浏览器直连出网由操作系统阻断，实际 HTTP 请求经受控采集器执行，共用现有 HTTP 限速与许可。固定 URL / IP / Host / SNI 和父观察记录身份，拒绝借页面改变扫描目标范围。外部来源资源未获采集时，截图可能不完整，页面会显示该状态。

## 截图数据与界面

- JS/DOM 与截图各有完成、部分完成或异常状态；其中一项失败保留已有 HTTP 和另一项成功结果。
- 图片单独存储于 `http_screenshots`，与任务、attempt、父观察记录及完成凭证绑定。旧执行和失效父记录不能覆盖当前结果。
- Control 校验 PNG 内容、尺寸和摘要，生成小尺寸缩略图；不接受 Worker 文件路径，不把 PNG/base64 塞入 HTTP 列表 JSON。
- `GET /api/observations/{id}/screenshot` 返回原 PNG，`?thumbnail=true` 返回缩略图，两者均要求管理员认证，遵循当前接受执行的结果可见性。
- 列表按可见区域懒加载缩略图，点击查看大图；认证令牌通过请求头传递，不出现在图片 URL。详情保留截图状态、JS/DOM 证据及 HTTP 报文。
- 图片随所属任务/观察记录删除；当前使用 PostgreSQL bytea，尚未实现 OSS 归档和长期图片保留策略。

PoC 仍需任务显式开启，并按确认指纹匹配；候选指纹与截图本身不触发 PoC。

## Chrome 安装与升级

Chrome 不进入 Agent 发布包，构建也不要求事先下载 Chrome。发布包只携带小型安装脚本、版本要求和隔离 wrapper。

Worker bootstrap 配置 Google 官方签名 apt 软件源，检测安装版本；满足最低要求或已装更新版本时跳过 Chrome 下载，缺少或过旧时再安装。普通 Agent 升级仍检查版本，但不会每次重新分发浏览器。可在 Worker 基础镜像中提前安装同样的依赖，减少抢占式实例首次启动时间。

安装失败记录浏览器不可用，不阻断普通扫描。安装状态和运行时检查分别负责“安装是否成功”和“当前能否安全启动”；不能凭有二进制文件就宣称浏览器可用。支持平台、版本、签名源与幂等行为见 [浏览器安装说明](../deploy/browser/README.md)。

验证结果见 [真实验证记录](HTTP_BROWSER_VALIDATION.md)。代码支持不等于对所有网站、所有上游规则或大规模持续负载完成验收。
