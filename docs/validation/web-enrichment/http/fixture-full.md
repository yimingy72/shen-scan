# 本地合成目标：完整 HTTP 请求与响应

状态：**未利用**。无漏洞利用。本次为 HTTP 产品确认功能验收；以下报文来自实际 Agent/helper 对自建目标的请求，正文未截断。JSON 原件见 [fixture-traffic.jsonl](fixture-traffic.jsonl)。无认证值。

## 1. http://127.0.0.1:18583/start

请求：

```http
GET /start HTTP/1.1
Host: 127.0.0.1:18583
User-Agent: shen-scan/2
Accept: text/html,application/xhtml+xml,*/*;q=0.8
Accept-Charset: utf-8
Accept-Encoding: identity
Connection: close


```

响应：

```http
HTTP/1.1 302 Found
Date: Sun, 18 Oct 2026 00:23:32 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Location: /home
Content-Length: 11

redirecting
```

## 2. http://127.0.0.1:18583/home

请求：

```http
GET /home HTTP/1.1
Host: 127.0.0.1:18583
User-Agent: shen-scan/2
Accept: text/html,application/xhtml+xml,*/*;q=0.8
Accept-Charset: utf-8
Accept-Encoding: identity
Connection: close


```

响应：

```http
HTTP/1.1 200 OK
Date: Sun, 18 Oct 2026 00:23:32 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 204

<html><head><title>Owned WordPress fixture</title><meta name="generator" content="WordPress 6.2"><link rel="icon" href="/favicon.ico"></head><body><a href="/wp-content/theme.css">fixture</a></body></html>
```

## 3. http://127.0.0.1:18583/favicon.ico

请求：

```http
GET /favicon.ico HTTP/1.1
Host: 127.0.0.1:18583
User-Agent: shen-scan/2
Accept: text/html,application/xhtml+xml,*/*;q=0.8
Accept-Charset: utf-8
Accept-Encoding: identity
Connection: close


```

响应：

```http
HTTP/1.1 200 OK
Date: Sun, 18 Oct 2026 00:23:32 GMT
Content-Type: image/x-icon
Connection: close
Content-Length: 20

owned-synthetic-icon
```

## 4. http://127.0.0.1:18583/readme.html

请求：

```http
GET /readme.html HTTP/1.1
Host: 127.0.0.1:18583
User-Agent: shen-scan/2
Accept: text/html,application/xhtml+xml,*/*;q=0.8
Accept-Charset: utf-8
Accept-Encoding: identity
Connection: close


```

响应：

```http
HTTP/1.1 200 OK
Date: Sun, 18 Oct 2026 00:23:33 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 132

<html><title>WordPress ReadMe</title><body>Semantic Personal Publishing Platform. Synthetic product confirmation only.</body></html>
```

## 复现

在隔离环境中提供上述 `/start`、`/home`、`/favicon.ico`、`/readme.html` 响应并启用内置 WordPress 被动与补采规则。创建仅 HTTP、PoC 关闭的任务，输入 `/start` 的 URL。控制面调用见 [smoke-create.json](smoke-create.json)，最终结果见 [smoke-observation.json](smoke-observation.json)。临时端口和任务 ID 为这次实际运行值；重新运行时替换为自己的本地地址。认证占位符使用自己的测试凭据。
