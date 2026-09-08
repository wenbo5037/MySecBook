---
title: "HTTP1.1：方法头部持久连接与管线化"
category: "00-基础通用/03-计算机网络"
tags: [HTTP1.1, 方法, 头部, 持久连接, 管线化, 请求走私]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# HTTP1.1：方法头部持久连接与管线化

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | HTTP/1.1是面向文本行(BYTE流)的请求-响应式应用层协议，默认keep-alive持久连接，支持管线化（pipelining）但受限 |
| 核心用途 | Web应用传输层的底子；理解请求/响应格式、方法、头部、状态码是Web安全的基础 |
| 请求格式 | `METHOD SP Request-URI SP HTTP/1.1 CRLF` + Headers + 空行 + Body |
| 持久连接 | HTTP/1.1默认开启 keep-alive，一个TCP连接可承载多个请求-响应 |
| 管线化 | 一次连接并发发送多个请求，但响应必须按序返回(队头阻塞) |
| 常见风险 | Host头注入、CRLF注入、请求走私(CL-TE/TE-CL)、HTTP响应拆分、方法滥用 |
| 关联知识 | [[14-HTTP2多路复用与HTTP3核心变化]]、[[15-TLS1.2与TLS1.3握手流程逐消息解析]]、[[01-HTTP请求走私：CL-TE与TE-CL]] |

## 1. 概述

### 1.1 技术定义

**HTTP/1.1**（RFC 7230-7235演进自RFC 2616）是万维网基础的应用层协议，定义客户端与服务器之间以**请求（Request）-响应（Response）**为单位交换消息的规则。它运行在TCP（默认TLS 443/TCP 80）之上，是Web安全（SQL注入、XSS、SSRF等所有应用漏洞）的上层容器。

HTTP/1.x的重要特征是**面向文本**：请求行/状态行、头部字段、消息体均为可按字节解析的文本行，以CRLF分隔。这带来实现简单、人类可读的好处，也为注入类攻击（CRLF注入、请求走私）埋下隐患。

### 1.2 知识体系定位

- HTTP/1.1是Web应用层的**核心协议**，是 Web 安全研究（见 [[03-Web安全]] 相关）的基础
- 与更先进的HTTP/2（见 [[14-HTTP2多路复用与HTTP3核心变化]]）、HTTP/3形成演进谱系
- 传输安全由TLS（见 [[15-TLS1.2与TLS1.3握手流程逐消息解析]]）保障
- 安全角度：绝大多数Web攻击（Host头注入、CRLF、请求走私、响应拆分）都是对HTTP/1.1解析歧义的利用

### 1.3 核心应用场景

- Web开发与调试（curl、浏览器的DevTools、Postman）
- 安全测试（Burp Suite、SQLMap均解析HTTP/1.1）
- 反向代理/网关/负载均衡转发HTTP/1.1
- 抓包还原请求（见 [[16-抓包实战：tcpdump过滤与Wireshark协议还原]]）

### 1.4 技术演进简史

| 时间 | 里程碑 | 说明 |
|------|--------|------|
| 1991 | HTTP/0.9 | 极简，只有GET、无头、无状态码 |
| 1996 | HTTP/1.0（RFC 1945） | 引入各种方法、头部、状态码；默认关闭连接（Connection: keep-alive需显式） |
| 1997 | HTTP/1.1（RFC 2068→2616→7230） | 默认持久连接、管线化、Host必填、chunked、缓存控制正式化 |
| 2005-2015 | 安全焦点：CL-TE/TE-CL请求走私 | 因前后端对Content-Length/Transfer-Encoding解析差异产生的攻击 |
| 2015 | HTTP/2 标准化 | 缓解1.1的队头阻塞，见 [[14-HTTP2多路复用与HTTP3核心变化]] |
| 2022+ | HTTP/1.1 仍广泛存量 | 大量老服务、代理、内网系统仍用1.1 |

## 2. 核心原理

### 2.1 请求消息结构（HTTP/1.1）

```
Request-Line:  METHOD SP request-target SP HTTP-version CRLF
Header*:        header-field ":" OWS field-value OWS CRLF
CRLF (空行)
message-body:  可选，长度由 Content-Length 或 chunked 决定
```

字节逐项：

```
POST /login.php HTTP/1.1\r\n
Host: example.com\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 27\r\n
\r\n
username=admin&password=123
```

- 请求行以方法开始，`/login.php` 为目标（HTTP/1.1中"绝对路径形式"，Host头必填）
- 头部每行以CRLF结尾
- 空行（单独CRLF）分隔头部与正文
- 正文长度由`Content-Length`或`Transfer-Encoding: chunked`决定

### 2.2 响应消息结构

```
Status-Line:  HTTP-version SP status-code SP reason-phrase CRLF
Header*
CRLF
message-body
```

```
HTTP/1.1 200 OK\r\n
Content-Type: text/html; charset=utf-8\r\n
Content-Length: 123\r\n
\r\n
<html>...123字节正文...</html>
```

### 2.3 状态码分类与安全关键码

| 范围 | 含义 | 安全相关示例 |
|------|------|--------------|
| 1xx | 信息性 | 100 Continue（分体发送前预检，与request smuggling相关） |
| 2xx | 成功 | 200 OK、204 No Content |
| 3xx | 重定向 | 301/302（钓鱼/Open Redirect）、303 See Other、304 Not Modified |
| 4xx | 客户端错误 | 401 Unauthorized、403 Forbidden、404 Not Found（信息泄露/存在性判断）、405 Method Not Allowed、418 I'm a teapot |
| 5xx | 服务器错误 | 500（内部错误泄露栈）、502/504（网关） |

**安全上重点**：`401/403/404/405/500` 的状态差异常被用做**存在性/路径信息泄露**的探测探针；`100 Continue` 与 `Content-Length` 相结合是CL-TE走私的关键。

### 2.4 主要方法

| 方法 | 语义 | 幂等 | 安全点 |
|------|------|------|--------|
| GET | 获取资源 | 是 | 不应有副作用；URL泄密（日志/Referer） |
| POST | 创建/提交 | 否 | 常见漏洞注入向量 |
| PUT | 上传/覆盖资源 | 是 | 若可匿名上传→任意文件上传；DoS/覆盖 |
| DELETE | 删除资源 | 是 | 未授权删除风险 |
| PATCH | 部分更新 | 否 | JSOn Patch诊断乱序漏洞 |
| HEAD | 仅返回头部 | 是 | 探测存在性/长度 |
| OPTIONS | 查询支持的方法 | 是 | 暴露CORS/方法、fingerprint |
| CONNECT | 建立隧道 | 否 | 代理越权、SSRF隧道 |
| TRACE | 回显请求 | 是 | XST（跨站跟踪）；建议禁用 |

`OPTIONS * HTTP/1.1` 返回服务器支持的方法集合。

### 2.5 持久连接（Keep-Alive）

HTTP/1.1 **默认**在连接关闭前保持TCP连接（对比1.0默认关闭）。用 `Connection: keep-alive` / `close` 控制。

```
客户端                                 服务器
  |---> GET /1 (req1) ------------------>|
  |<--- HTTP/1.1 200 (resp1) ------------|
  |---> GET /2 (req2, 同一TCP连接) ------>|
  |<--- HTTP/1.1 200 (resp2) ------------|
  |---> Connection: close (req3) -------->|
  |<--- HTTP/1.1 200 + Connection: close -|
  |<--- FIN ------------------------------|
```

持久连接避免为每个资源重新建立TCP+TLS（大幅降低延迟与握手开销）。浏览器通常每个域 6 个并发连接。

**保持存活如何确定消息边界**：消息体长度由两种方式明确：
1. `Content-Length`：固定字节数
2. `Transfer-Encoding: chunked`：分块传输，每块前一行是十六进制长度，0结束

边界确定的重要性在于——**如果前后端对边界的理解不一致，就会产生请求走私**。

### 2.6 管线化（Pipelining）

管线化允许客户端在第一个请求的响应未到前，在同一连接上**连续发送多个请求**：

```
连接: [req1][req2][req3]  ->  [resp1][resp2][resp3]
```

**严格的限制（parser规范）**：服务器**必须按请求顺序**返回响应（HTTP/1.1逐响应、FIFO），不允许乱序。因此若第一个请求慢（如大响应/慢后端），后续响应全部阻塞——这就是HTTP/1.1的**队头阻塞（Head-of-Line Blocking）**。

```
req1(慢,如大视频)  req2 req3 (都要等req1返回)
     |-------------|----|-----   ← req2/3被req1的响应阻塞
```

由于这个队头阻塞 + 实现复杂（很多服务器不完全支持），管线化实际极少被浏览器使用（现代Chrome默认关闭，靠并发连接+多路复用HTTP/2替代）。

## 3. 详细知识点

### 3.1 常用请求头部（安全视角）

| 头部 | 含义 | 安全点 |
|------|------|--------|
| `Host` | 目标主机 | Host头注入/毒化，绝对URI走私 |
| `Content-Type` | 正文媒体类型 | multipart解析边界、类型混淆绕过WAF |
| `Content-Length` | 正文字节长度 | CL-TE走私、缓冲区差异 |
| `Transfer-Encoding` | chunked | TE-CL走私、编码混淆 |
| `Authorization` | Basic/Bearer | 泄露、弱口令、信息暴露 |
| `Cookie` | 会话Cookie | 会话固定/劫持、HTTP-only、Secure |
| `Referer` | 来源URL | 泄露敏感令牌（QueryString） |
| `X-Forwarded-For / X-Real-IP` | 代理真实IP | 伪造IP绕过访问控制/限速 |
| `Cache-Control` | 缓存策略 | 缓存投毒/辅助隐私问题 |
| `Content-Security-Policy` | CSP策略 | 缓解XSS（配置漏配暴露风险） |
| `Set-Cookie` | 服务器下发Cookie | Secure/HttpOnly/SameSite属性 |
| `Strict-Transport-Security` | HSTS | 强制HTTPS防止降级 |
| `Access-Control-Allow-Origin` | CORS | 不当配置(通配*配合Credential)风险 |

### 3.2 Host头注入

HTTP/1.1**强制** `Host` 头存在，服务器用它决定虚拟主机、构造绝对URL、重置密码邮件链接等。若服务器信任`Host`而未校验（或存在重复Host、绝对URI走私），攻击者可控：

```
POST /reset HTTP/1.1
Host: victimsite.com           ← 正常
Host: attacker.com             ← 注入(未校验) → 重制密码邮件发向attacker.com
```

**变体**：
- 重复Host头（两个Host）→ 解析歧义
- 绝对URI走私：`GET http://evil/ HTTP/1.1` + 多余Host
- Host以点号/空格结尾（`Host: victim.com.`）解析为不同主机

**漏洞利用面**：密码重置投毒、缓存投毒、凭据盗取、SMTP头注入、Web缓存污染（`Host`导致的缓存键攻击，见 [[02-Web缓存投毒与缓存欺骗]]）。

### 3.3 CRLF注入（HTTP响应拆分/头部注入）

CRLF（`\r\n`）在HTTP/1.1中用于**分隔头与消息**。若应用把用户的输入（未过滤`\r\n`）拼进响应头部，攻击者可向响应**注入额外头部甚至伪造整个后续响应**（Response Splitting），进而实现：Set-Cookie注入、跨站脚本/钓鱼、缓存污染、并发请求走私。

```
攻击输入: 重定向参数 url 中包含 %0d%0a
  Location: /redirect?url=evil%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<script>...
产生的响应头:
Location: /redirect?... 
Set-Cookie: admin=1
<script>...</script>   ← 响应体被注入脚本
```

**防御**：
- 所有进入头部/响应的用户输入做CRLF转义（`\r`/`\n` → `%0d`/`%0a` 或移除）
- 服务器层面拒绝含 `\r\n` 的未编码头部值
- 使用框架的参数化头部设置（自动过滤）

### 3.4 请求走私（Request Smuggling）

核心：**CL与TE同时存在或前后端对消息边界理解不一致**时，攻击者构造一个"部分请求"，使前端（如Nginx）认为请求在A处结束、后端（如Tomcat/Uvicorn）认为在B处结束，从而把残留的请求字节"走私"给后端作为新请求。

**类型**（RFC 7230明确禁止同时使用CL与TE）：

- **CL.TE**：前端用Content-Length确定边界，后端用Transfer-Encoding。攻击者设`CL: 4`（真长度）但正文是chunked编码，后端把chunk解码后读到作为请求的一部分（走私）。

```
前端: 
Content-Length: 4
Transfer-Encoding: chunked

SP    ← 4字节正文
后端(用chunked)解读:
后续字节走私为第2个请求:
0

GET /admin HTTP/1.1
Host: ...
...
```

- **TE.CL**：前端用chunked，后端用Content-Length。

- **TE.TE**：前后端都支持chunked但解析差异（如`Transfer-Encoding : chunked`多空格、`X: chunked`伪装）导致一端被混淆。

**影响**：走私可以：
1. 绕过前端WAF（向不可见的后端发恶意请求）
2. 毒化其他用户的请求（Session固定/污染）
3. 窃取其他用户请求（捕获含Cookie的请求）
4. 缓存投毒与CDN越权

详细复现见 [[01-HTTP请求走私：CL-TE与TE-CL]]。

### 3.5 HTTP/1.1 与 HTTPS（TLS 在1.1之上的位置）

HTTP/1.1运行于TCP，安全由TLS（见 [[15-TLS1.2与TLS1.3握手流程逐消息解析]]）层包裹。加密的是**上层HTTP内容**，HTTP本身的方法、头部、正文在TLS内部加密传输，而TCP/UDP端口、SNI等元数据仍可见。

HTTP/1.1 + TLS 连接建立流程：
```
TCP三次握手 (1 RTT)
TLS握手      (1-2 RTT, TLS1.2为2, TLS1.3为1)
HTTP请求/响应 (持久连接后若干)
```

## 4. 实战与示例

### 4.1 环境准备

```bash
# 用curl/netcat观察HTTP/1.1原始消息
curl -v http://example.com
# 或用 nc(netcat) 手动构造请求
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' | nc example.com 80
```

创建本地测试服务器（观察HTTP/1.1）：

```python
# http11_demo.py - 简单实现看请求解析
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.end_headers()
        self.wfile.write(b"hello")
    def log_message(self, fmt, *a): pass
HTTPServer(('127.0.0.1',8080), H).serve_forever()
```

### 4.2 观察持久连接与keep-alive

```bash
# 观察同一连接上的多个请求
curl -v -o /dev/null http://127.0.0.1:8080/ http://127.0.0.1:8080/xxx 2>&1

# 抓包看连接复用
sudo tcpdump -i lo -nn -A -c 20 'tcp port 8080'
```

看输出：`Connection: keep-alive` 默认，连接单一（SYN只一次）。

### 4.3 观察管线化与队头阻塞（用nc演示）

用netcat手动管线化请求，观察服务器如何按序返回：

```bash
printf 'GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nGET /b HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc 127.0.0.1 8080
# 观察返回顺序: 先a后b
```

队头阻塞演示：让服务器处理`/slow`（延迟）时后续请求等：

```python
# 在handler.do_GET中加入
if self.path == '/slow':
    time.sleep(5)
# 抓包可看到 /slow 请求后, 后续响应的ACK延迟
```

### 4.4 CL-TE走私本地复现（授权靶机/代理）

用Python双服务模拟前后端解析差异并验证走私（精简演示，实操仍建议使用PortSwigger靶场/虚拟环境）：

```python
# front.py 假设按CL解析
def parse_headers(data):   # 简单CL解析
    ...
# 发送包含CL与chunked的混合消息观察不同解析器的处理
payload = b'''POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nSP\x00\x00\x00\x00'''

# 前端按CL读到"SP   "结束 -> 剩余字节是走私内容
# 后端按chunked: 把后续当chunk(0长度结尾) + 第2个请求
```

**安全提示**：走私涉及多服务，务必在隔离的测试环境（本地虚拟机/靶场）进行，不要对公网发起。

### 4.5 观察状态码与信息泄露

```bash
# 探测路径存在性
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/nonexist  # 404
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/           # 200
# 观察 405 (方法不允许)
curl -s -X DELETE -i http://127.0.0.1:8080/
```

### 4.6 报错与解决

| 现象 | 原因 | 解决 |
|------|------|------|
| curl报 `HTTP/1.1 400 Bad Request` | Host缺失/非法 | 检查是否带Host，或curl `-H "Host:..."` |
| nc发送后服务器无响应改挂起 | 未按1.1发CRLF或未关闭连接 | 用`\r\n`，末尾加 `Connection: close` |
| linux nc被其他程序占用 | 端口冲突 | 换端口或用`socat - TCP:127.0.0.1:8080` |
| 走私<Lab>演示不出现预期 | 前后端解析差异未满足 | 确认CL与TE同时存在/头顺序对、目标支持chunked |

## 5. 常见坑与避坑指南

1. **依赖Content-Length而忘记处理chunked**：解析单头不可靠。收到消息时若不支持Transfer-Encoding应返回501，而非把它当CL消息解析（否则走私）。

2. **过分相信单一解析器：前后端差异**：请求走私/缓存投毒都源于前后端解析不一致。测试和防护都要"双端视角"思考：前端看到什么边界？后端看到什么？

3. **Host头注入测试时忽略多Host/绝对URI**：只测单Host不够，实测重复Host、首行绝对URI、Host带点/空白等变体。

4. **CRLF只看URL编码**：`%0d%0a`可能被解码一次或两次，AGENTS里常说解码层级不同导致过滤绕过。检查双层解码、以及头部值中被透传的原始CR字符。

5. **安全坑：CORS/缓存键价值被低估**：把`Access-Control-Allow-Origin: *`配合`credentials`或用`Host`/`Origin`做缓存键控制，会导致投毒与跨域数据窃取。别只看状态码，头部字段同样critical。

6. **不要在生产环境直接测请求走私**：走私payload会影响同一代理/连接的其他真实用户（窃取/污染请求），必须在隔离环境、PortSwigger靶场或本地多服务复现后，再评估线上影响。

7. **状态码不等于安全结论**：`403`不代表安全、`200`未必成功——需结合响应体实际内容与业务语义综合判断（某oway隐藏功能返回200带错误JSON）。

## 6. 知识关联

- [[14-HTTP2多路复用与HTTP3核心变化]] —— HTTP/1.1的队头阻塞问题在HTTP/2/3的解决
- [[15-TLS1.2与TLS1.3握手流程逐消息解析]] —— HTTP/1.1 + TLS安全传输
- [[01-HTTP请求走私：CL-TE与TE-CL]] —— 请求走私详细复现（同一系列的 Web 安全篇）
- [[12-DNS协议：记录类型递归迭代全流程]] —— 发起HTTP请求前的DNS解析
- [[16-抓包实战：tcpdump过滤与Wireshark协议还原]] —— 还原HTTP/1.1请求与响应
- [[03-Web安全/05-高级专题/03-点击劫持与UI覆盖攻击]] —— 响应头缺失导致的前端风险

## 7. 参考资料

| 类型 | 资源 | 说明 |
|------|------|------|
| RFC | [RFC 7230 - HTTP/1.1 Message Syntax and Routing](https://www.rfc-editor.org/rfc/rfc7230) | 消息格式、CL/TE、连接管理 |
| RFC | [RFC 7231 - Semantics and Content](https://www.rfc-editor.org/rfc/rfc7231) | 方法、状态码、缓存语义 |
| RFC | [RFC 7232-7235](https://www.rfc-editor.org/rfc/rfc7232) | 条件请求/认证/缓存控制 |
| RFC | [RFC 9110-9112 (2022归并)](https://www.rfc-editor.org/rfc/rfc9110) | 新版HTTP语义合并 |
| RFC | RFC 8540/RFC 8559 | 报文历史勘误 |
| 安全 | PortSwigger Research - "HTTP Request Smuggling" (James Kettle) | 请求走私权威研究 |
| 安全 | OWASP - "HTTP Request Smuggling" & "SMTP Header Injection" | 攻击面与防护 |
| 书 | 《HTTP: The Definitive Guide》Gourley & Totty | HTTP权威参考 |
| 工具 | curl、Burp Suite、nc/socat、tshark、httpie | 构造与解析工具 |
