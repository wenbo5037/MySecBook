---
title: "DNS协议：记录类型递归迭代全流程"
category: "00-基础通用/03-计算机网络"
tags: [DNS, 递归查询, 迭代查询, 记录类型, DNSSEC, DoH]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# DNS协议：记录类型递归迭代全流程

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | DNS是将域名映射到IP及其他信息的分布式分级数据库系统，查询分递归与迭代两种模式 |
| 核心用途 | 域名解析、邮件路由(MX)、证书验证(TXT/CAA)、抗污染(DNSSEC)、DNS隧道/隐蔽通信 |
| 记录类型 | A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, PTR, DNAME, CAA, DNSKEY, DS, RRSIG, NSEC |
| 查询流程 | 递归解析器→迭代根/TLD/权威服务器→逐级返回NS+胶水记录→最终A记录 |
| 常见风险 | 缓存投毒(Kaminsky)、DNS隧道、NXDOMAIN洪泛、DNS重绑定、劫持/污染、DNSSEC误配 |
| 关联知识 | [[16-抓包实战：tcpdump过滤与Wireshark协议还原]]、[[11-UDP特性与QUIC协议设计动机]]、[[15-TLS1.2与TLS1.3握手流程逐消息解析]] |

## 1. 概述

### 1.1 技术定义

**DNS（Domain Name System，域名系统）**是互联网的分布式、分层、可缓存的命名系统，负责域名到IP地址（及更多资源记录）的**双向映射**。DNS基于UDP（端口53）为主、TCP（大响应/传送）为辅，是几乎所有互联网服务（HTTP、邮件、CDN、云）的底层依赖。

**递归查询（Recursive）**：客户端将整个解析任务交给递归解析器（如ISP DNS、8.8.8.8），解析器代劳走完全部步骤。
**迭代查询（Iterative）**：解析器逐步向根/顶级域/权威服务器请求，若当前服务器不能直接回答则返回"下级服务器地址"，解析器自行前往。

### 1.2 知识体系定位

DNS位于**应用层**，跑在传输层UDP之上（见 [[11-UDP特性与QUIC协议设计动机]]）。它既是基础服务，也是攻击面极其丰富的目标：投毒、劫持、隧道、放大DDoS、重绑定、信息泄露等。安全从业者需深刻理解其记录类型、解析路径、缓存机制，才能开展防御与检测。

### 1.3 核心应用场景

- 名称解析（正向A/AAAA、反向PTR）
- 邮件路由（MX）、服务发现（SRV）、TXT策略（SPF/DKIM/DMARC）
- 内容分发（CDN智能DNS）、负载均衡（多A轮询）
- 安全：DNSSEC信任链、DoH/DoT隐私、DNS防火墙、威胁情报IOC
- 攻击：DNS隧道、重绑定、投毒、放大

### 1.4 技术演进简史

| 时间 | 里程碑 | 说明 |
|------|--------|------|
| 1983 | RFC 882/883 | 初版DNS替代HOSTS文件 |
| 1987 | RFC 1034/1035 | 现代DNS核心规范，沿用至今 |
| 1993 | RFC 1536/1537 | 缓存与负缓存机制 |
| 2005 | RFC 4033-4035 | DNSSEC引入（RRSIG/DS/NSEC） |
| 2008 | Kaminsky漏洞 | DNS缓存投毒重大事件 |
| 2010 | 有符号的根区 | 根区年开始DNSSEC签名 |
| 2016 | RFC 7858 (DoT)、2018 RFC 8484 (DoH) | 加密DNS传输兴起 |
| 2018 | DNS over HTTPS大规模部署 | 隐私与抗劫持 |

## 2. 核心原理

### 2.1 DNS 分级架构

DNS采用严格的树状分级：

```
                       .  (根区 Roots, 13组IP地址)
                        |
     +------------------+------------------+
     |                  |                  |
    com               org                net ...
     |                  |
   example.com        example.org (二级域)
     |                  |
   www.example.com   mail.example.org (主机)
```

| 层级 | 责任 | 示例 |
|------|------|------|
| 根服务器 | 指向各TLD（顶级域）的NS | a.root-servers.net (198.41.0.4) 等 |
| TLD服务器 | 指向具体二级域的NS（com/net/org/cn...） | a.gtld-servers.net |
| 权威服务器 | 返回域内具体记录 | ns1.example.com |
| 递归解析器 | 替客户端完成全部查询（客户端视角） | 8.8.8.8、114.114.114.114 |

### 2.2 一次完整解析：递归+迭代

以客户端 (`10.0.0.5`) 查询 `www.example.com` 为例：

```
客户端
  | 1. 待解析 www.example.com (递归)
  v
递归解析器 (8.8.8.8)
  | 2. 查缓存? 没有 → 发起迭代
  v
根服务器
  | 3. "我不认识 www.example.com, 请找 .com 域->a.gtld-servers.net (NS)"
  v
.com TLD服务器
  | 4. "请找 example.com 的权威->ns1.example.com (NS + 胶水记录)"
  v
example.com 权威
  | 5. "www.example.com -> 93.184.216.34 (A)"
  v
递归解析器 (缓存结果, TTL内复用)
  | 6. 返回 A 记录给客户端
  v
客户端(浏览器) 拿到IP
```

抓包视角（一次迭代查询的多条UDP/ TCP 消息），命令 `dig +trace`。

### 2.3 DNS报文结构

一个DNS消息（Message）统一格式：

```
+---------------------+
| Header (12 bytes)   |  ← ID, 标志, QDCOUNT, ANCOUNT...
+---------------------+
| Question            |  ← 问题区(域名+类型+类)
+---------------------+
| Answer              |  ← 应答区
+---------------------+
| Authority           |  ← 权威区(NS等)
+---------------------+
| Additional          |  ← 附加区(胶水记录/CDN映射)
+---------------------+
```

Header关键字段：
- **ID(16bit)**：事务ID，请求/响应匹配，是投毒攻击的关键目标
- **QR**：0=查询 1=响应
- **Opcode**：QUERY=0, IQUERY=1, STATUS=2, NOTIFY=4, UPDATE=5
- **AA**（Authoritative Answer）：响应是否来自权威
- **TC**（Truncated）：响应截断（UDP放不下提示用TCP）
- **RD**（Recursion Desired）：请求递归
- **RA**（Recursion Available）：服务器支持递归
- **QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT**：各区域计数

### 2.4 缓存与TTL

每条记录携带 TTL（Time To Live，秒）。递归/客户端按TTL缓存。TTL=0的MUST NOT缓存。缓存机制既提效也是投毒攻击的"驻留窗口"——投毒成功后恶意记录在TTL内长期存活。

```
常见TTL示例:
- 根/TLD区: 相对短 (根区2天)
- 权威NS: 通常 86400 (1天)
- A记录/CDN: 60~300 (短以支持CDN切换)
- 负缓存 TTL (NXDOMAIN): SOA的 MINIMUM
```

## 3. 详细知识点

### 3.1 记录类型（Resource Records）

| 类型 | 全称/用途 | 实例值 |
|------|-----------|--------|
| A | IPv4地址 | `www.example.com. 300 IN A 93.184.216.34` |
| AAAA | IPv6地址 | `example.com. IN AAAA 2606:2800:220:1::` |
| CNAME | 别名指向另一域名 | `www IN CNAME example.com.` |
| MX | 邮件交换服务器(带优先级) | `IN MX 10 mail.example.com.` |
| NS | 域名服务器 | `IN NS ns1.example.com.` |
| TXT | 任意文本(SPF/DKIM/验证) | `"v=spf1 include:_spf.google.com ~all"` |
| SRV | 服务定位(优先级/权重/端口) | `_sip._tcp IN SRV 10 60 5060 sip.example.com.` |
| SOA | 起始授权(区版本/主从) | `IN SOA ns1 root (serial refresh retry expire minimum)` |
| PTR | 反向域名(IP→主机) | `34.216.184.93.in-addr.arpa IN PTR www.example.com.` |
| CAA | 证书颁发授权(HTTPS) | `IN CAA 0 issue "letsencrypt.org"` |
| DNSKEY | DNSSEC公钥 | `IN DNSKEY 256 3 8 AwEAAa...` |
| DS | 子区委派签名(父区记录子区DNSKEY摘要) | `IN DS 12345 8 2 <sha256hex>` |
| RRSIG | 记录签名 | `IN RRSIG A 8 2 3600 <sig>` |
| NSEC/NSEC3 | 无存在证明(防线) | `IN NSEC host1.example.com.` |
| DNAME | 子树重定向 | 类似CNAME但作用于整个子树 |

**正向解析**：A/AAAA。**反向解析**：PTR（通过 `in-addr.arpa` 和 `ip6.arpa`）。

用 `dig` 查不同类型：

```bash
dig A www.baidu.com
dig +short MX gmail.com
dig @8.8.8.8 +trace example.com   # 看完整解析路径
dig -x 8.8.8.8                     # 反向PTR查询
dig TXT google.com                 # SPF记录
dig CAA letsencrypt.org
```

### 3.2 递归查询全流程（逐包）

用 `dig +trace` 逐步展示递归解析器做迭代时的完整路径：

```bash
$ dig +trace +nodnssec www.example.com
;; Received ...
;; ->>HEADER<<- ... opcode: QUERY, status: NOERROR ... RD: 
;; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; root 区 -> 返回13个根服务器的NS与A(胶水)
;; Received 240 bytes from 127.0.0.53#53 (本地递归)

;; com zone:
;;   NS a.gtld-servers.net ... (13个.com NS)
;;   Received 496 bytes from 192.5.5.241#53 (a.root-servers.net)

;; example.com. zone:
;;   NS ns1.example.com. + 胶水记录(A 记录)
;;   Received 81 bytes from 192.12.94.30#53 (a.gtld-servers.net)

www.example.com.  300  IN  A  93.184.216.34
;; Received 64 bytes from ns1.example.com#53 (权威)
```

这完整演示了一次迭代解析：根→com TLD→example.com权威→A记录，与2.2节图示吻合。

### 3.3 DNS攻击详解

#### (a) 缓存投毒（Kaminsky攻击, 2008）

Kaminsky漏洞核心：攻击者向递归解析器发送大量**伪造的响应包**，猜测/碰撞事务ID+源端口，使解析器把恶意记录缓存进受害者看得到的缓存中。

```
攻击者在递归解析器上投毒某域名(victim.com)的权威应答
  → 使解析器以为www.victim.com由攻击者NS权威
  → 之后所有指向victim.com CDN/邮件/登录的流量被劫持
```

防投毒措施（现代递归服务器）：
- 随机源端口（0x20编码/端口随机化, RFC 6056）
- 提高事务ID与端口的熵
- 0x20随机大小写（域名编码）校验
- DNSSEC签名验证（根治）

#### (b) DNS隧道

把数据封装进DNS查询/响应的子域名或TXT记录中，绕过防火墙（DNS常被放行）。伪装成正常域名解析流量，用于C2回连、文件外传、隐蔽通信。

```
攻击者C2域名: c2.badguys.com
  受害主机把外传数据base32编码进子域名查询:
  exfil1234.c2.badguys.com         ← 本质是DNS查询携带数据
  攻击者DNS服务器解析并解码
```

检测：DNS查询QPS异常、子域名高熵随机串、NXD响应极多、TTL异常小、查询域名与历史不符。工具：iodine、dnscat2（检测用）；防御用DNS防火墙/白名单聚合。

#### (c) NXDOMAIN 洪泛

攻击者向递归解析器发送海量**不存在的域名**查询，每个都触发上游解析+负缓存，耗光递归服务器CPU/缓存/带宽，形成DNS DDoS。属资源耗尽型攻击。

防御：限速、缓存负结果（SOA MINIMUM）、CNAME权威委派、聚合任意域名（wildcard +泛解析）。

#### (d) DNS重绑定（DNS Rebinding）

利用DNS应答TTL极短+解析顺序，让恶意网页的同一域名先后解析到攻击者服务器和受害者内网IP，从而让**受害浏览器**（受害者特权）访问其内网服务（SSRF/TOTP绕过）。

```
攻击网页 www.evil.test 引用了 victim.internal (受控域名)
第1次解析 -> 攻击者web服务器(提供恶意JS)
之后JS请求 victim.internal 时域名被重新绑定到127.0.0.1或内网IP
  → 攻击者JS以"可信来源"访问内网应用(浏览器自动带上cookie/信任)
```

防御：DNS绑定检查（Firefox 默认1.1.1.1+限制）、浏览器拦截私有IP（domain resolution policy）、反SSRF代理校验。

#### (e) 其他：劫持/污染、**DNS over cleartext 中间人**

区域传送攻击（AXFR未限制）、TSIG密钥泄露、DNS劫持（改解析器配置）、DNS污染（GFW等对特定域名返回错误IP）。

### 3.4 DNSSEC 信任链

DNSSEC用签名保证**数据完整性+来源认证**（不加密）。思想：每个区用私钥对记录签名（RRSIG），父区用DS记录"背书"子区DNSKEY，形成自根到叶的信任链。

```
根区: (公开发布的根DNSKEY) → 签名 → 根区的 RRSIG
  |
  |____ DS记录(com): 摘要 com 的 DNSKEY ← 由根签名的DS
  |
com区: DNSKEY(=com的ZSK/KSK) ← com的DS由根签名验证
  |
  |____ DS记录(example.com)
  |
example.com: DNSKEY + RRSIG(A记录)
  |
  v
客户端 验证: A记录用example.com的DNSKEY验证RRSIG
             example.com的DNSKEY用com的DS验证
             com的DNSKEY用根签名验证
             根DNSKEY是"信任锚"(预置或通过本地信任锚)
```

**验证流程**：
1. 解析器获取权威返回的 `example.com` 的 `A` 记录 + `RRSIG(A)`
2. 用区公钥 `ZSK` 验证 `RRSIG(A)` 签名
3. 用父区 `DS` 记录验证 `ZSK`/`KSK`（链式）
4. 自顶向下逐层认证直到根信任锚
5. 若某环签名无效 → SERVFAIL（Bogus）

`dig +dnssec` 展示签名记录：
```bash
dig +dnssec A cloudflare.com @1.1.1.1
# 输出里带 RRSIG A DNSKEY
dig +dnssec +short DS cloudflare.com    # 查看父区的DS
```

### 3.5 DoH / DoT：加密DNS传输

- **DoT（DNS over TLS, RFC 7858）**：TCP 853，加密但保留端口可被DPI识别
- **DoH（DNS over HTTPS, RFC 8484）**：复用443端口，混在HTTPS流量中更难被封，但使本地解析器难以做策略控制

```bash
# 测试DoH (curl)
curl -s -H "accept: application/dns-message" \
  "https://cloudflare-dns.com/dns-query?dns=<base64url编码的DNS查询>"
```

**安全性对比**：DoH/DoT加密**传输**（防窃听/防篡改/防中间人DNS投毒），但**不加密解析内容本身**不防缓存。DNSSEC则提供数据完整性。二者互补。缺点：DoH绕过了运营商/企业DNS策略，可能被用于规避监控。

## 4. 实战与示例

### 4.1 环境准备

```bash
sudo apt install -y dnsutils bind9-utils tcpdump dnsmasq
# 本地DNS服务器: dnsmasq 或 bind
# 抓包: tcpdump/tshark
```

### 4.2 抓取DNS查询逐包解析（递归+迭代）

```bash
sudo tcpdump -i eth0 -nn -vv 'port 53' -c 20
# 在另一终端执行
dig A www.baidu.com
```
观察：来源端口53（UDP）、Question区、Answer区、TTL。

### 4.3 搭建本地权威+递归DNS验证迭代路径

用 `dnsmasq` 做递归，配自定义host验证解析：

```bash
# /etc/dnsmasq.conf 增加
# 监听本地, 增加自定义解析
echo "address=/mal.test/10.0.0.66" | sudo tee -a /etc/dnsmasq.conf
systemctl restart dnsmasq
# 测试自定义域
dig @127.0.0.1 mal.test
```

用bind手工建一个简单权威区感受SOA/NS/记录：

```named
# /etc/bind/zb.zone
$TTL 300
@ IN SOA ns1.zb. root.zb. ( 2026090901 1h 15m 1w 1d )
@ IN NS ns1.zb.
@ IN A 192.168.1.5
ns1 IN A 192.168.1.5
www IN A 192.168.1.6
```

### 4.4 用Python/tshark自动化解析安全相关的DNS行为

**检测子域名随机串（DNS隧道/随机域名）**：

```python
import re, string, math

def entropy(s: str) -> float:
    if not s: return 0
    prob = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(p*math.log2(p) for p in prob)

def suspicious(label: str):
    # 高熵+长随机子域 => 可能是隧道/随机域名(DGA)
    entropy_val = entropy(label)
    if len(label) >= 20 and entropy_val > 3.5:
        return True
    if re.search(r'[0-9]{4,}', label) and entropy_val > 3.0:
        return True
    return False

# 示例
print(suspicious("a3f8k2q9zc1v7b4m6x0pswq"))  # True (高熵)
print(suspicious("www"))                     # False
```

**用tshark提取DNS查询域名**：
```bash
tshark -r dns.pcap -Y 'dns.qr==0' -T fields -e dns.qry.name | sort | uniq -c
```

### 4.5 抓包观察DNS重绑定/污染特征

- 重绑定：同一域名的A记录在不同时刻返回不同IP（TTL小），tshark按会话统计变化
- 污染：DNS响应中的A记录与真实值不符，或返回错误IP / 返回多个"假"值

```bash
# 抓某域名多次解析, 看返回IP是否稳定
for i in {1..10}; do dig +short bad.example.com @8.8.8.8; sleep 1; done
```

### 4.6 报错与解决

| 现象 | 原因 | 解决 |
|------|------|------|
| `dig: connection timed out` | UDP53被防火强拦 | 测试TCP `+tcp`；确认UDP可达 |
| SERVFAIL（DNSSEC） | 签名不匹配/信任链断 | `dig +dnssec +norecurse` 排查RRSIG；检查DS正确性 |
| 解析结果被污染返回错误IP | DNS劫持/污染/脏缓存 | 换DoH/DoT、`dig +dnssec`、刷新cache（清理受害缓存） |
| 大响应被截断(TC=1) | UDP 512/4096限制 | 用TCP，或启用EDNS0 (`+edns`) |
| 负缓存导致解析不到新记录 | SOA MINIMUM太大 | 改小TTL，flush负缓存 |

## 5. 常见坑与避坑指南

1. **事务ID与源端口随机化未启用**：老配置/某些嵌入式解析器固定端口，投毒极易。确保递归服务器支持源端口随机化（RFC 6056）。

2. **误把DoH/DoT当DNSSEC**：DoH只加密传输通道，不验证内容来源；要防"弄虚作假的解析结果"必须DNSSEC。两者用途不同。

3. **CNAME与MX记录易混淆/配错**：MX记录的值必须是A/AAAA主机名，不是CNAME别名；且MX配置错误会破坏整个邮箱可靠性（dangling CNAME）。

4. **区域传送（AXFR）未限制**：权威服务器若对任意IP开放AXFR，等于公开全部内部主机/纪录（信息泄露）。务必限制到从服务器的IP。

5. **安全坑：DNS隧道检测误报**：合法的公共SaaS（如某些随机子域名的CDN、ZeroSSL验证、DDNS）也可能触发"高熵子域"报警。检测要结合上下文（QPS、TTL、域名信誉、白名单）而非单一特征。

6. **DNS重绑定测试误伤**：做内网安全测试时若解析到私有地址，浏览器/代理可能拦截或缓存，导致测试结果不可复现。测试时善用 `--resolve` 或独立解析器。

7. **负缓存毒NXD响应放大**：滥用不存在域名可撑爆递归缓存。对权威/递归都建议负缓存TTL约束 + 限速。

## 6. 知识关联

- [[16-抓包实战：tcpdump过滤与Wireshark协议还原]] —— DNS抓包、跟随UDP流分析解析过程
- [[11-UDP特性与QUIC协议设计动机]] —— DNSSEC记录与UDP特性、反射放大攻击的关系
- [[15-TLS1.2与TLS1.3握手流程逐消息解析]] —— DoH/DoT、证书与DNS的关系
- [[13-HTTP1.1：方法头部持久连接与管线化]] —— DNS解析是HTTP请求前的必要步骤
- [[14-HTTP2多路复用与HTTP3核心变化]] —— HTTP/3经DNS + DoH的部署方式

## 7. 参考资料

| 类型 | 资源 | 说明 |
|------|------|------|
| RFC | [RFC 1034/1035 - DNS](https://www.rfc-editor.org/rfc/rfc1035) | DNS核心规范 |
| RFC | [RFC 4033-4035 - DNSSEC](https://www.rfc-editor.org/rfc/rfc4033) | DNSSEC引入 |
| RFC | [RFC 8484 - DNS Queries over HTTPS (DoH)](https://www.rfc-editor.org/rfc/rfc8484) | DoH |
| RFC | [RFC 7858 - DNS over TLS (DoT)](https://www.rfc-editor.org/rfc/rfc7858) | DoT |
| RFC | [RFC 6056 - Port Randomization](https://www.rfc-editor.org/rfc/rfc6056) | 投毒防护 |
| 论文 | Karst·Kaminsky, "It's the End of the Cache as We Know It" (2008) | Kaminsky漏洞分析 |
| 工具 | `dig`、`host`、`nslookup`、`dnsmasq`、`bind9`、`scapy`、`dnschef` | 解析/测试/攻击复现 |
| 教程 | DNS Made Easy 图解 / IETF DNSSEC入门 | 可视化解析流程 |
| 书 | 《DNS and BIND》Cricket Liu | 权威DNS管理与疑难排查 |
| 检测 | dnstap、dnspython、iodine/dnscat2 文档 | 解析监控与隧道工具 |
