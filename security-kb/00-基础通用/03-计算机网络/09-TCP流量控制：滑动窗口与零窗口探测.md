---
title: "TCP流量控制：滑动窗口与零窗口探测"
category: "00-基础通用/03-计算机网络"
tags: [TCP, 滑动窗口, 流量控制, 零窗口, 窗口探测]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---
# TCP流量控制：滑动窗口与零窗口探测

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
| --- | --- |
| 本质定义 | 滑动窗口是TCP端到端**流量控制**（flow control）机制，防止发送方淹没接收方缓冲区；零窗口是指接收方通告窗口为0、发送方停止发送的状态 |
| 核心用途 | 协调收发双方处理能力差异；窗口缩放应对高速网络；零窗口探测维持连接活性；防止接收缓冲区溢出 |
| 关键参数 | 发送窗口SWND、接收窗口RWND、通告窗口Advertised Window、窗口缩放因子Wscale、SWS阈值、持续计时器Persist Timer |
| 常见风险 | 零窗口DoS、窗口操纵攻击、TCP窗口预测投毒、Silly Window Syndrome、Nagle算法与延迟ACK冲突 |
| 关联知识 | [[07-TCP三次握手四次挥手：逐包状态分析]]、[[08-TCP状态机与TIME_WAIT调优]]、[[10-TCP拥塞控制：从Reno到BBR算法演进]] |

## 1. 概述

### 1.1 技术定义

TCP滑动窗口（Sliding Window）是TCP协议中用于**端到端流量控制**的核心机制。它解决的核心问题是：发送方和接收方的主机处理能力、内存缓冲区大小并不相同，如果发送方以全速率推送数据，可能瞬间填满接收方的接收缓冲区，导致数据丢失、重传风暴，甚至连接崩溃。

与"拥塞控制"（congestion control）不同，**流量控制**是接收方主导的、端到端的缓冲区管理机制；而拥塞控制是发送方感知网络中间设备（路由器、交换机）拥塞状态的机制。二者的发送窗口最终由 `min(拥塞窗口cwnd, 接收窗口rwnd)` 决定。

### 1.2 知识体系定位

在TCP协议栈中，滑动窗口位于传输层的**可靠传输**与**流量控制**领域，与三次握手、重传机制、拥塞控制并列，构成TCP可靠性四大支柱：

- **连接管理**：三次握手、四次挥手（见 [[07-TCP三次握手四次挥手：逐包状态分析]]）
- **可靠传输**：确认号、超时重传、快速重传
- **流量控制**：滑动窗口、窗口缩放、零窗口处理（本文）
- **拥塞控制**：慢启动、拥塞避免、Fast Recovery（见 [[10-TCP拥塞控制：从Reno到BBR算法演进]]）

### 1.3 核心应用场景

- **普通文件传输**：FTP、HTTP大文件下载，窗口决定吞吐量上限
- **高速长距离网络**：需要窗口缩放（RFC 7323）才能利用高带宽高时延网络（BDP）
- **移动网络/OTT**：弱网环境窗口更新频繁，观察窗口值可诊断卡顿
- **安全分析**：通过窗口异常判断TCP DoS攻击、僵尸连接、僵尸网络CC流量

### 1.4 技术演进简史

| 时间 | 里程碑 | 说明 |
| --- | --- | --- |
| 1974 | 论文《A Protocol for Packet Network Intercommunication》 | 滑动窗口思想由Vint Cerf与Bob Kahn提出 |
| 1981 | RFC 793 | TCP正式定义16位窗口字段，最大65535字节 |
| 1984 | Nagle算法（RFC 896） | 解决小包问题 |
| 1986 | Silly Window Syndrome缓解 | 接收方窗口小于MSS时不通告部分窗口 |
| 1992 | RFC 1323 | 正式提出窗口缩放（Window Scaling）与时间戳选项 |
| 2014 | RFC 7323 | 更新窗口缩放规范，Window Scaling上限14bit |

## 2. 核心原理

### 2.1 三个窗口的定义与关系

TCP流量控制涉及三个核心窗口概念：

| 概念 | 英文 | 含义 | 决定者 |
| --- | --- | --- | --- |
| 接收窗口 | RWND (Receive Window) | 接收方尚未读取、可接纳的字节数 | 接收方 |
| 通告窗口 | AWND (Advertised Window) | 通过ACK报文通告给发送方的RWND值 | 接收方 |
| 发送窗口 | SWND (Send Window) | 发送方允许一次在途发送的字节上限 | 发送方 |

逐个解释：

- **RWND**：接收方本地概念。假设接收缓冲区大小为 `RcvBuf`，已读取给应用的数据为 `Read`，已收到未确认的字节为 `InFlight`，则 `RWND = RcvBuf - InFlight`（近似）。
- **AWND**：接收方在每个ACK的TCP头部16位字段中填充RWND，通知发送方"你最多还能发多少字节给我"。
- **SWND**：发送方维护，受控于 `SWND = min(cwnd, AWND)`。其中cwnd来自拥塞控制（见第10篇）。当AWND=0时，SWND=0，发送方停止发送。

### 2.2 滑动窗口的工作机制

用图说明。假设MSS=100字节，发送方已发送字节0~499，其中0~299已ACK，300~499在途未确认：

```
发送方已发送字节序号:
0   100  200  300  400  500  600
|----|----|----|----|----|----|
 ^                 ^         ^
已确认           已发送未确认    可用窗口边界
 [   已确认区间   ][  在途数据  ][  可新发送区间  ]
```

滑动窗口是"三段式"：

1. **已发送并已确认**（窗口左侧滑出）
2. **已发送未确认**（窗口内部，等待ACK）
3. **未发送但允许发送**（窗口内可用空间）

当ACK到达，确认字节300，窗口右缘向右推进300字节：

```
0   100  200  300  400  500  600  700  800
|----|----|----|----|----|----|----|----|
                ^                 ^
     已确认至300    [ 在途 300-599 ][ 可发至800 ]
```

### 2.3 窗口缩放（Window Scaling）

TCP头部窗口字段只有16位，最大表示65535字节。但在高带宽时延乘积（BDP）网络中，如千兆网RTT=100ms，BDP = 1Gbps × 0.1s ≈ 12.5MB，远大于64KB。若不用窗口缩放，TCP吞吐量上限为 `65535 / RTT = 5.24Mbps`，完全无法利用链路。

RFC 7323 引入窗口缩放因子（Window Scale Factor），在TCP选项中携带：

```
TCP Option Kind=3 (Window Scale), Len=3, Shift count=7
```

实际通告窗口 = 16位窗口值 << shift count。shift最大14，因此最大窗口 = 65535 << 14 ≈ 1GB。

⚠️ 缩放因子只在**SYN报文**中协商，双方取各自宣告值，连接建立后不可再更改，除非重协商（RFC 7323 允许）。

### 2.4 零窗口与持续计时器

当接收方缓冲区满（RWND=0），它会通告 AWND=0。发送方收到零窗口后必须**停止发送**，进入"零窗口探测"循环：

```
接收方buff满->AWND=0->发送方暂停发送
   |                          |
   |    (接收方处理后)          |  启动Persist Timer
   | 发送窗口更新ACK(AWND>0)   |  定时发送1字节探测
   |<-------------------------|  直到收到窗口更新
   v                          v
收到窗口更新ACK -> 恢复发送     若探测ACK丢失则重发
```

- **持续计时器（Persist Timer）**：与重传计时器（RTO）不同，它的目的是防止"窗口更新ACK丢失后双方死锁"。若发送方只是等待更新而不做任何动作，接收方的窗口更新ACK一旦丢失，双方将永久僵持（死锁）。
- 持续计时器采用**指数退避**：首次约1.5秒，逐渐增大到60秒上限；即使探测包（含1字节数据）被丢弃也会继续，因为TCP不允许探测包被无限重传放弃。
- 探测包携带1字节数据并重新发送原始确认号，可强制接收方回复窗口值。

## 3. 详细知识点

### 3.1 发送窗口与接收窗口的完整状态机

发送窗口内部进一步分为四个区间：

```
                    发送窗口(SWND)
|_________________________________________________|
|  已确认段  |  已发送未确认段  |  可立即发送段  |  不可发送段  |
             ^               ^              ^
            SND.UNA         SND.NXT       SND.UNA+SWND
```

- **SND.UNA**：最早的未确认字节序号
- **SND.NXT**：下一个要发送的字节序号
- **SND.UNA + SWND**：发送窗口右缘
- 发送方收到ACK后，SND.UNA右移，窗口右缘随之右移。这就是"滑动"。

**窗口推进的三种可能**：

- ACK字节号 > SND.UNA：窗口**正向滑动**（normal）
- ACK窗口值 > 0：窗口**扩张**
- ACK窗口值 < 上次：窗口**收缩**（shrink，应避免——RFC 1122 建议接收方不要收缩窗口，可能导致混乱）

### 3.2 SWS（Silly Window Syndrome）与Nagle算法

**SWS**（呆滞窗口综合征）描述一种低效状态：发送方每次只发送几十字节的小段、接收方只通告小窗口，往返频繁，网络被小包浪费。

**接收方侧SWS避免（Clark's remedy）**：接收方不立即通告已释放的小窗口，而是等到TCP缓冲区至少空出1个MSS空间或缓冲区空一半以上，才通告新窗口。

**发送方侧SWS避免 = Nagle算法（RFC 896）**：

```python
# Nagle算法伪代码
if 有一分片正在传输(未确认):
    缓冲当前数据, 合并, 延迟发送
else:
    立即发送当前数据
```

即：**已确认的数据尽量一次性合并为满MSS的段发送；只有在前一个段的ACK到来时，才发送待缓冲数据**。代码示例（Python模拟）：

```python
class NagleSender:
    def __init__(self, mss=1460):
        self.mss = mss
        self.in_flight = False   # 是否有未确认段

    def on_ack(self):
        self.in_flight = False
        self.flush()

    def send(self, data: bytes):
        self.buf += data
        if not self.in_flight:
            self.flush()

    def flush(self):
        while len(self.buf) >= self.mss:
            chunk, self.buf = self.buf[:self.mss], self.buf[self.mss:]
            self.send_segment(chunk)
            self.in_flight = True
        if self.buf and not self.in_flight:
            self.send_segment(self.buf)
            self.buf = b''
            self.in_flight = True
```

**Nagle与延迟ACK的冲突**是经典坑：交互式应用（如SSH、Telnet按键）如果发送布尔值小包，Nagle延迟+接收方延迟ACK（Windows 200ms，Linux 40ms）会叠加出约200-400ms的交互延迟。解决：网络编程中交互式应用设置 `TCP_NODELAY` 关闭Nagle。

### 3.3 零窗口探测（Zero Window Probe）精讲

**触发条件**：发送方收到 AWND=0 的ACK。

**机制**：进入持续发送循环：

1. 启动Persist Timer（指数退避：初始约1.5s~2.0s，倍增至最大60s，上限约10-11次）
2. 到期后发送**1字节**的探测段（零窗口探测段，ZWP）
3. 探测段触发接收方必须回ACK，其中携带当前AWND
4. 若AWND仍为0，继续退避探测；若>0，恢复数据传输

**探测包抓包特征**（tcpdump）：

```typescript
14:03:22.111111 IP 10.0.0.1.54321 > 10.0.0.2.80: Flags [P.], seq 500:501, ack 200, win 1460, length 1
```

单字节载荷、win字段代表发送方对接收方的通告窗口。

```bash
# 抓取零窗口与探测包
tcpdump -i eth0 'tcp[13] & 16 != 0' -v   # PSH标志
# 或过滤出窗口=0的ACK
tcpdump -i eth0 'tcp[tcpflags] & (tcp-ack) != 0 and tcp[14:2] == 0'
```

**为何要探测**：因为窗口更新ACK（纯ACK，无数据、窗口>0）在TCP中**不会**被重传。如果接收方窗口变为0后发送窗口更新ACK，而发送方恰好不发任何段、也不启动持续计时器，这个更新ACK丢失会导致双方永久僵持——发送方不知道该恢复、接收方以为已通知。持续计时器是防止这种死锁的关键。

### 3.4 延迟ACK与窗口更新的交互

接收方通常采用延迟ACK策略（RFC 1122）：收到数据后不立即ACK，而是等待最多500ms（Windows 200ms、Linux 40ms）或累积2个段后合并ACK。这减少了ACK数量（每2个数据段1个ACK），但带来交互延迟问题。

**窗口更新（Window Update）**：纯ACK、无数据、通告窗口>0，用于通知发送方"有新空间了"。它单独发送，不携带数据。

**缺陷**：TCP对纯ACK不重传，因此窗口更新丢失是"无痕"的。这就是为什么设计零窗口探测。当接收方窗口从0恢复，它应该在下一个段或延迟ACK中捎带窗口更新；但最稳妥的是发送窗口更新纯ACK。

### 3.5 滑动窗口的吞吐量计算

基于窗口的吞吐量极限公式：

```
吞吐量 = SWND / RTT
```

- 若 SWND = 64KB（无窗口缩放），RTT = 100ms，则吞吐量 = 64000/0.1 = 640KB/s ≈ 5.24Mbps
- 若 SWND = 4MB（启用缩放），RTT = 100ms，则吞吐量 = 4M/0.1 = 40MB/s ≈ 320Mbps

**BDP（带宽时延乘积）**：`BDP = 链路带宽 × RTT`，它表示"一扇内有数据（在途）"所需的最小窗口。若窗口 < BDP，链路利用率不足；窗口 ≥ BDP 才能跑满带宽。

```python
# 计算BDP与所需窗口缩放因子
def bdp_and_scale(bandwidth_bps, rtt_s):
    bdp_bytes = bandwidth_bps * rtt_s / 8
    window_max = 65535
    scale = 0
    while (window_max << scale) < bdp_bytes and scale < 14:
        scale += 1
    return bdp_bytes, scale

print(bdp_and_scale(1e9, 0.1))    # 千兆网100ms -> (12500000.0, 8)
print(bdp_and_scale(100e6, 0.05)) # 百兆网50ms  -> (625000.0, 4)
```

## 4. 实战与示例

### 4.1 环境准备

使用Linux为主（若Windows需以WSL或虚拟机运行）： 


```bash
# 环境: Ubuntu 20.04+ / CentOS 7+
sudo apt update && sudo apt install -y tcpdump curl iproute2
sysctl net.ipv4.tcp_window_scaling   # 确认窗口缩放开启 -> 1
```

### 4.2 观察滑动窗口增长（窗口缩放生效）

**操作**：从客户端向本机Python HTTP服务器发起大文件请求，同时用tcpdump抓包。

```bash
# 终端1: 启动HTTP服务器
python3 -m http.server 8080 --bind 127.0.0.1 &

# 终端2: 抓包
sudo tcpdump -i lo -nn -S 'tcp port 8080' -w /tmp/window.pcap
```

**验证**：用tshark查看window值随时间增长：

```bash
tshark -r /tmp/window.pcap -Y 'tcp.port==8080' -T fields -e tcp.window_size_value -e tcp.window_size_scalefactor -c 50
```

预期看到：窗口值（16位段内）不变（受限于缩放），但实际窗口大小 = 值×2^shift。初始握手时双方协商shift count（如7），此后会话期间实际窗口 = 值<<7。

### 4.3 构造零窗口并抓取探测包

用Python socket写一个"假接收方"：收到数据后通告窗口为0，观察发送方停止发送、周期探测。

```python
import socket, time

def recv_with_zero_window():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)  # 极小缓冲
    s.bind(('0.0.0.0', 9999))
    s.listen(1)
    conn, addr = s.accept()
    print(f"收到连接 {addr}")
    time.sleep(30)   # 不读取=>缓冲填满=>通告0窗口
    conn.close()

recv_with_zero_window()
```

对应发送方：

```python
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
s.connect(('127.0.0.1', 9999))
s.send(b'x' * 65536)  # 一次性填满接收缓冲
```

抓包观察：

```
# 窗口缩到0后, 每 ~1.5s~60s 出现一次 length=1 的探测段
tcpdump -i lo -nn -A 'tcp port 9999' | grep -E 'seq|win'
```

### 4.4 用tc模拟丢包观察窗口更新与死锁排查

使用Linux tc（traffic control）模拟延迟和丢包，观察窗口对性能影响：

```bash
# 50ms延迟 + 1%随机丢包
sudo tc qdisc add dev eth0 root netem delay 50ms loss 1%
# 测试iperf3吞吐
iperf3 -c 10.0.0.2 -t 10
# 清理
sudo tc qdisc del dev eth0 root
```

对比开启/关闭窗口缩放的吞吐差异：

```bash
# 关闭窗口缩放
sudo sysctl -w net.ipv4.tcp_window_scaling=0
iperf3 -c 10.0.0.2 -t 10
# 恢复
sudo sysctl -w net.ipv4.tcp_window_scaling=1
```

### 4.5 报错与解决

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| `tcpdump: no suitable device found` | 权限不足/设备未指定 | 加 `sudo`，确认 `-i` 网卡名 |
| 窗口值看起来<64K不增长 | 忘了看缩放因子 | 用 `tcp.window_size_scalefactor` 字段，实际窗口=value<<shift |
| 传输卡死、无进展迹象 | 零窗口持久僵持 | 查看双方是否在交换ZWP；检查应用是否停止读socket |
| Nagle+delayACK导致SSH卡 | 交互应用Nagle冲突 | 设置 `TCP_NODELAY` |

## 5. 常见坑与避坑指南

1. **混淆流量控制与拥塞控制**：流量控制是"接收方说慢点"，拥塞控制是"网络说慢点"。实际发送窗口 = `min(cwnd, rwnd)`，两者都会限制发送。排查瓶颈时要同时看两个窗口，很多新手只盯rwnd却忽略cwnd。
2. **窗口缩放只在SYN中协商**：Wscale一旦在三次握手中确定就固定。若抓包发现某连接Wscale=0，则该连接最高窗口=64KB，高速传输必然受限。诊断高带宽链路吞吐不足时先检查这个。
3. **零窗口更新ACK不可靠**：纯ACK不重传，窗口更新可能"无痕丢失"。这是设计使然，也解释了为何需要Persist Timer。安全上，攻击者可以利用这一点进行DoS（见下）。
4. **Nagle与延迟ACK叠加的延迟**：交互式和实时应用（SSH、游戏、RPC）必须 `TCP_NODELAY`，否则200-400ms延迟灾难。但同时，大批量传输不要滥用NODELAY，否则碎片化。
5. **窗口收缩（Window Shrink）**：不建议接收方动态收缩已通告窗口，会导致发送方数据超窗、行为不确定。RFC 1122规定接收方不应收缩窗口。
6. **安全坑：零窗口DoS与窗口操纵**：
   - 攻击者可伪造接收方通告AWND=0（发起方受害）或大量创建零窗口连接占资源，形成DoS。
   - 中间人可篡改ACK中的窗口字段，任意增大/减小窗口：增大导致接收缓冲区溢出、数据丢失；减小导致吞吐下降。
   - 某些恶意实现利用窗口=0并拖延回复，变相让受害连接"假死"且不触发RST（探测包仍会被响应），难以发现。

## 6. 知识关联

- [[07-TCP三次握手四次挥手：逐包状态分析]] —— 滑动窗口参数（SYN携带Wscale、MSS）在握手阶段协商，与本文衔接
- ‹WIKILINK:ENC:08-TCP%E7%8A%B6%E6%80%81%E6%9C%BA%E4%B8%8ETIME*WAIT%E8%B0%83%E4%BC%98› —— 连接生命周期与窗口收尾，探讨大窗口环境的TIME*WAIT资源占用
- [[10-TCP拥塞控制：从Reno到BBR算法演进]] —— cwnd与rwnd共同决定发送窗口，拥塞控制是另一大支柱
- [[01-OSI与TCP-IP分层模型：封装解封装全流程]] —— 传输层在整个栈中的位置
- [[16-抓包实战：tcpdump过滤与Wireshark协议还原]] —— 如何用tcpdump/Wireshark观察window字段与ZWP

## 7. 参考资料

| 类型 | 资源 | 说明 |
| --- | --- | --- |
| RFC | [RFC 793 - Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793) | TCP基础，滑动窗口原始定义 |
| RFC | [RFC 1122 - Requirements for Internet Hosts](https://www.rfc-editor.org/rfc/rfc1122) | 延迟ACK、窗口收缩规则、SWS规避 |
| RFC | [RFC 896 - Congestion Control in IP/TCP](https://www.rfc-editor.org/rfc/rfc896) | Nagle算法 |
| RFC | [RFC 7323 - TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc7323) | 窗口缩放、时间戳、PAWS |
| 书 | 《TCP/IP Illustrated, Vol.1》W. Richard Stevens（第20章） | 滑动窗口权威讲解 |
| 书 | 《Computer Networking: A Top-Down Approach》Kurose & Ross | 教学视角的窗口/丢包分析 |
| 工具 | `ss -tin`、`nstat`、`tcpdump`、`tshark` | 内核TCP统计与抓包审计 |
