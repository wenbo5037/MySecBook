---
title: "TCP拥塞控制：从Reno到BBR算法演进"
category: "00-基础通用/03-计算机网络"
tags: [TCP拥塞控制, Reno, CUBIC, BBR, 慢启动, 拥塞避免]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# TCP拥塞控制：从Reno到BBR算法演进

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 拥塞控制是发送方根据网络中间设备拥塞状况动态调节发送速率（cwnd）的机制，与流量控制形成对照 |
| 核心用途 | 避免网络拥塞崩溃（congestion collapse）；公平共享带宽；最大化链路利用率 |
| 关键参数 | 拥塞窗口cwnd、慢启动阈值ssthresh、RTT、RTO、丢包事件、AIMD、ECN标记 |
| 算法谱系 | Tahoe → Reno → NewReno → CUBIC（丢包损失型）；Vegas → BBR/BBRv2（时延/带宽型） |
| 常见风险 | 拥塞崩溃、攻击者ACK注入虚增cwnd、缓冲区膨胀BufferBloat、TCP流量公平性被打破 |
| 关联知识 | [[09-TCP流量控制：滑动窗口与零窗口探测]]、[[07-TCP三次握手四次挥手：逐包状态分析]]、[[16-抓包实战：tcpdump过滤与Wireshark协议还原]] |

## 1. 概述

### 1.1 技术定义

TCP**拥塞控制**（Congestion Control）是指发送方通过一系列算法，动态探测并适应网络瓶颈带宽，从而避免把过多的数据注入网络造成中间路由器队列溢出、大量丢包、重传激增、最终吞吐量反而暴跌（**拥塞崩溃**）的机制。

拥塞控制与流量控制的区别是关键：

| 维度 | 流量控制（第09篇） | 拥塞控制（本文） |
|------|--------------------|------------------|
| 参与者 | 端到端：接收方主导 | 端到端但感知网络：发送方主导 |
| 关注的资源 | 接收方缓冲区 | 网络链路的瓶颈带宽与队列 |
| 信号 | 通告窗口AWND | 丢包、RTT、ECN标记、显式拥塞通知 |
| 控制变量 | rwnd | cwnd |
| 最终窗口 | `SWND = min(cwnd, rwnd)` | 见左 |

### 1.2 知识体系定位

拥塞控制是TCP可靠传输三大支柱（流量控制、拥塞控制、重传）中与**网络整体稳定性**关系最密切的一环。它决定了互联网在过载时是"排队"还是"崩溃"。安全攻防中，对拥塞控制的操纵可被用于拒绝服务、抢占带宽、隐蔽通信。

### 1.3 核心应用场景

- 数据中心（DCTCP）、广域网（CUBIC/BBR）性能优化
- 大文件传输、CDN、流媒体体验优化
- 网络诊断：分析丢包率、RTT抖动、带宽利用率
- 攻击检测：攻击者虚增cwnd放大自身流量、拥塞攻击拖垮网络

### 1.4 技术演进简史

| 时间 | 里程碑 | 说明 |
|------|--------|------|
| 1986 | 互联网拥塞崩溃事件 | 现代学者Van Jacobson在LBL发现"路由器丢包→重传→更丢"的恶性循环 |
| 1988 | Jacobson论文《Congestion Avoidance and Control》 | Tahoe算法诞生 |
| 1990 | Reno | 新增快速恢复（Fast Recovery） |
| 1996 | NewReno（RFC 2582→RFC 3782→RFC 6582） | 改进多包丢失场景，避免RTO停滞 |
| 1999 | Vegas | 基于RTT/时延而非丢包预测拥塞（未能普及） |
| 2008 | CUBIC | Linux默认算法，基于三次函数，高带宽长时延友好 |
| 2016 | BBR | Google，基于带宽与时延的模型算法，广域网提升巨大 |
| 2021 | BBRv2 | 引入丢包与ECN协方差感知，修正BBRv1对拥塞无响应的缺陷 |

## 2. 核心原理

### 2.1 拥塞崩溃的根源

拥塞崩溃（Congestion Collapse）的机制链条：

```
网络某个瓶颈队列满
   ↓ 路由器开始丢包
   ↓
发送方等待RTO超时 并重传
   ↓
发送方不知道拥塞, 仍以最大速率重传（甚至更激进）
   ↓
更多包注入 → 队列更满 → 更多丢包 → 更多重传
   ↓
吞吐量急剧下降到近乎崩溃, 而重传流量占用全部带宽
```

Jacobson的洞察：**必须把丢包当作网络拥塞的信号**，并且发送方要主动"退避"而不是盲目重传。2008年的著名案例（Stampede / 拥塞崩溃再次出现于某些自研拥塞控制不完善的场景）证明这个问题的现实性。

### 2.2 拥塞窗口（cwnd）与三个状态

发送方维护拥塞窗口 `cwnd`，与接收窗口 `rwnd` 共同决定发送窗口：

```
SWND = min(cwnd, rwnd)
```

初始阶段（Linux默认 initcwnd=10×MSS，RFC 6928）：

```
cwnd = 10 * MSS
```

拥塞控制按**状态机**运行，标准TCP（Reno/NewReno/CUBIC）约四个阶段：

- **慢启动（Slow Start）**：cwnd每次收到ACK翻倍（指数增长）
- **拥塞避免（Congestion Avoidance）**：cwnd每轮RTT线性+1×MSS（加法增长）
- **快速重传/快速恢复（Fast Retransmit / Fast Recovery）**：连续3个重复ACK触发，cwnd减半
- **超时重传（RTO）**：超时触发，cwnd归1，ssthresh 减半

### 2.3 AIMD 图示

AIMD（Additive Increase Multiplicative Decrease，加性增、乘性减）是拥塞控制的经典哲学：

```
cwnd
  ^
  |                    ____________
  |            ________/  出现拥塞↓(乘性减)
  |        ___/
  |     __/              加性增(+1MSS/RTT)
  |   _/
  | _/
  +------------------------------------------> time
   \          拥塞事件           拥塞事件
    \__________/\________/\____
```

### 2.4 慢启动与ssthresh

```python
# 伪代码: 慢启动与拥塞避免
cwnd = 1 * MSS      # 或 initcwnd = 10*MSS
ssthresh = 65535    # 或按系统设置的初值

def on_ack(rtt_ms):
    global cwnd
    if cwnd < ssthresh:
        cwnd *= 2            # 慢启动: 指数增长
    else:
        cwnd += MSS          # 拥塞避免: 线性增长

def on_loss():
    global cwnd, ssthresh
    ssthresh = max(cwnd // 2, 2 * MSS)
    # 超时: cwnd=1*MSS, 重传后重新慢启动
    # 快速重传: cwnd = ssthresh (或 Reno 减半后加法)
```

## 3. 详细知识点

### 3.1 Tahoe 与 Reno

**Tahoe（1988）**：
- 每个拥塞事件（超时或3个重复ACK）都导致 cwnd=1，进入慢启动
- 问题：3个重复ACK本来可以确认为"网络仍通"，却被降为1再慢启动，浪费吞吐

**Reno（1990）关键改进 —— 快速恢复**：

当收到3个重复ACK（triple-duplicate ACK）：
1. 快速重传丢失段
2. ssthresh = cwnd/2
3. **cwnd = ssthresh**（不减到1）→ 进入快速恢复，跳过慢启动
4. 每再收到一个重复ACK，cwnd += 1×MSS（相当于"假装"数据已离开网络）
5. 收到新ACK，退出快速恢复，进入拥塞避免

```python
def on_triple_dup_ack():
    # 快速重传+快速恢复 (Reno)
    global cwnd, ssthresh
    ssthresh = max(cwnd // 2, 2 * MSS)
    cwnd = ssthresh
    fast_retransmit()

def on_dup_ack_during_recovery():
    global cwnd
    cwnd += MSS          # 加性增长模拟窗口滑开
```

Reno 的缺陷：一个窗口内丢失**多个包**时，只触发一次快速重传，其余丢失段要等超时，导致停滞。这正是 NewReno 解决的问题。

### 3.2 NewReno（改进多包丢失）

NewReno（RFC 6582）改进了快速恢复逻辑：在没有新数据ACK之前，持续本RTT内"回传"部分ACK（partial ACK）时，不退出快速恢复，而是重传接下来缺失的段。只有当收到确认**原窗口全部数据**的ACK时，才退出快速恢复。

```
完整RTT内丢失段A、B、C:
- 收到3dup: 重传A, 进入快速恢复
- 收到partial ACK(确认A): 重传B
- 收到partial ACK(确认B): 重传C
- 收到确认窗口全部数据的ACK: 退出FR, 进入CA
```

NewReno 显著减少多包丢失时的RTO停滞，成为标准Linux/BSD默认实现的基础之一。

### 3.3 CUBIC（当前Linux默认）

CUBIC 抛弃了"线性"拥塞避免，改用**三次函数**（cubic function）控制cwnd增长，尤其适合高带宽长时延（BDP大）网络：在距离上次拥塞事件较近时缓慢增长（靠近瓶颈避免再次拥塞），较远时快速增长（探索更高带宽）。

三次函数模型：

```
W(t) = C * (t - K)^3 + W_max
```

- `W_max`：拥塞事件前的窗口值
- `C`：缩放常数（默认0.4），控制增长曲线陡峭度
- `K`：恢复到W_max所需的时间
- `t`：距上次拥塞事件的时间

```
cwnd
  ^
  |      W_max→ (平台期)
  |   ____/```````\___
  |  /               \   CUBIC: 接近W_max时增速放缓(避免振荡),
  | /                 \  远离W_max时增速加快(快速探索)
  +---------------------------> time
      拥塞事件
连载演进:  Q逻辑 W_CUBIC 与 TCP友好区(W_tcp)取max
```

特点：
- **TCP友好性**：与标准Reno/NewReno竞争时受"友好区"约束，不抢占普通流量
- **不依赖RTT**：增长算法与RTT无关，适合跨地区/卫星链路
- 在Linux内核 `net.ipv4.tcp_congestion_control=cubic`（默认）

验证当前算法：
```bash
sysctl net.ipv4.tcp_congestion_control   # 输出 cubic 或 bbr
cat /proc/sys/net/ipv4/tcp_available_congestion_control
```

### 3.4 BBR：带宽时延模型

**BBR（Bottleneck Bandwidth and Round-trip propagation time）**由Google于2016年开源，与前面"丢包即拥塞"的哲学**根本不同**。

核心思想：带宽与时延是网络的两种"物理量"，用它们直接构建模型，而不依赖丢包作为唯一的拥塞信号。

两个核心指标：
- **BtlBw（瓶颈带宽）**：路径最窄处每单位时间可传递的字节数（最大传输速率）
- **RTprop（往返传播时延）**：无队列时RTT的最小值

BBR 将以"追最大上传速率"为目标。它通过周期性探测BtlBw与RTprop：

- **带宽探测（Drain与ProbeBW阶段）**：先以更高速率发送探测更高带宽（增长BtlBw估计），若任回显估计不准则回退Drain排空队列
- **时延探测（ProbeRTT）**：周期性收缩到4×MSS维持200ms，测量最小RTT，避免在检测队列时测量到排队延迟

```
BBR状态机:
Startup -> Drain -> ProbeBW <-> (周期性) ProbeRTT
   ↑          ↓
   |____拥塞____|
```

BBR相对CUBIC的优势（实测）：在标准高带宽广域网中吞吐可提升2-27倍，同时降低排队时延（BufferBloat问题）。挑战：
- 与丢包型（Reno/CUBIC）流量共存时可能"霸道"占带宽（公平性问题）
- BBRv1对突发拥塞（如短时BufferBloat）反应迟钝

**BBRv2（2021）**：严格增加对丢包与ECN的响应（协方差感知），维持公平性，避免过度占用队列。

### 3.5 快速重传、快速恢复与ECN

**快速重传**：收到3个连续重复ACK，即使未等RTO超时也立即重传丢失段。前提：接收方对乱序段发送ACK。

**SACK（Selective Acknowledgment，RFC 2018）**：允许接收方精确告知发送方"哪些段收到了、哪些没收到"，避免NewReno盲目重传。几乎所有现代TCP栈默认开启。

**ECN（Explicit Congestion Notification，RFC 3168）**：让路由器在队列将满时**标记**而不是丢弃数据包，发送方据此减小cwnd。流程：

```
发送方: ECN-Capable(ECT)标志
  ↓
路由器队列高水位: 将CE(Congestion Experienced)位置1 (而非丢弃)
  ↓
接收方: 回复带ECE标志的ACK
  ↓
发送方: 进入拥塞避免, 用CWR标志告知已响应
```

ECN避免了丢包这一"昂贵"的拥塞信号。安全上：ECN也可被中间人滥用（误标记/撤销标记）干扰拥塞状态。

## 4. 实战与示例

### 4.1 环境准备

```bash
# Ubuntu 22.04+ / 内核支持
sudo apt install -y iperf3 tcpdump iproute2 ethtool
# 查看当前拥塞控制算法与可选项
sysctl net.ipv4.tcp_congestion_control
cat /proc/net/tcp_available_congestion_control
```

### 4.2 切换并对比 Reno/CUBIC/BBR 吞吐

```bash
# 加载模块（如有需要）
sudo modprobe tcp_bbr
# 切换全局算法
sudo sysctl -w net.ipv4.tcp_congestion_control=reno
# 在客户端测吞吐
iperf3 -c 10.0.0.2 -t 20
# 依次换 cubic / bbr 重复对比
sudo sysctl -w net.ipv4.tcp_congestion_control=cubic
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
# 记录三次的 Bandwidth 指标对比
```

预期：在有一定丢包（0.1%~1%）的高延迟链路，BBR > CUBIC > Reno 明显。

### 4.3 模拟丢包观察慢启动与拥塞避免

```bash
# 用tc加入延迟与丢包
sudo tc qdisc add dev eth0 root netem delay 40ms loss 0.5%
# 抓CWND变化 (Linux 用 ss -tin 可看 cwnd)
ss -tin | grep -E 'cwnd|rtt|MSS'

# 没有丢包时, 观察慢启动指数增长随后进入线性增长
# 用tcpdump抓ACK, 用tshark看 cwnd 字段
sudo tcpdump -i eth0 -nn -w /tmp/cong.pcap
tshark -r /tmp/cong.pcap -T fields -e tcp.analysis.bytes_in_flight \
       -e tcp.analysis.ack_rtt | head
```

### 4.4 ECN 启用与验证

```bash
# Linux 默认开启 ECN 接收/关闭发送
sudo sysctl -w net.ipv4.tcp_ecn=1   # 1=发送方支持ECN, 2=接收方也支持
# 用iperf3 + tcpdump 观察 ECE 标志
sudo tcpdump -i eth0 'tcp[13] & 0xc0 != 0' -v   # ECE(bit6)/CWR(bit7)
```

### 4.5 安全实验：观察恶意ACK注入对cwnd的影响

原理：合法ACK确认N字节会推进SND.UNA；若攻击者伪造ACK确认未发送的字节，发送方的cwnd可能被虚增（发送更多数据），或被诱导提前推进窗口（流量放大）。演示用scapy构造伪造ACK（仅授权实验室环境）：

```python
from scapy.all import *
# 伪造ACK确认seq=100000 (未发送), 使发送方认为窗口滑开
pkt = IP(src=spoof_server, dst=real_server) / \
      TCP(sport=server_port, dport=client_port, seq=X,
          ack=100000, flags='A', window=65535)
send(pkt)
```

观察发送方是否因此发送更多数据（流量放大），这也是"ACK split"/"ACK injection"攻击的原理基础。

### 4.6 报错与解决

| 现象 | 原因 | 解决 |
|------|------|------|
| `modprobe: FATAL: Module tcp_bbr not found` | 内核未编译BBR | 换新内核，或Ubuntu官方内核默认有 |
| iperf3 无法连接 | 防火墙/UDP丢包 | 确认用 `-P` 并发与 `-w` 设置窗口 |
| 切换cc不生效 | sysctl 全局 | 单独连接级 `ip tcp_metrics` 或 `setsockopt TCP_CONGESTION` |
| cwnd不增长 | 内核tcp_congestion不同 | 查看`socket`级 `ss -tin` 的 `cwnd` |

## 5. 常见坑与避坑指南

1. **混淆丢包与拥塞**：丢包不都是拥塞——无线信道误码、攻击丢包、黑洞路由都会丢。CUBIC/BBR都非完美。分析时要结合丢包率与RTT共同判断是阈值问题还是拥塞。

2. **BufferBloat误区**：把"带宽够、延迟爆"一并归咎于拥塞。实际是路由器队列过大（bufferbloat），CUBIC直到填满队列才丢包，RTT被拉爆。解法是AQM（如CoDel/fq_codel）而非简单调cwnd。

3. **BBR ≠ 万能**：BBRv1在跨ISP/移动网络等"公平性敏感"场景可能抢占其他流。生产上行若非测试环境，慎用全局bbr，可per-socket启用。

4. **initcwnd 过大会导致突发**：`initcwnd=10` 虽然加快启动，但突发注入易瞬时打满队列。对弱网/移动端建议谨慎调。

5. **安全坑：恶意ACK/CWND操纵**：攻击者通过在握手中发送未签发ACK、或定期发送大ACK，虚增受害方cwnd，放大其自身吞吐、占用更多带宽（"拥塞放大"）。检测：检查ACK确认的字节数是否与实际发送不符、是否存在无数据段的异常大量ACK。

6. **ECN被中间人干扰**：中间人可撤销CE标记（隐藏拥塞，导致受害发送方超载）或伪造CE标记（误导减小cwnd）。严格传输不能用无保护的ECN，应结合TLS等加密。

7. **公平性测量陷阱**：测"算法是否公平"要用同比条件（相同RTT/丢包），否则BBR vs CUBIC的对比不公平。跨云厂商环境差异大，务必控制变量。

## 6. 知识关联

- [[09-TCP流量控制：滑动窗口与零窗口探测]] —— cwnd与rwnd协同决定实际发送窗口，本文是其姊妹篇
- [[07-TCP三次握手四次挥手：逐包状态分析]] —— InitCWND、MSS协商与拥塞窗口初值建立
- [[08-TCP状态机与TIME_WAIT调优]] —— 连接生命周期与拥塞状态重置
- [[16-抓包实战：tcpdump过滤与Wireshark协议还原]] —— 用Wireshark可视化cwnd/RTT/重传
- [[01-OSI与TCP-IP分层模型：封装解封装全流程]] —— 传输层在协议栈的定位

## 7. 参考资料

| 类型 | 资源 | 说明 |
|------|------|------|
| 论文 | Van Jacobson, "Congestion Avoidance and Control" (SIGCOMM 1988) | Tahoe算法奠基之作，必读 |
| RFC | RFC 5681 - TCP Congestion Control | Reno/NewReno正式规范 |
| RFC | RFC 6582 - The NewReno Modification | NewReno快速恢复改进 |
| RFC | RFC 8312 - CUBIC | CUBIC算法规范 |
| RFC | RFC 8961/RFC 9002 | 拥塞控制更新与QUIC拥塞控制 |
| 论文 | Neal Cardwell et al., "BBR: Congestion-Based Congestion Control" (ACM Queue 2016) | BBR理论与动机 |
| 论文 | "BBRv2: A Model-based Congestion Control" (IETF) | BBRv2介绍 |
| RFC | RFC 2018 - SACK、RFC 3168 - ECN | 选择性确认与显式拥塞通知 |
| 书 | 《TCP/IP Illustrated Vol.1》Stevens | 拥塞控制经典章节 |
| 视频/课程 | "TCP Congestion Control" by Neal Cardwell (YouTube) | BBR作者本人讲解 |
| 工具 | `ss -tin`、`nstat`、`iperf3`、`tc` | 测量与仿真工具 |
