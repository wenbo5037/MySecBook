---
title: "路由协议概览：RIP-OSPF-BGP"
category: "00-基础通用/03-计算机网络"
tags: [路由协议, RIP, OSPF, BGP, 距离矢量, 链路状态, 路径矢量, 前缀劫持, RPKI, AS-path]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# 路由协议概览：RIP-OSPF-BGP

> **合规声明**：本文涉及的攻防技术仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 路由协议分类 | 距离矢量(RIP)、链路状态(OSPF)、路径矢量(BGP) |
| RIP | UDP 520端口，最大跳数15，跳数≥16=无穷，30s更新 |
| OSPF | 组播224.0.0.5/224.0.0.6，Hello 10s，Dijkstra算法，区域(Area)划分 |
| BGP | TCP 179端口，AS-path属性，eBGP/iBGP，路径矢量 |
| 距离矢量 | "我告诉你我听到的"，只交换整张路由表摘录 |
| 链路状态 | "我告诉你我的邻居"，全网一致同步DB，自己算最短路径 |
| 路径矢量 | 记录完整AS路径，防环路，可策略过滤 |
| 安全事件 | AS7007事件(1997)、巴基斯坦YouTube封禁(2008) |
| 防御机制 | RPKI、前缀过滤、AS-path过滤、BGP劫持监测 |
| 关联知识 | [[01-OSI与TCP-IP分层模型：封装解封装全流程]], [[04-IP协议头逐字段解析与分片重组]] |

## 1. 概述

### 1.1 技术定义

**路由协议**是运行在路由器上的、用于自动交换网络可达信息、构建路由表（转发信息库）的协议。路由器据此决定将IP包交给哪个下一跳。

三大类：
- **距离矢量（Distance Vector）**：典型为RIP。路由器只向邻居传递"到目的地的距离（跳数/度量）"和"从哪个接口学来"的信息，基于Bellman-Ford算法。
- **链路状态（Link-State）**：典型为OSPF。路由器广播自己的链路状态（连接了哪些邻居、链路代价），全网统一LSDB后各自运行Dijkstra算法计算最短路径树。
- **路径矢量（Path-Vector）**：典型为BGP。与传统距离矢量不同，路径矢量在路由信息中携带完整AS路径（AS-path）来防环路并支持策略控制，是互联网域间路由的事实标准。

### 1.2 知识体系定位

**IGP（Interior Gateway Protocol，内部网关协议）**：AS内部运行（如RIP、OSPF、IS-IS）
**EGP（Exterior Gateway Protocol，外部网关协议）**：AS之间运行（如BGP）

路由协议与现代网络攻防高度相关：
- BGP劫持、前缀劫持是国家级/组织级攻击（巴基斯坦YouTube事件）

- 路由协议本身无强认证，攻击者可注入伪造路由信息

- 了解路由选择才能理解"黑洞路由""路由泄露"等运维/安全术语

### 1.3 核心应用场景

- **园区/数据中心内部**：OSPF或IS-IS建立IGP
- **小型网络**：RIP（很少在生产用，多用于学习）
- **跨AS互联**：运营商/企业出口用eBGP
- **云与CDN**：Anycast（多个相同前缀宣告到不同地点）依赖BGP
- **安全运维**：路由过滤、RPKI、BGP日报监测

### 1.4 技术演进简史

| 时间 | 协议 | 意义 |
|------|------|------|
| 1982 | RIP 1（RFC 1058） | 首个广泛使用的动态路由协议 |
| 1988 | OSPF 1 | 链路状态思想的引入 |
| 1989 | OSPF 2（RFC 1247） | 链路状态标准定型 |
| 1989 | BGP 3 | 域间路由雏形 |
| 1995 | BGP 4（RFC 1771） | 现代BGP（支持CIDR） |
| 1997 | AS7007事件 | 前缀劫持影响全球Internet |
| 1998 | OSPF 2 RFC 2328 | 现行版本 |
| 2008 | 巴基斯坦YouTube事件 | BGP劫持典型案例 |

## 2. 核心原理

### 2.1 距离矢量：RIP

**思想**：每个路由器维护到自己已知目的地的距离；通过周期性与邻居交换路由表（距离向量），逐步收敛。Bellman-Ford算法。

```
R1 --- R2 --- R3 --- R4

R1的路由表(部分):
  目的    下一跳   跳数(度量)
  192.0.2.0/24   直连     0
  203.0.113.0/24  R2      1
  198.51.100.0/24 R2      2   (经R2转发)

R1周期性地(每30秒)把整张表告诉R2、R3...
R2收到后: 若R1声称"到达X需要2跳"，则R2经R1到X=3跳，若比表中更优则更新
```

**RIP特点**：

| 维度 | 说明 |
|------|------|
| 传输 | UDP, 端口520 |
| 更新频率 | 每30s整表广播；失效超时180s；垃圾回收120s |
| 度量 | 仅跳数 |
| 最大网径 | 15跳（16=不可达，无穷大） |
| 环路抑制 | 水平分割(不把从X学来的路由再告诉X)、毒性逆转、触发更新 |
| 版本 | RIPv1(广播)、RIPv2(多播224.0.0.9+子网掩码+明文认证)、RIPng(IPv6) |

**安全要点**：
- RIPv1无认证，可被伪造路由注入
- RIPv2的认证基于共享密钥（MD5），易被暴力/拦截
- 攻击者可宣告"到我目的一切距离为1"，导致所有流量被吸到攻击路由器

### 2.2 链路状态：OSPF

**思想**：每台路由器用Hello发现邻居，把自己直接相连的链路状态（邻居+代价）泛洪(LSA Flooding)到全区域；每台路由器都拥有完整一致的LSDB，再运行Dijkstra计算最短路径。

```
   +---------+      +---------+      +---------+
   |   R1    |      |   R2    |      |   R3    |
   |  Area 0 |------|         |------|         |
   +---------+      +---------+      +---------+
       ||              ||
   LSA泛洪: R1给所有人发"我与R2直连,代价1,代价..."
   每台都有完整LSDB:
   R1: {R1-R2:1, R1-R3:1, R2-R3:1}
   R2: {R1-R2:1, R1-R3:1, R2-R3:1}
   R3: {R1-R2:1, R1-R3:1, R2-R3:1}
   每台各自Dijkstra算最短路径树
```

**OSPF关键参数/行为**：

| 维度 | 说明 |
|------|------|
| IP协议 | IP协议号89（非UDP/TCP） |
| 组播 | 224.0.0.5（所有OSPF路由器）、224.0.0.6（指定路由器DR/BDR） |
| Hello | 默认10s（P2P/broadcast），40s死亡 |
| 度量 | 代价=接口带宽倒数参考(如10^8/带宽) |
| 收敛 | 秒级（靠LSA泛洪+SPF重算） |
| 区域 | Area 0(骨干)+非骨干(必须连Area0)；ABR/ASBR |
| LSA类型 | Type1路由器LSA、Type2网络LSA、Type3汇总LSA、Type4 ASBR汇总、Type5外部LSA |
| 认证 | 可选明文/MD5（area authentication） |

**Dijkstra算法（简化）**：

```
以R1为根的SPF树（示例拓扑 R1-R2(1), R1-R3(1), R2-R3(1)）:
   初始化: dist={R1:0, R2:inf, R3:inf}, 集合U=未定
   1. 取dist最小的R1, 松弛: R2->1, R3->1
   2. 取Dist最小R2, 松弛: R1(不更新), R3: 1(R2->R3=1)+1=2 >1 保持
   3. 取R3, 松弛: R2经R3=2>1 保持
   完全遍历 → 得到每个节点的最短距离

   结果: R1->R2(1), R1->R3(1), R1->R2->R3(2, 不选最优路径)
```

**OSPF安全威胁**：
- 无尽LSA（LSDB轰炸/拓扑震荡）：伪造大量LSA填满LSDB或频繁改变拓扑 → CPU/内存耗尽
- 泛洪弱化：攻击者进入一个area即可注入LSA
- 无认证区域：任何人加入可注入路由

### 2.3 路径矢量：BGP

**思想**：**每个AS是一个自治系统（拥有独立路由策略）**。BGP在AS之间传播路由，每条路由携带**完整AS路径（AS-path）**，防止环路；同时携带多种属性（如LOCAL_PREF、MED、Community）供策略决策。

```
AS100 --- eBGP --- AS200 --- eBGP --- AS300
  |                    |                   |
AS路径: AS100为10.0.0.0/24宣告:
  到达10.0.0.0/24的路径: 100
AS200学到: [100], 下一跳=AS100的接口
AS200再给AS300宣告: [200 100] (追加自己的AS)
AS300学到全路径: 100 200 → 明确无环
```

**BGP关键属性**：

| 属性 | 类型 | 说明 | 影响决策 |
|------|------|------|---------|
| AS-path | Well-known mandatory | 累计经过的AS，防环 | 同时是决策因素之一 |
| Next-hop | Well-known mandatory | 下一跳IP | 决定下一跳 |
| Origin | Well-known mandatory | IGP/EGP/Incomplete | 优先级低 |
| LOCAL_PREF | Well-known discretionary | 本AS内传播的出站偏好 | 高者优先 |
| MED | Optional non-transitive | 在AS间传递的入口偏好 | 低者优先 |
| Community | Optional transitive | 打标供策略使用 | 由策略处理 |
| Atomic-Aggregate / Aggregator | - | 聚合/防循环 | 特殊 |

**BGP决策过程（简化顺序）**：
1. 丢弃下一跳不可达的
2. 取LOCAL_PREF最高
3. AS-path最短（不含本地路径）
4. Origin最优先（IGP>EGP>Incomplete）
5. MED最低（仅同一AS邻居比较）
6. eBGP优于iBGP
7. IGP度量最小到达下一跳
8. 路由器ID最小/最老

**BGP环路防护**：
- eBGP：收到AS-path中包含本AS号的 → 拒绝
- iBGP：**防环采用"不把从iBGP学到的路由再通告给其他iBGP邻居"（全互联或路由器反射器）**

**语音/连接**：
- eBGP：AS之间，默认TTL=1（需直连或重写TTL），使用多跳（TTL>1）时需指定
- iBGP：AS内，自身AS内传递，用IGP相互可达

## 3. 详细知识点

### 3.1 RIP具体细节

**RIPv2报文格式**：

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Command (1=请求,2=响应) |  Version (2) |        Unused        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Address Family (2)      |        Route Tag (2)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Subnet Mask                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Next Hop                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Metric (跳数)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**RIP环路问题与对策**：

```
R1---R2 (断链场景)        原状态: R1->R2:1, R2->R1:1

R2检测到与网络X断链 → 把到X标记为16(无穷)
R2 30s更新: "到X=16"
R1 同时广播: "到X=2"  (它从R2学来, 认为仍可达)
若水平分割未开 → R2收到R1的"到X=2"，更新为3
之后R1/R2互相对话: 路由在两者间"计数到无穷"→ 直到16
收敛极慢(可达分钟级)
```

**计数到无穷的缓解**：水平分割/毒性逆转/触发更新，但RIP本质上收敛慢。

**安全**：攻击者可在RIPv2上用已知明文认证密钥(或暴力)注入路由，将流量吸到攻击者——"RIP注入"攻击。生产网络一般不用RIP。

### 3.2 OSPF LSA与区域

**OSPF区域结构**：

```
        +------------------------------+
        |         Area 0 (Backbone)     |
        |   R1 ------ R2 ------- R3     |
        +------------------------------+
               |ABR          |ABR
        +------+------+      +------+------+
        |   Area 1    |      |   Area 2    |
        |  R4-R5      |      |  R6-R7      |
        +-------------+      +-------------+

ABR(区域边界路由器): 连接Area0和其他区域的性能汇总/路由
ASBR(自治系统边界): 引入外部路由(BGP/静态)到OSPF
```

**LSA类型**：

| 类型 | 说明 | 泛洪范围 |
|------|------|---------|
| 1 路由器LSA (Router) | 本路由器的链路与邻居 | 区域内 |
| 2 网络LSA (Network) | 由DR描述的多路访问网络 | 区域内 |
| 3 网络汇总LSA (Summary) | 由ABR汇总区域内路由 | 跨区域 |
| 4 ASBR汇总LSA | 描述ASBR位置 | 跨区域 |
| 5 外部LSA (External) | 外部注入路由 | 全AS |
| 7 NSSA外部LSA | NSSA区域外部 | NSSA区域内 |

**OSPF邻接关系状态机**：

```
Down → Init → Two-Way → ExStart → Exchange → Loading → FULL
 (Hello)  (双向邻居)    (主从协商) (DBD)     (LSR/LSU补全)

选举DR/BDR (2-way后): 组播路由选择; BDR防单点
若优先级为0 → 不参选DR (作DROther)
```

**OSPF安全细节**：
- 泛洪滤波（Filter）、被动接口(
passive interface)可避免向不信任网段发Hello
- Area authentication (明文/MD5) 需要配置
- 若攻击者能接入访问交换机端口并发Hello，可能获邻接 → 注入假LSA/进行拓扑震荡

### 3.3 BGP eBGP/iBGP细节

**eBGP vs iBGP**：

| 维度 | eBGP | iBGP |
|------|------|------|
| 邻居AS | 不同AS | 相同AS |
| 下一跳 | 对端接口IP（仅当直连）| 保持eBGP的下一跳（可能不可达，需IGP可达）|
| 环路防护 | AS-path含自身AS拒绝 | 从iBGP学到的不再传其他iBGP邻居 |
| 典型场景 | 运营商互联、企业出口 | AS内部传递路由（全互联或RR/联盟）|
| 起源 | 外部注入 | 内部（同步IGP） |

**BGP下一跳处理（关键）**：
```
AS100 ---- eBGP ---- R2(AS200) ---- iBGP ---- R3(AS200)
          10.0.0.1                 (TTL=64, IP单播)

R2宣告 10.0.0.0/8: Next-hop=10.0.0.1 (eBGP直连)
R2把路由发给iBGP邻居R3: Next-hop仍=10.0.0.1
R3去查IGP(OSPF)能否到达10.0.0.1 → 能 (或不能，若IGP不通则丢弃)
```

**eBGP多跳**：
```
AS100 R1 ---- (非直连) ---- R2 AS200
配置neighbor ... ebgp-multihop 2
需指定TTL
也要确保IGP能互通携带BGP报文？多跳时BGP用TCP(179)在任意可达IP间建立
```

**BGP策略与过滤**：
- inbound/outbound route-map/filter-list (AS-path ACL)
- 前缀列表(prefix-list)
- 社区(Community)标签打点控制
- RPKI (ROA) 验证来源

### 3.4 BGP劫持类型

**前缀劫持（Prefix Hijacking）**关键点：受害者并没有"非法入侵"BGP的数据面，而是利用BGP信任模型在公告路径中放入自己。

```
正常:
  广播 192.0.2.0/24 (属于AS100, 路径[100])
             AS200 ---> AS300 ---> AS400  (走AS100方向)

AS200劫持 (故意/意外):
  广播 192.0.2.0/24 (却宣称路径[200] 或 [200 100]的伪造)
  使其他AS(如AS300/AS400)认为存在更优的路径经AS200→劫持
```

**类型**：
1. **前缀劫持（水淹式）**：宣告一个更具体或更优的前缀；BGP用最长匹配+AS path等决策，可能覆盖原路径
2. **AS路径伪造（Path Injection）**：伪造AS路径假装是受害者的一部分
3. **MOAS（Multiple Origin AS）**：同一前缀被多个AS宣告

**案例：巴基斯坦YouTube事件（2008）**：

```
背景: 巴基斯坦政府要求封锁YouTube
处理: 巴基斯坦电信将YouTube前缀198.18.0.0/15宣告为自己的(SLAACK)
      但无意中经由其上游转发到全球

结果:
  全球RTT众多用户的YouTube流量被导向巴基斯坦 → 大范围黑屏
  YouTube真实路径被更长(更具体的/16)前缀覆盖?
  教训: 宣告的"更具体路由(如/24)"往往优先, 可被意外劫持
```

**检测与防御**：
- BGP学雷锋monitor（RouteViews、BGPmon、Pathsendants）
- 前缀发布后的自动验证（如Google的"透明"前缀发布）
- RPKI Origin验证（ROA签名要求AS origin匹配）
- AS-path / 前缀过滤
- IRR (Internet Routing Registry) 一致性检查

### 3.5 RPKI（基于资源PKI）

**RPKI机制**：

```
互联网号码资源机构(IANA/IANA) → 颁发给RIR(APNIC等) → LIR/AS → ROA

ROA(建立授权记录): 认证某个AS有权宣告某前缀

路由器配置: bgp rpki ...; 分别验证:
  有效(Valid) / 无效(Invalid) / 未知(Unknown)
策略: 默认丢弃Invalid路由
```

**RPKI限制**：
- 只验证AS origin，不验证路径完整性
- 只覆盖前缀宣告授权，无法防AS-path伪造
- 需要RIR建设基础设施，当前覆盖率仍然有限（2026年多数主要前缀已有ROA，但中小AS仍少）

## 4. 实战与示例

### 4.1 实验环境（GNS3 / Docker 模拟）

```bash
# 可选: 使用FRRouting (FRR) 容器模拟多AS
docker pull frrouting/frr

# 启动拓扑（文档很长）, 或使用GNS3图形模拟
# 简化：单机跑FRR练习命令行
sudo apt install -y frr

# 启用RIP/OSPF/BGP守护进程
sudo sed -i 's/^zebra=yes/zebra=yes/;s/^ospfd=no/ospfd=yes/;s/^bgpd=no/bgpd=yes/' /etc/frr/daemons
sudo service frr restart

# 进入vtysh
sudo vtysh
```

### 4.2 配置RIP（最小示例）

```bash
vtysh

conf t
router rip
 version 2
 network 192.168.1.0/24
 network 10.0.0.0/8
 passive-interface eth1

# 查看
show ip rip
show ip route rip
```

### 4.3 配置OSPF

```bash
vtysh

conf t
router ospf
 router-id 1.1.1.1
 network 192.168.1.0/24 area 0
 network 10.0.0.0/8 area 1
 area 1 enable  # 到区域1
 redistribute connected

# 查看
show ip ospf neighbor
show ip ospf database
show ip route ospf
```

### 4.4 配置eBGP

```bash
vtysh

conf t
router bgp 65001              # 本AS
 neighbor 10.0.0.2 remote-as 65002   # eBGP对端
 network 192.168.10.0/24      # 宣告本网段
!
# 过滤(安全): 只接受/24以内
 ip prefix-list PL-INGRESS seq 5 permit 0.0.0.0/0 le 24
 neighbor 10.0.0.2 prefix-list PL-INGRESS in

# 查看
show bgp summary
show bgp ipv4 unicast
show bgp nexthop
```

### 4.5 用bash/tcpdump捕获BGP/OSPF报文

```bash
# BGP为TCP 179号
sudo tcpdump -i eth0 -nn tcp port 179 -w bgp.pcap

# OSPF为协议号89
sudo tcpdump -i eth0 -nn proto 89 -w ospf.pcap
```

### 4.6 手工分析OSPF Hello包

```bash
tshark -r ospf.pcap -V | head -100

# 关键字段观察:
# OSPF Header:
#   Version 2
#   Type 1 (Hello)
#   Router ID: 1.1.1.1
#   Area ID: 0.0.0.0
#   Checksum
# Hello Payload:
#   Network Mask: 255.255.255.0
#   Hello Interval: 10
#   Router Priority: 1
#   Router Dead Interval: 40
```

### 4.7 RPKI验证命令行示例

```bash
# 若使用FRR编译支持RPKI:
router bgp 65001
 bgp rpki server 1.1.1.1 3323
 neighbor 10.0.0.2 route-map RM in

route-map RM permit 10
 match rpki valid
# 丢弃Invalid: 使用独立的route-map

# 查看
show bgp rpki table
```

### 4.8 常见报错与解决

```bash
# 报错1: OSPF邻居停留在EXSTART
# 说明: MTU不一致
# 解决: 两端统一MTU (接口ip mtu 1500)

# 报错2: eBGP邻居无法建立(TCP连不通)
# 检查: 直连? TTL? ACL? 防火墙?
#    --多跳需 ebgp-multihop

# 报错3: BGP学不到路由
# 检查: network宣告了吗? AS-path被过滤了吗?
#   show bgp ipv4 unicast summary, show route-map/filter
```

## 5. 常见坑与避坑指南

### 5.1 混淆度量标准（跳数vs代价vs AS路径）

**问题**：RIP跳数最小、OSPF代价最小、BGP AS路径最短，但决策还要按属性顺序。初学者容易混用。

**避坑**：区分三个协议的度量体系，理解"OSPF代价是接口口径"、"BGP的AS路径只是众多属性之一（决策第3步）"。

### 5.2 把OSPF的路由选择错当"全局最优"

**问题**：OSPF只在区域内保证计算最短路径，跨区域靠ABR汇总，汇总路由可能不是严格最优。

**避坑**：理解area汇总的精度损失；主干Area0设计要合理，否则次优路径。

### 5.3 忽略BGP同步/下一跳可达性问题

**问题**：iBGP下一跳必须能被IGP解析，否则路由被判定为不可达。

**避坑**：iBGP邻居间若无直连I/G路由，需确保下一跳可达（next-hop-self或IGP可路由）；排查时`show bgp`里状态"only valid for iBGP neighbors"需检查下一跳。

### 5.4 双栈/多出口下AS路径不能唯一判优

**问题**：AS路径短≠最优路径。还需考虑LOCAL_PREF、政策。攻击者可能故意缩短路径伪造（BA50等）使得路由被吸引。

**避坑**：do not solely trust AS path; 配合RPKI、前缀过滤、运营商策略防护。

### 5.5 忘记防火墙放行组播/特殊协议

**问题**：OSPF(协议89)、BGP(TCP 179)、RIP(UDP 520)时常被ACL/防火墙误拦，导致邻居起不来。

**避坑**：检查NF防火墙（如Linux `iptables`）、云安全组需放行对应协议/端口；OSPF应用`ip multicast`组地址放行。

### 5.6 依赖"静态路由"习惯忽略动态协议的安全面

**问题**：即使使用动态路由，攻击者若能进入二/三层控制面（如被插入的接入端口），可注入伪造路由（RIP伪造/OSPF泛洪/BGP伪造eBGP）。

**避坑**：所有IGP启用认证（MD5/密钥），BGP启用邻居认证（TCP MD5或支持现代扩展），限制协议只有在信任边界接口激活（passive-interface），用ACL限制管理面。

## 6. 知识关联

- [[01-OSI与TCP-IP分层模型：封装解封装全流程]] — 路由协议在L3的工作位置
- [[04-IP协议头逐字段解析与分片重组]] — IP包逐跳转发依赖路由表，TTL实现跳限制
- [[05-IPv6核心机制与安全影响]] — OSPFv3/RIPng/BGP在IPv6下的支持（Next Header等领域）
- [[03-ARP协议原理与ARP欺骗攻防]] — 同属控制面（解析/选路）中容易被注入的部分

## 7. 参考资料

1. RFC 1058 - Routing Information Protocol (1988) - https://datatracker.ietf.org/doc/html/rfc1058
2. RFC 2328 - OSPF Version 2 (1998) - https://datatracker.ietf.org/doc/html/rfc2328
3. RFC 1771 - A Border Gateway Protocol 4 (BGP-4) (1995) - https://datatracker.ietf.org/doc/html/rfc1771
4. RFC 4271 - A Border Gateway Protocol 4 (BGP-4) (2006) - https://datatracker.ietf.org/doc/html/rfc4271
5. RFC 6810 - RPKI-Based Origin Validation (2013) - https://datatracker.ietf.org/doc/html/rfc6810
6. RFC 6480 - RPKI架构 (2012) - https://datatracker.ietf.org/doc/html/rfc6480
7. FRRouting (FRR) 文档：https://docs.frrouting.org/
8. 巴基斯坦YouTube事件分析：https://www.nanog.org/papers/2017/BGPhijacking-Behavior_Mar_26.pdf
9. AS7007事件（1997）：https://www.merit.edu/blogs/incidents/as7007-explanation/
10. 《路由技术（第1版）》 周青 主编 - ISBN 978-7-115-22177-7