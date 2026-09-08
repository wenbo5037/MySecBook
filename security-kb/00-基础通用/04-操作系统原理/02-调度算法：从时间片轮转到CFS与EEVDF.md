---
title: "调度算法：从时间片轮转到CFS与EEVDF"
category: "00-基础通用/04-操作系统原理"
tags: [调度, CFS, EEVDF, 实时调度, 操作系统]
level: 主攻
type: ai-generated
status: 完成
updated: 2025-07-17
---

# 调度算法：从时间片轮转到CFS与EEVDF

> 本文内容聚焦操作系统调度算法原理，属于计算机学科通识知识。文中涉及的实时调度、优先级等概念均为合法操作系统课程与系统编程实践范畴，未涉及任何攻击性技术。请读者遵守所在机构与国家的法律法规，仅在授权环境中进行实验。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 调度(Scheduling)是操作系统在多个可运行任务中选择下一个占用 CPU 的进程/线程的机制，是资源分配的核心决策过程 |
| 核心用途 | 平衡吞吐量、响应时间、公平性与实时性，在有限 CPU 资源上高效服务多任务 |
| 关键参数 | 时间片、优先级/权重(nice)、vruntime、虚拟截止时间(virtual deadline)、调度类(SCHED_OTHER/FIFO/RR/DEADLINE)、调度域 |
| 常见风险 | FIFO 的"护航效应"、SJF 的饥饿、RR 的时间片开销、优先级反转、RT 进程饿死普通进程、多核负载不均 |
| 关联知识 | [[01-进程本质：PCB结构与进程创建流程]]、[[05-上下文切换：开销来源与实测分析]]、[[08-同步原语：互斥锁自旋锁信号量条件变量]] |

## 1. 概述

CPU 是稀缺资源，而系统中的可运行进程往往多于 CPU 核心数。**调度器(CPU scheduler)** 负责决定：在任一时刻，哪个进程占用哪个 CPU，以及它能运行多久。这一决策直接影响系统的吞吐量、交互响应速度和公平性。

调度无处不在：既有操作系统内核级调度（进程/线程如何获得 CPU），也有用户态调度（协程、goroutine、线程池如何选择任务）。理解内核调度是现代并行编程、性能调优与系统故障排查的必经之路。

从安全角度看，调度器的公平性也关乎**防拒绝服务(DoS)**：若调度策略存在缺陷（如 RT 进程无限运行、nice 值语义被滥用），单个进程就可能独占 CPU 饿死其他进程，造成系统级 DoS。因此调度器设计本身是系统安全的一部分。

**调度问题抽象**：

```ascii
就绪队列(Ready Queue)               CPU 核心
+------------------+               +--------+
| P3  P1  P5  P2   | ----------->  |  CPU0  |
+------------------+    调度决策    +--------+
    (挑选下一个)          ↓          +--------+
  FCFS/SJF/RR/CFS                 |  CPU1  |
  /EEVDF 等策略                     +--------+
```

## 2. 核心原理

### 2.1 调度目标（四元目标）

| 目标 | 含义 | 度量指标 |
|------|------|---------|
| 吞吐量(Throughput) | 单位时间完成的进程数 | 完成作业数/秒 |
| 响应时间(Response Time) | 从提交到首次响应的延迟 | 毫秒级 |
| 等待时间(Waiting Time) | 在就绪队列中等待的总时长 | 平均等待时间 |
| 周转时间(Turnaround Time) | 从提交到完全完成的时间 | 平均周转时间 |
| 公平性(Fairness) | 各进程获得 CPU 的机会均衡 | 分配比例/最大最小公平 |
| 实时性(Real-time) | 在截止期限内完成任务 | 是否满足 deadline |
| CPU 利用率(Utilization) | CPU 忙的时间比例 | 百分比 |

目标之间常相互冲突。例如最大化吞吐量可能导致长作业留存（影响响应时间）；追求公平又可能牺牲实时性。调度器必须在目标间权衡，这也解释了为何调度算法层出不穷。

### 2.2 调度发生的时机（调度事件）

1. 进程从运行态转入就绪态（时间片耗尽、被抢占）。
2. 进程从运行态转入阻塞态（等待 I/O 或锁）。
3. 进程从运行态结束（exit）。
4. 进程从阻塞态回到就绪态（I/O 完成、信号唤醒）。

**可抢占(preemptive) vs 非抢占(non-preemptive)**：现代内核普遍采用可抢占调度，即运行中的进程在时间片内也可能被更高优先级进程打断。

```ascii
非抢占调度: 进程自行放弃 CPU
  P1(运行) ....... P1退出 --> P2
  主动权在进程
可抢占调度: 调度器可强制剥夺
  P1(运行)<--时间片耗尽--> 调度器选 P2 运行
  主动权在调度器
```

### 2.3 调度的分层：调度类(Scheduling Class)

Linux 把进程按调度类分层管理，优先级从高到低：

```
停止类     stop_sched_class        (migration/stop 线程)
截止时限类  dl_sched_class          SCHED_DEADLINE
实时类     rt_sched_class          SCHED_FIFO / SCHED_RR
公平类     fair_sched_class        SCHED_NORMAL/OTHER (CFS/EEVDF)
空闲类     idle_sched_class        SCHED_IDLE
```

调度器先看高优先级类是否有可运行任务，高类不为空时低类根本不会被选择——这是**优先级调度的刚性前提**。

## 3. 详细知识点

### 3.1 经典算法

为便于对比，以下以到达时间负载为例：

```
作业 | 到达时间 | 运行时长(P)
P1   | 0        | 5
P2   | 1        | 3
P3   | 2        | 3
```

#### 3.1.1 先来先服务 FCFS(First-Come, First-Served)

非抢占，按到达顺序执行。实现简单但不是抢占式，会产生**护航效应(convoy effect)**——一个长作业会阻塞后面所有短作业，大幅拉高平均等待时间。FCFS 下平均等待 = (0+4+7)/3 ≈ 3.67。

缺点：对短作业不公平，响应差。

#### 3.1.2 最短作业优先 SJF / 最短剩余时间优先 SRTF

- SJF(Shortest Job First)：非抢占，选择预计运行时间最短的作业。理论最优（最小化平均等待），但需要预知运行时间，且长作业可能**饥饿(starvation)**。
- SRTF(Shortest Remaining Time First)：SJF 的可抢占版本，谁剩余时间短谁运行。响应更好但切换更频繁。

SJF 的平均等待 = (0+4+3)/3 ≈ 2.33，优于 FCFS。但"预计运行时间"在现实中无法准确获得，只能估计（如指数平均法）。

#### 3.1.3 时间片轮转 RR(Round Robin)

抢占式，每个进程获得固定**时间片(time quantum) q**，耗尽后移到队尾。q 的选择极其关键：

- q 太大 → 退化为 FCFS，交互恶化。
- q 太小 → 切换过于频繁，上下文切换开销占比升高（极端时 CPU 全耗在切换上）。

经验法则：q 应大于典型上下文切换时间（几百微秒），现代系统普遍在 1~10ms 量级。RR 对交互式任务公平，但累积运行时间长的作业周转会变差。

#### 3.1.4 多级反馈队列 MLFQ(Multilevel Feedback Queue)

同时兼顾"响应快"与"吞吐高"的实战算法：

- 多级队列，优先级从高到低。
- 高优先级队列时间片短，低优先级队列时间片长（或允许运行更久）。
- 新进程进入最高优先级队列——它消耗完时间片仍未完成，被降级到下一级队列。
- 低优先级进程长时间得不到 CPU，会**优先级老化(aging)** 提升回高队列，避免饥饿。

```ascii
MLFQ 结构（现代内核调度思想）
  Q0[最高优先级, q=8ms ] --> 耗尽降级到 Q1
  Q1[        , q=16ms] --> 耗尽降级到 Q2
  Q2[        , q=32ms] --> 耗尽继续留在 Q2（或老化升级）
  新进程总是进入 Q0
```

MLFQ 无需预知运行时间，自动让短交互作业快速完成、长作业让位——这是现代调度器的核心思想雏形。

### 3.2 Linux 调度器演进

| 版本 | 调度器 | 核心思想 |
|------|--------|---------|
| Linux 2.4 | O(n) 调度器 | 每次全局扫描所有任务选最优，随进程数线性变慢 |
| Linux 2.6.0~2.6.23 | O(1) 调度器 | 140 个优先级桶+位图，常数时间查找；但复杂且公平性差 |
| Linux 2.6.23~6.5 | CFS | 完全公平调度，红黑树+vruntime |
| Linux 6.6+ | EEVDF | 最早虚拟截止时间优先，取代 CFS 的"分片"机制 |

#### 3.2.1 O(n) → O(1)

- O(n)：每次调度遍历所有进程，进程数多时调度开销线性增长，令人无法接受。
- O(1)：140 级优先级队列（0~99 实时、100~139 普通），用位图(bitmap)快速定位非空最高优先级队列，查找 O(1)。但普通进程的动态优先级计算 heuristic 复杂、不公平，且响应差。

#### 3.2.2 CFS(Completely Fair Scheduler) —— Linux 2.6.23 引入

CFS 由 Ingo Molnár 提出，核心思想由"时间片 + 优先级队列"变为"**红黑树 + 虚拟运行时间(vruntime)**"。

**核心原理：公平共享 CPU**

每个进程记录 `vruntime`（虚拟运行时间）。调度时总是选择 `vruntime` **最小**的进程运行——即"历史上获得 CPU 最少"的进程，宏观上达到完全公平。

```ascii
CFS 红黑树
          [vruntime=100]
         /             \
   [90]                 [110]
        \             /       \
        [95]     [108]         [120]
    ↑ 每次取最左节点(最小 vruntime)运行
```

- 普通进程的 `vruntime` 按权重折算递增。权重由 nice 决定。
- 红黑树保证插入、删除、查找最左节点都在 **O(log N)**。
- **调度周期(sched_latency)**：每个周期内确保所有可运行进程至少运行一次。周期过大影响交互，过小频繁切换。默认 `sched_latency_ns = 6ms`（6.6 前）。

**nice(优先级) 与权重的换算**

nice 范围 -20~+20，默认 0。内核通过 `sched_prio_to_weight[]` 表把 nice 映射为权重：

```c
static const int prio_to_weight[40] = {
 /* -20 */ 88761, 71755, 56483, 46273, 36291,
 /* -15 */ 29154, 23254, 18705, 14949, 11916,
 /* -10 */  9548,  7620,  6100,  4904,  3906,
 /*  -5 */  3121,  2501,  1991,  1586,  1277,
 /*   0 */  1024,   820,   655,   526,   423,
 /*   5 */   335,   272,   218,   172,   137,
 /*  10 */   110,    87,    70,    56,    45,
 /*  15 */    36,    29,    23,    18,    15,
};
```

权重翻倍的 nice 间隔约 5——即 nice 每增加 5，获得的 CPU 份额约减半。权重(w)越大，`vruntime` 增速越慢（`vruntime += delta_exec * NICE_0_LOAD / weight`），因而占用 CPU 更多。

**sleeper fairness（睡眠者公平）**

交互式进程（如文本编辑器）经常睡眠等待输入。若按严格 vruntime，它们唤醒后 vruntime 落后，能"立即抢占"长期占用 CPU 的进程，从而获得良好交互响应。CFS 利用这一点实现 sleeper fairness：睡眠进程唤醒时保留落后优势，快速获得调度。

**CFS 的问题**：每个进程公平共享 CPU，但"公平"不区分"短交互"与"长计算"；且缺乏对**延迟(latency)**的显式控制，实时性不足。

### 3.3 EEVDF —— Linux 6.6 默认调度器

EEVDF(Earliest Eligible Virtual Deadline First)，由论文 *EEVDF: An Efficient Multiprocessor Scheduling Algorithm for Uniprocessor Systems* (1995, P.S. Li) 提出，Con Kolivas 等早期探索，2023 年被 Peter Zijlstra 合并进 Linux 6.6。

#### 3.3.1 核心概念：vlag 与 virtual deadline

- **vlag(virtual lag)**：进程"应有的"虚拟运行时间与实际 vruntime 之差，衡量进程被"欠"了多少 CPU。vlag > 0 表示该进程应尽快得到补尝（eligible）。
- **virtual deadline（虚拟截止时间）**：`vene = vruntime + (决定权重下的期望运行时长)`。EEVDF 在每个调度点选择 **vlag ≥ 0（eligible）且 virtual deadline 最小**的进程运行。

```ascii
EEVDF 检查流程
每个调度点:
  1) 计算每个就绪进程的 vlag
  2) 过滤 vlag ≥ 0 的"迟到"进程(eligible)
  3) 在这些进程中选择 virtual deadline 最早者运行
  4) 运行期间更新 vruntime
```

#### 3.3.2 EEVDF 与 CFS 的区别

| 维度 | CFS (2.6.23~6.5) | EEVDF (6.6+) |
|------|------------------|--------------|
| 选择标准 | vruntime 最小者 | eligible 且 virtual deadline 最早者 |
| 时间片 | 按调度周期动态分片 | 每次获得一段明确的 slice，运行到 deadline 或被抢占 |
| 延迟控制 | 间接，靠调度周期 | 更显式，可配置 |
| 公平性 | 长期公平 | 兼顾公平与延迟 |
| 新进程 | 立即抢占 | 也有抢占权 |
| 复杂任务 | 分片粒度不均 | 每个进程获得确定的执行区间 |

**EEVDF 的实际影响**：
- 改善了 **Latency 敏感工作负载**（交互、Meson/竞争性任务）的响应。
- 在混部负载（后台任务+交互任务）下公平性与延迟更优。
- 可通过切换 `sched_features` 中的 `EEVDF` 配置。

验证当前内核是否用 EEVDF：
```bash
uname -r
grep -i eevdf /boot/config-$(uname -r) 2>/dev/null
zgrep EEVDF /proc/config.gz 2>/dev/null
```

#### 3.3.3 nice 值语义在 EEVDF 下的变化

传统观点："nice 改变优先级"——在 EEVDF 中，nice 主要通过改变**权重**进而影响 **vlag/virtual deadline 的计算**。效果是：低 nice（高权重）进程每次获得更长的执行 slice、更早满足 eligible，但**不会无限抢占**——它跑完一段 slice 后仍会被公平让出。

实践中常见的理解偏差："把进程 nice 设为 -20 就能永远霸占 CPU"。实际上 EEVDF 仍保证公平共享，只是份额偏好高权重者；若要真正意义的实时独占，需用实时调度类（下面的 SCHED_*）。

### 3.4 实时调度：SCHED_FIFO / SCHED_RR / SCHED_DEADLINE

**Linux 实时进程**（RT priority 0~99，数字越小优先级越高，可配合 nice）。RT 进程优先级恒高于普通(Fair)进程。

| 策略 | 行为 |
|------|------|
| SCHED_FIFO | 实时先进先出：除非自己阻塞/退出或被更高 RT 抢占，否则一直运行；**无时间片** |
| SCHED_RR | 实时轮转：同优先级 RT 进程按时间片轮转 |
| SCHED_DEADLINE | 基于 deadline 的实时调度，最严格 |

**SCHED_DEADLINE** 使用 **EDF(Earliest Deadline First)** 算法，进程声明：运行周期(period)、运行预算(runtime)、截止时间(deadline)，内核保证在 deadline 前完成。这是最先进的确定性实时调度；但若多个 DL 进程同时需求超过 CPU 能力，同样无法保证。

**优先级继承(Priority Inheritance)**：解决**优先级反转(priority inversion)** 的经典手段。某高优先级进程等待一个被低优先级进程持有的锁，若中优先级进程抢占了低优先级进程，高优先级反而被"饿死"称为优先级反转。

```ascii
优先级反转问题
  P_High (优先级高) 等待锁L ---> Lock L 被 P_Low 持有
  P_Mid  (中) 抢占 P_Low（P_Low 没法释放锁）
  → P_High 无限等待，P_High 的 deadline 被错过

优先级继承解决:
  P_Low 持锁期间被临时提升到 P_High 的优先级
  → P_Low 尽快释放锁，避免反转
```

经典案例：1997 年美国火星探测器 Mars Pathfinder 的优先级反转导致系统反复重启，正是靠启用优先级继承修复。

### 3.5 多核调度：负载均衡与 NUMA 感知

单核→多核的扩展带来新问题：

1. **负载均衡(Load Balancing)**：防止某些核空闲而另外的反核过载。内核周期性（`scheduler_tick` + 空闲时 `idle_balance`）在运行队列(per-CPU runqueue, `struct rq`)之间迁移任务。
   - **newidle_balance**：CPU 空闲时主动拉任务。
   - **nohz idle balancing**：无时钟期间的空闲均衡。
   - **wake affine**：被唤醒任务优先放到上次运行的 CPU，保持缓存局部性。

2. **NUMA(Non-Uniform Memory Access) 感知**：现代多路 CPU 中，访问本地内存 vs 远端内存延迟差异显著。调度器倾向把任务留在其内存所在的 NUMA 节点，并尽量不做跨节点迁移（nodemask 控制）。

3. **调度域(Scheduling Domain)层级**：从单个 CPU → 核、socket → NUMA 节点 → SMP 全系统，构成树状层级。负载均衡在此层级中自底向上进行，避免每次全局扫描（O(1) 开销）。

```ascii
调度域层级示意
        System (全系统)
      /      |       \
   NUMA0    NUMA1   NUMA2      <- NUMA 节点域
   /   \    /   \   /   \
  CPU0 CPU1 CPU2 CPU3 CPU4 CPU5  <- 核心域
```

### 3.6 用户态调度：协程与线程池

内核调度并非唯一调度者。用户态也可以做调度：

- **协程/goroutine**：用户态自行管理与切换用户栈，无需陷入内核，切换开销远低于内核线程切换。见 [[04-协程原理：用户态调度与栈管理]]。
- **线程池**：应用在用户态维护任务队列，选择空闲 OS 线程执行。
- **作用域**：用户态调度只控制"任务如何在已获得的 OS 线程上运行"，真正的 CPU 分配权仍在内核调度器。

两者配合形成两层调度：内核负责"线程↔CPU"，用户态负责"任务↔线程"。

## 4. 实战与示例

### 4.1 用 chrt / nice / taskset 观察调度

```bash
# ---- nice: 查看与设置普通优先级权重 ----
# 以 nice=10 运行
nice -n 10 ./cpu_heavy
# 查看 nice 值 (NI 列)
ps -o pid,ni,stat,comm

# ---- chrt: 实时调度 ----
# 查看某进程调度策略与优先级
chrt -p 1234

# 以 SCHED_FIFO 优先级 50 运行
sudo chrt -f 50 ./rt_task
# 以 SCHED_RR 优先级 30 运行
sudo chrt -r 30 ./rt_task
# 以 SCHED_DEADLINE 运行需要额外参数
sudo sysctl sched_rt_runtime_us=1000000   # 放宽 RT 限额（危险，慎用）

# ---- taskset: 绑定 CPU ----
# 查看 CPU 亲和性
taskset -p 1234
# 绑定到 CPU0-1
taskset -c 0,1 ./task

# ---- 查看调度信息 ----
# 各进程 CPU 时间、优先级
ps -eo pid,psr,pri,ni,stat,comm
```

**重要安全提示**：`sched_rt_runtime_us` 控制 RT 进程能占用的 CPU 时间配额（默认约 95%），防止 RT 进程无限饿死普通进程——这正是 RT 防 DoS 的关键内核机制，生产环境切勿随意调为 100%。

### 4.2 分析 /proc/schedstat 与调度统计

```bash
# 各 CPU 调度统计
cat /proc/schedstat
# 示例输出（每个 CPU 三行）
# cpu0 123456 7890 12345      # 运行时间、放弃、各类统计
# rt0   0 0 0                 # 实时调度统计
# 后面是 runnable/wait 时间

# 查看某进程运行时间
cat /proc/<pid>/stat | awk '{print "utime:"$14, "stime:"$15, "nvcsw:"$22, "nivcsw:"$23}'
# 字段参考 proc(5)：
# 14 utime: 用户态时间(clock ticks)
# 15 stime: 内核态时间
# 22 nvcsw: 主动(voluntary)上下文切换
# 23 nivcsw: 非主动(involuntary)切换
```

### 4.3 演示 nice 对 CPU 份额的影响

```bash
# 两个 CPU 密集型进程：默认 nice 0
taskset -c 0 sh -c 'while :; do :; done' &
taskset -c 0 sh -c 'while :; do :; done' &
# 观察两边 CPU 时间基本对半
ps -o pid,ni,time,stat,comm --sort=time

# 将其中一个设为 nice 10
renice 10 -p <pid>
# 观察其 CPU 时间增速明显下降，另一个约占 ~64%

# kill
kill %1 %2
```

### 4.4 SCHED_FIFO 实时进程示例（C 语言）

```c
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>

int main(void) {
    struct sched_param sp;

    /* 设置为 SCHED_FIFO，优先级 50（需要 root） */
    sp.sched_priority = 50;
    if (sched_setscheduler(0, SCHED_FIFO, &sp) == -1) {
        perror("sched_setscheduler");
        exit(EXIT_FAILURE);
    }

    printf("调度策略: ");
    int policy = sched_getscheduler(0);
    switch (policy) {
        case SCHED_FIFO:   printf("SCHED_FIFO\n"); break;
        case SCHED_RR:     printf("SCHED_RR\n");   break;
        case SCHED_OTHER:  printf("SCHED_OTHER\n"); break;
        default:           printf("unknown(%d)\n", policy);
    }

    /* 严格周期任务：每 10ms 执行一次 */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (int i = 0; i < 50; i++) {
        /* 模拟周期处理 */
        ts.tv_nsec += 10 * 1000 * 1000;      /* 10ms 周期 */
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_nsec -= 1000000000L;
            ts.tv_sec++;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
    }
    printf("周期任务完成\n");
    return 0;
}
```

编译运行：
```bash
gcc -o rt_demo rt_demo.c
sudo ./rt_demo          # 需要 root 设置 SCHED_FIFO
chrt -p $$              # 另一个终端验证
```

**注意**：SCHED_FIFO 实时进程若不阻塞/不退出会独占 CPU，导致系统交互卡死——务必在安全环境测试，且设计好退出/让步逻辑（可用 `sched_yield()` 主动让出）。

### 4.5 用户态协程调度器原型（Python）

展示用户态"任务→线程"两层调度的思想：

```python
import time
from concurrent.futures import ThreadPoolExecutor

class UserScheduler:
    """简化的用户态任务调度器（round-robin）"""
    def __init__(self, nthreads=4):
        self.pool = ThreadPoolExecutor(max_workers=nthreads)
        self.queue = []

    def submit(self, fn, *args):
        self.queue.append((fn, args))

    def run(self, tick=0.01):
        while self.queue:
            fn, args = self.queue.pop(0)
            # 简易轮转：总是取出队首提交
            self.pool.submit(fn, *args)
            # 真实的用户态调度器会在此决定任务何时执行、何时让出
        self.pool.shutdown(wait=True)

def task(name, n):
    for i in range(n):
        print(f"[{name}] step {i}")
        time.sleep(0.001)

if __name__ == "__main__":
    s = UserScheduler(nthreads=2)
    for i in range(5):
        s.submit(task, f"T{i}", 3)
    s.run()
```

真正的用户态调度器（如 Go runtime、libco）在此之上实现了栈切换、work-stealing、同步等，见 [[04-协程原理：用户态调度与栈管理]]。

## 5. 常见坑与避坑指南

### 5.1 CFS/EEVDF 对 I/O 密集型进程的"错觉"

**现象**：交互/网络服务进程占用 CPU 不高，但响应时延抖动明显。
**原因**：I/O 密集型进程常在睡眠后唤醒，vlag/睡眠者公平使它们能较快获得 CPU；但若系统被大量 CPU 密集任务淹没，交互进程仍需排队。纯靠"看 CPU% 判断健康"会误导。
**避坑**：用延迟直方图(p99)、`/proc/<pid>/schedstat` 的 wait 时间，而非仅看 CPU 占用。

### 5.2 EEVDF 引入后 nice 语义的变化与误用

**现象**：有人把后台任务 nice 调大(nice=19)以为能"让路"，结果交互任务仍偶发卡顿。
**原因**：EEVDF 下 nice→权重→slice/vlag 影响是**比例性**的，非绝对禁用。台任务仍会周期运行，只是份额小。
**避坑**：真正的"让路"用 SCHED_IDLE 或 cgroups CPU 配额(cpu.max)；实时需求用 SCHED_* 且设好 `sched_rt_runtime_us` 配额。

### 5.3 RT 进程饿死普通进程（RT 导致系统"假死"）

**现象**：设置 SCHED_FIFO 且不 block 的进程导致 ls、ssh 都无法响应。
**原因**：RT 优先级恒高于普通进程，实时进程若无让出/期限，普通进程永远得不到 CPU。
**避坑**：
- 实时任务必须 self-paced（周期 sleep/block），设超时退出。
- 保持 `sched_rt_period_us`/`sched_rt_runtime_us`（默认 1s/0.95s）不被禁用，防止 RT 无限占用 CPU（这是内核内置的 RT DoS 防护）。
- 生产环境严格限制实时进程创建权限(CAP_SYS_NICE)。

### 5.4 优先级反转导致的实时任务超时

**现象**：实时任务偶尔错过 deadline，即使 CPU 并未跑满。
**原因**：实时任务等锁，锁被低优先级进程持有，且被中优先级进程抢占 → 反转。典型于 Mars Pathfinder 事故。
**避坑**：
- 内核/POSIX 互斥锁启用优先级继承（如 `pthread_mutexattr_setprotocol(PTHREAD_PRIO_INHERIT)`）。
- 缩短持锁临界区，避免在持锁期间做慢调用。
- 高优先级任务避免依赖低优先级任务释放的资源路径。

### 5.5 多核负载不均导致假"瓶颈"

**现象**：机器整体 CPU 剩余很多，但某应用仍慢。
**原因**：绑核(taskset)、NUMA 节点不均、或某个核成为热点（如单 goroutine）。
**避坑**：
- `mpstat -P ALL 1` 看各核利用率是否均衡。
- 检查 `taskset`/`sched_setaffinity`/cpuset 限制。
- NUMA 场景用 `numactl` 保持内存本地化，避免远端内存引起慢速路径。
- 超过单核吞吐的密集任务要并行化（线程池/goroutine）。

### 5.6 误以为设置高 nice 就能"抢占"CPU

**现象**：把进程 nice 设成 -20，以为能霸占 CPU。
**原因**：nice/CFF 只影响**公平份额比例**，不能保证绝对优先。
**避坑**：需要确定性优先/独占时用实时调度类或 cgroup；并始终做好防饿死的配额控制。

### 5.7 调度统计数字的解读误区

**现象**：看到进程 `involuntary_ctxt_switches` 很大就认为异常。
**原因**：非主动切换多可能是因为时间片耗尽（正常）或被更高优先级抢占；也可能是因为系统过载。
**避坑**：结合 CPU 负载、`/proc/loadavg`、等待时间一起判断；单看切换次数无法判定好坏。

## 6. 知识关联

- [[01-进程本质：PCB结构与进程创建流程]]：task_struct 中的调度字段(sched_class/vruntime)与本文调度算法直接对应。
- [[05-上下文切换：开销来源与实测分析]]：调度决策落地为上下文切换，q 的选择与切换开销互为约束。
- [[08-同步原语：互斥锁自旋锁信号量条件变量]]：阻塞/唤醒是调度状态迁移的触发源，优先级反转与锁密切相关。
- [[04-协程原理：用户态调度与栈管理]]：用户态协程调度的补充视角，与内核调度形成两层调度架构。
- [[03-线程模型：内核线程用户线程与混合模型]]：线程被内核调度器调度的对象，理解多线程并发与公平性。

## 7. 参考资料

1. Abraham Silberschatz, Peter Galvin, Greg Gagne. *Operating System Concepts* (第十版), Wiley. 第五章 CPU Scheduling 的经典算法讲解。
2. Andrew S. Tanenbaum. *Modern Operating Systems* (第四版), Pearson. 调度算法与实时调度部分。
3. Robert Love. *Linux Kernel Development* (第三版), Addison-Wesley. 第四章 Process Scheduling 对 CFS 的权威讲解。
4. Peter A. Dinda, *The Linux kernel scheduler* 及内核源码 `kernel/sched/`。
5. Li, P. S., et al. "EEVDF: An Efficient Engineering Virtual Deadline First scheduling algorithm." IEEE/Real-Time Systems, 1995. EEVDF 原始论文。
6. Linux 内核文档：`Documentation/scheduler/sched-design-CFS.rst`, `Documentation/scheduler/sched-rt-group.rst`, `Documentation/scheduler/sched-deadline.rst`。
7. Linux 内核源码：`kernel/sched/fair.c`（CFS/EEVDF）、`kernel/sched/rt.c`、`kernel/sched/deadline.c`、`kernel/sched/core.c`。
8. man pages: `sched_setscheduler(2)`, `sched_getparam(2)`, `nice(2)`, `chrt(1)`, `taskset(1)`, `sched_yield(2)`, `proc(5)`。
9. POSIX 实时扩展：IEEE Std 1003.1b-1993，优先级调度与实时接口。
10. Daniel P. Bovet, Marco Cesati. *Understanding the Linux Kernel* (第三版), O'Reilly. 调度器实现细节。
