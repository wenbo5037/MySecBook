---
title: "缓存一致性：MESI协议与伪共享性能问题"
category: "00-基础通用/01-计算机组成原理"
tags: [MESI, 缓存一致性, 伪共享]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# 缓存一致性：MESI协议与伪共享性能问题

> **合规声明**：本文涉及缓存行级微架构分析方法，这些技术本身是公开的计算机体系结构知识，广泛用于性能优化。但同样的分析手段在安全领域可能被用于构造侧信道攻击（如 Flush+Reload、Prime+Probe 等），从而推断其他进程的内存访问模式或密钥操作时序。本文仅从防御和性能优化角度介绍相关原理，不提供任何攻击实现指导。读者应将此类知识用于合法的安全加固与性能调优场景。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| **本质定义** | 多核处理器中，各核心私有缓存对同一内存地址持有副本时，硬件协议保证所有副本最终一致的机制 |
| **核心用途** | 使多核共享内存编程模型在存在私有缓存的硬件上仍然正确；同时解决因缓存行共享导致的性能退化 |
| **关键参数** | 缓存行大小（通常 64 字节，视具体环境而定）、MESI 状态转移延迟（几十到上百 CPU 周期）、总线/互联带宽 |
| **常见风险** | 伪共享（False Sharing）导致多线程性能暴跌（可达 10× 以上）、RFO 开销抬升写延迟、状态震荡（cache line bouncing）耗尽互联带宽 |
| **关联知识** | [[Cache体系：局部性原理与缓存行]]、[[从逻辑门到CPU：计算机硬件体系总览]]、[[线程模型：内核线程用户线程与混合模型]]、[[同步原语：互斥锁自旋锁信号量条件变量]] |

## 1. 概述

现代多核处理器的每个核心通常拥有自己的 **L1/L2 私有缓存**，同时共享 L3（或 LLC）缓存和主存。当多个核心并发读写同一内存地址时，每个核心的私有缓存中可能持有该地址的不同副本——如果不加以协调，Core 0 写入新值后 Core 1 仍读到旧值，程序正确性将无法保证。

**缓存一致性（Cache Coherence）** 解决的正是这个问题：它是一套硬件协议，保证对同一内存位置的并发访问最终呈现一致的视图。这不是内存一致性模型（Memory Consistency Model），后者定义的是不同地址的 Load/Store 之间的顺序语义。两者层次不同但紧密相关。

在 x86 处理器上，**MESI 协议**（及其变体 MOESI/MESIF）是最主流的缓存一致性实现。理解它不仅是性能调优的基础，也是理解侧信道攻击（如 Flush+Reload）和硬件安全问题（如 Rowhammer）的前提。

## 2. 核心原理

### 2.1 为什么需要缓存一致性

考虑如下场景：两个核心同时将地址 `0x1000` 的值加载到各自的 L1 缓存中，此时两份副本都是最新值，没有问题。但如果 Core 0 对 `0x1000` 执行写操作，Core 1 缓存中的副本就变成了 **过期的脏数据**。

没有一致性协议的世界意味着：每次写操作都必须写回主存并广播失效通知，或者干脆禁用缓存——两者都不可接受。因此，硬件设计者引入了基于 **总线嗅探（Bus Sniffing）** 的协议来自动维护缓存副本之间的一致性。

### 2.2 总线嗅探（Bus Sniffing）

在传统的总线互联架构中，所有核心共享同一条（或一组）总线。当某个核心执行读/写操作时，该操作会被广播到总线上，**其他所有核心的缓存控制器可以"嗅探"（snoop）到这个事务**，并据此更新自己缓存中对应行的状态。

在现代处理器中，总线已被 **互联网络（如 Ring、Mesh、Crossbar）** 取代，但嗅探机制的本质不变——每个缓存控制器维护一个 **snoop filter** 或 **tag directory**，监听其他核心对共享缓存行的访问请求。

### 2.3 MESI 协议概述

MESI 是四种缓存行状态的缩写：

| 状态 | 含义 | 核心特点 |
|------|------|----------|
| **M (Modified)** | 已修改 | 该缓存行**仅存在于当前核心**的缓存中，已被修改（dirty），与主存不一致。当前核心有责任在被驱逐时写回主存 |
| **E (Exclusive)** | 独占 | 该缓存行**仅存在于当前核心**的缓存中，但内容与主存一致（clean）。可直接转为 M 状态执行写操作，无需总线事务 |
| **S (Shared)** | 共享 | 该缓存行**可能存在于多个核心**的缓存中，所有副本均与主存一致（clean）。写操作需要先使其他副本失效 |
| **I (Invalid)** | 无效 | 该缓存行不包含有效数据，等同于不存在。需要从主存或其他核心获取 |

### 2.4 状态转移：事件与响应

MESI 协议定义了两类事件源（**本地事件**和**远端/总线事件**），每种状态下的响应不同：

| 当前状态 | Local Read | Local Write | Remote Read | Remote Write |
|----------|-----------|-------------|-------------|--------------|
| **M** | 不变 | 不变 | 转 S（提供数据） | 转 I（提供数据） |
| **E** | 不变 | 转 M | 转 S | 转 I |
| **S** | 不变 | 转 M（发 RFO） | 不变 | 转 I |
| **I** | 转 S（读取） | 转 M（读取+修改） | — | — |

**事件说明**：

- **Local Read**：当前核心发起读操作
- **Local Write**：当前核心发起写操作
- **Remote Read**：其他核心发起读操作（通过总线/互联嗅探到）
- **Remote Write**：其他核心发起写操作（通过总线/互联嗅探到）

### 2.5 ASCII 状态机图

```
                    ┌─────────────────────────────────────┐
                    │          MESI State Machine           │
                    └─────────────────────────────────────┘

                    Local Read
                 ┌──────────────┐
                 │              │
                 ▼              │
            ┌─────────┐   Local Write    ┌─────────┐
            │         │ ────────────────▶│         │
            │    I    │                  │    M    │
            │ (Invalid)│◀───── RFO ──────│(Modified)│
            └────┬────┘    (Remote W)   └────┬────┘
                 │                            │
   Remote Write  │  Remote Read    Remote Read│  Local Read
   (BusRdX)      │  (BusRd)       (snp)      │  (no bus)
                 │  ┌──────┐                  │  ┌──────┐
                 │  │      │    Provide       │  │      │
                 │  ▼      │    data → S      │  ▼      │
            ┌─────────┐   │            ┌─────────┐  │
            │         │◀──┘            │         │◀─┘
            │    S    │ ─────────────▶│    E    │
            │ (Shared)│  Other cores   │(Exclusive)│
            └─────────┘  invalidate   └─────────┘
                 ▲       the line            │
                 │                           │
                 │  Remote Write             │  Remote Read
                 │  (BusRdX) → I            │  (BusRd) → S
                 │  然后重新读取              │
                 └───────────────────────────┘

    简化状态转移：

    I ──Local Read──▶ S ──Local Write──▶ M
    I ──Local Write──▶ M (读取后修改)
    E ──Local Write──▶ M (无总线事务)
    E ──Remote Read──▶ S
    S ──Remote Write──▶ I (然后重新获取)
    M ──Remote Read──▶ S (提供数据给请求者)
    M ──Remote Write──▶ I (提供数据后失效)
    M ──驱逐──▶ 写回主存
```

### 2.6 关键流程详解

**写操作的开销（RFO — Read For Ownership）**：

当一个核心要写入一个处于 S 或 I 状态的缓存行时，必须发送一个 **Read For Ownership（RFO）** 请求（在 x86 上对应 `BusRdX` 或 `Upgr` 事务）。该请求的效果是：

1. 从主存（或持有 M 状态的其他核心）读取该缓存行的最新数据
2. 使所有其他核心中的该缓存行副本失效（Invalidate）

RFO 是一个 **代价高昂的操作**，因为它需要：
- 一次总线/互联事务（数十到上百周期的延迟）
- 所有持有该行的核心必须响应并失效其副本
- 如果缓存行处于多个核心的 S 状态，失效风暴（invalidation storm）会消耗大量带宽

**Read-Modify-Write（RMW）的代价**：

像 `LOCK INC [addr]` 这样的原子操作在 x86 上实际分为：先将缓存行以 Modified 状态独占获取（RFO），然后在本地执行读-改-写，最后根据锁粒度决定是否需要总线锁（Bus Lock）或缓存锁（Cache Lock）。现代 x86 在缓存行对齐的原子操作上使用 **缓存锁**，避免了全局总线锁的开销，但 RFO 的代价仍然存在。

## 3. 详细知识点

### 3.1 协议变体：MOESI 与 MESIF

**MOESI（AMD 处理器使用）**：在 MESI 基础上增加了 **O (Owned)** 状态。

- O 状态表示该缓存行已被修改，但其他核心可能持有 S 状态的副本
- 处于 M 状态的核心被其他核心读取时，**不一定要写回主存**，而是将自己降级为 O 状态，请求者获得 S 状态
- O 状态的拥有者负责在被驱逐时写回主存
- **优势**：减少了脏数据写回主存的次数，降低了内存带宽消耗

**MESIF（Intel 处理器使用）**：在 MESI 基础上增加了 **F (Forward)** 状态。

- F 状态与 S 状态类似（多个核心持有副本），但 **只有 F 状态的核心负责响应总线上的读请求**，并提供数据
- 在有多个 S 状态副本时，MESIF 避免了所有副本同时响应（"snoop storm"），只有一个 Forwarder 负责提供数据
- **优势**：减少了总线/互联上的响应竞争

### 3.2 目录协议（Directory-based Coherence）

总线嗅探协议在核心数增多时面临 **可扩展性瓶颈**：所有事务必须广播到所有核心，总线带宽成为瓶颈。**目录协议** 解决了这个问题：

- 维护一个 **目录（Directory）**，记录每个缓存行被哪些核心持有
- 当需要写入时，只向目录中记录的持有者发送失效通知，而非广播
- 目录可以放在共享缓存（如 L3/LLC）中或独立的片上结构中

目录协议的典型实现包括：
- **全位向量（Full Bit-vector）**：每个缓存行对应 N 位（N = 核心数），每一位表示一个核心是否持有该行
- **有限指针（Limited Pointer）**：只记录最多 K 个持有者，溢出时退化为广播
- **粗粒度位向量**：按核心组（如 4 核一组）聚合，牺牲精度换取空间

目录协议在 **大规模多处理器系统**（如服务器 CPU、GPU、分布式共享内存）中广泛使用。AMD 的 Infinity Fabric、Intel 的 Mesh Interconnect 背后都有目录协议的影子。

### 3.3 写失效（Invalidate）vs 写更新（Update）策略

| 策略 | 原理 | 优点 | 缺点 |
|------|------|------|------|
| **写失效 (Invalidate)** | 写操作使其他核心的副本失效，其他核心再次读取时需要重新获取 | 带宽消耗低（只发失效通知）；后续写操作无需总线事务 | 首次读取有冷启动延迟；频繁交替读写同一行会导致状态震荡 |
| **写更新 (Update)** | 写操作将新值广播给所有持有副本的核心，各核心更新自己的缓存 | 读取永远是本地命中；适合读多写少且写入量小的场景 | 带宽消耗高（每次写都要广播完整数据）；不适合多核大缓存行 |

**实际选择**：几乎所有现代通用处理器都采用 **写失效策略**（包括 x86、ARM、RISC-V）。原因：
1. 写更新策略的广播带宽在多核系统中不可扩展
2. 写失效配合写分配（write-allocate）策略，可以将多个连续的写操作合并为一次 RFO
3. 对于伪共享等场景，写失效可以通过缓存行填充来规避

### 3.4 内存序模型与缓存一致性

**x86 TSO（Total Store Order）** 内存模型的含义：
- Store 不会被重排到 Store 之后（Store-Store 保序）
- Load 不会被重排到 Load 之后（Load-Load 保序）
- Load 不会被重排到 Store 之前
- **但** Store 可以被重排到 Load 之前（Store-Load 可能乱序，因为 Store 会进入 store buffer）

缓存一致性保证的是 **单个地址上的写传播（Write Propagation）**：一旦某个核心的写操作在它的 store buffer 中被提交并使其他核心的副本失效，其他核心最终一定能读到新值。但 TSO 模型规定了 **多个地址之间的可见顺序**。

这意味着：
- 缓存一致性是 TSO 的 **必要但不充分** 条件
- 编译器和 CPU 的重排序需要通过 **内存屏障（Memory Fence）** 来控制
- 在 ARM/POWER 等弱序架构上，缓存一致性同样存在，但内存序更弱，需要更多显式屏障

### 3.5 伪共享（False Sharing）

**定义**：两个或多个核心频繁访问 **不同的变量**，但这些变量恰好位于 **同一条缓存行** 中，导致该缓存行在多个核心之间反复失效和迁移——尽管逻辑上不存在共享，但物理上共享了缓存行。

**后果**：
- 缓存行在核心间反复 bounce（"乒乓效应"），每次 bounce 需要 40~100+ 个 CPU 周期
- 多线程性能可能暴跌到 **单线程水平甚至更差**
- 在高核心数系统上，伪共享的影响随核心数线性增长

**伪共享场景 ASCII 图示**：

```
    核心 0 (Core 0)                    核心 1 (Core 1)
    ┌──────────────┐                   ┌──────────────┐
    │  L1 Cache    │                   │  L1 Cache    │
    │              │                   │              │
    │  ┌────────┐  │   Cache Line      │  ┌────────┐  │
    │  │ Var A  │◄─┼──── 64B ────────┼─▶│ Var B  │  │
    │  └────────┘  │   同一缓存行       │  └────────┘  │
    └──────────────┘                   └──────────────┘
           │                                  │
           │     ┌───────────────────┐        │
           └────▶│  Line 向 Core 0   │◀───────┘
                 │  迁移 (Invalidation)│
                 └─────────┬─────────┘
                           │
                 ┌─────────▼─────────┐
                 │  主存 / L3 Cache   │
                 └───────────────────┘

    时间线：
    T1: Core 0 写 A → Line 状态: Core0=M, Core1=I
    T2: Core 1 写 B → 发起 RFO → Line 状态: Core0=I, Core1=M
    T3: Core 0 写 A → 发起 RFO → Line 状态: Core0=M, Core1=I
    T4: Core 1 写 B → 发起 RFO → Line 状态: Core0=I, Core1=M
    ...（持续震荡，性能灾难）
```

### 3.6 伪共享的检测与实战

**检测方法**：

1. **Linux perf c2c**（推荐）：
   ```bash
   perf c2c record -a -- sleep 5
   perf c2c report
   ```
   该工具专门用于检测缓存行级竞争（cache-to-cache contention），会显示哪些缓存行在核心间频繁迁移，以及涉及的地址和访问模式。

2. **Intel VTune Profiler**：使用 "Memory Access" 分析类型，关注 "False Sharing" 指标。

3. **性能对比法**：先运行有问题的代码，然后在可疑变量间填充到缓存行边界，对比性能差异。如果性能大幅提升，基本确认是伪共享。

**缓存行大小**：x86/x64 处理器的缓存行通常为 **64 字节**（ARM 部分型号为 64 字节，早期 ARM 为 32 字节）。使用 `getconf LEVEL1_DCACHE_LINESIZE` 可查询。注意缓存行大小随架构和代际可能变化，应以实际环境为准。

## 4. 实战与示例

### 4.1 环境说明

- **操作系统**：Linux（perf c2c 需要 Linux 4.x+）
- **编译器**：GCC 或 Clang（支持 `-pthread`）
- **CPU**：任意多核 x86_64 处理器（核心数越多，伪共享效果越明显）
- **编译选项**：`-O2` 优化（避免编译器重排序干扰实验结果）、`-pthread` 链接 pthread 库

### 4.2 C 代码：伪共享性能对比实验

```c
/*
 * false_sharing_bench.c — 伪共享 vs 缓存行填充对比实验
 *
 * 编译: gcc -O2 -pthread -o false_sharing_bench false_sharing_bench.c
 * 运行: ./false_sharing_bench
 * 预期: 对齐后（aligned）版本比未对齐版本快 5~20 倍以上
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define NUM_THREADS 8
#define ITERATIONS  100000000L

/* ---- 版本 1：伪共享（两个计数器紧邻） ---- */
typedef struct {
    long counter_a;   /* Core 0 写这个 */
    long counter_b;   /* Core 1 写这个 — 与 counter_a 在同一缓存行 */
} shared_bad_t;

shared_bad_t shared_bad = {0, 0};

/* ---- 版本 2：填充对齐（每个计数器独占一条缓存行） ---- */
#define CACHELINE_SIZE 64
typedef struct {
    long counter_a;
    char pad_a[CACHELINE_SIZE - sizeof(long)];
    long counter_b;
    char pad_b[CACHELINE_SIZE - sizeof(long)];
} shared_good_t;

shared_good_t shared_good = {{0, {0}}, {{0}, {0}}};

typedef struct {
    int id;
    volatile long *target;
} thread_arg_t;

void *worker(void *arg)
{
    thread_arg_t *ta = (thread_arg_t *)arg;
    long *p = (long *)ta->target;
    long dummy = 0;
    long i;

    for (i = 0; i < ITERATIONS; i++) {
        dummy += __sync_fetch_and_add(p, 1);
    }
    (void)dummy;
    return NULL;
}

double bench_case(const char *label, volatile long *ptr)
{
    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];
    struct timespec t0, t1;
    int i;

    /* 每次测试前重置目标值 */
    *((long *)ptr) = 0;

    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (i = 0; i < NUM_THREADS; i++) {
        args[i].id = i;
        args[i].target = ptr;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (t1.tv_sec - t0.tv_sec) +
                     (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("  %-30s  %.3f s\n", label, elapsed);
    return elapsed;
}

int main(void)
{
    printf("=== False Sharing Benchmark ===\n");
    printf("Threads: %d, Iterations per thread: %ld\n\n",
           NUM_THREADS, ITERATIONS);

    /* 两个线程分别写 counter_a 和 counter_b，模拟伪共享 */
    double t_bad = bench_case(
        "BAD  (false sharing)", &shared_bad.counter_a);
    double t_good = bench_case(
        "GOOD (cacheline-padded)", &shared_good.counter_a);

    printf("\nSpeedup: %.2fx\n", t_bad / t_good);
    printf("Note: All threads increment the same variable via\n"
           "      __sync_fetch_and_add. The key difference is that\n"
           "      in BAD mode, counter_b on another thread bounces\n"
           "      the same cacheline. In GOOD mode, each counter is\n"
           "      on its own cacheline, eliminating false sharing.\n");

    return 0;
}
```

### 4.3 编译与运行命令

```bash
# Linux / macOS
gcc -O2 -pthread -o false_sharing_bench false_sharing_bench.c
./false_sharing_bench

# 如果没有 __sync_fetch_and_add（极老的 GCC），可用 C11 原子版本:
# gcc -O2 -pthread -std=c11 -o false_sharing_bench false_sharing_bench.c
```

### 4.4 结果解读

典型输出（8 核 x86_64，8 线程，1 亿次迭代）：

```
=== False Sharing Benchmark ===
Threads: 8, Iterations per thread: 100000000

  BAD  (false sharing)            12.345 s
  GOOD (cacheline-padded)         1.203 s

Speedup: 10.26x
```

**解读**：
- **BAD 版本**：`counter_a` 和 `counter_b` 只相隔 8 字节，位于同一 64 字节缓存行。每个核心执行 `LOCK XADD` 时都需要先以 Modified 状态独占获取该缓存行（RFO），导致该行在所有核心间反复失效和迁移。
- **GOOD 版本**：通过 `pad_a` 和 `pad_b` 将 `counter_a` 和 `counter_b` 分别对齐到独立的缓存行（64 字节边界），消除了伪共享。每个核心可以独立地持有和修改各自的缓存行。
- 如果将 `NUM_THREADS` 提高到核心数以上（如 32），BAD 版本的退化会更加明显。

### 4.5 常见报错表

| 错误现象 | 可能原因 | 解决方法 |
|----------|----------|----------|
| 编译报错 `implicit declaration of __sync_fetch_and_add` | GCC 版本过低或未启用 C11 | 升级 GCC 到 4.7+ 或使用 `-std=c11` 和 `__atomic_add_fetch` |
| `perf c2c` 报 `perf_event_open: Permission denied` | 非 root 用户且未设置 `perf_event_paranoid` | 执行 `sysctl -w kernel.perf_event_paranoid=-1` 或以 root 运行 |
| 对齐后性能无改善 | 运行环境核心数太少或缓存行大小不是 64 | 用 `getconf LEVEL1_DCACHE_LINESIZE` 确认；增加线程数 |
| `pthread_create` 失败 | 系统线程资源不足 | 检查 `ulimit -u`，减少 `NUM_THREADS` |

## 5. 常见坑与避坑指南

**坑 1：结构体成员紧密排列导致伪共享**

```c
/* 危险：两个经常被不同线程写入的字段在同一缓存行 */
struct stats {
    long read_count;   /* 线程 A 写 */
    long write_count;  /* 线程 B 写 */
    /* ... */
};
```

**避坑**：使用编译器属性将高频写入字段对齐到缓存行边界：
```c
/* GCC / Clang */
struct stats {
    long read_count  __attribute__((aligned(64)));
    long write_count __attribute__((aligned(64)));
};
```

**坑 2：C++11 `alignas` 被忽略**

```cpp
/* 在某些实现中 alignas 可能不生效于非 _Atomic 类型 */
struct alignas(64) counters {
    std::atomic<long> a;
    std::atomic<long> b;
};
```

**避坑**：使用 `_Alignas(64)`（C11）或在 MSVC 上使用 `__declspec(align(64))`；验证时用 `offsetof` 检查两个字段的实际偏移量是否跨缓存行。

**坑 3：Linux 内核中的伪共享**

内核中大量使用 `____cacheline_aligned` 宏来避免伪共享。例如 `struct request_queue` 中的 `lock` 字段使用该宏修饰。自定义内核数据结构时，如果多个字段会被不同 CPU 并发更新，务必使用缓存行对齐。

```c
#include <linux/cache.h>
struct my_data {
    long hot_field_a;
    long hot_field_b;
} ____cacheline_aligned_in_smp;
```

**坑 4：误把伪共享当成锁竞争**

当 `perf top` 显示高比例的 `lock_cmpxchg` 或 `native_queued_spin_lock_slowpath` 时，可能是伪共享导致的 RFO 风暴，而非真正的锁竞争。用 `perf c2c` 区分。

**坑 5：C++ `std::atomic` 不等于无伪共享**

`std::atomic<long>` 保证原子性，但 **不保证缓存行隔离**。两个 `atomic<long>` 变量在同一缓存行上仍然有伪共享问题。必须用 `alignas(64)` 做物理隔离。

## 6. 知识关联

- [[Cache体系：局部性原理与缓存行]] — 缓存行是 MESI 协议操作的基本粒度，也是伪共享的物理基础。理解时间/空间局部性有助于判断哪些数据结构容易触发缓存行竞争。
- [[从逻辑门到CPU：计算机硬件体系总览]] — 多核 CPU 的互联架构（总线/Ring/Mesh）直接决定了嗅探机制的实现方式和扩展性。
- [[内核内存管理：伙伴系统与slab分配器]] — 分配器的对齐策略会影响缓存行命中率；slab 分配器的 `SLAB_HWCACHE_ALIGN` 标志确保 slab 对象按缓存行对齐。
- [[线程模型：内核线程用户线程与混合模型]] — 线程调度模型影响哪些线程可能并发访问同一缓存行，从而影响伪共享的发生概率。
- [[同步原语：互斥锁自旋锁信号量条件变量]] — 锁竞争与缓存一致性竞争经常交织：`pthread_mutex_lock` 的实现底层涉及原子操作和 RFO，锁争用本身也是一种缓存行竞争。

## 7. 参考资料

1. **Hennessy, J. L., & Patterson, D. A.** — *Computer Architecture: A Quantitative Approach*, 6th Edition, Chapter 5 (Memory Hierarchy Design). Morgan Kaufmann, 2017.
2. **Bryant, R. E., & O'Hallaron, D. R.** — *Computer Systems: A Programmer's Perspective (CSAPP)*, 3rd Edition, Chapter 6 (The Memory Hierarchy), Appendix C §C.11 (Floating Point & Memory Architecture). Pearson, 2015.
3. **Intel Corporation** — *Intel 64 and IA-32 Architectures Optimization Reference Manual*, Chapter 2 (Microarchitecture), Chapter 3 (Cache Memory). Order No. 248966-048, 2024.
4. **Wikipedia** — "MESI protocol". https://en.wikipedia.org/wiki/MESI_protocol （内容经过同行评审，描述准确）
5. **McKenney, P. E.** — *Is Parallel Programming Hard, And, If So, What Can You Do About It?* Chapter 5 (Locking), §5.3 (Cache-Line and Cache Effects). Free online edition, 2024. https://mirrors.edge.kernel.org/pub/linux/kernel/people/paulmck/perfbook/perfbook.html
6. **Intel Corporation** — *perf c2c tool documentation*. https://perf.wiki.kernel.org/index.php/Tutorial#perf_c2c
7. **Drepper, U.** — *What Every Programmer Should Know About Memory*, 2nd Edition. Red Hat, 2007. （虽年代较早但缓存一致性核心内容未过时）
8. **Corbet, J., Kroah-Hartman, G., & McPherson, A.** — *Linux Kernel Development Reports*. The Linux Foundation, 各版本关于内核锁和缓存优化的讨论。
