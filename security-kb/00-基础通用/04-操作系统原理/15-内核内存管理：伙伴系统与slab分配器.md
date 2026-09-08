---
title: "内核内存管理：伙伴系统与slab分配器"
category: "00-基础通用/04-操作系统原理"
tags: [内核内存, 伙伴系统, slab, 内存分配, 操作系统]
level: 主攻
type: ai-generated
status: 完成
updated: 2025-07-17
---

# 内核内存管理：伙伴系统与slab分配器

> **合规声明**：本文内容用于操作系统内核内存管理原理与系统性能/稳定性研究的合法工程研究。文中涉及的伙伴系统、slab/slub、内存回收、OOM 机制均属开发与运维用途。正文中提到的内核堆喷射（heap spray）、slab 溢出等安全概念仅用于**防御性**研究与漏洞分析讲解，严禁用于实际攻击或未授权利用。若进行内核漏洞研究（如 CVE-2016-6187 分析）请仅在隔离实验环境与授权范围内进行。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 内核内存管理是"为内核自身与内核服务分配物理内存"的子系统；伙伴系统按 2^n 页块管理页，slab/slub 在其上提供对象级缓存复用 |
| 核心用途 | kmalloc/vmalloc/vmalloc_node 分配、对象缓存（struct file/inode 等）、内存回收与 OOM |
| 关键参数 | MAX_ORDER（默认 11，单次最大 4MB）、ZONE（DMA/NORMAL/HIGHMEM）、slab 对象 size、kmem_cache |
| 常见风险 | kmalloc 大小限制、vmalloc 不适合 DMA、slab 碎片化、OOM killer 误杀、堆喷射/溢出攻击面 |
| 关联知识 | [[01-物理内存管理：分区分页分段演进史]]、[[02-虚拟内存原理：多级页表与地址翻译]]、[[05-内存页保护属性：从RWX到NX-XD位]] |

---

## 1. 概述

**内核内存管理（Kernel Memory Management）** 负责管理"操作系统内核自己使用的那部分内存"。它与用户态内存管理（malloc 那一套）完全不同：用户态进程想要内存，通过 brk/mmap 走内核按需分配；而内核本身的内存分配器要直接面对**物理页**，且运行在最高特权级，任何内存管理错误都会导致内核崩溃（oops/panic）或成为严重安全漏洞。

内核内存管理要解决的核心矛盾是：内核里的分配请求**大小跨度极大**、**频率极高**、**对象类型固定**。比如：

- 进程 fork 时要分配一个 `struct task_struct`（约几 KB 的固定结构体）。
- 打开一个文件要分配 `struct file`。
- 驱动程序可能要分配一个 1 页（4KB）的 DMA 缓冲区。
- 也可能需要分配几十 MB 的连续物理内存给某个大块（如页面缓冲池）。

如果像用户态 malloc 那样每次都直接从伙伴系统要一整页，那么对"每次只需要 64 字节的 `struct file`"来说，一整页 4KB 会被浪费掉 98% 以上。因此 Linux 采用**两层分配架构**：

1. **伙伴系统（Buddy System）**：管理**物理页**的分配与回收，按 2 的幂次（order 0 到 MAX_ORDER）分块，解决"页"粒度的分配。
2. **slab/slub 分配器**：建立在伙伴系统之上，管理**对象（object）**级缓存，把同一类型的对象（如同一大小的结构体）批量缓存复用，解决"小而固定"对象的分配效率与内存碎片问题。

这种"两层结构"是内核内存管理的关键骨架。此外还需理解 **kmalloc 与 vmalloc 之分**、**zone（内存分区）**、**内存回收与 OOM** 等。

从安全角度，内核内存管理是"内核漏洞"的富矿：slab 对象复用导致的 **UAF（Use-After-Free）**、内核堆喷射（heap spray）、slab 溢出（如 CVE-2016-6187 的 snd_seq 堆溢出）等，都是 red team 与 blue team 都必须掌握的领域。本文在原理之外，会从防御视角给出安全相关的讲解。

---

## 2. 核心原理

### 2.1 为什么需要专门的内核内存管理

归根结底有三个理由：

1. **物理内存直接映射**：内核启动后，物理内存大部分被直接映射到内核虚拟地址空间的一个固定区域（`PAGE_OFFSET` 起，即"直接映射区"）。内核访问"物理页 X"往往通过 `__va()`/直接地址算术完成，无法套用用户态的"页表懒分配 + 按需换入换出"逻辑。
2. **分配特征迥异**：内核内存不能像用户态那样轻易 swap 出去，且很多分配（如 DMA）要求**物理连续**，甚至要求特定辖区（ZONE_DMA）。
3. **性能与安全要求高**：内核是共享的服务者，内存分配不能拖垮整体；同时运行在 ring 0，越界/越用直接崩溃或可被攻击者利用提权。

**kmalloc vs vmalloc** 是理解的关键：

| 维度 | kmalloc | vmalloc |
|------|---------|---------|
| 物理连续性 | **物理连续** | 虚拟连续，物理可分散 |
| 大小范围 | 受 MAX_ORDER 限制（默认单次 ≤ 约 4MB-8MB） | 可很大（几百 MB 甚至 GB 级） |
| 性能 | 快（直接区，无需建页表） | 慢（需建立页表映射） |
| 适用 | 绝大多数内核对象、驱动、DMA | 大块、非连续物理可接受场景 |
| DMA 支持 | 可以 | **不可以**（设备需要物理连续地址时不能用 vmalloc） |

### 2.2 伙伴系统（Buddy System）

**伙伴系统** 把物理内存划分成 **页（page，通常是 4KB）**，并以 **2^n 的块**为单位管理。所有空闲块按 order（阶）分类放入一个 `free_area[MAX_ORDER+1]` 数组，`free_area[order]` 管理所有大小为 `2^order` 页的块链表。

```text
free_area 数组（MAX_ORDER=11，即 2^0 .. 2^11 页）
┌────────────┬────────────────────────────────┐
│ order=0    │ 1 页 (4KB)   空闲块链表         │
│ order=1    │ 2 页 (8KB)   空闲块链表         │
│ order=2    │ 4 页 (16KB)  空闲块链表         │
│ ...        │                                │
│ order=10   │ 1024 页 (4MB) 空闲块链表        │
│ order=MAX  │ (2^MAX_ORDER 页) 空闲块链表     │
└────────────┴────────────────────────────────┘

分配 2^n 页：
  1) 从 free_area[n] 找一块
  2) 若无 → 向 free_area[n+1] 借一块
  3) 找不到则再向上借更大的块，借到的块**分裂**成两半（伙伴），
     一半给请求者，另一半挂回更小的阶
  4) 一直分裂到满足 order

释放 2^n 页：
  1) 看它的"伙伴"（buddy，同阶、物理相邻、由同一块分裂而来）是否空闲
  2) 伙伴也空闲 → 合并成 2^(n+1) 的大块
  3) 否则挂回 free_area[n]
  4) 合并可逐级向上进行
```

**伙伴（buddy）** 的定义：两个大小相同、物理地址相邻、且由**同一个更大块**分裂出来的块互为伙伴。只有伙伴才能被合并回大块。这一规则保证物理内存不会"细小碎片化"到无法提供给大请求（区别于用户态堆的外部碎片问题）。

**分配流程伪代码**（简化）：

```python
def alloc(order):
    for o in range(order, MAX_ORDER+1):
        if free_area[o] 非空:
            block = free_area[o].pop()
            while o > order:
                o -= 1
                # 分裂 block：上/下两半
                half = 伙伴(block)
                free_area[o].append(half)   # 空闲的半块放回
                block = 其余半块继续用
            return block
    return NULL   # 无足够大块 → 触发内存回收或 OOM
```

**碎片化问题**：虽然伙伴系统避免了"无法合并的大块"，但长期反复分配/释放不同 order 的块，会导致**大量小块把内存切碎**，使高阶（大块）分配频繁失败。这也是引入 slab（对象缓存，很少变化 order）来缓解碎片化的原因之一。

### 2.3 SLAB 分配器

**SLAB**（命名来自教科书概念"slab"）在伙伴系统之上加一层**对象缓存**。核心思想是：**相同大小的对象反复创建/销毁很频繁，与其每次从伙伴系统要新页，不如把释放的对象缓存复用**。

SLAB 的三个核心要素：

```text
SLAB 架构
┌─────────────────────────────────────────────┐
│  kmem_cache（对象缓存，每种大小/类型一个）    │
│  ├─ 若干 slab（一块连续页面，来自伙伴系统）   │
│  │    每个 slab 被切成固定大小的"对象"        │
│  │    slab = [obj][obj][obj]...[空闲]        │
│  └─ 三种 slab 状态：                          │
│        partial（部分空闲）/ full / empty      │
└─────────────────────────────────────────────┘

分配对象：
  1) 从 kmem_cache 找 partial/full 中的空闲对象
  2) 无空闲 → 从伙伴系统新申请一个 slab（若干页）
  3) 首次使用时调用对象**构造函数**（可无）

释放对象：
  1) 对象放回缓存（可选调用析构函数）
  2) 该 slab 全空 → 可整块还给伙伴系统
```

**kmem_cache 的创建**（以内核代码为例）：

```c
#include <linux/slab.h>

/* 创建一个新的对象缓存：size 为对象大小，name 为其名字 */
struct kmem_cache *cache =
    kmem_cache_create("my_obj_cache", sizeof(struct my_obj),
                      0 /*对齐*/, 0 /*flags*/, NULL /*ctor*/);

/* 从缓存分配/释放一个对象 */
struct my_obj *p = kmem_cache_alloc(cache, GFP_KERNEL);
kmem_cache_free(cache, p);

/* 销毁缓存（所有 slab 归还） */
kmem_cache_destroy(cache);
```

SLAB 的**原子性设计**：SLAB 认为对象分配后，在释放前的整个生命周期内内容不被清零/覆写，从而能**直接复用内存**而避免每次构造的开销——这既是 SLAB 高效的原因，也是 UAF 漏洞能稳定利用的温床（对象残留数据可被攻击者控制）。

### 2.4 SLUB 分配器（Linux 默认）

**SLUB** 由 Christoph Lameter 于 2007 年提出（Linux 2.6.23 起），逐步取代 SLAB 成为 Linux 默认实现。SLUB 的动机是**简化 SLAB**、去掉复杂且易错的 per-CPU slab 队列，同时提升多核性能与可调试性。

SLUB 的核心设计：

```text
SLUB 关键优化
┌────────────────────────────────────────────────┐
│ 每个 kmem_cache 有一个 per-CPU 部分：          │
│   kmem_cache_cpu（slab_cpu）                  │
│   ├─ freelist：当前对象空闲链表头指针          │
│   ├─ tid：事务 id，用于无锁快速分配            │
│   └─ page：当前正在使用的 slab 页             │
│                                              │
│  分配：从 freelist 弹出对象（无锁快速路径）     │
│  释放：把对象压回 freelist（对应 CPU）         │
└────────────────────────────────────────────────┘
```

- **无锁快速路径**：大多数分配/释放在**本 CPU 的 freelist** 上进行，靠 `tid` 事务序号防止重入，无需全局锁，因此多核下吞吐极高、锁竞争极小。
- **freelist 管理**：SLUB 在 slab 的**每个对象头部**直接记录"下一个空闲对象"指针（`freepointer`），从而**不再需要 slab 元数据结构**，大幅简化。
- **partial/full 状态**：SLUB 用 `slab->partial` 链表管理部分空闲的 slab；全空 slab 通过 `discard_slab` 整块归还伙伴系统。

通过 `/proc/slabinfo` 可以查看所有 kmem_cache 的实时统计（数量、大小、活性对象数）。

### 2.5 vmalloc 与页表开销

**vmalloc** 在内核虚拟地址空间找一个**连续的虚拟地址范围**，然后把**物理上分散**的页通过页表映射到这段虚拟地址。它解决的是"物理不必连续"的大块分配。代价是：

```text
vmalloc 的开销：
1. 每次都要建立新的页表项（映射分散物理页）
2. 页表本身占用内存，且 TLB 缓存可能失效 → 性能比 kmalloc 差
3. 涉及 TLB shootdown（多核同步清除 TLB）
```

正因为要"建立页表 + 刷新 TLB"，vmalloc 明显慢于 kmalloc。**适用**：分配大块且不要求物理连续时（如某些内核模块缓冲区）；**不适合**：DMA（设备需物理连续地址）、以及高频小分配。

### 2.6 高端内存与 zone

**zone（内存分区/区）** 是伙伴系统把物理内存按用途与管理方式划分的区域。x86-32 下经典的三种 zone：

| Zone | 位置 | 特点 |
|------|------|------|
| **ZONE_DMA** | 低端（<16MB） | 早期设备 DMA 只能访问这段 |
| **ZONE_NORMAL** | 16MB~896MB | 直接被内核映射（线性映射区） |
| **ZONE_HIGHMEM**（高端内存） | >896MB | **不能**被内核线性映射，需临时页表访问 |

**高端内存（High Memory）** 是 32 位内核的经典难题：内核虚拟地址空间只有约 1GB，无法一次性映射全部物理内存，超过 896MB 的物理内存（HIGHMEM）只能"按需临时映射"来访问。这极大增加了内存管理复杂度。**64 位内核已经完全消除了高端内存问题**（虚拟地址空间巨大），因此现代 64 位 Linux 主要是 ZONE_DMA 与 ZONE_NORMAL（或更细的 DMA32/MOVABLE）。理解 highmem 有助于读懂老内核代码与 32 位嵌入式场景。

### 2.7 内存回收与 OOM

当物理内存紧张时，内核靠**内存回收（Reclaim）** 和 **OOM Killer（Out-Of-Memory Killer）** 两级应对：

- **kswapd（内核交换守护进程）**：后台内核线程，周期性扫描并回收内存（页缓存中的脏页写回、丢弃干净页、回收 slab、必要时换出匿名页）。
- **direct reclaim（直接回收）**：分配器在 fast path 拿不到内存时，就地同步执行回收，会阻塞当前进程——这是内存紧张时卡顿的常见原因。
- **OOM Killer**：回收后仍无法满足关键分配（如内核想要保留内存却不足）时，触发 OOM 判定，按某种评分（`oom_badness`，考虑 RSS、OOM score）选择一个进程杀掉以释放内存。

```text
内存分配慢路径：
allocate_page()
   ├─ 慢路径 → wake_up_kswapd() 唤醒后台回收
   ├─ 仍不够 → direct reclaim（当前进程同步回收，阻塞）
   ├─ 仍不够 → OOM　→ oom_kill_process()
   │               （选择一个进程 kill）
   └─ 返回
```

OOM killer 需要运维关注：`/proc/sys/vm/oom_kill_allocating_task`、`/proc/<pid>/oom_score_adj`（-1000 豁免，如数据库常设置以免被误杀）。

---

## 3. 详细知识点

### 3.1 分配 API 选型速查

| 你需要 | 调用 | 说明 |
|--------|------|------|
| 小块连续物理内存（驱动/内核对象） | `kmalloc(size, flags)` | 受 MAX_ORDER 限制，快，可用 GFP |
| 分配后清零 | `kzalloc(size, flags)` | `kmalloc` + 清零 |
| 大块非连续虚拟 | `vmalloc(size)` | 虚拟连续物理分散 |
| 带缓存的对象分配 | `kmem_cache_alloc(cache, flags)` | 最快、复用对象 |
| 指定 node 分配 | `kmalloc_node(size, flags, node)` | NUMA 下在指定内存节点分配 |

**kmalloc 与 kmalloc_node**：在多路/ NUMA（Non-Uniform Memory Access）系统中，`kmalloc_node` 允许指定在**某个 NUMA 节点**上分配，让分配发生在"距离当前 CPU 最近"的内存，降低跨节点访问延迟，显著提升 NUMA 系统性能。

### 3.2 flags（GFP）的语义

`GFP`（Get Free Pages）标志控制分配行为的重要方面：

```c
GFP_KERNEL   // 普通内核分配，可以睡眠（可调用回收/阻塞）
GFP_ATOMIC   // 原子上下文（中断/自旋锁内），不可睡眠，分配更快失败
GFP_HIGHUSER // 给用户态页的分配
__GFP_ZERO   // 分配后对象清零
__GFP_DMA    // 要求 ZONE_DMA（用于 DMA 缓冲）
__GFP_HIGHMEM// 允许使用 HIGHMEM
```

**中断上下文必须用 `GFP_ATOMIC`**，若误用 `GFP_KERNEL` 会在原子上下文尝试睡眠导致「scheduling while atomic」内核 panic。

### 3.3 /proc/slabinfo 字段解读

```bash
$ head -5 /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <object_size> <objperslab> ... <objsize> ...
kmalloc-192       1024  1024    192   21    1 : tunables ...
kmalloc-8         512   512      8  512    1 : tunables ...
```

- `active_objs`：当前正在被使用的对象数。
- `num_objs`：缓存中总共分配的对象数（含空闲）。
- `object_size`：单个对象大小。
- `objsper slab`：每个 slab 放几个对象。

`slabtop` 是交互式实时查看工具（类 `top`），能按活动对象数/Z 大小排序，帮助诊断内核内存增长与泄漏。

### 3.4 物理内存直接映射与 PAGE_OFFSET

理解内核内存管理的另一个关键点是**直接映射（direct mapping）**。现代 64 位内核把物理内存"直接映射"到内核虚拟地址空间的一个线性区域，起点称为 `PAGE_OFFSET`（x86-64 通常约 `ffff888000000000` 附近，具体由 `CONFIG_PAGE_OFFSET` 与 KASLR 决定）：

```text
x86-64 内核地址空间（示意）：
┌──────────────────────────────────────────────┐
│ FIXADDR/  vmalloc 区域  vmalloc(...)         │
│ ...                                          │
│ PAGE_OFFSET ──► 物理内存直接映射区（线性映射）  │
│   内核访问"物理页 X"只要用  __va(phys)        │
│   不需要额外建页表（KASLR 后基址随机化）       │
└──────────────────────────────────────────────┘
```

直接映射意味着内核访问大多数物理内存**不需要建立专门的页表项**，`kmalloc` 拿到的内存就落在直接映射区，所以快。而 `vmalloc` 不同——它落在 vmalloc 区域，需要**临时建立页表映射**，这就是 vmalloc 慢的物理原因。理解 `PAGE_OFFSET`/直接映射，是把"kmalloc 快、vmalloc 慢"从经验上升为原理的必经之路。

### 3.5 页表开销与物理连续的另一面

内存分配的"物理连续性"还影响着系统的**页表与 TLB**。`vmalloc` 使用**分散的物理页**，意味着要用很多页表项去描述，且 TLB 命中率可能更低；而 `kmalloc` 的连续物理内存常通过大页（hugepage）等方式获得更好的 TLB 覆盖。因此在内核里"少用 vmalloc、多用 kmalloc + 合理分配"不仅是为了 DMA，也是为降低虚拟内存映射开销与 TLB miss。

**内存热插拔与内存压缩**是更高级的话题：`memory_hotplug` 允许在线插拔内存；`zswap`/`zram` 通过压缩内存页来扩展可用内存。这些都属于"内核内存管理"这个大主题的延伸，本文聚焦分配器主线，将其点到为止。

### 3.6 内存回收的细化指标

`/proc/meminfo` 中与回收相关的关键指标：

```bash
# 查看内存压力与回收状态
$ cat /proc/meminfo | grep -E '^(MemTotal|SwapTotal|Dirty|Shmem|Cached|AnonPages)'
$ watch -n 1 "awk '/pgscan_direct|pgsteal_/ {print}' /proc/vmstat"   # 回收计数
```

- `pgscan_direct`/`pgsteal_direct` 持续增长：说明频繁发生 **direct reclaim**（同步回收），内存长期紧张。
- `kswapd` 线程的高 CPU 占用：后台回收压力大。
- 这些指标是判断"该加内存 / 该调优 / 有内存泄漏"的重要依据，也和本文 [[01-物理内存管理：分区分页分段演进史]] 的历史背景一脉相承。

### 3.7 安全视角：为什么内核分配器是攻击面

1. **内核堆喷射（Kernel Heap Spray）**：攻击者不断分配大量相同大小的对象，把可控制的数据填入 slab（如 `msg_msg`、`key` 对象、`userfaultfd` 对象等），使目标对象附近"布满可控数据"，配合 UAF/溢出把数据用起来。防御者要做到**对象隔离**、用 `KASLR`/`SLAB_FREELIST_RANDOM` 增加利用难度。
2. **slab 溢出（metaclass）**：写越界到**相邻对象**，可改写相邻对象的函数指针、长度字段，实现任意读写（提权）。
3. **CVE-2016-6187**：Linux 内核 `sound/core/seq/seq_prioq.c` 的 `snd_seq_prioq` 模块存在**整数溢出 → 堆溢出**（在 `snd_seq_*` 中），可被本地用户触发，用于权限提升。以此为代表的"slab 对象溢出"是内核安全研究的经典题型，**仅用于防御研究与漏洞分析**。
4. **SLAB_FREELIST_RANDOM / SLUB_DEBUG**：内核通过 `slub_debug`（检测越界写、越界释放、Double free、内存泄漏）、freelist 随机化（`SLAB_FREELIST_RANDOM`）、`KASAN`（Kernel Address Sanitizer，编译期检测越界/越用）来抵御与检测利用。`CONFIG_SLAB_FREELIST_RANDOM`、`CONFIG_RANDOM_KMALLOC_CACHES` 等均是当前发行版提升内核堆安全的开关。

防御视角的落地建议：生产环境开启 `KASLR`、`CONFIG_SLAB_FREELIST_RANDOM`、`CONFIG_SLAB_FREELIST_HARDENED`、`CONFIG_SLUB_DEBUG`（按需）、`CONFIG_KASAN`（测试环境），并及时打内核安全补丁。

---

## 4. 实战与示例

### 4.1 实时监控内核内存

```bash
# 查看伙伴系统各 order 的空闲块数（用于诊断大块分配失败）
$ cat /proc/buddyinfo
Node 0, zone   Normal    134  215  109   42   15    ...
#  对应 order0 order1 order2 order3 ... 的空闲块数

# 查看各 zone 的内存情况
$ cat /proc/zoneinfo | grep -A4 'Node 0, zone' 

# 查看内核内存总体（slab 占比、active 对象）
$ grep -E '^(Slab|SReclaimable|SUnreclaim)' /proc/meminfo

# 实时分配热点
$ slabtop -s c    # 按当前活动对象数排序
```

### 4.2 用 slabtop 定位内核内存泄漏

```bash
$ slabtop -o | head -20
# 关注 ACTIVE OBJS 持续增长、但 nobjs 不降的缓存。
# 若某 name 的 active_objs 无限上涨且 object 对应某内核对象
# （如 filp / dentry / tcp_sock），往往是有对象没释放（泄漏）。

# 也可以周期性采样对比
$ for i in 1 2 3; do grep -c 'xxxxx' /proc/slabinfo; sleep 5; done
```

### 4.3 内核模块示例：定义并使用一个 kmem_cache

```c
/* slab_demo.c —— 学习用内核模块，演示 kmem_cache 分配/释放 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>

struct demo_obj {
    char   name[32];
    int    id;
};
static struct kmem_cache *demo_cache;

static int __init slab_demo_init(void)
{
    struct demo_obj *obj;

    demo_cache = kmem_cache_create("demo_obj_cache",
                                   sizeof(struct demo_obj), 0, 0, NULL);
    if (!demo_cache)
        return -ENOMEM;

    obj = kmem_cache_alloc(demo_cache, GFP_KERNEL);
    if (!obj) {
        kmem_cache_destroy(demo_cache);
        return -ENOMEM;
    }
    obj->id = 42;
    snprintf(obj->name, sizeof(obj->name), "hello-slab");
    pr_info("allocated demo_obj id=%d name=%s from cache %s\n",
            obj->id, obj->name, cachep_name ? "" : "demo_obj_cache");

    kmem_cache_free(demo_cache, obj);
    kmem_cache_destroy(demo_cache);
    return 0;
}

static void __exit slab_demo_exit(void) { }

module_init(slab_demo_init);
module_exit(slab_demo_exit);
MODULE_LICENSE("GPL");
```

编译后 `insmod slab_demo.ko`，再用 `grep demo_obj_cache /proc/slabinfo` 可看到该缓存被创建并（释放对象后）回收。这部分展示的是**合法内核模块开发**。

### 4.4 触发与观察 OOM（仅测试环境）

```bash
# 仅限测试机！先用 cgroup 限制，避免影响宿主
$ mkdir /sys/fs/cgroup/memory/memtest
$ echo 64M > /sys/fs/cgroup/memory/memtest/memory.limit_in_bytes
$ echo $$ > /sys/fs/cgroup/memory/memtest/tasks
$ stress-ng --vm 4 --vm-bytes 128M   # 分配远超限制
# 观察 dmesg 出现 "Out of memory: Kill process" 与 oom_score
```

生产环境应关注 `oom_score_adj`，对关键进程（如数据库、Kubernetes 组件）设置 `-1000` 豁免被误杀。

### 4.5 直接回收与内存压力的观测实战

在内存紧张的服务器上，用 `vmstat` 和 `/proc/vmstat` 判断是否发生了 direct reclaim 与 swap：

```bash
# vmstat 的 si/so（swap in/out）与 r（运行队列）可反映内存压力
$ vmstat 2
procs -----------memory---------- ---swap-- -----io----
 r  b   swpd   free   buff  cache   si   so    bi    bo
 1  0  12345  1200   512  102400    0    12     5    20

# 细看回收计数，判断 direct reclaim 是否频繁
$ grep -E 'pgscan_(direct|kswapd)|pgsteal_(direct|kswapd)' /proc/vmstat
pgscan_kswapd 50213
pgscan_direct 834567    # 若 direct 很高 → 同步回收频繁 → 内存不足
pgsteal_kswapd 49871
pgsteal_direct 833210
```

当 `pgscan_direct` 远超 `pgscan_kswapd`，说明 kswapd（后台回收）来不及，频繁触发**同步直接回收**，应用会周期性卡顿。配合 `slabtop`/`buddyinfo` 定位是"伙伴系统碎片"还是"slab 泄漏"，再决定扩容、调优 `vm.swappiness`、或排查对象泄漏。

### 4.6 理解并正确设置 vm.swappiness

`/proc/sys/vm/swappiness`（0-100，默认 60）控制内核"在回收匿名页（换出到 swap）与回收文件页缓存之间"的倾向：

```bash
# 查看/设置（临时）
$ cat /proc/sys/vm/swappiness
60
$ echo 10 > /proc/sys/vm/swappiness   # 低：更偏好保留文件缓存

# 永久：写入 /etc/sysctl.conf
```

在**交互式/数据库**场景通常调低 swappiness 减少 swap 抖动；在**有大量匿名内存需要**的场合可能需要平衡。理解 swappiness 需要先理解"匿名页 vs 文件页"的区别：文件页（页缓存）可随时丢弃重读，匿名页（进程堆/栈）只能写回 swap——内核正是按这个权衡来决定先回收谁，这本身就是内存回收原理的直接应用。

---

## 5. 常见坑与避坑指南

| # | 坑点 | 说明 | 避坑方法 |
|---|------|------|----------|
| 1 | kmalloc 大小限制 | 受 `MAX_ORDER`（默认 11，单次 ≤ 约 4MB/可调 8MB）限制，过大分配失败 | 大块用 `vmalloc`；明确是否需要物理连续 |
| 2 | vmalloc 不适合 DMA | 设备需要物理连续地址，vmalloc 提供的是虚拟连续 | DMA 用 `kmalloc`/`GFP_DMA` 或 `dma_alloc_coherent` |
| 3 | 中断上下文误用 GFP_KERNEL | 会尝试睡眠 → 「scheduling while atomic」panic | 中断/自旋锁内用 `GFP_ATOMIC` |
| 4 | slab 碎片化/对象泄漏 | 反复分配不同大小导致对象残留或泄漏，内存"莫名上涨" | `slabtop`/`/proc/slabinfo` 定位；`slub_debug` 检查 |
| 5 | OOM killer 误杀 | 内存紧张时随机(按分值)杀进程，可能伤到关键服务 | 设置 `oom_score_adj=-1000`；用 cgroup 隔离；扩容或优化内存 |
| 6 | NUMA 假饥饿 | 默认 node 分配可能使某 node 内存耗尽而其他 node 空闲 | `kmalloc_node` 显式指定；`numactl` 分配策略 |
| 7 | 忽视 `slub_debug` 关闭 | 生产若开 slub_debug 会显著增加开销并可能轻易 panic | 生产谨慎开，测试/安全加固按需开 |
| 8 | 堆喷射/溢出利用面 | 未开内核加固时 exploit 难度低 | 开 `SLAB_FREELIST_RANDOM`、`HARDENED`、`KASLR`、KASAN |

---

## 6. 知识关联

- [[01-物理内存管理：分区分页分段演进史]]：伙伴系统管理的是"页"，而页/分段/分区的演进史正是理解物理内存组织的前提。
- [[02-虚拟内存原理：多级页表与地址翻译]]：kmalloc 走直接映射、vmalloc 要建页表，都是"物理→虚拟"地址翻译的不同策略；buddy/slab 分配的是物理内存，虚拟地址由其参与建立。
- [[05-内存页保护属性：从RWX到NX-XD位]]：内核内存与用户内存共享页表保护属性；NX/W^X 等页保护既是内核内存管理的延伸，也是防御堆喷/代码执行的边界。
- [[14-文件系统原理：inode目录项与日志机制]]：`struct inode`/`struct file`/dentry 等文件系统对象正是通过 slab 缓存高效分配，二者在对象缓存层面直接相关。
- [[10-内核态用户态：特权级与模式切换]]：内核内存管理运行在 ring 0，其安全性与越界直接影响内核态攻击面。

---

## 7. 参考资料

- Mel Gorman. *Understanding the Linux Virtual Memory Manager*. Prentice Hall, 2004.（伙伴系统、zone、page allocator 权威著作）
- Robert Love. *Linux Kernel Development*, 3rd Edition.（slab/slub、kmalloc/vmalloc、OOM 的清晰讲解）
- Daniel P. Bovet & Marco Cesati. *Understanding the Linux Kernel*, 3rd Edition.（伙伴系统与 slab 深入）
- Linux Kernel 源码：`mm/page_alloc.c`（伙伴系统）、`mm/slub.c`（默认分配器）、`mm/slab.c`（老 slab）、`mm/vmalloc.c`、`mm/oom_kill.c`
- kernel.org 文档：`Documentation/vm/slub.rst`（SLUB 与 slub_debug）、`Documentation/admin-guide/sysctl/vm.rst`（内存 sysctl）
- man 手册：`slabtop(1)`、以及 `/proc/buddyinfo`、`/proc/slabinfo`、`/proc/zoneinfo` 的 procfs 说明
- CVE-2016-6187：Linux sound/core/seq 堆溢出（安全分析仅用于防御研究）
- NVD/LWN：`LWN.net` 关于 SLUB 引入（Kernel: 2.6.23）与 slab 演进的系列文章
