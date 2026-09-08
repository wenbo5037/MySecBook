---
title: DMA与MMIO：外设访问内存的两种途径
category: 00-基础通用/02-内存与存储体系
tags: [DMA, MMIO, 外设, PCIe, 安全视角]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# DMA与MMIO：外设访问内存的两种途径

> **合规声明**：本文涉及的攻防视角仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | MMIO（Memory-Mapped I/O） | DMA（Direct Memory Access） |
|------|--------------------------|----------------------------|
| 本质定义 | 将设备寄存器映射到CPU物理地址空间，CPU通过load/store指令直接访问 | 外设绕过CPU直接读写主存，由DMA控制器接管总线事务 |
| 数据流向 | CPU ↔ 设备寄存器 ↔ 内存（CPU全程参与） | 外设 → 内存 或 内存 → 外设（CPU仅参与配置） |
| CPU开销 | 每次访问均消耗CPU时钟周期 | 仅配置和完成中断消耗CPU，传输过程CPU空闲 |
| 典型延迟 | 纳秒级（受总线仲裁影响） | 微秒到毫秒级（取决于传输块大小） |
| 适用场景 | 设备控制寄存器读写、小量状态查询、中断状态清除 | 大批量数据搬运：磁盘I/O、网络帧收发、GPU纹理上传 |
| 安全风险 | MMIO区域Cache导致的一致性问题；侧信道泄露 | DMA攻击：恶意设备可绕过CPU直接读写任意物理内存 |
| 防御机制 | Cache属性正确设置（UC/WC/WB） | IOMMU（Intel VT-d / AMD-Vi）实现DMA重映射与隔离 |
| 关联知识 | PCIe BAR、x86 MMIO-hole、APIC MMIO | Scatter-Gather、IOMMU页表、Thunderbolt攻击面 |

## 1. 概述

### 1.1 外设与CPU共享内存的本质需求

现代计算机系统中，CPU不是唯一的计算引擎。GPU处理图形渲染、网卡收发网络帧、NVMe SSD提供高速存储——这些外设（Peripheral Device）都需要与系统内存（Main Memory）交换数据。

核心矛盾在于：CPU通过内存总线（Memory Bus）访问内存，外设通过PCIe/PCIe Express总线访问内存，两条总线通过北桥（Northbridge）或集成内存控制器（Integrated Memory Controller）相连。

如何让外设高效、安全地访问内存，催生了两种截然不同的技术路径：
- **MMIO**：让CPU像访问内存一样访问设备寄存器
- **DMA**：让设备像CPU一样直接访问内存

两者并非互斥，而是互补——MMIO负责控制面（Control Plane），DMA负责数据面（Data Plane）。

### 1.2 知识体系定位

本文处于硬件安全知识体系的核心枢纽位置，向下衔接物理内存管理与页保护属性，向上支撑DMA攻击与IOMMU防御、PCIe安全、Thunderbolt攻击面分析等高阶课题。

```
                    ┌─────────────────────────┐
                    │     软件安全层          │
                    │  操作系统、驱动、固件    │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │     IOMMU 防御层        │
                    │  Intel VT-d / AMD-Vi    │
                    └──────────┬──────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                                 │
    ┌─────────▼─────────┐          ┌───────────▼───────────┐
    │      MMIO 路径     │          │      DMA 路径          │
    │ CPU → 设备寄存器   │          │ 外设 → 主存（旁路CPU） │
    └─────────┬─────────┘          └───────────┬───────────┘
              │                                │
    ┌─────────▼────────────────────────────────▼───────────┐
    │              PCIe / PCIe Express 总线                 │
    └─────────┬────────────────────────────────┬───────────┘
              │                                │
    ┌─────────▼─────────┐          ┌───────────▼───────────┐
    │   物理内存总线     │          │   设备（NIC/GPU/SSD）  │
    │   DDR4/DDR5       │          │   Thunderbolt/USB     │
    └───────────────────┘          └───────────────────────┘
```

### 1.3 核心应用场景

**MMIO 典型场景：**
- 读取网卡的链路状态寄存器（Link Status Register）
- 配置NVMe控制器的Submission Queue Base Address
- 访问APIC（Advanced Programmable Interrupt Controller）的中断命令寄存器
- x86架构中访问0xFEE00000地址段的Local APIC

**DMA 典型场景：**
- NVMe SSD将数据块直接写入预分配的内存缓冲区（PRP / Scatter-Gather List）
- 网卡将接收到的以太网帧直接DMA到Ring Buffer
- GPU通过DMA将纹理数据从系统内存拷贝到显存（VRAM）
- Intel GPU的GuC（Graphics Microcontroller）通过DMA提交工作队列

### 1.4 技术演进简史

```
1980s        1990s        2000s        2010s        2020s
  │            │            │            │            │
  ▼            ▼            ▼            ▼            ▼
┌─────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌─────────┐
│ PIO │ → │  MMIO  │ → │  DMA   │ → │ IOMMU  │ → │ DMA-Buf │
│时代 │   │ 普及   │   │ 主导   │   │ 普及   │   │ 统一   │
└─────┘   └────────┘   └────────┘   └─────────┘   └─────────┘
```

- **PIO时代（1980s）**：CPU逐字节读写设备I/O端口，x86使用IN/OUT指令，效率极低
- **MMIO普及（1990s）**：将设备寄存器映射到物理地址空间，消除端口数量限制
- **DMA主导（2000s）**：PCI/PCIe设备普遍支持Bus Master DMA，大批量数据不再经过CPU
- **IOMMU普及（2010s）**：Intel VT-d、AMD-Vi提供DMA地址重映射，隔离恶意设备
- **DMA-Buf统一（2020s）**：Linux DMA-Buf框架统一跨设备DMA共享，兼顾效率与安全

---

## 2. 核心原理

### 2.1 PIO（Programmed I/O）：CPU直接搬运数据

PIO是最原始的外设访问方式。CPU使用专用的I/O指令（如x86的IN/AL,0x60和OUT DX,AL）或通过I/O端口空间（0x0000-0xFFFF）与设备通信。

**工作流程：**

```
  CPU                        设备                       内存
   │                          │                          │
   │── IN AL, 0x60 ──────────>│                          │
   │<── AL = 0x41 ────────────│                          │
   │                          │                          │
   │── OUT DX, AL ───────────>│                          │
   │                          │                          │
   │  (重复N次，每次搬运1字节)  │                          │
   │── IN AL, 0x60 ──────────>│                          │
   │<── AL = 0x42 ────────────│                          │
   │  ...                     │                          │
```

**致命缺陷：**
- 每搬运一个字节/字都需要CPU执行一条指令
- 对于1GB/s的磁盘传输，CPU需要每秒执行约10亿次IN/OUT指令
- CPU带宽被完全占用，无法执行其他计算
- 不可扩展：随着外设速度提升，CPU成为不可逾越的瓶颈

PIO在现代系统中已近乎消亡，仅在极少数低速设备（如传统串口COM1/COM2）和系统引导早期阶段仍有使用。

### 2.2 MMIO（Memory-Mapped I/O）：将设备寄存器映射到物理地址空间

MMIO的核心思想：让CPU使用与访问内存相同的load/store指令（如x86的MOV指令）来访问设备寄存器。

**地址空间布局（x86-64典型）：**

```
虚拟地址空间（48-bit VA）
┌────────────────────────────────────────────┐ 0x0000_7FFF_FFFF_FFFF
│              用户空间                       │
├────────────────────────────────────────────┤ 0xFFFF_8000_0000_0000
│              内核空间                       │
├────────────────────────────────────────────┤
│  ...                                       │
├────────────────────────────────────────────┤ 0xFFFF_C000_0000_0000
│  Fixmap / vDSO / 特殊映射                   │
└────────────────────────────────────────────┘

物理地址空间（64-bit PA，实际使用46-52位）
┌────────────────────────────────────────────┐ 0x0000_0010_0000_0000
│              MMIO Hole（384GB+）            │ ← PCIe设备BAR映射区
├────────────────────────────────────────────┤ 0x0000_0000_FFFF_FFFF
│              低4GB（DMA区）                 │ ← 传统32-bit DMA设备
├────────────────────────────────────────────┤ 0x0000_0000_0000_0000
│              物理内存（DRAM）               │
└────────────────────────────────────────────┘
```

**MMIO访问流程：**

```
CPU                        北桥/内存控制器               设备寄存器
 │                              │                           │
 │── MOV RAX, [0xFE00_0000] ──>│                           │
 │    (地址匹配PCIe BAR)        │── PCIe Memory Read ──────>│
 │                              │<── 返回寄存器值 ──────────│
 │<── 返回数据 ─────────────────│                           │
```

MMIO的关键优势：
- CPU可以使用所有成熟的内存访问指令（原子操作、条件加载等）
- 支持更大的寄存器空间（理论上可达64-bit地址范围）
- 可以利用CPU的内存访问流水线优化

MMIO的地址由PCIe设备通过BAR（Base Address Register）声明，由系统固件（BIOS/UEFI）在枚举阶段分配。

### 2.3 DMA（Direct Memory Access）：外设直接读写主存

DMA彻底改变了外设访问内存的模式。DMA控制器（DMA Controller）接管总线，外设可以不经过CPU直接读写系统内存。

**DMA传输流程：**

```
  CPU                    DMA控制器                 外设                   内存
   │                        │                      │                      │
   │──①配置DMA描述符────────>│                      │                      │
   │  (源地址/目标地址/长度)  │                      │                      │
   │                        │                      │                      │
   │──②设置设备DMA使能───────>│── Bus Request ──────>│                      │
   │                        │                      │                      │
   │  (CPU继续执行其他任务)   │                      │                      │
   │                        │                      │                      │
   │                        │<── 数据就绪 ─────────│                      │
   │                        │                      │                      │
   │                        │── 读取/写入内存 ─────────────────────────────>│
   │                        │   (DMA占用总线)       │                      │
   │                        │                      │                      │
   │                        │<── 传输完成 ────────────────────────────────│
   │                        │                      │                      │
   │<──③完成中断(IRQ)───────│                      │                      │
   │──④处理传输结果─────────>│                      │                      │
```

**DMA传输的四个阶段：**
1. **配置阶段**：CPU向DMA控制器写入源地址、目标地址、传输长度
2. **请求阶段**：外设通过DMA请求信号（DREQ）通知DMA控制器
3. **传输阶段**：DMA控制器接管总线，直接在设备和内存之间搬运数据
4. **完成阶段**：传输完成后，DMA控制器通过中断通知CPU处理结果

### 2.4 MMIO vs DMA：同步/异步、CPU开销、适用场景对比

```
          MMIO 模型                      DMA 模型
    ┌─────────────────┐           ┌─────────────────┐
    │      CPU        │           │      CPU        │
    │  ┌───────────┐  │           │  ┌───────────┐  │
    │  │ Load/Store│  │           │  │ 配置/中断  │  │
    │  └─────┬─────┘  │           │  └─────┬─────┘  │
    │        │        │           │        │        │
    └────────┼────────┘           └────────┼────────┘
             │ 同步阻塞                     │ 异步回调
             ▼                              ▼
    ┌─────────────────┐           ┌─────────────────┐
    │   PCIe总线      │           │   DMA控制器     │
    │   Memory Read   │           │  ┌───────────┐  │
    │   Memory Write  │           │  │ 总线仲裁器 │  │
    └─────────────────┘           │  └─────┬─────┘  │
                                  │        │        │
                                  └────────┼────────┘
                                           │ 独占总线
                                           ▼
                                  ┌─────────────────┐
                                  │   系统内存      │
                                  └─────────────────┘
```

| 对比维度 | MMIO | DMA |
|---------|------|-----|
| 同步/异步 | 同步：CPU发出请求后等待响应 | 异步：CPU配置后可执行其他任务 |
| CPU占用 | 高：每次访问消耗CPU时钟 | 低：仅配置和中断消耗CPU |
| 传输效率 | 低：受CPU流水线限制 | 高：可接近内存总线带宽极限 |
| 适用数据量 | 小（几十字节到几KB） | 大（几KB到数GB） |
| 编程复杂度 | 低：简单load/store | 高：需管理描述符、同步、中断 |
| 安全风险 | 较低（CPU全程参与） | 较高（恶意DMA可访问任意内存） |
| 典型延迟 | ~100ns（跨NUMA节点更长） | ~10μs（启动延迟）+ 近线速传输 |

### 2.5 PCIe总线与设备内存映射

PCIe（PCI Express）是当前外设互连的主流标准。每个PCIe设备通过BAR（Base Address Register）向系统声明其所需的地址空间。

**PCIe地址空间模型：**

```
PCIe 设备视角                         系统视角
┌───────────────────┐       ┌────────────────────────────────────┐
│  BAR0: 寄存器空间  │──────>│  物理地址 0xFEBF_0000-0xFEBF_FFFF │ MMIO
│  (64KB, Non-Pref) │       │  (映射到CPU可访问的物理地址)        │
├───────────────────┤       ├────────────────────────────────────┤
│  BAR2: DMA缓冲区  │──────>│  物理地址 0x2000_0000-0x23FF_FFFF │ Prefetchable
│  (64MB, Prefetch) │       │  (支持WC/WB优化)                    │
├───────────────────┤       ├────────────────────────────────────┤
│  BAR4: ROM空间    │──────>│  物理地址 0xFEE0_0000-0xFEE3_FFFF │ MMIO
│  (256KB)          │       │  (Option ROM)                      │
└───────────────────┘       └────────────────────────────────────┘
```

PCIe配置空间中的BAR寄存器（每个设备最多6个BAR）采用以下编码：
- Bit 0：0=内存空间，1=I/O空间（PCIe时代几乎不用）
- Bit 2:1：00=32-bit，10=64-bit
- Bit 3：Prefetchable位
- Bit 4-31/63：基地址

系统固件在PCI枚举阶段遍历所有设备，根据BAR声明的大小分配不重叠的物理地址范围，并通过MMIO映射让CPU可以访问这些区域。

---

## 3. 详细知识点

### 3.1 MMIO深入：地址解码、Prefetchable/Non-Prefetchable、BAR寄存器

**PCIe BAR详解：**

每个PCIe设备通过配置空间的BAR寄存器声明其需要的地址空间大小和类型。BAR的最低几位是只读的硬件连线位，用于指示空间类型和大小。

**BAR位布局（32-bit内存BAR）：**

```
Bit 31              Bit 4    Bit 3      Bit 2:1    Bit 0
┌──────────────────────┬─────────┬──────────┬────────┬───┐
│     基地址 [31:4]    │Prefetch │ 类型     │ 保留   │ 0 │
│     (只读：写1读回)  │ able    │ (64/32)  │        │   │
└──────────────────────┴─────────┴──────────┴────────┴───┘
```

**Prefetchable vs Non-Prefetchable：**

| 属性 | Non-Prefetchable | Prefetchable |
|------|-----------------|--------------|
| 语义 | 对该区域的读取可能有副作用 | 对该区域的读取是幂等的 |
| Cache策略 | 必须使用Uncacheable（UC） | 可使用Write-Combining（WC）或Write-Back（WB） |
| 性能 | 读操作不可合并、不可重排 | 可通过WC合并写入，WB缓存读取 |
| 典型用途 | 控制寄存器、中断状态 | 大容量BAR（如NVMe的MSI-X表、GPU显存映射） |

**地址解码过程：**

```
CPU发出物理地址 0xFEBF0100
         │
         ▼
┌───────────────────────────┐
│   MMIO解码器（北桥/PCH）    │
│                           │
│   检查所有PCIe设备BAR      │
│   Device 00:00.0 BAR0=0xFEBF0000, size=64KB, 0xFEBF0000-0xFEBFFFFF
│   Device 01:00.0 BAR0=0xFED00000, size=1MB,  0xFED00000-0xFEDFFFFF
│                           │
│   地址落在 Device 00:00.0 BAR0范围内
│   偏移 = 0xFEBF0100 - 0xFEBF0000 = 0x100
│                           │
│   → 转发到 Device 00:00.0 的寄存器偏移0x100
└───────────────────────────┘
```

**MMIO与Cache的交互：**

x86架构中，MMIO区域必须通过MTRR（Memory Type Range Register）或PAT（Page Attribute Table）标记为Uncacheable，否则CPU可能缓存MMIO读取结果，导致：
- 状态寄存器读取返回过时值
- 中断状态被错误缓存
- 设备状态与内存视图不一致

Linux内核通过`ioremap()`函数将物理MMIO地址映射到内核虚拟地址，并自动设置正确的Cache属性。

### 3.2 DMA深入：DMA控制器架构、Scatter-Gather、描述符环

**DMA控制器架构演进：**

```
传统PIC DMA（8237）        现代DMA控制器
┌────────────────┐       ┌────────────────────────┐
│  8个DMA通道    │       │  集成在PCIe RC/PCH中    │
│  8-bit/16-bit  │       │  支持多设备并发DMA      │
│  最大64KB传输  │       │  支持64-bit地址         │
│  ISA总线       │       │  支持Scatter-Gather     │
└────────────────┘       │  MSI-X中断支持          │
                          └────────────────────────┘
```

**Scatter-Gather DMA：**

现代DMA控制器普遍支持Scatter-Gather模式，允许一次DMA事务在不连续的物理内存区域中传输数据。这通过描述符链表（Descriptor Chain）实现。

**Scatter-Gather描述符结构：**

```
描述符 0                      描述符 1                      描述符 2
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ Buffer Address   │   │ Buffer Address   │   │ Buffer Address   │
│ 0x1000_0000      │   │ 0x3000_0000      │   │ 0x5000_0000      │
│ Length: 4KB      │   │ Length: 4KB      │   │ Length: 4KB      │
│ Control: ND      │   │ Control: ND      │   │ Control: DD | IE │
│ (Next Desc)──────>──>│ (Next Desc)──────>──>│ (Done + Int En)  │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

- **ND (Next Descriptor)**：指向下一条描述符的地址
- **DD (Descriptor Done)**：标记当前描述符传输完成
- **IE (Interrupt Enable)**：传输完成时触发中断

**描述符环（Descriptor Ring）：**

高性能设备（如NVMe、高速网卡）使用环形描述符队列而非线性链表：

```
         ┌───────┐
         │  Head │ ← 设备读取位置（DMA控制器维护）
         └───┬───┘
    ┌────────┼────────────────────────┐
    │  ┌─────▼─────┐                  │
    │  │ 描述符 0  │ ──> Buffer A     │
    │  ├───────────┤                  │
    │  │ 描述符 1  │ ──> Buffer B     │
    │  ├───────────┤                  │
    │  │ 描述符 2  │ ──> Buffer C     │
    │  ├───────────┤                  │
    │  │    ...    │                  │
    │  ├───────────┤                  │
    │  │ 描述符 N  │ ──> Buffer N     │
    │  └───────────┘                  │
    │         ▲                       │
    └─────────┼───────────────────────┘
              │
         ┌────┴────┐
         │  Tail   │ ← 驱动写入位置（CPU维护）
         └─────────┘
```

Head和Tail指针的更新通过MMIO写入设备寄存器完成，设备和CPU之间通过内存屏障（Memory Barrier）确保一致性。

### 3.3 IOMMU（Intel VT-d / AMD-Vi）：DMA重映射与隔离

IOMMU（Input-Output Memory Management Unit）是DMA安全的关键防线。它将设备发出的DMA地址（IOVA，IO Virtual Address）重映射到物理地址，并提供访问控制。

**IOMMU核心功能：**
1. **DMA重映射（DMA Remapping）**：将设备的DMA地址翻译为物理地址
2. **设备隔离（Device Isolation）**：阻止未授权的DMA访问
3. **中断重映射（Interrupt Remapping）**：过滤和路由设备中断
4. **ATS（Address Translation Services）**：允许设备缓存IOMMU页表条目

**IOMMU与MMU的对比：**

```
     CPU MMU                           IOMMU
┌─────────────────┐             ┌─────────────────┐
│   虚拟地址(VA)   │             │   IO虚拟地址    │
│        │        │             │    (IOVA)       │
│        ▼        │             │        │        │
│   ┌─────────┐   │             │   ┌─────────┐   │
│   │ CR3寄存器│   │             │   │IOMMU根条│   │
│   │ 页目录   │   │             │   │目(RT)   │   │
│   └────┬────┘   │             │   └────┬────┘   │
│        │        │             │        │        │
│        ▼        │             │        ▼        │
│   页表遍历      │             │   页表遍历      │
│        │        │             │        │        │
│        ▼        │             │        ▼        │
│   物理地址(PA)   │             │   物理地址(PA)   │
└─────────────────┘             └─────────────────┘
      保护进程内存                    保护系统内存
      防止用户空间越权                防止设备DMA越权
```

### 3.4 Intel DMA Remapping：VT-d的页表与RID翻译

Intel VT-d（Virtualization Technology for Directed I/O）是Intel平台上的IOMMU实现。其核心机制是将PCIe Requester ID（RID）映射到一组页表条目。

**VT-d翻译流程：**

```
设备发出DMA请求
  Source: PCIe Device (BDF: 02:00.0 → RID=0x0200)
  Target: 物理地址 0x0000_0010_0000_0000
         │
         ▼
┌─────────────────────────────────────────┐
│              VT-d 翻译引擎               │
│                                         │
│  1. RID → Domain ID 映射               │
│     Source ID Table: RID 0x0200 → Domain 5
│                                         │
│  2. Domain 5 的 IOMMU 页表             │
│     Context Entry → PGD → PMD → PTE     │
│                                         │
│  3. IOVA 0x1000_0000 → PA 0x2000_0000  │
│                                         │
│  4. 访问权限检查:                        │
│     - 读权限? ✓                         │
│     - 写权限? ✓                         │
│     - 可执行? ✗ (No-Execute bit)        │
│                                         │
│  5. Snoop Control: 设备需缓存一致性     │
└─────────────────────────────────────────┘
         │
         ▼
    物理内存控制器
    实际访问 PA 0x2000_0000
```

**VT-d Context Table结构：**

```
全局上下文条目表
┌──────────────────────────────────────────┐
│ RID 0x0000 (BDF 00:00.0) → Root Table    │
│ RID 0x0001 (BDF 00:01.0) → Root Table    │
│ RID 0x0002 (BDF 00:02.0) → Root Table    │
│ RID 0x0200 (BDF 02:00.0) → Root Table    │
│ ...                                       │
│ RID 0xFFFF (BDF FF:0F.0) → Root Table    │
└────────────────────┬─────────────────────┘
                     │
                     ▼
              Root Table (每Domain一个)
┌──────────────────────────────────────────┐
│ Offset 0x00: [Present] [AW=48bit] [ctx]──> Context Entry
│ Offset 0x08: [Present] [AW=48bit] [ctx]──> Context Entry
│ ...                                       │
└──────────────────────────────────────────┘
                     │
                     ▼
              Context Entry
┌──────────────────────────────────────────┐
│ [Present] [T] [EMT] [RID_PASID]         │
│ [SLPTP] → 二级页表基地址                  │
│ [DID] = Domain ID                        │
│ [AW] = Address Width                     │
└──────────────────────────────────────────┘
```

**Linux内核IOMMU配置：**

```
# 启用Intel VT-d
intel_iommu=on

# 启用IOMMU passthrough（所有设备直通，无重映射）
intel_iommu=pt

# 启用IOMMU严格模式（同步TLB刷新，更安全但更慢）
iommu.strict=1

# 查看IOMMU域状态
cat /sys/kernel/iommu_groups/*/type
```

### 3.5 Thunderbolt与外部DMA攻击面

Thunderbolt（雷电）接口提供了极高的外部连接带宽（Thunderbolt 4: 40Gbps），但也引入了巨大的安全风险。Thunderbolt端口直连PCIe总线，外部设备可以通过DMA直接访问系统内存。

**Thunderbolt DMA攻击路径：**

```
攻击者设备                    Thunderbolt线缆              被攻击主机
┌────────────┐              ┌──────────────┐          ┌──────────────┐
│ 小型FPGA/  │              │              │          │              │
│ 微控制器   │── PCIe ────>│ Thunderbolt  │── PCIe ─>│ PCH/CPU      │
│ (恶意DMA   │  连接        │ 控制器       │  根复合体 │ IOMMU?       │
│  设备)     │              │              │          │              │
└────────────┘              └──────────────┘          └──────────────┘
                                                         │
                                                    如果IOMMU关闭:
                                                    ┌────▼─────┐
                                                    │可直接DMA  │
                                                    │读写任意   │
                                                    │物理内存   │
                                                    └──────────┘
```

**攻击前提条件：**
- 物理访问：攻击者需要接触目标机器的Thunderbolt/USB-C端口
- IOMMU未启用：Linux默认不启用IOMMU（需要`intel_iommu=on`）
- 物理安全锁：部分设备有Thunderbolt安全级别设置（BIOS/UEFI）

**已知攻击工具：**
- Inception（Thunderbolt DMA攻击框架）
- PCILeech（PCIe DMA攻击工具，支持多种硬件）
- ThunderClap（Thunderbolt安全分析框架）

### 3.6 安全视角：DMA攻击、FireWire DMA、PCIe Hotplug、IOMMU绕过

**DMA攻击的攻防全景：**

```
攻击向量                        防御机制
─────────                      ─────────
FireWire DMA ──────────────>   IOMMU（Intel VT-d / AMD-Vi）
Thunderbolt DMA ───────────>   Thunderbolt Security Level
PCIe Hotplug DMA ──────────>   BIOS/UEFI PCIe安全设置
ExpressCard DMA ───────────>   IOMMU Passthrough模式
USB4 DMA ──────────────────>   Kernel DMA Protection
恶意网卡DMA ───────────────>   IOMMU设备隔离
```

**FireWire DMA攻击（历史经典）：**

IEEE 1394（FireWire）接口是最早的DMA攻击向量之一。FireWire控制器支持等时（Isochronous）传输模式，允许外部设备读取主机内存中的数据。

攻击步骤：
1. 连接FireWire设备到目标主机
2. 通过DMA读取物理内存的特定偏移量
3. 搜索内存中的密钥、密码、加密密钥
4. 可选：通过DMA写入修改内存中的数据

**PCIe Hotplug DMA：**

支持热插拔的PCIe设备（如通过Thunderbolt或PCIe外接盒）在插入时会被系统枚举。如果IOMMU未启用，新设备可以立即发起DMA请求访问系统内存。

**IOMMU绕过技术：**

即使启用了IOMMU，攻击者仍可能通过以下方式绕过：
1. **DMA重映射不完整**：某些设备未被正确纳入IOMMU域
2. **ATS缓存投毒**：利用ATS功能缓存过时的翻译条目
3. **RmRR（Reserved Memory Region Reporting）漏洞**：某些BIOS错误地将设备配置为绕过IOMMU
4. **系统启动时间窗口**：IOMMU完全配置前存在短暂的DMA不受限窗口

---

## 4. 实战与示例

### 4.1 lspci 解析BAR空间映射

```bash
# 列出所有PCI设备及其BAR映射
lspci -v -s 02:00.0

# 输出示例：
# 02:00.0 Ethernet controller: Intel Corporation Ethernet Controller X710
#     Region 0: Memory at df000000 (64-bit, prefetchable) [size=16M]
#     Region 3: Memory at e1000000 (64-bit, prefetchable) [size=32M]

# 查看MMIO资源分配
lspci -v -s 02:00.0 | grep "Memory at"

# 查看所有设备的BAR大小（使用setpci）
setpci -s 02:00.0 BAR0.l
# 输出：df000000 0100000c（表示64-bit, prefetchable, 16MB）

# 解析BAR0的基地址和大小
# BAR0值：0xdf000000
# Bit 0: 0（内存空间）
# Bit 2:1: 10（64-bit地址）
# Bit 3: 1（Prefetchable）
# 写1到所有位再读回得到大小：size = ~(0x01000000 - 1) + 1 = 16MB
```

### 4.2 /proc/iomem 查看物理地址分配

```bash
# 查看物理内存映射
cat /proc/iomem | grep -i "pci\|mmio\|device"

# 输出示例：
# df000000-dfffffff : PCIe Bus 02:00.0 device (Intel X710 BAR0)
# e1000000-e2ffffff : PCIe Bus 02:00.0 device (Intel X710 BAR3)
# fed00000-fed03fff : PCH Device (LPC Controller)
# feee0000-feefffff : Local APIC

# 查看特定设备的MMIO范围
lspci -v | grep -A 20 "Ethernet" | grep "Memory at"

# 检查是否存在IOMMU组
ls -la /sys/kernel/iommu_groups/
# 列出所有IOMMU组
for g in $(ls /sys/kernel/iommu_groups/); do
    echo "IOMMU Group $g:"
    ls /sys/kernel/iommu_groups/$g/devices/
done
```

### 4.3 内核参数 intel_iommu=on 的配置

```bash
# 临时启用（GRUB编辑模式，重启失效）
# 在GRUB菜单按'e'，在linux行末尾添加：
# intel_iommu=on iommu=pt

# 永久启用
# Debian/Ubuntu:
sudo nano /etc/default/grub
# 修改：GRUB_CMDLINE_LINUX_DEFAULT="quiet splash intel_iommu=on iommu=pt"
sudo update-grub

# RHEL/CentOS/Fedora:
sudo grubby --update-kernel=ALL --args="intel_iommu=on iommu=pt"

# 验证IOMMU状态
dmesg | grep -i iommu
# 期望输出：
# [    0.000000] DMAR: IOMMU enabled
# [    0.xxx000] intel_iommu: using DMAR domain mode

# 查看IOMMU组详情
find /sys/kernel/iommu_groups/ -maxdepth 1 -type d | wc -l

# 强制设备进入IOMMU隔离（调试用）
echo 1 > /sys/kernel/iommu_groups/X/devices/Y/iommu_group/devices/Y/enable
```

### 4.4 简单的PCI设备DMA读写概念验证（框架代码）

```c
// dma_probe.c - 简单的PCIe设备DMA概念验证
// 用途：演示DMA传输的配置流程（仅用于学习研究）

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>

#define DMA_SIZE (4096)  // 4KB DMA缓冲区

static struct pci_dev *pdev;
static void *dma_virt;
static dma_addr_t dma_phys;

static irqreturn_t dma_irq_handler(int irq, void *data)
{
    pr_info("DMA transfer complete\n");
    // 检查设备中断状态寄存器（通过MMIO）
    // 清除中断
    return IRQ_HANDLED;
}

static int __init dma_init(void)
{
    int ret;

    // 查找目标PCIe设备
    pdev = pci_get_device(0x8086, 0x1521, NULL); // Intel X710
    if (!pdev) {
        pr_err("Device not found\n");
        return -ENODEV;
    }

    // 启用设备并设置Bus Master（允许DMA）
    ret = pci_enable_device(pdev);
    if (ret) return ret;

    pci_set_master(pdev); // 关键：设置Bus Master位，允许DMA

    // 分配DMA一致性缓冲区
    dma_virt = dma_alloc_coherent(&pdev->dev, DMA_SIZE,
                                   &dma_phys, GFP_KERNEL);
    if (!dma_virt) {
        pr_err("DMA buffer allocation failed\n");
        ret = -ENOMEM;
        goto err_disable;
    }

    // 通过MMIO配置DMA控制器
    // 假设BAR0映射了设备控制寄存器
    void __iomem *bar0 = ioremap(pci_resource_start(pdev, 0),
                                  pci_resource_len(pdev, 0));

    // 写入DMA源地址到设备寄存器
    writel(lower_32_bits(dma_phys), bar0 + 0x100); // DMA_SRC_ADDR_LO
    writel(upper_32_bits(dma_phys), bar0 + 0x104); // DMA_SRC_ADDR_HI

    // 写入传输长度并启动DMA
    writel(DMA_SIZE, bar0 + 0x108);   // DMA_LENGTH
    writel(0x1, bar0 + 0x10C);        // DMA_START (启动传输)

    pr_info("DMA configured: phys=0x%llx virt=%p\n",
            (u64)dma_phys, dma_virt);

    iounmap(bar0);
    return 0;

err_disable:
    pci_disable_device(pdev);
    return ret;
}

static void __exit dma_exit(void)
{
    if (dma_virt)
        dma_free_coherent(&pdev->dev, DMA_SIZE,
                          dma_virt, dma_phys);
    pci_disable_device(pdev);
}

module_init(dma_init);
module_exit(dma_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DMA Demo Module");
```

**安全研究注意事项：**
- 此代码仅用于理解DMA配置流程
- 在真实攻击中，恶意设备不需要CPU配合即可发起DMA
- IOMMU启用后，此代码中的DMA地址会被IOMMU重映射

---

## 5. 常见坑与避坑指南

### 5.1 MMIO区域的Cache属性（Uncacheable vs Write-Combining）

**问题：** MMIO区域的Cache属性设置错误导致数据不一致或性能问题。

**正确设置：**

| Cache属性 | 适用场景 | Linux设置方式 |
|-----------|---------|--------------|
| Uncacheable (UC) | 设备控制寄存器、中断状态 | `ioremap()`默认行为 |
| Write-Combining (WC) | Prefetchable BAR、帧缓冲区 | MTRR或PAT设置 |
| Write-Back (WB) | 仅用于真正可缓存的MMIO（罕见） | 需要特殊硬件支持 |
| Write-Through (WT) | 极少用于MMIO | 不推荐 |

**常见错误：**
- 使用`ioremap_wc()`映射控制寄存器→状态读取可能过时
- 使用`ioremap()`映射帧缓冲区→性能极差（每帧都写回内存）
- 未正确处理Write-Combining区域的写入合并→部分写入丢失

### 5.2 DMA一致性（coherent）与流式（streaming）映射

**两种DMA映射方式：**

| 特性 | 一致性DMA（Coherent） | 流式DMA（Streaming） |
|------|----------------------|---------------------|
| 同步 | 自动维护CPU与设备一致性 | 需要手动同步（sync操作） |
| 性能 | 较低（每次访问都同步） | 较高（批量同步优化） |
| 分配 | 启动时分配，生命周期长 | 随时分配，使用后立即释放 |
| 用途 | DMA描述符、设备控制结构 | 网络帧缓冲区、磁盘I/O |
| API | `dma_alloc_coherent()` | `dma_map_single()` / `dma_map_sg()` |

**流式DMA的同步陷阱：**

```c
// 错误：忘记同步导致设备看到过时数据
dma_map_single(dev, buf, size, DMA_TO_DEVICE);
// 修改buf内容...
// 缺少：dma_sync_single_for_device(dev, phys, size, DMA_TO_DEVICE);
// 设备可能读到旧数据

// 正确：在CPU修改后同步给设备
dma_map_single(dev, buf, size, DMA_TO_DEVICE);
memcpy(buf, data, size);
dma_sync_single_for_cpu(dev, phys, size, DMA_TO_DEVICE); // 正确方向！
```

### 5.3 IOMMU默认关闭的风险

**问题：** 多数Linux发行版默认不启用IOMMU，导致所有DMA设备可以访问任意物理内存。

**风险场景：**
- Thunderbolt设备：外部设备可直接DMA读写主机内存
- PCIe Hotplug：新插入的设备立即获得无限制的DMA权限
- 虚拟机：VF passthrough时如果不启用IOMMU，虚拟机可通过DMA攻击宿主机
- 内核DMA保护：Windows 10+的Kernel DMA Protection需要IOMMU支持

**解决方案：**
- 始终在内核参数中添加`intel_iommu=on`或`amd_iommu=on`
- 对于虚拟化环境，使用`iommu=pt`平衡安全与性能
- 对于需要直通的设备，创建专门的IOMMU域进行隔离

### 5.4 Thunderbolt DMA攻击的物理前提

**攻击条件清单：**
1. ✅ 物理访问：需要接触目标机器的Thunderbolt/USB-C端口（5-15秒）
2. ✅ 设备：需要特制的DMA攻击硬件（FPGA/专用芯片）
3. ❓ IOMMU状态：如果IOMMU启用，攻击受限
4. ❓ Thunderbolt安全级别：BIOS设置可能阻止未授权设备
5. ❓ 系统关机状态：关机时DMA不受保护（S3/S4休眠更危险）

**防御建议：**
- 启用IOMMU并验证：`dmesg | grep -i iommu`
- 设置Thunderbolt安全级别为"User Authorization"
- 在BIOS中禁用Thunderbolt外部DMA
- 物理安全：使用端口锁或禁用不需要的Thunderbolt端口

---

## 6. 知识关联

本文与以下知识模块形成强关联：

- **[[物理内存管理：分区分页分段演进史]]**：理解物理地址空间是理解MMIO/DMA地址映射的基础。MMIO区域位于物理地址空间的高端，DMA通常使用低4GB区域或通过IOMMU映射。

- **[[内存页保护属性：从RWX到NX-XD位]]**：页保护属性控制CPU对内存的访问权限，而MMIO的Cache属性控制CPU对设备内存的访问行为。两者共同构成内存访问控制的完整图景。

- **[[USB固件攻击与BadUSB原理]]**（06-物联网安全）：USB设备可通过DMA（如FireWire、Thunderbolt）或固件漏洞攻击主机系统。DMA攻击是USB安全的重要补充视角。

- **[[JTAG-SWD调试：OpenOCD实战]]**（06-物联网安全）：JTAG/SWD是另一种绕过CPU直接访问系统资源的途径。与DMA类似，JTAG提供了"物理后门"，防御思路也类似——需要硬件级的访问控制。

- **[[DMA与MMIO：外设访问内存的两种途径]]**（自身关联）：本文章本身作为DMA与MMIO技术的综合参考，可作为后续DMA安全研究、IOMMU配置、Thunderbolt安全分析的起点。

---

## 7. 参考资料

1. **PCI Express Base Specification Revision 5.0** — PCI-SIG官方规范，定义了BAR、配置空间、DMA等核心机制。 [https://pcisig.com/specifications/](https://pcisig.com/specifications/)

2. **Intel VT-d Specification** — Intel官方IOMMU技术文档，详细描述DMA重映射、中断重映射等机制。 [https://www.intel.com/content/www/us/en/developer/articles/technical/intel-virtualization-technology-for-directed-i-o.html](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-virtualization-technology-for-directed-i-o.html)

3. **Linux Kernel DMA Mapping Documentation** — 内核官方DMA映射指南，涵盖一致性映射和流式映射的正确使用。 [https://www.kernel.org/doc/html/latest/core-api/dma-api.html](https://www.kernel.org/doc/html/latest/core-api/dma-api.html)

4. **Thunderclap: Finding Speculative Execution Vulnerabilities in IOMMU (Black Hat 2019)** — Thunderbolt DMA攻击与IOMMU安全研究的经典论文。 [https://thunderclap.io/](https://thunderclap.io/)

5. **PCILeech: Direct Memory Access Attacks** — PCIe DMA攻击工具与研究平台，支持多种硬件接口。 [https://github.com/ufrisk/pcileech](https://github.com/ufrisk/pcileech)

6. **Linux IOMMU Subsystem Documentation** — 内核IOMMU子系统设计文档，包括Intel VT-d和AMD-Vi的集成。 [https://www.kernel.org/doc/html/latest/driver-api/iommu.html](https://www.kernel.org/doc/html/latest/driver-api/iommu.html)

7. **Rosetta for IOMMUs: IOMMU技术的全面综述** — 学术论文，系统性地分析了IOMMU的安全模型和已知攻击向量。 [https://www.usenix.org/system/files/sec21-leberhand.pdf](https://www.usenix.org/system/files/sec21-leberhand.pdf)
