---
title: 内存页保护属性：从RWX到NX-XD位
category: 00-基础通用/02-内存与存储体系
tags: [NX, DEP, W^X, 内存保护, 安全机制]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# 内存页保护属性：从RWX到NX-XD位

> **合规声明**：本文涉及的攻防视角仅用于授权测试与学习研究，禁止用于任何未授权目标。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 内存页保护属性是CPU MMU（Memory Management Unit，内存管理单元）通过PTE（Page Table Entry，页表项）中的标志位，对每个4KB/2MB/1GB内存页施加的读（Read）、写（Write）、执行（Execute）权限控制机制 |
| 核心用途 | 防止恶意代码注入后在数据页执行、阻止ROP/JOP等代码复用攻击、实现W^X安全策略、支持数据执行保护（DEP） |
| 关键参数 | R/W位（bit 1）控制读写、NX/XD位（bit 63）控制执行权限、User/Supervisor位（bit 2）区分用户态与内核态 |
| 常见风险 | mprotect滥用导致RWX页产生、JIT编译器的W^X困境、Shared Memory权限冲突、绕过NX的ROP链攻击 |
| 关联知识 | [[虚拟内存原理：多级页表与地址翻译]]、[[栈溢出原理：覆盖返回地址到控制流劫持]]、[[ROP技术详解：gadget搜索与链构造]] |

## 1. 概述

### 1.1 内存页保护的本质定义

内存页保护属性（Memory Page Protection Attributes）是现代操作系统和CPU协同工作的核心安全机制。每个虚拟内存页在页表中都有对应的PTE，其中包含多个标志位来定义该页的访问权限。这些标志位由CPU的MMU在每次内存访问时进行硬件级检查，任何违反权限的访问都会触发Page Fault（缺页异常），进而由操作系统决定如何处理——通常会向违规进程发送SIGSEGV（Linux）或EXCEPTION_ACCESS_VIOLATION（Windows）信号。

页保护的核心理念可以概括为：**并非所有内存页都允许所有类型的访问**。在最小权限原则（Principle of Least Privilege）指导下，每个页面只被赋予完成其功能所需的最小权限集。例如，代码段（.text）只需读和执行权限，不需要写权限；数据段（.data/.bss）只需读写权限，不需要执行权限；而堆和栈通常只需要读写权限。

这种细粒度的权限控制使得即使攻击者成功将shellcode注入到进程的某个数据页中，只要该页没有执行权限，CPU就会在尝试执行时拒绝访问，从而阻止攻击。

### 1.2 知识体系定位

内存页保护属性在安全知识体系中处于基础与核心的交叉点。向上，它直接服务于操作系统安全机制的设计与实现；向下，它深刻影响着二进制安全（Binary Security）和漏洞利用（Exploitation）的攻防格局。

从攻击视角看，内存页保护是漏洞利用必须跨越的第一道关卡。传统的栈溢出攻击利用RWX（Read-Write-Execute，可读可写可执行）权限的内存页，通过覆盖返回地址跳转到注入的shellcode。NX位的引入直接摧毁了这一经典攻击路径，迫使攻击者转向ROP、JOP、COP等代码复用（Code Reuse）技术，深刻改变了二进制安全的攻防格局。

从防御视角看，NX/DEP只是内存保护的第一层。SMEP（Supervisor Mode Execution Prevention）、SMAP（Supervisor Mode Access Prevention）进一步保护内核免受用户态页面的代码执行和数据访问；CET（Control-flow Enforcement Technology）和Shadow Stack则从控制流完整性（Control-Flow Integrity）角度提供更深层的保护。理解这些机制的演进逻辑，对于安全架构设计和渗透测试都至关重要。

### 1.3 核心应用场景

内存页保护属性的应用场景涵盖系统安全的方方面面：

**代码注入防护**：最直接的应用场景。通过将代码段标记为不可写、数据段标记为不可执行（W^X策略），阻止攻击者在进程内存中注入并执行恶意代码。这在Web服务器、网络服务等高暴露面的程序中尤为重要。

**数据执行保护（DEP）**：Windows XP SP2引入的NX技术，通过NX位保护栈、堆等数据区域不被当作代码执行。Linux下对应的能力由Exec-Shield补丁（早期）和内核CONFIG_X86 NX/PAGE_NX_ENABLE配置提供。

**共享内存安全**：多个进程共享的内存区域（如mmap的匿名映射或文件映射）需要精确设置保护属性。共享代码库需要RX权限，共享数据需要RW权限，不允许出现RWX权限。

**JIT编译安全**：Java、JavaScript等JIT（Just-In-Time，即时编译）编译器需要在运行时生成机器码。安全的JIT实现严格遵循W^X：先分配RW页，写入编译后的机器码，再通过mprotect将页权限改为RX，最后跳转执行。

**内核保护**：现代操作系统内核利用NX位防止用户态代码在内核态执行，利用SMEP/SMAP防止内核代码访问用户态数据。这是纵深防御（Defense in Depth）策略的重要组成部分。

### 1.4 保护机制演进简史

| 年代 | 机制 | 关键特性 | 对抗的威胁 |
|------|------|----------|------------|
| 1995 | x86段保护（Segment Protection） | 基于段描述符的DPL权限检查 | 用户态越权访问内核段 |
| 2001 | PaX PAGEEXEC | 软件模拟NX，对不可执行页执行时触发#PF | 栈/堆代码注入执行 |
| 2004 | x86 PAE NX bit | 硬件NX位（PTE bit 63），Intel提出 | 栈/堆代码注入执行 |
| 2005 | AMD NX bit | AMD64架构原生支持NX | 同上 |
| 2006 | Intel VT-x/EPT | 硬件虚拟化支持 | 虚拟机逃逸 |
| 2010 | Windows DEP全面开启 | NX扩展为Data Execution Prevention | 用户态代码注入 |
| 2011 | ARM XN bit | ARMv6/v7不可执行位 | 移动端代码注入 |
| 2012 | SMEP（Intel） | 内核不可执行用户态页 | 内核态代码复用 |
| 2014 | SMAP（Intel） | 内核不可访问用户态数据 | 内核数据泄露/篡改 |
| 2015 | PAN（ARMv8.1） | 类似SMAP的ARM实现 | 内核态用户态数据访问 |
| 2016 | Intel CET | Shadow Stack + Indirect Branch Tracking | ROP/JOP攻击 |
| 2018 | ARM BTI/MTE | Branch Target Identification + Memory Tagging | 间接跳转攻击 |
| 2019 | Windows HVCI | 基于Hyper-V的代码完整性验证 | 内核代码篡改 |
| 2020 | Intel LASS | Linear Address Space Separation | 内核/用户态地址空间混淆 |
| 2022 | ARM CCA | Confidential Compute Architecture | 安全世界数据保护 |

## 2. 核心原理

### 2.1 内存保护的粒度：页级保护 vs 段级保护

x86架构历史上支持两种内存保护粒度：段级保护（Segment-level Protection）和页级保护（Page-level Protection）。

段级保护基于GDT（Global Descriptor Table，全局描述符表）和LDT（Local Descriptor Table，局部描述符表）中的段描述符。每个段描述符包含DPL（Descriptor Privilege Level，描述符特权级）、段基址、段界限和类型位（如Code/Data、Read/Write等）。在Protected Mode下，CPU会在每次内存访问时检查CPL（Current Privilege Level，当前特权级）是否满足DPL要求。段保护的粒度是整个段（最大4GB），粒度太粗，难以实现精确的单页控制。

页级保护在paging机制启用后生效，是现代操作系统使用的主要保护方式。每个PTE关联一个固定大小的页（通常4KB），页内所有地址共享相同的保护属性。32位x86的PTE为32位宽，64位模式下（PAE或long mode）PTE扩展为64位。页级保护的优势在于粒度足够细，且由MMU硬件直接检查，性能开销极低。

在现代操作系统中，段保护和页保护同时生效，但段保护的作用已大幅弱化。Linux和Windows在保护模式下将所有用户段的基址设为0、界限设为最大值，使段保护形同虚设，完全依赖页级保护。这简化了安全模型：只需关注PTE中的保护位即可。

```
x86-64 PTE 结构（64位）
┌────────────────────────────────────────────────────────────────────────────┐
│ Bit 63  │ NX/XD位：1=不可执行，0=可执行                                    │
│ Bit 62-52│ Available（操作系统自用）                                        │
│ Bit 51-12│ 物理页帧号（PFN, Physical Frame Number）                        │
│ Bit 11   │ Global（全局页，TLB刷新时不删除）                                │
│ Bit 10   │ Available                                                        │
│ Bit 9    │ Available                                                        │
│ Bit 8    │ PAT（Page Attribute Table索引）                                  │
│ Bit 7    │ Dirty（脏页：已被写过）                                          │
│ Bit 6    │ Accessed（已访问：被读或写过）                                    │
│ Bit 5    │ PCD（Page Cache Disable）                                        │
│ Bit 4    │ PWT（Page Write-Through）                                        │
│ Bit 3    │ U/S（User/Supervisor）：0=仅内核，1=用户可访问                   │
│ Bit 2    │ R/W（Read/Write）：0=只读，1=可读写                              │
│ Bit 1    │ PWT? 不，bit1是dirty的bit6，这里是R/W的bit1... 不对              │
│ Bit 0    │ Present（页面是否在物理内存中）                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

更精确的位图如下：

```
63    62                   52 51                                      12 11 10 9 8   7   6   5   4   3   2   1   0
┌───┬────────────────────────┬──────────────────────────────────────────┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│NX │     Available          │              物理页帧号（PFN）           │ G │ A │ D │ P │ P │ P │ A │ D │ U │ R │ P │
│/XD│     (OS used)          │              (bits 51-12)               │   │ v │ i │ A │ C │ W │ V │ / │ / │ / │ r │
│   │                        │                                          │   │ l │ r │ T │ D │ T │ L │ S │ W │ e │ e │
└───┴────────────────────────┴──────────────────────────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘

与安全最相关的位（加粗）：
  bit 63: NX/XD      → 执行权限控制（本文核心）
  bit 3:  U/S         → 用户/内核权限
  bit 2:  R/W         → 读写权限控制
  bit 0:  Present     → 页面是否存在于物理内存
```

### 2.2 PTE保护位详解

PTE中的每个标志位都有明确的硬件语义，CPU的MMU在每次地址翻译时都会检查这些位。以下逐一详解与安全直接相关的保护位：

**Present位（bit 0）**：标记该页是否当前存在于物理内存中。当操作系统将页面换出到swap空间时，此位被清零。此时访问该页会触发Page Fault，操作系统在handler中将页面换回并重新设置Present位。从安全角度看，Present=0的页面无法被访问，可用于实现按需分配（Demand Paging）和copy-on-write（COW）语义。

**R/W位（bit 1）**：控制读写权限。R/W=0表示只读（Read-Only），R/W=1表示可读写（Read-Write）。对于代码段，通常设置为R/W=0（只读），防止运行时被意外或恶意修改。对于数据段、堆和栈，通常设置为R/W=1。当CPU检测到对R/W=0页面的写操作时，会触发Page Fault。Linux内核利用COW机制实现fork()和mmap(MAP_PRIVATE)的高效实现。

**U/S位（bit 3）**：User/Supervisor位。U/S=0表示该页仅内核态（Ring 0）可访问；U/S=1表示用户态（Ring 3）也可访问。这是操作系统隔离用户空间和内核空间的基本机制。内核代码和数据页设置U/S=0，用户态进程无法直接访问这些页。任何用户态程序尝试访问U/S=0的页都会触发#PF，且错误码中User/Supervisor位=0表示是内核页违规。

**NX/XD位（bit 63）**：No-eXecute / eXecute Disable位。这是本文的核心位。NX=1表示该页不可执行（Non-Executable），CPU禁止从该页取指令。NX=0表示该页可执行。在传统32位PTE中没有此位，Intel在引入PAE（Physical Address Extension）后将PTE扩展到64位，利用bit 63作为NX位。在x86-64 long mode下NX位天然可用。当CPU检测到从NX=1的页取指令时，会触发#PF，错误码中Instruction Fetch位=1。

```
内存保护属性组合（典型配置）
┌──────────────────┬─────┬─────┬─────┬────────────────────────────┐
│ 区域              │ R/W │ NX  │ U/S │ 实际权限                    │
├──────────────────┼─────┼─────┼─────┼────────────────────────────┤
│ .text（代码段）   │  0  │  0  │  1  │ R-X（只读可执行）           │
│ .rodata（只读数据）│  0  │  1  │  1  │ R--（只读不可执行）         │
│ .data（已初始化） │  1  │  1  │  1  │ RW-（可读写不可执行）       │
│ .bss（未初始化）  │  1  │  1  │  1  │ RW-（可读写不可执行）       │
│ Heap（堆）        │  1  │  1  │  1  │ RW-（可读写不可执行）       │
│ Stack（栈）       │  1  │  1  │  1  │ RW-（可读写不可执行）       │
│ [vdso]            │  0  │  0  │  1  │ R-X（只读可执行）           │
│ libc.so（共享库） │  0  │  0  │  1  │ R-X（只读可执行）           │
│ 传统漏洞利用窗口  │  1  │  0  │  1  │ RWX（极危险，现代OS已禁用） │
└──────────────────┴─────┴─────┴─────┴────────────────────────────┘
```

### 2.3 W^X原则：写与执行互斥的安全哲学

W^X（Write XOR Execute）是一种内存安全策略，其核心思想是：**任何内存页要么可写，要么可执行，但不能同时可写和可执行**。这用XOR逻辑运算来表达：如果W=1则X必须为0，如果X=1则W必须为0。

W^X的名称来源于Bitwise XOR运算符，其中^表示异或。在逻辑上，W和X不能同时为1，这意味着RWX（读-写-执行）权限的页面是被禁止的。这种策略直接阻断了经典代码注入攻击：攻击者无法同时写入shellcode到某个页并执行它。

然而，W^X并非完美的银弹。在实际系统中，存在一些RWX页面的合法需求：

1. **JIT编译器**：Java HotSpot、V8 JavaScript引擎等需要动态生成机器码。安全的实现通过严格的mprotect调用序列来临时实现W→RW→W^X→RX的权限切换。
2. **动态链接器**：ld-linux.so在加载共享库时可能需要修改GOT（Global Offset Table），该区域可能需要RW权限，同时PLT（Procedure Linkage Table）需要RX权限。现代实现将GOT和PLT分离到不同的页以满足W^X。
3. **调试器和热补丁**：调试器（如gdb）在设置断点时需要写入代码页，这与W^X冲突。某些系统允许调试器使用mprotect临时解除NX保护。

从防御演进看，W^X是NX/DEP的理论基础，但W^X绕过技术（ROP、JOP、COP）的发展也推动了更深层防御机制（CET、Shadow Stack、VBS/HVCI）的诞生。W^X本质上提高了攻击成本，将攻击从"直接注入执行"推高到"代码复用"，但并未完全消除攻击可能性。

### 2.4 NX/DEP：Windows数据执行保护

NX（No-eXecute）是AMD/Intel在硬件层面引入的执行权限控制机制。在Windows平台上，这一技术被封装为DEP（Data Execution Prevention，数据执行保护），提供两种模式：

**Opt-in DEP（optin）**：仅对明确标记了IMAGE_DLLCHARACTERISTICS_NX_COMPAT的可执行文件启用DEP。这是Windows XP SP2的默认行为，兼容性好但保护不全面。

**Opt-out DEP（optout）**：对除明确排除的程序外的所有进程启用DEP。通过bcdedit /set nx AlwaysOn设置全局启用。Windows Server 2003 SP1+和Windows Vista+默认使用此模式。

DEP的工作原理与硬件NX位完全一致：当进程的某个页面PTE的NX位被设置后，CPU在该页执行指令时会触发异常。Windows内核在异常处理中区分合法执行和恶意执行，对于非法执行终止进程。

然而，DEP（即硬件NX）可以被绕过。经典的return-to-libc攻击不注入代码，而是将控制流重定向到libc中已有的函数（如system()），该函数所在的代码页有RX权限，完全合法。这推动了ASLR（Address Space Layout Randomization，地址空间布局随机化）的引入——通过随机化libc等模块的基址，使攻击者难以预测目标函数的地址。NX + ASLR的组合至今仍是内存安全的基础防线。

```
DEP/NX的攻防逻辑
┌───────────────────────────────────────────────────────────────┐
│  攻击者发现栈溢出漏洞                                          │
│         │                                                     │
│         ▼                                                     │
│  尝试将shellcode写入栈/堆并跳转执行                            │
│         │                                                     │
│         ▼                                                     │
│  CPU检测到目标页NX=1，拒绝执行 → #PF                          │
│         │                                                     │
│         ▼                                                     │
│  攻击者转向：return-to-libc / ROP / JOP                       │
│         │                                                     │
│         ▼                                                     │
│  防御者引入ASLR + Stack Canary + CET                          │
└───────────────────────────────────────────────────────────────┘
```

### 2.5 NX bit在不同架构的实现

NX位并非x86独有，主流CPU架构都有对应的实现，但命名和细节各不相同：

| 架构 | 位名称 | PTE中的位置 | 引入时间 | 特殊说明 |
|------|--------|------------|----------|----------|
| x86（PAE） | NX bit | PTE bit 63 | 2004（Intel）、2005（AMD） | 需启用PAE模式，32位页表扩展为64位 |
| x86-64 | NX bit | PTE bit 63 | 2003（AMD64） | long mode天然支持，无需PAE |
| ARMv7 | XN bit | L1/L2描述符bit 0 | ARMv6+ | Extension Never，区分于Thumb指令集 |
| ARMv8 (AArch64) | UXN/PXN | L3描述符bits 54/53 | ARMv8.0 | UXN=用户态不可执行，PXN=特权态不可执行 |
| ARMv8.1 | PAN | 独立系统寄存器 | ARMv8.1 | Privileged Access Never，类似SMAP |
| RISC-V | 无可执行位 | — | — | 依赖PMA/PMP硬件机制，软件层通过PMP寄存器控制 |
| MIPS | 无可执行位 | — | — | 依赖kseg0/kseg1段属性，软件模拟NX |
| POWER | No-Execute | 页表描述符bit 3 | Power ISA | 类似x86 NX |
| SPARC | No-Execute | 页表描述符bit 64 | UltraSPARC | 早期SPARC无此位 |

ARMv8的双NX位（UXN/PXN）值得特别说明。UXN（Unprivileged eXecute Never）阻止用户态代码执行该页，PXN（Privileged eXecute Never）阻止内核态代码执行该页。这种设计允许更精细的控制：例如可以将某个页标记为仅用户态可执行（UXN=0, PXN=1），或者仅内核态可执行（UXN=1, PXN=0），这是x86 NX位无法直接做到的。

## 3. 详细知识点

### 3.1 x86内存保护机制演进：段保护 → PAE NX → SMEP/SMAP

x86架构的内存保护经历了从简单到复杂的演进过程，每个阶段都是对前一阶段不足的弥补。

**第一阶段：段保护（Protected Mode, 1985+）**

80386引入的Protected Mode为每个段定义了DPL（0-3），CPL低于DPL的代码无法访问该段。段保护的粒度是段（最大4GB），一个段内的所有地址共享相同的权限。由于粒度太粗，一个4GB的段内无法区分代码和数据，段保护在实践中主要用于区分用户态和内核态的段，无法实现W^X。

**第二阶段：PAE NX位（2004+）**

Intel在Pentium III的P6微架构中引入PAE模式，将PTE从32位扩展到64位，利用bit 63作为NX位。这提供了页粒度的执行权限控制，直接支持W^X策略。启用PAE需要操作系统修改页表处理代码，并且在32位Linux中启用NX会减少可用的虚拟地址空间（从4GB降到约3.5GB，因为PAE使用三级页表）。

**第三阶段：SMEP（2011+）**

SMEP（Supervisor Mode Execution Prevention）是Intel在Ivy Bridge（第二代酷睿）中引入的硬件特性。它阻止Ring 0内核代码执行标记为用户态（U/S=1）的页面。在SMEP之前，内核中的函数指针如果被攻击者控制，可以指向用户态的shellcode，而内核态有RX权限执行用户页。SMEP通过CR4寄存器的bit 20启用，一旦启用，内核执行用户页的代码会触发#PF。

**第四阶段：SMAP（2014+）**

SMAP（Supervisor Mode Access Prevention）是Intel在Haswell（第四代酷睿）中引入的进一步加固。它阻止Ring 0内核代码读写标记为用户态（U/S=1）的页面（除非AC flag被设置）。这防御了内核通过用户态指针进行数据泄露和篡改的攻击。SMAP通过CR4寄存器的bit 21启用。内核可以通过临时清除AC flag来合法访问用户态数据（使用copy_from_user/copy_to_user）。

```
x86保护机制演进的防御能力
┌──────────────┬─────────────────┬─────────────────────┬──────────────────┐
│ 机制          │ 防御目标         │ 攻击绕过方式         │ 粒度              │
├──────────────┼─────────────────┼─────────────────────┼──────────────────┤
│ 段保护        │ 用户态越权       │ 调整段选择子          │ 段级（粗粒度）    │
│ PAE NX       │ 数据区代码执行   │ return-to-libc/ROP   │ 页级（4KB）      │
│ SMEP         │ 内核执行用户页   │ 构造内核页ROP链       │ 页级（4KB）      │
│ SMAP         │ 内核访问用户数据 │ 利用AC flag临时解除   │ 页级（4KB）      │
│ CET          │ ROP/JOP攻击     │ ret2csu等高级绕过     │ 控制流级         │
└──────────────┴─────────────────┴─────────────────────┴──────────────────┘
```

### 3.2 ARM内存保护：PXN/UXN与ARMv8.1 PAN

ARM架构的内存保护机制从ARMv6开始引入XN位，到ARMv8/ARMv9已经发展出一套完整的多层保护体系。

ARMv7的页表描述符中，XN（eXecute Never）位位于L1描述符的bit 0和L2描述符的bit 0。当XN=1时，该页不可执行。ARMv7区分了Section（1MB）和Small Page（4KB）两种粒度，XN位在两种粒度下都有效。与x86不同的是，ARM的XN位可以直接在页表描述符中设置，而x86需要启用PAE或long mode才能使用NX位。

ARMv8（AArch64）引入了双不可执行位：UXN（Unprivileged eXecute Never，bit 54）和PXN（Privileged eXecute Never，bit 53）。这种设计使得ARM可以独立控制用户态和内核态的执行权限，提供了比x86 NX更细粒度的控制。

| ARMv8页表属性位 | Bit位置 | 功能 | 典型配置 |
|----------------|---------|------|----------|
| UXN | bit 54 | 用户态不可执行 | 代码段UXN=0，数据段UXN=1 |
| PXN | bit 53 | 内核态不可执行 | 内核代码PXN=0，用户数据PXN=1 |
| AP[2:1] | bits 7,6 | 访问权限 | 读写/只读/无访问 |
| AF | bit 10 | 访问标志 | 按需设置 |
| SH[1:0] | bits 9,8 | 共享属性 | 非共享/内部共享 |

ARMv8.1引入的PAN（Privileged Access Never）类似于x86的SMAP，但实现方式不同。PAN通过系统寄存器控制，当PAN=1时，内核态代码（EL1）无法直接通过Load/Store指令访问用户态（EL0）的虚拟地址空间。内核必须使用显式的user access操作（如copy_from_user）来临时解除PAN限制。ARMv8.3的FEAT_UAO（User Access Override）进一步允许通过指令前缀（LDTR/STTR）来控制PAN的临时解除。

ARMv8.5的MTE（Memory Tagging Extension）则从另一个维度增强内存安全：它为每个16字节内存标签（tag）附加4位元数据，用于检测Use-After-Free（UAF）和Buffer Overflow（缓冲区溢出）。MTE与NX/UXN/PXN协同工作，提供了更全面的内存保护。

### 3.3 mmap与mprotect：用户态控制页保护属性

在Linux/POSIX系统中，用户态程序通过两个核心系统调用来管理内存页保护属性：mmap和mprotect。

**mmap**用于创建新的内存映射，其protect参数指定初始保护属性：

```c
#include <sys/mman.h>

// 典型mmap调用：分配RW页（用于数据）
void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// 分配RX页（用于代码，危险但合法）
void *code = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// 分配RWX页（应尽量避免）
void *rwx = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

**mprotect**用于修改已存在映射的保护属性：

```c
#include <sys/mman.h>

// 典型安全JIT模式：先RW写入代码，再改为RX执行
void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// 写入编译后的机器码
memcpy(p, shellcode, shellcode_len);

// 切换为RX（不可写，可执行）
mprotect(p, 4096, PROT_READ | PROT_EXEC);

// 跳转执行
((void(*)())p)();
```

在安全审计中，一个关键关注点是：是否存在RWX权限的mmap/mprotect调用。如果程序调用mmap时指定了PROT_READ | PROT_WRITE | PROT_EXEC，或者先创建RW页再通过mprotect改为RWX，这都是严重的安全隐患。静态分析工具如grsecurity的PaX补丁中的MPROTECT功能可以检测和阻止此类行为。

Windows平台对应的API是VirtualAlloc/VirtualProtect。VirtualAlloc的flProtect参数可指定PAGE_READWRITE、PAGE_EXECUTE_READ等；VirtualProtect用于修改已有内存区域的保护属性。Windows的NtQueryVirtualMemory和VirtualQuery可以查询指定地址的当前保护属性。

安全敏感的mprotect/mmap审计要点：

1. 检查是否允许RWX权限（应禁止）。
2. 检查mprotect是否在代码注入路径上被调用（如在接收到网络数据后）。
3. 检查mmap的MAP_JIT标志使用是否符合W^X流程。
4. 检查是否通过mmap映射了可执行文件（PROT_EXEC + MAP_PRIVATE）。

### 3.4 W^X绕过技术历史：ROP、JOP、COP、BROP

NX/DEP的引入将经典代码注入攻击推入了"后NX时代"。攻击者转向利用程序自身已有的代码片段（gadget），通过精心构造的控制流劫持来执行恶意操作。以下按时间顺序梳理主要的W^X绕过技术：

**return-to-libc（1997）**

由Nergal在Phrack杂志发表。核心思想：不注入任何代码，将栈上的返回地址覆盖为libc中system()函数的地址，同时构造好参数。这完全绕过了NX，因为system()在libc的代码段中，具有RX权限。攻击的局限性在于需要知道libc的加载地址，这正是ASLR所防御的。

**ROP - Return-Oriented Programming（2007）**

由Hovav Shacham在CCS 2007发表。ROP将return-to-libc的思想泛化：不再局限于完整的libc函数，而是利用以ret指令结尾的短代码片段（gadget）。每个gadget执行一小段有用操作（如mov eax, [ebx]; ret），通过栈上的返回地址链将多个gadget串联起来。x86架构的变长指令集天然为ROP提供了丰富的gadget——即使在非预期的指令对齐处，也可能解码出有用的指令序列。

```
ROP链示意
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ gadget 1 │───→│ gadget 2 │───→│ gadget 3 │───→│ gadget N │
│ mov eax,  │    │ pop ebx; │    │ int 0x80 │    │ ...     │
│ [esp+4]; │    │ ret      │    │ (syscall)│    │         │
│ ret      │    │          │    │          │    │         │
└─────────┘    └─────────┘    └─────────┘    └─────────┘
     ↑                                                     │
     └─────────── 栈上返回地址链串联 ───────────────────────┘
```

**JOP - Jump-Oriented Programming（2011）**

由Bletsch等人提出。JOP不依赖ret指令，而是利用间接跳转指令（jmp [reg]、call [reg]等）作为gadget的结束。JOP绕过了基于ret指令的防御（如shadow stack），因为控制流通过间接跳转而非ret传递。JOP的gadget选择比ROP更受限，但足以构造图灵完备的计算。

**COP - Counter-Oriented Programming（2014）**

由Davi等人提出。COP利用x86的LOOP指令和相关计数器操作构造gadget链。COP的gadget以loop指令结束，每次循环修改RCX寄存器并跳转回循环头。这提供了另一种绕过ret指令检测的方式。

**BROP - Blind ROP（2014）**

由Bittau等人提出。BROP允许攻击者在完全不知道目标程序二进制内容的情况下构造ROP链。通过栈溢出的探测，攻击者可以逐字节扫描找到以下gadget：pop rdi; ret（设置参数）、ret（纯滑行）、syscall; ret（系统调用）。BROP利用了栈溢出时程序崩溃后重启的行为，在每次崩溃中探测一位信息。

**COP/CFI绕过的持续演进**

2016年后的绕过技术更加多样。ret2csu利用__libc_csu_init中的通用gadget，可以设置rdi/rsi/rdx/rcx/r8/r9六个参数寄存器。Dirty COW（CVE-2016-5195）则从内核层面利用COW竞态条件绕过页保护。Spectre/Meltdown（2018）通过推测执行绕过SMAP/SMEP等硬件保护机制。

### 3.5 CET（Control-flow Enforcement Technology）与Shadow Stack

CET是Intel在2016年提出、2020年在Tiger Lake架构中首次实现的硬件级控制流完整性（CFI）保护。CET包含两个子技术：Shadow Stack和Indirect Branch Tracking（IBT）。

**Shadow Stack（影子栈）**

传统栈只有一个，保存函数返回地址。Shadow Stack维护第二个只读栈，专门保存返回地址的副本。当函数通过call指令调用时，返回地址同时被压入主栈和影子栈。当函数通过ret返回时，CPU自动比较主栈和影子栈顶部的返回地址：如果一致，正常返回；如果不一致（说明返回地址被篡改），触发#CP（Control Protection Exception）。

影子栈完全由硬件管理，影子栈所在的物理页对软件只读。操作系统在进程创建时分配影子栈，在上下文切换时切换CSTP（Shadow Stack Base Pointer）寄存器。用户态程序无法修改影子栈内容，这使得传统的栈溢出覆盖返回地址的攻击方式完全失效。

```
Shadow Stack工作原理
┌──────────────────────────────────────────────────────┐
│  函数A调用函数B                                       │
│    │                                                 │
│    ├── 主栈压入返回地址0x401234                       │
│    └── 影子栈压入返回地址0x401234（硬件自动）         │
│                                                      │
│  函数B返回时                                          │
│    │                                                 │
│    ├── 主栈弹出0x401234（可能被攻击者篡改为0x7fff5678）│
│    └── 影子栈弹出0x401234（硬件保护，不可篡改）       │
│                                                      │
│  CPU比较：0x401234 ≠ 0x7fff5678 → #CP异常！          │
└──────────────────────────────────────────────────────┘
```

**Indirect Branch Tracking（IBT）**

IBT防御JOP等间接跳转攻击。它要求所有间接跳转（jmp [reg]、call [reg]）的目标地址必须指向endbr64/endbr32指令。endbr64是一条NOP-like指令（不改变程序状态），放在合法的间接跳转目标处作为标记。如果间接跳转到非endbr64的位置，CPU触发#CP异常。

IBT的保护是粗粒度的：它只检查目标是否以endbr64标记，不检查跳转路径是否符合预期的CFG（Control-Flow Graph）。更细粒度的CFI保护需要Intel CET的后续演进（如ENDBRANCH指令序列检测）或软件实现的CFG。

**Shadow Stack的攻击绕过**

即使有了Shadow Stack，攻击者仍有绕过手段：

1. **ret2csu**：利用__libc_csu_init中的gadget调用__libc_csu_gadget，通过pop rbx/pop rbp控制寄存器，间接执行恶意操作。返回地址仍然合法，Shadow Stack不会检测到异常。
2. **Sigreturn-Oriented Programming (SROP)**：利用sigreturn系统调用恢复整个寄存器上下文（包括RSP和RIP），可以将栈指针和指令指针都设置为任意值，完全绕过Shadow Stack。
3. **在合法ret目标处劫持控制流**：如果攻击者可以控制函数参数（如通过ROP设置rdi），即使返回地址合法，也可以通过函数内的逻辑（如虚函数调用、函数指针间接调用）实现恶意目的。

### 3.6 VBS/HVCI：虚拟化层面的代码完整性

VBS（Virtualization-based Security，基于虚拟化的安全）和HVCI（Hypervisor-Enforced Code Integrity，虚拟机监控器强制代码完整性）是微软在Windows 10/11中引入的内核级安全架构，利用Hyper-V虚拟机监控器（VMM, Virtual Machine Monitor）来保护关键的内核数据和代码。

**VBS的架构原理**

VBS利用硬件虚拟化（VT-x/AMD-V）将系统分为两个世界：Normal World（正常世界，运行Windows内核和用户态）和Secure World（安全世界，运行VTL 1，即Secure Kernel）。VTL 0（正常世界）的所有内存操作都由VTL 1的Secure Kernel和Hypervisor进行二次检查。

```
VBS架构层级
┌─────────────────────────────────────────────┐
│  用户态应用（Ring 3, VTL 0）                  │
├─────────────────────────────────────────────┤
│  Windows内核（Ring 0, VTL 0）                │
├─────────────────────────────────────────────┤
│  Secure Kernel（VTL 1）                      │
├─────────────────────────────────────────────┤
│  Hypervisor（Ring -1, 所有VTL）              │
├─────────────────────────────────────────────┤
│  硬件（VT-x / AMD-V / EPT / NPT）           │
└─────────────────────────────────────────────┘
```

**HVCI的工作原理**

HVCI是VBS的一个具体应用。它通过Hypervisor的EPT/NPT（Extended/Nested Page Table，扩展/嵌套页表）机制，将内核代码页标记为只读（RO）+不可执行禁止（即RX，允许读取和执行，不允许修改）。任何尝试修改内核代码的操作（如patchguard检测到的内核代码修改、rootkit安装hook）都会被Hypervisor在EPT层面拦截。

HVCI的保护粒度不依赖于传统的PTE R/W位，而是在EPT/NPT层面实施的"二级页表"检查。即使攻击者获得了VTL 0内核的最高权限（Ring 0, CR0.WP可以绕过），也无法修改被Hypervisor保护的内核代码页。

**HVCI的保护范围**

- 内核代码段（.text）：强制RX，不可写。
- 关键内核数据结构：通过EPT控制读写权限。
- 驱动程序加载：所有内核驱动必须通过WHQL签名验证，由VTL 1的Secure Kernel执行。
- 断点保护：禁止在受保护的内核页上设置硬件断点（DR0-DR3）。

HVCI的性能开销主要来自两次页表翻译（Guest PTE → EPT → 物理地址）和VTL切换。在实际测量中，HVCI的开销通常在1-3%之间，对于大多数工作负载可以接受。

### 3.7 安全视角：W^X绕过、return-to-libc、ret2dlresolve

从纯粹的安全攻防视角来看，NX/W^X保护的核心博弈可以总结为：**防御者通过页保护限制代码执行位置，攻击者通过代码复用或元数据劫持绕过限制**。以下是三种关键绕过技术的深入分析：

**W^X绕过的根本困境**

W^X的安全假设是：程序不会同时需要写入和执行同一块内存。但程序的某些功能（JIT、动态加载、调试）确实需要这种能力。攻击者利用这些合法功能来创建RWX窗口。

在实际利用中，攻击者首先通过信息泄露（如格式化字符串漏洞、信息泄露bug）获取libc基址或栈地址，从而绕过ASLR。然后，利用已有的RWX页面（如某些存在设计缺陷的程序）或通过mprotect系统调用将目标页改为RWX。mprotect本身可以通过ROP链调用：构造`mprotect(page_aligned_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC)`的参数，通过syscall执行。

**return-to-libc的利用细节**

经典的return-to-libc攻击在64位系统上的参数传递需要遵循System V AMD64 ABI：前六个整数参数通过rdi, rsi, rdx, rcx, r8, r9传递。攻击者需要找到pop rdi; ret等gadget来设置参数寄存器。

典型的system()调用ROP链构造：
1. pop rdi; ret → 指向"/bin/sh"字符串的地址
2. system()函数的地址（需ASLR绕过）

如果system()地址未知（ASLR保护），攻击者可以使用ret2plt技巧：通过PLT中的system@PLT条目间接调用，因为PLT地址在PIE（Position Independent Executable）关闭时是固定的。

**ret2dlresolve的高级利用**

ret2dlresolve是return-to-libc的高级变体，它不需要知道libc的基址或目标函数地址。攻击者在栈上伪造一个Elf_Rela结构和Elf_Sym结构，通过dl-resolve机制在运行时动态解析任意函数名（如system）并跳转执行。

这个技术利用了动态链接器`_dl_runtime_resolve`的实现：当PLT中首次调用某个函数时，PLT跳转到ld.so的resolver，resolver根据GOT中的重定位信息查找函数地址。攻击者通过劫持GOT条目指向伪造的重定位结构，可以解析任意函数名。

ret2dlresolve的关键在于：
1. 控制栈上的Elf_Rela结构中的r_info字段，指定虚假的Elf_Sym索引。
2. 控制Elf_Sym结构中的st_name字段，指向攻击者控制的字符串（如"system"）。
3. 确保resolver在解析过程中不会访问无效内存。

## 4. 实战与示例

### 4.1 pmap 查看进程内存保护属性

`pmap`是Linux下查看进程内存映射的标准工具，可以显示每个映射区域的地址范围、权限、偏移和映射对象：

```bash
# 查看当前bash进程的内存映射
pmap -x $$

# 输出示例（节选）
Address           Kbytes     RSS   Dirty Mode  Mapping
0000000000400000     532     280       0 r-x-- bash
0000000000685000      32      32      32 rw--- bash       [ anon ]
000000000068d000      28      28      28 rw--- bash       [ anon ]
00007f8a3c600000    1832     456       0 r-x-- libc-2.31.so
00007f8a3c7c9000    1868       0       0 ----- libc-2.31.so
00007f8a3c9a0000       8      16      16 rw--- libc-2.31.so
00007f8a3cb9f000      16      12      12 rw--- [ anon ]
00007ffc12340000     132      20      20 rw--- [ stack ]
00007ffc1235f000      12       0       0 r-x-- [ anon ]    ← 可执行匿名页（可疑！）
```

权限列的含义：r=read, w=write, x=execute, p=private（COW映射）。

安全审计要点：
- 寻找RWX权限（rwxp）的区域，这是潜在的安全风险。
- 检查是否有可执行的匿名映射（如最后一行），这可能是JIT或shellcode加载点。
- 检查[stack]区域是否为RW（不应有X），如果是RWX则DEP未启用。

### 4.2 /proc/PID/maps 解读权限标志

`/proc/PID/maps`是procfs提供的进程内存映射视图，每行格式为：

```
地址范围        权限  偏移   设备  inode  路径名
00400000-00485000 r-xp 00000000 08:01 1234567  /usr/bin/bash
```

权限字段的四个字符含义：
- 第1位：r（可读）或 -（不可读）
- 第2位：w（可写）或 -（不可写）
- 第3位：x（可执行）或 -（不可执行）
- 第4位：p（私有/COW映射）或 s（共享映射）

```bash
# 查看特定进程的maps
cat /proc/1/maps | head -20

# 搜索所有可执行匿名映射
grep 'r.xp.*\[anon\]' /proc/self/maps

# 查找可能的RWX区域（安全审计）
awk '$2 ~ /^rwxp/ {print "DANGER:", $0}' /proc/self/maps

# 结合grep查找特定库的映射
cat /proc/$(pgrep sshd)/maps | grep libc
```

### 4.3 mprotect 修改页保护属性的代码示例

以下是一个完整的示例，展示如何使用mmap和mprotect实现安全的W^X内存管理：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096

// 对齐到页边界（向下取整）
#define PAGE_ALIGN(x) ((void *)((unsigned long)(x) & ~(PAGE_SIZE - 1)))

// 安全的代码分配：RW → 写入 → RX
void *alloc_executable_code(const unsigned char *code, size_t code_len) {
    // 分配RW页
    void *page = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    // 写入代码（此时页是RW的）
    memcpy(page, code, code_len);

    // 切换为RX（不可写，可执行）—— 实现W^X
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        munmap(page, PAGE_SIZE);
        return NULL;
    }

    return page;
}

// 不安全的分配（应避免）
void *alloc_unsafe_code(const unsigned char *code, size_t code_len) {
    // 直接分配RWX页——这是严重的安全反模式！
    void *page = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE | PROT_EXEC,  // RWX！
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return NULL;
    memcpy(page, code, code_len);
    return page;
}

int main() {
    // x86-64: xor eax, eax; ret（返回0）
    unsigned char shellcode[] = {
        0x31, 0xc0,  // xor eax, eax
        0xc3         // ret
    };

    printf("=== W^X安全分配示例 ===\n");
    void *safe = alloc_executable_code(shellcode, sizeof(shellcode));
    if (safe) {
        printf("安全页地址: %p (RX, 不可写)\n", safe);
        int result = ((int(*)())safe)();
        printf("执行结果: %d\n", result);
        munmap(safe, PAGE_SIZE);
    }

    printf("\n=== 不安全分配示例 ===\n");
    void *unsafe = alloc_unsafe_code(shellcode, sizeof(shellcode));
    if (unsafe) {
        printf("不安全页地址: %p (RWX!)\n", unsafe);
        // 检查页权限
        system("cat /proc/self/maps | grep -E 'rwx' || echo 'no rwx found'");
        munmap(unsafe, PAGE_SIZE);
    }

    return 0;
}
```

### 4.4 观察NX启用对栈溢出利用的影响

以下实验展示NX保护如何阻止传统的栈溢出shellcode执行：

```c
// vuln.c - 一个有栈溢出漏洞的程序
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // 未检查长度！
    printf("Input was: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
```

编译和测试：

```bash
# 编译时启用NX（默认行为）
gcc -o vuln vuln.c -fno-stack-protector

# 编译时禁用NX（危险！仅用于实验）
gcc -o vuln_nx_disabled vuln.c -fno-stack-protector -z execstack

# 查看NX状态
readelf -l vuln | grep GNU_STACK
# 输出: GNU_STACK 0x0000000000000000 0x0000000000000000 ... RW  0x10
# RW（无E标志）表示NX已启用

readelf -l vuln_nx_disabled | grep GNU_STACK
# 输出: GNU_STACK 0x0000000000000000 0x0000000000000000 ... RWX 0x10
# RWX（有E标志）表示NX已禁用

# 生成64字节的溢出payload，将返回地址覆盖为栈上shellcode地址
# （此处仅演示概念，实际需要结合ASLR禁用和栈地址计算）
python3 -c "print('A'*72 + '\x78\x56\x34\x12\x00\x00\x00\x00')" | ./vuln
# NX启用时：Segfault（shellcode无法执行）
```

## 5. 常见坑与避坑指南

### 5.1 W^X不是万能的：mprotect可被滥用

W^X的核心假设是"不可同时写入和执行"，但mprotect系统调用允许在运行时动态修改页保护属性。如果攻击者通过ROP链调用mprotect，可以将数据页（RW）改为RWX，然后跳转执行。这是W^X被绕过的最直接方式。

防御措施：
1. **限制mprotect的使用场景**：通过seccomp-bpf（Secure Computing Mode with Berkeley Packet Filter）系统调用过滤，禁止或严格限制mprotect的调用。例如，只允许mprotect将页从RW改为RX（不允许RWX），且不允许修改栈区域。
2. **grsecurity的MPROTECT**：PaX补丁中的MPROTECT功能可以检测和阻止非正常的mprotect调用，如将数据页改为可执行。
3. **SELinux/execmem**：SELinux的execmem权限控制进程是否可以创建可执行的内存映射。禁用execmem可以阻止mprotect创建RWX页。

### 5.2 JIT编译器的W^X困境

JIT编译器面临一个根本性的设计挑战：它必须动态生成机器码（需要写入+执行），但W^X策略禁止同时RWX。安全的JIT实现必须严格遵循权限切换流程。

Java HotSpot VM的实现示例：
1. CodeCache分配时使用RW权限。
2. 生成机器码时写入CodeCache（RW权限，可写不可执行）。
3. 编译完成后调用mprotect将对应页改为RX（可执行不可写）。
4. 后续修改需要先改回RW，修改后再改回RX。

潜在风险：
- **JIT喷射攻击（JIT Spray）**：攻击者利用JavaScript等JIT语言编写特定的代码模式，使JIT编译器生成包含攻击者所需常量的机器码片段。这些片段位于CodeCache中（RX权限），可以被ROP链引用。
- **mprotect竞态**：如果JIT的mprotect序列存在TOCTOU（Time-of-Check to Time-of-Use）窗口，攻击者可能在这个窗口内修改CodeCache内容。
- **CodeCache耗尽**：如果攻击者能够触发大量JIT编译，可能耗尽CodeCache，导致mprotect分配新的RW页，创造RWX窗口。

V8 JavaScript引擎的应对措施包括：CodeCache的guard page（哨兵页检测越界）、Cage-based内存分配（将CodeCache限制在固定地址范围内）、以及与操作系统协作的W^X验证。

### 5.3 Shared Memory的保护属性冲突

多个进程共享的内存区域需要精确设置保护属性，否则可能产生安全问题或功能异常：

**mmap MAP_SHARED与W^X冲突**：当多个进程通过MAP_SHARED映射同一个文件时，如果一个进程通过mprotect将映射改为RX（W^X），所有共享该映射的进程都会受到影响。这在数据库系统（共享内存缓存）和多进程服务器中是常见问题。

**共享库的GOT/PLT保护**：传统的GOT（Global Offset Table）在函数首次调用后需要被修改为实际地址（lazy binding），这要求GOT页具有RW权限。但W^X要求GOT页不可执行。现代实现将GOT和PLT分离到不同的页，PLT为RX（代码段），GOT为RW（数据段），解决冲突。

**shmget/shmat的安全问题**：System V共享内存（shmget）创建的共享段没有内置的保护属性控制，所有附加（shmat）的进程都可以完全读写。这在安全上是一个弱点：如果一个进程向共享段写入恶意数据，另一个进程可能执行这些数据。替代方案是使用mmap MAP_SHARED，它支持完整的保护属性控制。

### 5.4 ASLR + NX + Stack Canary的协同防御

现代操作系统的内存保护依赖多层机制的协同，任何单一机制都可能被绕过：

| 机制 | 防御目标 | 独立弱点 | 协同效果 |
|------|----------|----------|----------|
| NX/DEP | 代码注入执行 | return-to-libc/ROP可绕过 | 阻止直接代码注入 |
| ASLR | 地址随机化 | 信息泄露可绕过 | 使ROP地址难以预测 |
| Stack Canary | 栈溢出检测 | canary泄露可绕过 | 阻止ret地址覆盖 |
| PIE | 代码段随机化 | 信息泄露可绕过 | 使gadget地址难以预测 |
| RELRO | GOT只读 | 仅Full RELRO有效 | 防止GOT覆写 |
| CFI | 控制流完整性 | 绕过方法持续研究 | 防止非法间接跳转 |

协同防御的工作逻辑：
1. NX阻止攻击者在栈/堆上注入shellcode并执行。
2. ASLR/PIE使攻击者无法预测libc、程序代码的地址，无法构造ROP链。
3. Stack Canary在栈溢出覆盖返回地址时被检测到，阻止函数返回劫持。
4. RELRO防止通过覆写GOT条目劫持间接调用。
5. CET/Shadow Stack在返回地址被篡改时触发硬件异常。

安全审计的关键是验证这些机制是否全部启用：

```bash
# 检查NX
readelf -l binary | grep GNU_STACK    # RW=启用, RWX=未启用

# 检查PIE
readelf -h binary | grep Type         # DYN (共享目标)=启用, EXEC=未启用

# 检查Stack Canary
readelf -s binary | grep __stack_chk_fail  # 有=启用, 无=未启用

# 检查RELRO
readelf -l binary | grep GNU_RELRO   # 有=部分RELRO
readelf -d binary | grep BIND_NOW    # 有=Full RELRO

# 综合检查
checksec --file=binary  # 一站式检查工具
```

## 6. 知识关联

- [[从逻辑门到CPU：计算机硬件体系总览]] — 内存保护的硬件基础，MMU和TLB的工作原理
- [[虚拟内存原理：多级页表与地址翻译]] — PTE结构和页表层级是NX/XD位的载体
- [[栈溢出原理：覆盖返回地址到控制流劫持]]（02-二进制安全） — NX直接阻断的攻击类型
- [[ROP技术详解：gadget搜索与链构造]]（02-二进制安全） — NX引入后的主要绕过技术
- [[防护机制全集：NX-PIE-Canary-RELRO-FORTIFY]]（02-二进制安全） — NX在多层防御体系中的位置
- [[现代缓解机制：CFG-CET与VBS]]（02-二进制安全） — CET/Shadow Stack/VBS对W^X绕过的进一步防御

## 7. 参考资料

- [Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3: System Programming Guide](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) — Chapter 4 Memory Protection, Section 4.6 Protection
- [ARM Architecture Reference Manual (ARM ARM)](https://developer.arm.com/documentation/ddi0487/latest) — Chapter B3 Virtual Memory System Architecture
- [Microsoft Documentation: Data Execution Prevention (DEP)](https://learn.microsoft.com/en-us/windows/win32/secbp/data-execution-prevention) — Windows DEP技术细节
- [PaX Team, "Design and Implementation of PAGEEXEC and MPROTECT"](https://pax.grsecurity.net/docs/PageExec.txt) — W^X的早期实现
- [Hovav Shacham, "The Geometry of Fresh Flesh: Return-Oriented Programming](https://doi.org/10.1145/1315245.1315313) — CCS 2007
- [Intel CET Specification](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-paper-intel-cet-in-server-cpu.html) — Shadow Stack和IBT的详细规范
- [Microsoft Documentation: Virtualization-based Security (VBS)](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/device-guard-credential-guard) — HVCI架构说明
- [ARMv8.1 PAN and ARMv8.5 MTE Specification](https://developer.arm.com/documentation/) — ARM内存保护演进
- [Qualys, "The Stack Clash Vulnerability"](https://blog.qualys.com/vulnerabilities-threat-research/2017/06/19/the-stack-clash-vulnerability) — 栈保护的实际案例
- [Google Project Zero Blog](https://googleprojectzero.blogspot.com/) — 各类内存保护绕过技术的持续研究