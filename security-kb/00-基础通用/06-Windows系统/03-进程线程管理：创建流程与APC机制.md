---
title: "进程线程管理：创建流程与APC机制"
category: "00-基础通用/06-Windows系统"
tags: [进程, 线程, 创建流程, APC, EPROCESS, ETHREAD, 进程注入检测]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# 进程线程管理：创建流程与APC机制

> **合规声明**：本文以 Windows 内部机制研究与防御检测（EDR 监控、恶意代码行为识别、取证分析）为目的撰写。文中对进程镂空、APC 注入、远程线程等手法仅作机制层面的原理说明与检测面分析，不提供任何可直接利用的负载或完整攻击脚本。所有示例以合法渗透测试与安全研究为使用场景，请遵守当地法律法规与授权边界。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 进程（process）是资源容器（地址空间、访问令牌、句柄表、配额）；线程（thread）是可调度执行的最小单元；APC（Asynchronous Procedure Call，异步过程调用）是排队到目标线程上下文、由系统在特定时机插入执行的函数 |
| 核心用途 | 理解从 `CreateProcess` 到内核 `_EPROCESS`/`_ETHREAD` 的完整生命周期；APC 支撑 I/O 完成通知、进程/线程终止清理与注入检测；安全上用于识别进程镂空、Early Bird 注入与线程创建监控 |
| 关键参数 | `CREATE_SUSPENDED`/`DEBUG_PROCESS` 等创建标志；`QueueUserAPC` 触发时机依赖的 `alertable` 可告警等待参数（`SleepEx(ms, TRUE)`）；`_EPROCESS.UniqueProcessId`、`ActiveProcessLinks`、`_ETHREAD.StartAddress`；APC 三队列（特殊内核、普通内核、用户队列） |
| 常见风险 | 进程镂空（Process Hollowing）、Early Bird APC 注入、远程线程注入（CreateRemoteThread）、用户 APC 因未处于可告警等待而永不执行、EDR 用户态钩子被直接系统调用（direct syscall）绕过 |
| 关联知识 | [[01-Windows架构总览：内核执行体与子系统]]、[[02-对象管理器：内核对象与句柄机制]]、[[06-令牌机制：访问令牌与特权调整]]、[[08-ETW机制：事件采集架构与消费]]、[[11-Windows日志体系与关键EventID速查]] |

## 1. 概述

Windows 的"进程"与"线程"是一对极易混淆但本质不同的概念。**进程是资源的容器**：它拥有一个独立的虚拟地址空间（address space）、一份访问令牌（token）、一张句柄表（handle table），以及内存配额与安全属性；进程本身不执行任何代码。**线程才是真正"跑代码"的对象**：每个线程拥有独立的运行栈（内核栈 + 用户栈）、线程环境块（TEB）、APC 队列与调度状态（ready/running/waiting），由内核调度器（dispatcher）以线程为单位分配 CPU 时间。

理解这两层结构，是 Windows 方向一切后续知识（用户态调试、内核取证、EDR 原理、恶意样本分析、绕过与检测）的地基。本文分三个主题展开：

1. **对象层**：进程对象 `_EPROCESS` 与线程对象 `_ETHREAD` 的内部结构，以及它们与用户态 PEB/TEB/KPCR 的对应关系。
2. **流程层**：从用户态 `CreateProcess`，经 `ntdll!NtCreateUserProcess` 进入内核，到初始线程在加载器引导下运行入口点的完整创建链路；以及 `CreateThread` 的线程创建链路。
3. **机制层**：APC（Asynchronous Procedure Call，异步过程调用）——内核 APC 与用户 APC 的投递规则、队列结构与可告警等待（alertable wait），这是理解 I/O 完成、线程终止与多种注入手法的关键机制。

从安全视角看，这三个主题直接对应攻击面与检测面：进程创建的"挂起—写入—恢复"三步是进程镂空（Process Hollowing）与 Early Bird APC 注入的标准路径；`NtCreateThreadEx` 是远程线程注入的必经之地；而 APC 机制本身则是早鸟注入与部分持久化技法的载体。EDR 正是在 `NtCreateUserProcess`、`NtCreateThreadEx`、`NtResumeThread`、`NtQueueApcThread` 这些系统服务上布置用户态钩子与内核回调（callback），并借助 ETW 事件流还原进程创建的行为序列。

下文先建立"进程是容器、线程是执行体、APC 是异步介入点"这三个心智模型，再逐层深入结构、流程与安全应用。

## 2. 核心原理

### 2.1 进程与线程的对象模型

进程对象（executive process object，`_EPROCESS`）位于非分页内存池（nonpaged pool），由对象管理器（object manager）统一管理；其头部由对象头（`_OBJECT_HEADER`）包装，包含名称、引用计数、句柄表等通用信息。`_EPROCESS` 的第一个字段是调度器专用的进程对象 `_KPROCESS`（Process Control Block，进程控制块），调度器只关心 `_KPROCESS`，与执行体层面解耦。

每个进程至少有一个线程——**初始线程（initial thread）**。线程对象（`_ETHREAD`）的第一个字段是 `_KTHREAD`（Thread Control Block，线程控制块），调度器在 `_KTHREAD` 层面完成状态迁移与 CPU 分配。二者关系可用下图概括：

```
 _EPROCESS (进程对象, 非分页内存池)
 ┌──────────────────────────────────────────────────┐
 │ Pcb: _KPROCESS     ──► 调度器用的进程块            │
 │ UniqueProcessId     ◄─ PID                        │
 │ ActiveProcessLinks  ◄─► 双向链表, 挂入全局进程链表   │
 │ InheritedFromUniqueProcessId ◄─ 父 PID (取证关键)  │
 │ Peb                 ◄─► 用户态进程环境块 PEB       │
 │ Token               ◄─► EX_RUNDOWN_REF 访问令牌    │
 │ ImageFileName [14]  映像文件名 (如 notepad.exe)     │
 │ ThreadListHead ═══╤═══╤═══╤═══► 链接本进程全部线程   │
 └───────────────────┼───┼───┼──────────────────────┘
                     │   │   │
         ┌───────────┘   │   └────────────┐
         ▼               ▼                ▼
      _ETHREAD        _ETHREAD        _ETHREAD  (线程对象)
      ┌───────────────────────────────┐
      │ Tcb: _KTHREAD                 │
      │   ApcState.KernelApcQueue     │ ◄─ 内核 APC 队列
      │   ApcState.UserApcQueue       │ ◄─ 用户 APC 队列
      │   ApcState.UserApcPending     │ ◄─ 用户 APC 挂起标志
      │   State / ContextSwitches     │ ◄─ 调度状态
      │ CreateTime / Cid              │ ◄─ 创建时间 / (PID.TID)
      │ StartAddress                  │ ◄─ 线程例程(内核记录)
      │ Teb (指向用户态 _TEB)          │
      └───────────────────────────────┘
```

### 2.2 用户态与内核态的结构映射

一个线程运行时代码位于用户态，但它"挂在"两条链上：**执行体对象链**（`_ETHREAD` → `_EPROCESS`，供进程管理、退出清理、引用计数使用）与**调度器结构链**（`_KTHREAD` 落到某个 CPU 的 `_KPRCB`（Processor Control Block，处理器控制块）上）。同时，每个用户线程还有一个对应的**线程环境块 TEB（Thread Environment Block）**，存放在线程栈最低地址区域（下界下方），`_KTHREAD.Teb` 直接指向它；TEB 又通过 `PEB` 字段指回进程环境块（Process Environment Block），构成一条"双向桥"：

```
  内核态                                       用户态
 ┌────────────────────┐                 ┌──────────────────────┐
 │ _KTHREAD.Teb ──────┼────────────────►│ _TEB                 │
 │                    │                 │  NtTib / StackBase   │
 │ _ETHREAD.Teb ──────┼────────────────►│  ClientId (PID.TID)  │
 │ _EPROCESS.Peb ─────┼────────────────►│  PEB (x64: +0x60) ───┼──┐
 └────────────────────┘                 │ _PEB                 │  │
                                        │  ImageBaseAddress    │◄─┘
                                        │  Ldr (PEB_LDR_DATA)  │ 模块列表
                                        │  ProcessParameters   │ 命令行/环境
                                        │  BeingDebugged /     │ 反调试侦察点
                                        │  NtGlobalFlag        │
                                        └──────────────────────┘
```

x86-64 下内核态通过 `GS` 段寄存器基址访问当前 CPU 的 **KPCR（Kernel Processor Control Region，内核处理器控制区）**，`KPCR.CurrentPrcb`、`CurrentThread`、`NextThread`、`IdleThread` 记录了该 CPU 上正在运行/将要运行的线程；`syscall` 指令进入内核的第一件事就是基于 `MSR_GS_BASE` 定位当前 KPCR。用户态线程要获得自己的 PID/TID、TEB 指针等信息，也是从 KPCR/KUSER_SHARED_DATA 中推导的（例如 `GetCurrentThreadId` 内部逻辑）。

### 2.3 APC：异步过程调用

APC 的本质是"**在一个指定线程的上下文中排队执行一个函数**"。因为函数要在目标线程的栈、令牌与安全上下文中运行，所以 APC 不能由一个线程直接替另一个线程执行，只能"投递（deliver）"——由目标线程在将来的某个调度时机自己消费队列。这正是多线程异步通知的核心设计：I/O 完成通知、`ExitProcess` 的线程清理、定时器回调、以及大量注入技术都建立在这套机制上。

内核把 APC 分为三类（Windows Internals 的标准分类）：

1. **特殊内核 APC（special kernel APC）**：在内核态 APC_LEVEL（x86 IRQL=1 的中断级）上运行，禁用线程挂起与普通内核 APC，用于线程挂起、线程终止等不可延迟的场合。
2. **普通内核 APC（normal kernel APC）**：在 PASSIVE_LEVEL（IRQL=0）上运行，要求线程不在临界区（critical region）、也不处于高于 APC_LEVEL 的中断上下文；典型场景是 I/O 管理器把完成信息送回发起线程。
3. **用户 APC（user-mode APC）**：**只有当目标线程进入可告警等待（alertable wait）状态时**才会被投递，回调以内核构造陷阱帧、经 ntdll 的 `KiUserApcDispatcher` 返回用户态执行的方式完成。

三类优先级从高到低为：特殊内核 APC → 普通内核 APC → 用户 APC。投递时机是目标线程下次被调度、且满足对应条件（不在高 IRQL、不在临界区、处于可告警等待）时。

### 2.4 进程创建的两阶段模型

`CreateProcess` 不是一步到位的系统调用，而是"用户态启动器 + 内核建对象 + 新进程内加载器初始化"三个执行阶段拼接而成。简化示意：

```
调用者进程                               新进程(尚未运行业务代码)
──────────────                           ─────────────────────
kernel32!CreateProcessW
    │ CreateProcessInternalW: 参数校验、构造
    │ RTL_USER_PROCESS_PARAMETERS、与 csrss 协商
    │ 控制台/环境块/激活上下文
    ▼
ntdll!NtCreateUserProcess   (系统调用 #1)
    ▼  syscall
内核 PspCreateUserProcess:
    建立 _EPROCESS / 地址空间 / 映像 Section / 初始线程
    触发创建通知回调 + ETW ProcessStart 事件
    │ 内核把初始线程上下文扣在 ntdll 的
    ▼ PspUserProcessStartup, 然后返回调用者
调用者继续等待进程初始化完成
                                     ▲ 初始线程被首次调度
                                     │ PspUserProcessStartup
                                     │  再次调用 NtCreateUserProcess
                                     │  (第二轮: 补完寻址/安全初始化)
                                     ▼ LdrInitializeThunk
                                        LdrpInitializeProcess
                                        (加载导入表/TLS/延迟导入)
                                        │ 进入映像入口点 mainCRTStartup
                                        ▼ main()/WinMain() 开始执行
```

之所以需要"第二轮调用"，是因为从 Win7 起 `NtCreateUserProcess` 用一次系统调用同时创建进程和初始线程，而初始线程能被调度的前提是新进程的地址空间已就绪、ntdll 已映射进新地址空间——这些工作必须等初始线程真正运行于新地址空间后才能补完。内核把初始线程入口"勾"在 `PspUserProcessStartup` 上，让它以新进程身份补做第二轮 `NtCreateUserProcess`，随后进程才算"活"。## 3. 详细知识点

### 3.1 进程对象 `_EPROCESS`

`_EPROCESS` 是安全取证与 EDR 最常解析的结构。注意：**字段偏移随操作系统版本、构建号（build）而变化**，切勿硬编码；解析时建议用符号表（`ntkrnlmp` 的 PDB、`dt` 命令输出）或采用"扫描 ActiveProcessLinks 特征值"的方式动态定位。以下字段语义稳定：

| 字段 | 含义 | 安全用途 |
|------|------|----------|
| `Pcb`（`_KPROCESS`） | 调度器进程块：亲和性、进程态、地址空间 | 判断进程是否在运行/僵尸 |
| `UniqueProcessId` | 进程 PID | 比对全局 PID 表可发现隐藏进程 |
| `ActiveProcessLinks` | 双向链表，串起所有进程 | 手动遍历 `PsActiveProcessHead` 可发现被 ETW/回调"漏报"的进程 |
| `InheritedFromUniqueProcessId` | 父进程 PID | 父子关系是行为链分析的核心 |
| `Peb` | 指向用户态 `_PEB` | 校验 `PEB.ImageBaseAddress` 可发现镂空 |
| `Token` | 主令牌（EX_RUNDOWN_REF 包裹） | 提权与令牌窃取（见 [[06-令牌机制：访问令牌与特权调整]]） |
| `ImageFileName` | 映像名（固定长度缓冲） | 与 `PEB`/路径不一致即异常 |
| `ThreadListHead` | 本进程全部线程链表 | 线程枚举与注入线程发现 |
| `Session` / `Job` | 会话与作业对象 | 会话劫持、作业逃逸判断 |
| `CreateTime` / `ExitTime` | 创建/退出时间（FILETIME） | 时间线取证 |

结构关系参考（符号化的 `dt` 输出节选，不同版本偏移会有差异）：

```
lkd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x008 ProcessLock      : _EX_PUSH_LOCK
   +0x038 UniqueProcessId  : Ptr64 Void
   +0x040 ActiveProcessLinks : _LIST_ENTRY
   +0x050 RundownProtect   : _EX_RUNDOWN_REF
   +0x058 UniqueThreadId   : Ptr64 Void
   +0x060 Fsm              : Ptr64 _EX_FAST_REF
   +0x068 RecordLock       : ...
   +0x080 CreateTime       : _LARGE_INTEGER
   +0x168 Peb              : Ptr64 _PEB
   +0x1c8 InheritedFromUniqueProcessId : Ptr64 Void
   +0x2e0 ThreadListHead   : _LIST_ENTRY
   +0x2f0 ActiveThreads    : Uint4B
   +0x340 Token            : _EX_RUNDOWN_REF
   +0x440 ImageFileName    : [15] UChar
   ...
```

`dt _EPROCESS ActiveProcessLinks Pcb UniqueProcessId` 这类"只取字段"写法在脚本化取证中很常用。

### 3.2 线程对象 `_ETHREAD` 与 `_KTHREAD`

`_ETHREAD` 的存在意义是"执行体管理线程"：线程 ID、所属进程、开始地址、TEB 指针都在这一层；而真正决定"这个线程现在该不该跑、跑多久"的是 `_KTHREAD`。`_ETHREAD` 已合并了 `_KTHREAD`（Tcb 字段），因此调试时通常直接研究 `_ETHREAD`。

```
lkd> dt nt!_ETHREAD
   +0x000 Tcb              : _KTHREAD
   +0x008 CreateTime       : _LARGE_INTEGER
   +0x048 Cid              : _CLIENT_ID      ; UniqueProcess(PDB), UniqueThread(7DB)
   +0x058 ThreadsProcess   : Ptr64 _EPROCESS
   +0x060 StartAddress     : Ptr64 Void      ; 内核登记的线程例程
   +0x078 Teb              : Ptr64 _TEB      ; 用户态线程环境块
   +0x4c0 Win32StartAddress : Ptr64 Void     ; 由 ntdll 解析为模块名字符串
   +0x4d0 IoInfo           : Ptr64 _IO_INFO_STRUCT

lkd> dt nt!_KTHREAD ... ApcState ...  (节选)
   +0x000 Header           : _DISPATCHER_HEADER  ; 含 SignalState、Lock
   +0x040 Queue            : ...
   +0x068 KernelStack      : Ptr64 Void      ; 当前内核栈顶
   +0x070 InitialStack     : Ptr64 Void      ; 内核栈底(分配起点)
   +0x078 StackLimit       : Ptr64 Void
   +0x0c0 State            : _KTHREAD_STATE  ; Initialized/Ready/Running/Standby/...
   +0x0c8 Teb              : Ptr64 _TEB
   +0x0d0 ApcState         : _KAPC_STATE     ; ◄◄◄ APC 状态: 见 3.6 节
   +0x100 ApcStateInProgress/...  
   +0x2c0 Process          : Ptr64 _KPROCESS
   +0x2e0 Affinity         : _KAFFINITY
```

与安全相关的要点：

- `Cid`（Client Id）中的 `UniqueProcess`/`UniqueThread` 就是 PID/TID 对，Sysmon 与 WinDbg 的 `Cid 01e0.0114` 写法即来源。
- `StartAddress`/`Win32StartAddress`：内核记录线程真正的入口地址；如果一个线程是注入出来的，这个地址往往会指向非模块基址（例如 `0x000000...` 裸地址或 `kernel32!` 之外的地址）。竞态期间（ResumeThread 后）地址仍是原始 `LoadLibraryW` 或裸壳地址。
- `ApcState`（`_KAPC_STATE`）结构体是 APC 机制的核心（详见 3.6），里面同时内嵌 `ApcListHead[2]`（内核 APC 队列与用户 APC 队列）。
- `+0x061 Win32StartAddress` 之类字段由用户态 ntdll 在 `PspUserProcessStartup` 阶段把纯地址翻译成可读的模块名，取证时优先读这个字段（可读性更好）。

### 3.3 用户态视角：PEB、TEB 与 KPCR

**PEB（Process Environment Block，进程环境块）** 存在于用户地址空间，几乎所有用户态反调试/反检测代码都从这里读取信息：

```
lkd> dt nt!_PEB
   +0x000 InheritedAddressSpace
   +0x002 BeingDebugged      ; 反调试经典侦察点(IsDebuggerPresent 读取)
   +0x003 BitField
   +0x008 ImageBaseAddress   ; x64 下映像基址——镂空检测的关键
   +0x010 Ldr                : Ptr64 _PEB_LDR_DATA ; 已加载模块双向链表
   +0x020 ProcessParameters  : Ptr64 RTL_USER_PROCESS_PARAMETERS
                              ; 含 ImagePathName、CommandLine、Environment
   +0x030 ProcessHeaps
   +0x040 ReadOperationCount / WriteOperationCount
   +0x07c NtGlobalFlag
   +0x0d8 SessionId
   +0x100 ActCtx/AppCompatInfo
```

安全要点：

- `PEB.Ldr` 的模块链表正常情况下与 ETW 的 ImageLoad 事件一一对应；不一致（链表缺项、增项）是手工 Rootkit 的显著指纹。
- `PEB.ImageBaseAddress` 与 `NtUnmapViewOfSection` 行为对照，是检测进程镂空的重要证据（见 3.7 和 Sysmon EventID 25）。

**TEB（Thread Environment Block，线程环境块）** 是线程私有结构，配合 KPCR 完成用户态线程身份定位：

```
lkd> dt nt!_TEB
   +0x000 NtTib             : _NT_TIB
   +0x000 ExceptionList     ; SEH 链
   +0x008 StackBase / StackLimit   ; 线程栈边界(回栈鉴别)
   +0x028 SubSystemTib / 0x030 FiberData
   +0x038 EnvironmentPointer
   +0x048 ClientId          ; {UniqueProcess, UniqueThread} = PID.TID
   +0x050 ActiveRpcHandle
   +0x058 ThreadLocalStoragePointer
   +0x060 ProcessEnvironmentBlock  ; ◄─ PEB 指针(x64)
   +0x068 LastErrorValue / 0x07c CurrentLocale ...
   +0x07c Vdm/Lxss
   +0x1ab0 FlsData / +0x1808 TlsSlots
```

**KPCR** 是 CPU 局部数据：在 x86-64 中位于 `GS` 段（`MSR_GS_BASE`），`nt!_KPCR` 中 `Self`、`CurrentPrcb`、`CurrentThread`、`NextThread`、`IdleThread` 是内核调度与栈回溯的关键锚点；用户态安全代码很少直接操作它，但内核 Rootkit 常通过篡改 KPCR 的双链表结构隐藏线程。### 3.4 内核侧创建流程：`NtCreateUserProcess` 的内核阶段

`NtCreateUserProcess` 是 NT 中少有的"一次调用同时产出进程与初始线程"的系统服务。其内核实现大致分这几个阶段（函数名以 Windows Internals 第 7 版与 ReactOS 源码为准，具体符号随版本差异）：

1. **解析参数与属性列表（AttributeList）**：调用者通过 `_OBJECT_ATTRIBUTES`/属性列表传入映像 Section 句柄、文件句柄等；若未传 Section，内核用映像文件句柄创建 Section（`MmCreateDataFileSection` 或直接引用映射）。
2. **分配进程控制结构**：`PspAllocateProcess` 从非分页池分配 `_EPROCESS`，初始化进程对象头（对象类型、引用计数、句柄表根），并调用 `MmCreateProcessAddressSpace` 建立空地址空间（user/GDT page tables 结构）。此阶段还完成令牌（token）选择：默认继承父进程主令牌，`CREATE_NEW_PROCESS_GROUP` 等标志会影响会话/控制台等属性。
3. **解析映像信息**：从 Section 中读取 PE 头（`_IMAGE_NT_HEADERS`），取得地址空间大小（`SizeOfImage`）、子系统类型（Win32/Console/GUI）、入口点 RVA；GUI/控制台差异影响后续 csrss 交互。
4. **设置 PEB 与进程参数**：在**新进程的地址空间**里分配 PEB 与 `RTL_USER_PROCESS_PARAMETERS`（命令行、环境块、当前目录等在此落地）。这一步解释了为什么参数必须"提前序列化"——创建瞬间新进程的用户内存尚未完全布局。
5. **创建初始线程**：`PspAllocateThread` 分配 `_ETHREAD`，`KiInitializeContextThread` 设置初始线程上下文，把"启动时的入口"设定为 ntdll 的 `PspUserProcessStartup`（第二轮调用的承接点）；同时初始化该线程的内核栈、`_KTHREAD.ApcState`（空 APC 队列）与 TEB 占位。
6. **挂入全局链表并触发通知**：`PspInsertProcess` 把 `ActiveProcessLinks` 链入 `PsActiveProcessHead`，激活对象；随后调用**进程创建通知例程**（`PspCreateProcessNotifyRoutine`，即 `PsSetCreateProcessNotifyRoutineEx` 注册的回调）并发出 ETW `ProcessStart` 事件。**回调与 ETW 事件在此刻、于初始线程运行任何用户代码之前被触发**——这是 EDR 能"第一时间"看到新进程的根本原因。
7. **返回用户态**：第一次 `NtCreateUserProcess` 返回到调用者（kernel32），调用者随后 `WaitForProcessInit` 类操作等待新进程初始化完成；新进程的初始线程则从 `PspUserProcessStartup` 起跑，补做第二轮 `NtCreateUserProcess`（阶段 4、5 的剩余地址空间与安全初始化），再由 `LdrInitializeThunk → LdrpInitializeProcess` 完成导入、TLS、延迟导入、激活上下文解析，最终进入映像入口点。

一个需要强调的事实：**在阶段 6 之后、初始线程首次调度之前，进程/线程对象已经完整暴露在回调与 ETW 视线内**，但新进程的地址空间里还没有任何"我们自己的代码"。攻击者若想在入口点之前执行代码，唯一的路就是抢占这条"创建 → 初始化 → 入口点"时间线——这正是 Early Bird 注入的本质（见 3.7）。

### 3.5 线程创建：`CreateThread` → `NtCreateThreadEx`

普通用户的线程创建比进程创建简单得多，但仍然遵循"用户态启动器 + 内核建线程对象 + 新线程内初始化"的套路：

```
CreateThread / CreateRemoteThread (kernel32)
   │ 构造安全描述符/栈申请(CommitSize/ReserveSize)
   ▼
ntdll!NtCreateThreadEx
   │ syscall (pspic threads: StackSize, StartAddress, ...)
   ▼
内核 PspCreateThread
  PspAllocateThread: 分配 _ETHREAD, 内核栈(默认按 CPU 对齐/大小),
                     复制 ApcState 到新 _KTHREAD
  KiInitializeContextThread: StartAddress = 传入线程例程
  PspInsertThread: 挂入进程 ThreadListHead,
                   触发线程创建通知回调(PsSetCreateThreadNotifyRoutine)
                   + ETW ThreadStart 事件
   │ 若未传 CREATE_SUSPENDED, 线程直接进入 Ready
   ▼
新线程首次调度 → ntdll!LdrInitializeThunk(线程初始化:
                    LdrpInitializeThread) → 跳转到线程例程
```

安全上与进程创建对称的要点：

- **`CreateRemoteThread`**（跨进程创建线程）在内核模式上与 `CreateThread` 是同一实现（`NtCreateThreadEx`），"远程"的差异只在于调用者持有目标进程的句柄、并用 `virtual memory` 已有代码作为入口。这也是 Sysmon EventID 8（CreateRemoteThread）的检测对象。
- 线程创建回调（`PsSetCreateThreadNotifyRoutine`）提供的 `StartAddress` 是判断"线程是否正常"的第一手数据；若回调中看到 `StartAddress` 指向裸内存（非映像地址）或常见注入地址（如 `LoadLibraryW`、`KernelBase.dll!` 的导出地址），就意味着远程线程/注入。
- `CREATE_SUSPENDED` 对线程同样适用：线程对象已就绪但处于 Suspend 状态，直到 `ResumeThread` 才会被首次调度。攻击者常以"挂起进程 + 写远程内存 + 恢复"的时序完成注入（见 3.7）。

### 3.6 APC 机制详解："三队列三时机"与可告警等待

**队列结构**：每个线程的 `_KTHREAD` 内嵌一个 `_KAPC_STATE`，其中有两个双向链表 `ApcListHead[2]`：`ApcListHead[KernelApc]`（索引 0，内核 APC 队列）与 `ApcListHead[UserApc]`（索引 1，用户 APC 队列），外加 `KernelApcPending`/`UserApcPending` 两个挂起位：

```
_KTHREAD.ApcState
├── KernelApcInProgress   ; 正在投递内核 APC(防止重入)
├── KernelApcPending      ; 内核 APC 挂起标志(触发调度器检查)
├── UserApcPending        ; 用户 APC 挂起标志(仅 alertable 时消费)
├── Process               ; 归属进程(KPROCESS)指针
└── ApcListHead[0] ──────► 内核 APC 队列(特殊/普通)
    ApcListHead[1] ──────► 用户 APC 队列
```

**入队（Queue）**：

- 内核驱动：`KeInitializeApc(apc, thread, environment, KernelRoutine, RundownRoutine, NormalRoutine, ProcessorMode, NormalContext)` 初始化 `_KAPC`，再 `KeInsertQueueApc(apc, SystemArgument1, SystemArgument2, 0)` 入队。
- 用户态线程 A 给线程 B 排用户 APC：`QueueUserAPC(pfnApc, hThreadB, data)` → 内部走 `NtQueueApcThread`（特殊版本 `NtQueueApcThreadEx` 支持 SpecialUserApc）。内核随即设置目标线程对应的 `UserApcPending` 位，并向目标 CPU 发起一个 **APC 软件中断**，让调度器在目标线程下次切换时检查并投递。

**投递（Deliver）**：目标线程在 `KiDeliverApc` 中按下述顺序执行队列：

1. **特殊内核 APC**：任何时刻只要线程不在终止中即投递；运行于 APC_LEVEL，投递期间再屏蔽普通内核 APC 与线程挂起。
2. **普通内核 APC**：要求当前 IRQL ≤ APC_LEVEL 且线程不在临界区；投递前先屏蔽中断，投递后恢复。
3. **用户 APC**：要求**当前线程正处于可告警等待（alertable wait）**；投递形式是内核保存现场、构造陷阱帧，转向用户态 `ntdll!KiUserApcDispatcher`，由其调用用户回调 `NormalRoutine(context)`，回调结束后经 `NtContinue` 恢复用户线程继续执行；被中断的等待以 `STATUS_ALERTED` 返回，剩余等待时间被保留。

**可告警等待（alertable wait）** 相关的 API：`SleepEx(milliseconds, TRUE)`、`WaitForSingleObjectEx(handle, timeout, TRUE)`、`WaitForMultipleObjectsEx(..., TRUE)`、`WaitOnAddress`（Vista+ 的 address wait）等，`bAlertable=TRUE` 时该等待才可能被用户 APC 打断。**`Sleep()`、`WaitForSingleObject()`（不带 Ex）不可告警，用户 APC 永远不会投递**——这是初学 APC 时最容易踩的坑。

**三类典型使用场景**：

- I/O 完成通知：`ReadFileEx`/`WriteFileEx` 的完成回调本质是排到发起线程的用户 APC。
- 线程挂起/终止：`SuspendThread`/`TerminateProcess` 在内核用特殊内核 APC 推进（`KiSuspendThread`、`KiExitThread`）。
- 进程回收：`ExitProcess` 使用**特殊用户 APC**（无需可告警等待）把清理例程排进其余线程，保证进程退出时各线程统一跑完 DLL 卸载/资源清理。

**APC 投递流程清单（Todolist）**——便于在做内核调试或写检测规则时逐项核对：

1. 确认 APC 类型：内核（特殊/普通）还是用户。
2. 确认目标线程句柄存活：`NtQueueApcThread` 返回 `STATUS_THREAD_IS_TERMINATING` 即目标已死亡/销毁。
3. 入队：内核 `KeInsertQueueApc` 成功 → 目标 `KernelApcPending`/`UserApcPending` 置位。
4. 确认投递条件：内核 APC 看 IRQL 与临界区；用户 APC 看目标线程是否 alertable 等待。
5. 等待投递：用户态用 `SleepEx(...,TRUE)` 或 `WaitForXxxEx(...,TRUE)` 让出 CPU 并进入可告警状态。
6. 回调执行：用户回调经 `KiUserApcDispatcher` 运行，结束后恢复线程继续阻塞/执行。
7. 确认等待返回值：`WaitForSingleObjectEx` 返回 `WAIT_IO_COMPLETION`（= STATUS_USER_APC 对应的 0x000000C0）说明被用户 APC 打断。

### 3.7 安全视角：三种武器化路径与检测面

**路径一：进程镂空（Process Hollowing / RunPE）**。思路是"借用合法进程的壳，替换它的内容"。典型序列：

```
CreateProcess(..., CREATE_SUSPENDED)   ; 先让合法进程停在场
NtUnmapViewOfSection(hProcess, region) ; 把原映像映射解除, 地址空间"腾空"
VirtualAllocEx(...) → WriteProcessMemory ; 在原基址写入恶意映像/载荷
SetThreadContext / 修改 PEB.ImageBaseAddress ; 让入口点指向载荷
ResumeThread                             ; 合法外壳 + 恶意内容 开始跑
```

检测面（这正是为什么 EDR 如此关心 3.4 的阶段 6）：

- `NtUnmapViewOfSection 后再映射的地址 ≠ PEB.ImageBaseAddress` → 结构自相矛盾。
- 进程内既无 `ntdll` 之外的正常模块加载序列（ImageLoad 事件异常稀疏），映像文件在磁盘上不可见（无文件映射）。
- Sysmon **EventID 25（Process Tampering）** 专门标记这类"路径/内容被篡改"；EventID 8 若不匹配则配合 EventID 1 的行为序列（挂起→写入→恢复）共同判定。

**路径二：Early Bird APC 注入（APC Queue Injection）**。思路是"在合法进程的初始化窗口里插队执行"，命中 3.4 中"创建→初始化→入口点"的空档期：

```
CreateProcess(CREATE_SUSPENDED)      ; 进程就绪但不跑
VirtualAllocEx + WriteProcessMemory  ; 在初始线程地址空间写入载荷
QueueUserAPC(payload, hThread, 0)    ; 把用户 APC 排进"还没运行"的初始线程
ResumeThread                         ; 线程首次调度, 加载器初始化过程中
                                     ; 进入可告警等待 → 用户 APC 被投递
                                     ; → 载荷以该进程身份、在入口点之前运行
```

"Early Bird"的寓意：APC 在入口点代码之前先飞进去。因为进程创建回调与 ETW 事件在阶段 6 就已触发，监控侧并不缺事件——难点在于**时序窗口极短**，单纯靠 ETW 已经很难还原"谁在入口点之前执行了什么"，需要把 ETW ThreadStart/ImageLoad 与内核内存属性（可执行 + 无文件映射）或 Threat-Intelligence 事件的 WriteVirtualMemoryTargetProcess/WriteVirtualMemoryTargetThread 组合判定。

**路径三：远程线程与进程注入中间人（MITM/Race Window）视角。** 当攻击者与 EDR 同时希望"第一个进入新进程"时，争夺的正是同一条 `PspUserProcessStartup → 入口点` 时间线：

```
新进程时间线(从首次调度开始)
PspUserProcessStartup ─► LdrInitializeThunk ─► LdrpInitializeProcess ─► 入口点
      ▲                        ▲                        ▲
   攻击者: QueueUserAPC        EDR: 在自己的驱动回调里        攻击者的另一种
   (Early Bird 抢占)          用 KeAssureTriggered/内核APC     选择: SetThreadContext
                              或注入 DLL(等价 Early Bird)     直接改写 RSP/RIP
```

EDR 自身往往也"作弊"：它会在 `ProcessStart` 回调触发时立即把监控 DLL 排成用户 APC（或注册到加载器钩子 `AppInit_DLLs`/PLM 等），从而让自己先于目标程序入口点运行自己的代码——这与恶意 Early Bird 用的是同一套机制，只是目的相反。因此"APC 机制"不只是一个被利用的漏洞，它本身就是 EDR 实现"进程创建即监控"的支柱。理解了它的竞态特征（谁先入队、谁能第一个被投递），才算真正理解进程创建的"中间人"博弈。

### 3.8 EDR 如何监控线程/进程创建

监控手段按层级由低到高如下表：

| 层级 | 机制 | 能观察到什么 | 绕过的代价 |
|------|------|--------------|------------|
| 用户态钩子 | ntdll `NtCreateUserProcess`/`NtCreateThreadEx`/`NtQueueApcThread`/`NtResumeThread` 的内联钩子（inline hook）或 Detours | 进程/线程/队列/唤醒的参数与序列 | 直接系统调用（direct/indirect syscall）、`syscall` 指令手动构造 |
| 内核回调 | `PsSetCreateProcessNotifyRoutineEx` / `PsSetCreateThreadNotifyRoutine` / `PsSetLoadImageNotifyRoutine` | 进程启动、线程启动、映像加载（含所有 DLL） | 需内核层对抗（篡改回调数组） |
| 对象/句柄 | 对象管理器对 `Process`/`Thread` 类型的审计 | 打开进程、挂起等句柄操作 | 多数绕过无效 |
| ETW | `Microsoft-Windows-Kernel-Process`（ProcessStart/ThreadStart/ImageLoad）、`Microsoft-Windows-Threat-Intelligence`（远程虚拟内存写、远程线程创建等操作） | 无钩子的协议化事件流，含时间戳与 PID/TID | 需要与"消失的事件"作差（事件缺失本身也是信号） |
| 行为序列 | Sysmon EventID 1/7/8/25 + 日志聚合 | 父子链、注入链、镂空链 | 需要了解检测规则以免被白名单规避 |

实践要点：**优先级最高的信号往往不是单一事件，而是事件序列**——"创建挂起进程 → 向新进程写远程内存 → 向未运行线程排队用户 APC → 恢复线程"这个四元组几乎只出现在注入/镂空场景；Sysmon EventID 1 + 8 + 25 与上述 ETW 事件共同还原，才能把误报压到可接受水平。相关 ETW 细节见 [[08-ETW机制：事件采集架构与消费]]，EventID 语义见 [[11-Windows日志体系与关键EventID速查]]。## 4. 实战与示例

### 4.1 Windows 内核调试器观察进程与线程（WinDbg）

以下命令在 WinDbg 内核会话（或内存转储）中执行。转储类型与符号可用性决定了字段齐全度，输出为示例节选。

```text
lkd> !process 0 0            ; 列出全部进程 (Args 0 0 = 不展开线程)
PROCESS ffff9685ebdaf080
    SessionId: 1  Cid: 0f6c   Peb: 9ce9bcd000  ParentCid: 0d04
    DirBase: 1c80000002  ObjectTable: ffff9f8c0a8025c0  HandleCount: 123.
    Image: notepad.exe

lkd> !process 0 0 notepad.exe   ; 按映像名过滤
lkd> !process 0 1 notepad.exe   ; 第二个参数越"大"展示越详细
lkd> dt nt!_EPROCESS UniqueProcessId ActiveProcessLinks \
       InheritedFromUniqueProcessId ImageFileName Peb Token
lkd> !process ffff9685ebdaf080 4 ; 查看该进程及其全部 THREAD
THREAD ffff9f8c0b422080  Cid 0f6c.0134  Teb: 0000009ce9bcf000 ...
    Win32StartAddress: 0x00007ff749f11530   ; 解读为模块入口
    StackLimit ...  StartAddress: 0x00007ff749f11530
lkd> !thread ffff9f8c0b422080     ; 展开单线程(含等待对象/APC状态)
lkd> dt nt!_ETHREAD Tcb Teb Cid ThreadsProcess StartAddress Win32StartAddress
lkd> !peb                    ; 需要先 .process 切到目标进程上下文
lkd> !apc                    ; 列出各 CPU 队列中的内核/用户 APC:
;   Kernel APCs queued on CPU 0: ...
;   User APCs queued on CPU 1:  Thread: ffff...   ... 
```

`!apc` 的输出直接揭示"在这个 CPU 上还有哪些线程排着 APC 没跑"，是验证注入时序、判断用户 APC 是否滞留队列的一等利器。它对应本文 3.6 的"三队列"模型。

### 4.2 用户态观察：PowerShell / CIM

```powershell
# 进程与线程的数量形态
Get-Process -IncludeUserName | Select-Object Id, ProcessName, CPU, Responding, HandleCount

# 线程级细节：谁在等什么(粗略)、起止时间
Get-Process explorer | Select-Object -ExpandProperty Threads |
    Select-Object Id, ThreadState, WaitReason, StartTime, TotalProcessorTime

# 创建进程的父子链(取证时间线常用)
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath,
                  CreationDate, CommandLine |
    Where-Object { $_.Name -in 'notepad.exe','cmd.exe','powershell.exe' }
```

注意 `Get-Process` 只能看到"对象管理器认可的进程"，内核线程与隐藏进程都不在列表里——这本身就是与 `!process 0 0` 对比、定位 Rootkit 隐藏进程的手段。

### 4.3 C++：以 `CREATE_SUSPENDED` 创建进程并恢复

```cpp
#include <windows.h>
#include <stdio.h>

int wmain() {
    wchar_t cmd[] = L"C:\\Windows\\System32\\notepad.exe";
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        cmd, cmd, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED,               // 关键: 预恢复前不运行代码
        nullptr, L"C:\\", &si, &pi);
    if (!ok) { printf("CreateProcess failed: %lu\n", GetLastError()); return 1; }

    // [此处注入/修改上下文的挂点] —— 详见 3.7 路径一/路径二
    printf("Suspended PID=%lu TID=%lu, 此时初始线程尚未调度\n",
           pi.dwProcessId, pi.dwThreadId);

    ResumeThread(pi.hThread);          // 把初始线程放行
    WaitForInputIdle(pi.hProcess, 5000); // 等待窗口就绪(可选)

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

关于 `CREATE_SUSPENDED` 需要一个强调的说明：挂起发生在进程创建完成、回调/ETW 触发**之后**——所以"挂起"挡不住 EDR，却能挡住目标进程自己的代码。

### 4.4 C++：`QueueUserAPC` 且仅在可告警等待时投递

```cpp
#include <windows.h>
#include <stdio.h>

VOID CALLBACK MyApc(ULONG_PTR data) {
    printf("[target] APC delivered, data=0x%llx, executing on %lu\n",
           data, GetCurrentThreadId());
}

DWORD WINAPI Target(LPVOID) {
    printf("[target] thread starting, tid=%lu\n", GetCurrentThreadId());
    // 关键: 必须可告警(第二参数 TRUE); Sleep()/WaitForSingleObject 不行
    SleepEx(5000, TRUE);
    printf("[target] wait done\n");
    return 0;
}

int wmain() {
    HANDLE h = CreateThread(nullptr, 0, Target, nullptr, 0, nullptr);
    QueueUserAPC(MyApc, h, 0xABCD);
    WaitForSingleObjectEx(h, INFINITE, FALSE);  // 请观察回调先于 wait done 打印
    return 0;
}
```

把上面的 `SleepEx(5000, TRUE)` 改成 `Sleep(5000)` 或 `WaitForSingleObject(h, 5000)`，APC 就永远不会执行——这正是 3.6 强调的可告警等待陷阱。`WaitForSingleObjectEx(...)` 返回 `WAIT_IO_COMPLETION`（0x000000C0）表示等待被用户 APC 打断。

### 4.5 内核驱动观察 APC 队列（概念性伪代码）与检测脚本的思路

安全研究者常在内核侧挂钩 `PsSetCreateThreadNotifyRoutine` 观察全部线程启动，并结合队列状态判断注入。下面给出"检测规则思路"而不是完整驱动：

```text
规则思路(伪代码/检测表达式, 非可编译驱动):
  On ThreadCreate(ProcessId, ThreadId, CreateInfo):
      if CreateInfo == CREATE_TARGET:
          record "remote thread creation"          -> Sysmon EID 8 对应物
      if CreateInfo.StartAddress 不在任何已加载映像地址段:
          flag 可疑裸地址线程                      -> 注入特征
  On ProcessCreate(ProcessId, ParentId, Flags):
      if Flags & CREATE_SUSPENDED 且随后出现
         WriteVirtualMemory(Target=新进程) 后 ResumeThread:
          alert "挂起-写-恢复 序列"                -> 镂空/APC 注入特征
  ..................
```

在蓝队脚本层面，等价物就是 Sysmon + ETW 的组合查询：

```powershell
# 伪查询: 在日志聚合里找“挂起→远程写→恢复”序列(以 Sysmon 事件建模)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';
   ProviderName='Microsoft-Windows-Sysmon'} |
    Where-Object {
        $_.Id -in 1,8,25 -and
        $_.Message -match 'notepad' -and             # 常用合法外壳
        $_.Message -match 'CreateRemoteThread|Process Tampering'
    } | Select-Object -First 20
```

### 4.6 Early Bird 检测时间线（防御侧 Todolist）

当怀疑某进程被 Early Bird 注入时，按时间线重建证据：

1. 确认总体序列：进程创建（EventID 1 / ETW ProcessStart）→ 远程写（Threat-Intelligence WriteVirtualMemory）→ 用户 APC 队列（NtQueueApcThread 用户态钩子证据）→ 恢复（EventID 1 时间戳旁证）。
2. 对比 `!apc` / 内核抓取的线程 `ApcState`：若在"入口点已运行"的进程中仍残留用户 APC 列队，说明注入发生在上一次唤醒窗口。
3. 检查载荷地址是否为"无文件映射的可执行（PAGE_EXECUTE* + 无映像）"——用 ETW 的 Protection/PFN 信息与内存扫描工具双确认。
4. 交叉验证 `PEB.ImageBaseAddress` 与模块链、`Ldr` 链表是否自洽（对应 Sysmon 25 与 3.3）。
5. 落数据库：以 PID/TID + 时间戳 + 事件序列作为 IOC 供后续狩猎。

### 4.7 快速自测清单

- 在 WinDbg 里对 notepad 做 `!process 0 1` 并解读 `ParentCid`、`Peb`、`Win32StartAddress`。
- 用 `dt nt!_KTHREAD ApcState` 解释 `ApcListHead[2]` 的语义。
- 写一个最小 C++ 程序验证"非可告警等待下用户 APC 永不投递"。
- 对照 3.8 的表，口述"进程创建那一刻，从 HAL 到服务端一共出现了几条可观测事件流"。## 5. 常见坑与避坑指南

| 坑点 | 现象 | 原因 | 规避建议 |
|------|------|------|----------|
| 用户 APC 永不执行 | `QueueUserAPC` 返回成功但回调从不触发 | 目标线程只用 `Sleep()`/`WaitForSingleObject()` 等不可告警等待 | 用 `SleepEx(ms,TRUE)`/`WaitForSingleObjectEx(...,TRUE)`；或确认目标线程确实进入 alertable 状态 |
| 误认为 APC 立即执行 | 队列成功后马上读变量仍为旧值 | APC 需等目标线程被调度且满足投递条件 | 回调执行严格异步，读结果前先同步（事件/等待） |
| 对已死线程排 APC | 返回 `ERROR_THREAD_1_INACTIVE` 等 | 目标线程已退出或句柄已失效 | 排队前先校验句柄有效性，且线程退出后不要再碰 |
| 特殊/普通内核 APC 混用 | 在高 IRQL 上下文投递普通内核 APC 出现断言/卡死 | 投递条件（IRQL、临界区）不满足 | 用户态只关心用户 APC；写驱动时严格按 Windows Internals 的分类投递 |
| 误把 `!process 0 0` 当 PID 列表 | 对比 CID 时错位 | `Cid` 是 PID.TID（进程 ID.线程 ID） | 认准 `CID` 语义；进程 ID 看 `UniqueProcessId` |
| 硬编码 `_EPROCESS`/`_ETHREAD` 偏移 | 换版本符号失效 | 偏移随 build 不固定 | 用符号表（`dt`/PDB）或特征扫描；勿把 ×86 偏移当 ×64 |
| 忽略 `CREATE_SUSPENDED` 与回调时序 | 以为"挂起=无痕" | 对象创建、回调、ETW 在挂起之前已完成 | 挂起挡不住 EDR；要谈隐蔽必须处理事件流本身 |
| `CreateProcess` 忘记 `bInheritHandles` 语义 | 子进程意外继承句柄 | 第三/四参数(C/SecAttr)决定句柄继承 | 显式传参并审查继承性，避免句柄泄露给子进程 |
| 把 `PEB` 与 `TEB` 混淆 | 反调试代码读错基址 | PEB 是进程级、TEB 是线程级 | 记住 `TEB.PEB`(x64 +0x60)；`BeingDebugged` 在 PEB |
| 直接系统调用绕过误报 | 把 Harmony/syscall 直发当恶意 | 正常程序也可能用 direct/indirect syscall | 检测以"行为序列+对象属性"为主，syscall 方式仅作增强特征 |
| 只盯单事件 | 漏掉"挂起→写→恢复"组合 | 单一 EventID 无上下文 | 建立事件序列规则（3.8 的组合查询） |
| Early Bird 依赖竞态 | 教科书代码不稳定 | 投递发生在加载初始化窗口内，时序敏感 | 检测侧以窗口内事件为证据；攻击侧（研究用途）理解该竞态即可 |

## 6. 知识关联

- [[01-Windows架构总览：内核执行体与子系统]]：执行体/内核/ HAL 分层，`_EPROCESS` 与对象管理器在上层如何协同
- [[02-对象管理器：内核对象与句柄机制]]：进程/线程对象作为内核对象在对象管理器中的表示与引用计数
- [[06-令牌机制：访问令牌与特权调整]]：`_EPROCESS.Token` 与主令牌/模拟令牌、提权与令牌窃取的检测
- [[07-UAC与完整性级别：提权本质剖析]]：进程创建时完整性级别（integrity level）的继承与 SAFER 策略
- [[08-ETW机制：事件采集架构与消费]]：Kernel-Process 与 Threat-Intelligence 提供程序承载本文所述事件流
- [[09-PowerShell深入：引擎架构与AMSI机制]]：`Get-Process`/`Get-CimInstance` 在蓝队/红队侧更深的用法
- [[11-Windows日志体系与关键EventID速查]]：Sysmon EventID 1/7/8/25 与本文检测面的日志落地
- [[10-内核态用户态：特权级与模式切换]]：syscall 进入内核、KPCR 压栈切换在进程/线程创建中的具体出现
- [[12-中断与异常：中断向量与处理流程]]：APC 软件中断（software interrupt）与 DPC 在中断向量层面的关系
- [[04-进程管理：ps-top-信号机制与nice]]：与 Linux 侧进程/信号机制的横向对照

## 7. 参考资料

- Russinovich, Solomon, Ionescu, Yosifovich:《Windows Internals, Part 1》（第 7 版），第 5 章 Processes and Threads；第 1、2 章（系统架构与内核），以及 2009 年出版的第 6 版中关于 APC 的经典论述
- Pavel Yosifovich:《Windows Kernel Programming》——基于 _EPROCESS/_ETHREAD 的内核驱动开发与对象/APC 结构补充
- Microsoft Learn：*Asynchronous Procedure Calls*（`QueueUserAPC`、`SleepEx`、`WaitForSingleObjectEx` 的 alertable 语义）：https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
- Microsoft Learn：CreateProcessW / CreateThread API 文档与 `CREATE_SUSPENDED`、`DEBUG_PROCESS` 标志说明
- Google Project Zero (Mateusz Jurczyk / j00ru)：*Windows NT Kernel APC Internals Analysis*——内核 APC 队列实现与投递路径的最详细公开分析
- MITRE ATT&CK：T1055 Process Injection（含子技术 T1055.012 Process Hollowing、T1055.004 Asynchronous Procedure Call）
- Sysinternals / Sysmon EventID 参考：EventID 1（进程创建）、7（映像加载）、8（CreateRemoteThread）、25（Process Tampering）
- ReactOS 源码（开源 NT 实现）：`ntoskrnl/ke/apc.c`——`KeInsertQueueApc`/`KiDeliverApc` 的可读实现参考
- ethzurich/Palantir 及多个 EDR 公开白皮书中关于进程创建回调与早期注入窗口的分析（检测思路对比）

> 版本提示：字段偏移、标准事件序列均随 Windows 构建版本变化；本文结构（对象/流程/APC 机制）与检测结论具备跨版本稳定性，具体偏移请以符号与本地日志为准。