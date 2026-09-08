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
3. **机制层**：APC（异步过程调用内核 APC 与用户 APC 的投递规则、队列结构与可告警等待（alertable wait），这是理解 I/O 完成、线程终止与多种注入手法的关键机制。

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

之所以需要"第二轮调用"，是因为从 Win7 起 `NtCreateUserProcess` 用一次系统调用同时创建进程和初始线程，而初始线程能被调度的前提是新进程的地址空间已就绪、ntdll 已映射进新地址空间——这些工作必须等初始线程真正运行于新地址空间后才能补完。内核把初始线程入口"勾"在 `PspUserProcessStartup` 上，让它以新进程身份补做第二轮 `NtCreateUserProcess`，随后进程才算"活"。