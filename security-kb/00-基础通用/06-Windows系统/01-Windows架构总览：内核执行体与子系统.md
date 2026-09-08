---
title: "Windows架构总览：内核执行体与子系统"
category: "00-基础通用/06-Windows系统"
tags: [Windows架构, 内核, 执行体, 子系统, 驱动, Rootkit, 攻击面]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# Windows架构总览：内核执行体与子系统

> **合规声明**：本文仅用于合法的安全研究、渗透测试教学与防御对抗实践。禁止将文中描述的任意知识点、代码片段或命令运用于未授权系统、非法入侵、恶意软件开发或任何违反法律的行为。读者须遵守所在地法律法规及目标系统的授权条款，任何因滥用本文内容造成的后果由使用者自行承担。文中出现的所有技术细节均以"知己知彼、以攻促防"为立足点，最终目标是加固防御、提升检测能力。

## 核心速查表

| 维度 | 本质定义 | 核心用途 | 关键参数 | 常见风险 | 关联知识 |
|------|----------|----------|----------|----------|----------|
| 用户态 (User Mode) | 受保护的环形3 (Ring 3) 用户进程执行环境 | 运行应用程序、子系统进程与用户API | CS寄存器RPL=3；页表 U/S 位=1；`ntdll.dll` 转发 | 内存越界、提权漏洞、进程注入目标 | [[进程与线程管理]] |
| 内核态 (Kernel Mode) | 环形0 (Ring 0) 高特权执行环境，可访问全部内存 | 运行执行体、驱动程序、系统服务与中断处理 | CS RPL=0；CR0.WP 写保护；权限位 P=1 | 驱动漏洞放大、Rootkit 驻留地、BSOD | [[内核驱动开发]] |
| 执行体 (Executive) | `ntoskrnl.exe` 中的高管层组件集合（对象、内存、I/O、安全管理器等） | 提供原语服务与内核对象管理，是所有子系统的基础 | 导出的 `Ex*` / `Ob*` / `Mm*` / `Io*` / `Se*` / `Ps*` 函数族 | 系统服务表 (SSDT/SystemCall) 是挂钩攻击点 | [[SSDT挂钩原理]] |
| 内核 (Kernel) | `ntoskrnl.exe` 底层部分：线程调度、中断/异常、DPC、多处理器同步 | 提供最底层的机制而非策略 | `Ke*` 函数族、IDT、GDT | 中断劫持、DKOM 隐藏对象 | [[内核对象隐藏]] |
| 子系统 (Subsystem) | `csrss.exe` 用户态子系统进程；`win32k.sys` 内核实模式子系统 | 提供 Win32 / 控制台 / 图形输出等API语义 | `win32k.sys` 中的 `NtGdi*` / `NtUser*` | Win32k 漏洞是提权热点、图形驱动攻击面 | [[Win32k 提权]] |
| 会话管理 (Session Manager) | `smss.exe` 负责引导期的分区、子系统与Winlogon启动 | 第一阶段启动、环境变量与页面文件设置 | 注册表 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` | 可被劫持用于持久化 (RunOnce等) | [[持久化技术]] |
| 安全机制 | LSA (`lsass.exe`)、安全引用监视器 SRM、访问令牌 (Token) | 认证、访问控制、审计 | `Se*` 函数、SID、ACE/DACL/SACL、Token 句柄 | Token 窃取、LSASS 内存 dump、DCSync | [[访问令牌与提权]] |

## 1. 概述

Windows 操作系统是微软公司设计、实现并持续演进的一个庞大、闭源、通用型操作系统家族，其现代架构根植于 1993 年发布的 Windows NT 内核（Windows NT 3.1）。与早期基于 MS-DOS 的 Windows 9x 系列截然不同，Windows NT 从一开始就确立了"微内核思想 + 混合内核实现"的设计哲学：绝不把图形、窗口、进程管理这些通用机制统统塞进内核，而是通过严格的内外分层（用户态/内核态）、对象化管理（Object Manager）、以及可装卸的子系统（Subsystem）来构建整个系统。

从安全攻防的专业视角看，理解 Windows 架构的核心价值在于：**每一层明确的分界都同时是攻击面和防御面的天然战场**。攻击者寻找的是跨越用户态与内核态边界的通道（如驱动加载、Win32k 漏洞、任意句柄操作、越权 token），而 EDR（Endpoint Detection and Response，端点检测与响应）、反病毒软件与安全内核监控器则在截获这些通道（如挂钩 SSDT、注册内核回调、插桩系统服务分发点）。因此，把这张架构图刻进脑子里，是从事红队、蓝队、逆向、Rootkit 对抗乃至内核驱动开发的先决条件。

本篇文章属于"主攻级"（主攻）定位，意味着读者应当不满足于"知道有哪些组件"，而是要**逐层拆解其底层实现、内存布局、调用链与符号细节**，并能据此推导出攻击与检测的具体切入点。整篇文章将沿着以下主线展开：（1）用户态 vs 内核态的本质与特权环模型；（2）执行体（Executive）的组件构成与内核对象体系；（3）从 Win32 API 到原生 API（Native API）再到内核系统服务的完整调用链；（4）系统启动的第一/第二阶段与关键子系统进程（smss / csrss / winlogon / lsass / services）；（5）安全视角下的攻击面、Rootkit 目标与 EDR 挂钩点；（6）实战代码与命令示例；（7）常见坑与避坑指南；（8）知识关联；以及（9）权威参考资料。

## 2. 核心原理

### 2.1 特权环（Privilege Ring）模型

现代 x86/x64 CPU 为操作系统提供四级特权环（Protection Ring），编号为 Ring 0 到 Ring 3。Windows 只使用其中的两个：Ring 0（内核态，最高特权）与 Ring 3（用户态，最低特权）。x86 架构通过当前代码段寄存器 CS 的最低两位（RPL，Requested Privilege Level，请求特权级）来标识当前指令运行于哪一级。CS=RPL 0 表示内核态，CS=RPL 3 表示用户态。

```
                高特权（Ring 0：内核态）
  ┌─────────────────────────────────────────────────────┐
  │  ntoskrnl.exe  hal.dll  win32k.sys  ntfs.sys        │
  │  内核(Kernel) + 执行体(Executive) + 设备驱动(Drivers) │
  │  中断/异常/DPC  体系结构相关代码   图形内核            │
  ├─────────────────────────────────────────────────────┤
  │                系统服务分发 (KiSystemService)        │
  │   syscall/sysenter        +        SSDT(SystemCall) │
  ├─────────────────────────────────────────────────────┤
  │  ntdll.dll  (原生 API 转发层，用户态)                │
  │  kernel32.dll / user32.dll / gdi32.dll (Win32 API)  │
  │  smss.exe csrss.exe winlogon.exe lsass.exe services │
  │  应用程序进程                                    (low)│
  └─────────────────────────────────────────────────────┘
                低特权（Ring 3：用户态）
                受页表 U/S 位保护
```

由于 CPU 并不区分"特权环只有地铁图上的两级"，页表项中的 U/S（User/Supervisor）位配合环级加载控制（如 CR0 的写保护位 WP、SMEP/SMAP 等现代缓解）共同把用户态进程的限制落到实处：用户态代码无法执行 `in/out`、`cli/sti`、`lgdt/lidt` 等特权指令，也无法直接读写内核页；反之内核态代码可以任意访问全部物理与虚拟内存、控制 CPU 状态。

特权环的分界最终体现在**指令级能否执行**与**内存页等级访问**两方面，任何跨越都必须通过受控的"门"（Gate）：系统调用（System Call）、中断门（Interrupt Gate）与陷阱门（Trap Gate）。Windows x64 主要使用 `syscall` 指令（用户态）与对应的 `KiSystemCall64` 内核入口（内核态）完成上下文切换，这也就是安全领域常说的 **SYSCALL 入口** 与 **SSDT（System Service Descriptor Table，系统服务描述符表）** ——它们是可执行挂钩（hook）的核心锚点，我们将在后文展开。

### 2.2 分层与混合内核

Windows 并非纯粹意义的微内核（Microkernel）：它把进程/线程调度、内存分页、对象管理、中断处理等最敏感的机制放进了内核，但同时保留了子系统机制，同时又把设备驱动模块化、把图形（GUI/GDI）置于独立的内核实模式组件 `win32k.sys` 中。这种"机制与策略分离"的思想让 Windows 保持了可扩展性与性能，也解释了为什么 NT 内核在架构上常被称为 **混合内核（Hybrid Kernel）**。

```
                 ┌───────────────────────────────────────────────┐
                 │                System 进程 (PID 4)             │
                 │   内核线程：工作线程、内存管理、缓存管理        │
                 └───────────────────────────────────────────────┘
用户体验层 ──► Win32 子系统 (csrss.exe) + 会话/窗口/输入

API 转发层 ──► ntdll.dll  ──►  (syscall指令)
                       │
                       ▼
        ┌──────────────────────────────────────┐
        │  System Service Dispatch (SSDT)       │
        │  KiSystemCall64 / KiSystemService      │
        └───────────────┬──────────────────────┘
                        ▼
   ┌──────────────────────────────────────────────────────────────┐
   │               ntoskrnl.exe — 内核 + 执行体(Executive)        │
   │                                                              │
   │  ├─ 内核层 (Kernel): 线程调度/中断/DPC/多处理器同步           │
   │  │   Ke* 函数族、IDT、GDT、APIC                            │
   │  ├─ 执行体层 (Executive):                                   │
   │  │   ├ 对象管理器   Ob*   (Object Manager)                  │
   │  │   ├ 进程与线程   Ps*   (Process/Thread)                  │
   │  │   ├ 内存管理器   Mm*   (Memory Manager)                  │
   │  │   ├ I/O管理器    Io*   (I/O Manager)                     │
   │  │   ├ 缓存管理器   Cc*   (Cache Manager)                   │
   │  │   ├ 配置管理器   Cm*   (Configuration Manager, 注册表)    │
   │  │   ├ 安全引用监视器 Se*  (Security Reference Monitor)      │
   │  │   ├ 电源管理器   Po*   (Power Manager)                   │
   │  │   └ 本地过程调用  Lpc*  (LPC)                            │
   │  └─ 体系结构相关层 (HAL, hal.dll)                            │
   └──────────────────────────────────────────────────────────────┘
                        │
                        ▼
   ┌──────────────────────────────────────────────────────────────┐
   │    设备驱动 (Drivers): WDM / KMDF / NDIS 等, *.sys            │
   │    IRP 传递、即插即用 (PnP)、电源管理、I/O 堆栈               │
   └──────────────────────────────────────────────────────────────┘
                        │
                        ▼
                       硬件 (CPU/内存/设备控制器)
```

### 2.3 系统调用（System Call）与 API 分层

这是理解 Windows 安全的核心链条。当一个用户应用程序想要读写文件、创建线程或分配内存时，它通常调用的是 Win32 API（如 `CreateFile`、`CreateThread`、`VirtualAlloc`）。但 Win32 API 本身并不直接进入内核——它位于 `kernel32.dll` / `user32.dll` / `gdi32.dll` 中，最终会调用 Windows 原生 API（Native API）层 `ntdll.dll` 中导出的 `NtXxx` / `ZwXxx` 函数。`ntdll.dll` 中的这些函数仅仅是一个薄封装：它们把参数压入寄存器，设置系统调用号，然后执行 `syscall` 指令陷入内核。

内核收到中断/陷入后，由 `KiSystemCall64` 定位到 SSDT（系统服务描述符表），依据系统调用号查表，把控制权交给对应的内核例程（如 `NtCreateFile` 的内核实现，位于 `ntoskrnl.exe`）。系统服务编号（SSN，System Service Number）在 Windows 各版本间并不稳定，这也是为什么类似 `SysWhispers`、`Halo's Gate` 这类工具需要通过动态解析来获取调用号。

```
Win32 API (kernel32.dll/ntdll)                      Native API (ntdll.dll)
  CreateFileW  ──►  NtCreateFile (ntdll)                NtCreateFile (内核 ntoskrnl)
  CreateThread ──►  NtCreateThread (ntdll)              NtCreateThread
  VirtualAlloc ──►  NtAllocateVirtualMemory (ntdll)     NtAllocateVirtualMemory
        │                  │                                 │
        ▼                  ▼                                 ▼
     调用约定         转发(forwarder)                    SSDT 表查系统服务号
     API层逻辑      设置寄存器+syscall               KiSystemCall64 → 内核例程
```

安全意义：EDR 通常会在**三个层次**实施监控以便互相弥补盲点——用户态 API 挂钩（Inline Hook 于 `ntdll.dll` / `kernel32.dll` 的头部）、内核态 SSDT 挂钩（修改 SSDT 表项指向自己的过滤函数）、以及底层 ETW（Event Tracing for Windows）/内核回调（如 `PsSetCreateProcessNotifyRoutine` 注册的进程创建回调）。攻击者为了规避用户态 hook，会使用"直接系统调用"（Direct Syscall）：直接从用户态执行 `syscall`，绕过 `ntdll.dll` 中的被钩函数，这一技术在 Cobalt Strike 的 BOF（Beacon Object File）、各类利用 shellcode 中极其常见。

## 3. 详细知识点

### 3.1 内核态与用户态的本质边界

Windows 把虚拟地址空间分为两部分：上半部分（x64 为指针最高位为 1 的 128TB 高半区）属于**系统空间（System Space）**，内核态可访问；下半部分（低 128TB）属于**用户空间（User Space）**，每个进程私有的、受 U/S 位保护。内核态可以无差别访问两者，而用户态只能访问自己的低半区用户页。

关键底层机制：

- **CS 段与 RPL**：`CS` 寄存器的最低两位指示当前特权级，Windows 中用户态 RPL=3，内核态 RPL=0。x64 下 `SYSRET`/`SYSCALL` 会自动切换 RPL，配合 FS/GS 段寄存器存放用户态与内核态的线程信息块（分别为 TIB 与 KPCR）。
- **页表权限位**：PTE（Page Table Entry）中的 `U/S` 位决定页是用户页还是系统页；`W`（可写）位；`N`（不可执行 NX）位配合 DEP。此外现代 CPU 与 OS 还引入了 **SMEP（Supervisor Mode Execution Prevention，管理模式执行保护）** 与 **SMAP（Supervisor Mode Access Prevention，管理模式访问保护）**——内核无法再直接执行（SMEP）或访问（SMAP）用户态页，给传统的"内核提权后直接调用用户态小函数"（ret2user）类攻击带来巨大阻碍，迫使攻击者转向 ROP（Return-Oriented Programming，面向返回的编程）这类 gadget 复用技术。
- **GDT/IDT/LDT**：全局描述符表（GDT）定义段属性，中断描述符表（IDT）定义中断/异常处理例程的地址。IDT 在 Ring 3 可读但不可写；Rootkit 若篡改 IDT 指向恶意处理函数即可实现"中断挂钩"（IDT Hooking），但因缺乏健壮性如今已不常见，更多被用于反调试触发检测而非驻留。
- **上下文切换与 TSS**：x64 下任务状态段（TSS）主要用于维护 RSP0（内核栈指针）、I/O 权限位图与 AST（APIC 相关状址）。每次从用户态进入内核态，`KiSystemCall64` 会从 TSS 读出 RSP0 切换到该线程的内核栈。

安全含义：用户态与内核态的界限一旦被攻破（例如驱动存在类型混淆或池溢出漏洞被利用，或者攻击者成功伪造签名加载了恶意驱动，或通过"驱动器签名绕过"载入未签名模块），攻击者即获得 Ring 0 全权，可：

- 修改任意进程的 EPROCESS（执行体进程结构）标志位、Token 字段以实现隐藏与提权；
- 挂钩 SSDT/内核函数/`IRP Handler` 实现 Rootkit 隐藏（DKOM，Direct Kernel Object Manipulation，直接内核对象操作）；
- 读写物理内存（IoAllocateMdl + MmMapLockedPagesSpecifyCache）更换用户态代码；
- 关闭 PatchGuard（KPP）相关保护后的任意修改（此项有争议且高度危险）。

### 3.2 执行体（Executive）与 ntoskrnl.exe

执行体是 `ntoskrnl.exe` 实现的高管层，由多个职责分明的组件构成。它们不是单独的模块，而是同一二进制内以函数前缀区分的逻辑组件。下面逐一说明，并标注每个组件的安全关注点：

#### 3.2.1 对象管理器（Object Manager，Ob*）

对象管理器管理系统内核对象（Object），如进程对象、线程对象、文件对象、事件、互斥体、信号量、令牌等。任何可被命名的内核实体都被纳入一个 `\` 根下的对象命名空间（Object Namespace），例如 `\Device\PhysicalMemory`、`\BaseNamedObjects`、`\Windows`。

安全关注点：

- 对象访问检查（Object Access Check）由安全引用监视器（SRM）依据对象的 DACL/SACL 执行；但对象管理器本身允许持有句柄者通过 `ObReferenceObjectByHandle` 等 API 获取对象指针。
- 穷举对象命名空间可泄露系统路径与设备名（信息收集）。
- Rootkit 可通过 `ObRegisterCallbacks`（句柄操作回调）拦截/过滤句柄的打开与复制操作，从而隐藏进程、防止其他进程打开受保护进程的句柄。EDR 同样会利用该 API 实现进程保护与对抗。

#### 3.2.2 进程与线程管理器（Process/Thread Manager，Ps*）

管理进程与线程对象、创建销毁、调度参数、以及通过 `PsSetCreateProcessNotifyRoutineEx` / `PsSetCreateThreadNotifyRoutine` / `PsSetLoadImageNotifyRoutine` 提供回调。系统进程 `System`（PID 4）是所有内核工作线程的宿主。

安全关注点：

- 进程创建与镜像加载回调是 EDR 检测恶意进程/脱壳/模块注入的核心手段，同时也是恶意驱动/合法安全驱动两者争夺的关键扩展点。
- `Ps*` 导出的结构如 `PspCreateProcessNotifyRoutine`、`PspLoadImageNotifyRoutine` 常被恶意代码当作 SSDT 之外的另一个钩子表进行扫描与篡改（部分 Rootkit 会整体摘除这些回调以规避监控）。

#### 3.2.3 内存管理器（Memory Manager，Mm*）

负责虚拟内存管理、工作集（Working Set）、分页（Paging）与缺页处理、以及地址空间描述（VAD，Virtual Address Descriptor）。核心结构：`_EPROCESS`（进程）、`_KPROCESS`、`_MMVAD`、页表基址 PTE 等。内存保护标志 PAGE_EXECUTE_READWRITE 等在此层面体现。

安全关注点：

- 内存注入（如 `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + `NtCreateThreadEx`，即经典的"VirtualAlloc/WriteProcessMemory/CreateRemoteThread"进阶版）通过 Win32 API 或 Native API 均可完成。
- `MmMapIoSpace` 允许驱动直接映射物理地址，被用于读写 MSR/PCI 配置；若被滥用则可能破坏内核完整性。
- EDR 依赖内存扫描（扫描仍未脱壳的注入镜像特征）与"被注入页面"审计来检测。

#### 3.2.4 I/O 管理器（I/O Manager，Io*）

提供统一 I/O 请求模型：WDM/KMDF 驱动通过 I/O 请求包（IRP，I/O Request Packet）与上层交互。每个设备对象（Device Object）链组成设备栈（Device Stack），IRP 依次穿过各层驱动直至物理设备，再原路返回。

安全关注点：

- IRP 派发处理函数表（MajorFunction 数组）是过滤驱动与文件过滤驱动（如 minifilter，`FilterManager` 即 `Flt*`）的钩挂点。
- 恶意"文件微过滤驱动"（minifilter）可在文件系统层面隐藏/篡改文件，是核心级 Rootkit 的重要手段。
- 篡改驱动对象（`_DRIVER_OBJECT`）的 `MajorFunction` 指针是常见 Rootkit 手法，EDR 通过"IRP 堆栈扫描"来识别异常驱动。

#### 3.2.5 缓存管理器（Cache Manager，Cc*）

为文件系统提供统一的缓存读写机制（虚拟块缓存 VBC），与内存管理器联动。安全关注点：缓存数据的"脏页/延迟写"机制影响取证（例如断电数据丢失），恶意软件利用缓存绕过磁盘层监测属于边缘话题。

#### 3.2.6 配置管理器（Configuration Manager，Cm*）

封装注册表（Registry）操作，维护 `\Registry` 对象树，映射到 `HKLM\SYSTEM` 等配置单元（Hive）。底层由 `\Device\PhysicalMemory` 上的 `CM` 数据结构与 `\SystemRoot\System32\config` 下的 Hive 文件支撑。

安全关注点：

- 注册表项的 `Run`、`RunOnce`、`Image File Execution Options`（IFEO）、`Services` 键、`Winlogon` 键、计划任务等是 Windows 持久化（Persistence）的最常见位置。
- RunOnce 由 smss 在第一/第二阶段启动时处理，是"持久化与启动组件"的重要挂点。

#### 3.2.7 安全引用监视器（Security Reference Monitor，Se*）

负责访问控制的核心：验证主体（通过访问令牌 Token 表达其 SID 与特权）对对象（通过 DACL/SACL 与 ACE）的访问是否被允许，维护了"Token/ACL→决策"的判定逻辑（`SeAccessCheck`、`SePrivilegeCheck`）。它保证安全决策在统一的一处做出——这是 Windows 安全模型的基础。

安全关注点：

- **Token 结构（_TOKEN）** 是提权攻击的核心目标：通过泄露/复制 Token、`AssignProcessToJobObject`、进程提权（如 SeDebugPrivilege、SeImpersonatePrivilege）等手段，"窃取 SYSTEM 令牌"。
- 内存中的 LSASS 进程持有高权 Token 与认证凭据，是凭据转储（Credential Dumping，如 Mimikatz sekurlsa::logonpasswords）的直接目标。
- 恶意驱动若能调用 `Se*`（如 `SeDebugPrivilege` 提升、直接改 Token），即可在无签名校验的门槛下完成提权。

#### 3.2.8 电源管理器（Power Manager，Po*）与本地过程调用（LPC）

电源管理器协调系统与设备的电源状态（Sleep/Hibernate）；LPC（Local Procedure Call，本地过程调用）是内核提供的高效局部队间通信机制，被 `csrss.exe`、`lsass.exe` 以及早期 ISR 使用。ALPC（Advanced LPC）为其高级版本，常用于服务通信。安全关注点：ALPC 端口可被泄露漏洞利用（如 PrintNightmare 远程利用中涉及 RPC/ALPC 的组件）。

### 3.3 内核（Kernel）层与体系结构支持（HAL）

区别于执行体，内核层（Kernel）是 `ntoskrnl.exe` 中更底层、更与 CPU 紧耦合的部分（`Ke*` 函数族）：

- **线程调度**：优先级驱动的抢占式多任务（32 个优先级级别），时间片、中断优先级（IRQL）模型。此处强调 Windows 并非完全抢占式——在 DPC 层与中断上存在非抢占窗口。
- **中断与异常**：IDT 分发，软中断（`KiDispatchInterrupt`）、异常处理、DPC（Deferred Procedure Call，延迟过程调用，`KiExecuteAllDpcs`）。
- **多处理器同步**：自旋锁（Spinlock，`KeAcquireSpinLock`）、快速互斥（Fast Mutex）、资源 ERESOURCE 等。
- **DPC 队列**：`KDPC` 用于把高 IRQL 下的工作延迟到调度器环境执行。

HAL（Hardware Abstraction Layer，硬件抽象层）位于 `hal.dll`，把内核与具体硬件平台隔离：封装了中断控制器（APIC）、时钟、DMA 转换、PCI 总线等。NTD/Aml 追求"HAL 之上代码与平台无关"。

安全关注点：IRQL 与 DPC 是驱动开发的高危区——错误地在高 IRQL 下申请分页内存或调用 `ExAcquireResourceExclusiveLite` 等会引起死锁或蓝屏；在攻防对抗中，恶意驱动也会刻意在高 IRQL 上"自旋"消耗 CPU、或将敏感操作延迟到 DPC 以规避中断级检测。

### 3.4 设备驱动体系（Device Drivers）与过滤驱动

Windows 驱动按框架可分为 WDM（Windows Driver Model，Windows 驱动模型）、KMDF（Kernel Mode Driver Framework，内核模式驱动框架，基于 WDM 的对象化封装）与 UMDF（User Mode Driver Framework，用户模式驱动框架）。现代 Windows 更推荐 Kernel-mode Driver Framework（KMDF）。设备驱动通过 `DriverEntry` 入口注册 `IRP major function` 分发表，并创建设备对象（`IoCreateDevice`）。共享设备由 `\Device\` 与 `\DosDevices\`（符号链接）暴露给用户态。

**设备栈与过滤驱动**：一个设备往往由多层驱动构成（总线驱动→功能驱动→过滤驱动），构成设备栈。上层过滤驱动（Upper Filter）与下层过滤驱动（Lower Filter）分别在每个 IRP 经过时前后查看。**文件系统微过滤驱动（Minifilter）** 基于 FltMgr 注册回调和 IRP 处理，用于在文件系统层拦截读写——这是文件隐藏、监控、篡改的枢纽。

安全关注点：

- 内核驱动是执行本机任意代码的强力途径，Windows 要求**签名驱动**（WHQL/EV 签名），64 位系统强制 Kernel Mode Code Signing（KMCS）。但存在旧签名泄漏、证书伪造、测试签名绕过（需系统开启 test mode），以及 2020 年前后公开的"Bring Your Own Vulnerable Driver（BYOVD）"攻击手法。
- 恶意驱动一旦进入 Ring 0，往往不再依赖任何用户态 API，直接以 SYS 形式加载（或嵌入内核池）。

### 3.5 Win32k.sys —— 内核实模式图形子系统

`win32k.sys` 是 Windows 内核中承担 Win32 图形（GUI）、窗口管理（WM）、用户输入（UxTheme）、以及部分图形驱动的实现。它在历史上承担了绝大部分 GDI（Graphics Device Interface）与 USER 子系统调用，因此对应着大量 `NtGdi*`、`NtUser*` 系统服务。大量 Win32k 漏洞（如 CVE-2019-1458、CVE-2021-1732、白象相关 CVE）被广泛用于 Windows 本地提权（LPE）。

安全关注点：

- 图形内核直接处理来自用户空间的按键、鼠标消息与绘图指令，攻击面大；近年趋势是把 `win32k.sys` 分解并下沉（如 `win32kfull.sys`、`win32kbase.sys`、`win32k.sys`），同时引入更多缓解（如 2023 年起的"cros 权限"、内存守卫 TAP）。
- EDR 会针对 `NtUser*` / `NtGdi*` 的 SSDT 表项做监控，以捕捉利用图形内核漏洞的提权行为（GDI Objects 滥用导致的内核对象释放重用是经典利用手法）。

### 3.6 原生 API（Native API）与 ntdll.dll

`ntdll.dll` 是用户态最低层的 DLL：它导出了所有 `Nt*`/`Zw*` 系统服务包装函数、运行库基础（heap、RTL）、以及 LDR（PE Loader）相关的装载函数（`LdrLoadDll` 等）。`Kernel32.dll`、`User32.dll`、`Advapi32.dll`、`Shell32.dll` 等高层 DLL 最终都依赖它。

`Nt*` 与 `Zw*` 的区别：在用户态二者完全等价（`Zw*` 实际上并没有特定区分，仍是转发到 ntdll 的同一包装）；但在内核态，`Zw*` 系列会走系统服务分发（即使在内核里也重新穿越分发器、遵循 IRQL 约束），而直接调用对应的 `Nt*` 函数则只是普通函数调用。这个区别对驱动编写与利用都有现实的正确性影响。

安全关注点：`ntdll.dll` 是被内联挂钩（inline hook）最密集的用户态模块。EDR 会 patch `ntdll.dll` 的 `NtCreateProcessEx`、`NtWriteVirtualMemory`、等入口实现监控，而攻击者则通过"直接系统调用"规避。

### 3.7 用户态子系统与系统进程

Windows 的"子系统"概念落在地上就是一组用户态进程：

- **smss.exe（Session Manager Subsystem，会话管理器）**：系统启动的第一阶段进程。它的工作包括：读取注册表 `Session Manager` 键、建立分页文件、初始化环境变量、创建 `\BaseNamedObjects`、启动 csrss.exe 与 winlogon.exe，随后退出并把自己"固化"为系统会话管理器。它是最早的"无依赖进程"，因此也被持久化玩法（如 RunOnce、BootExecute）盯上。
- **csrss.exe（Client/Server Runtime Subsystem，客户端/服务器运行时子系统）**：实现 Win32 子系统的服务器端。它维护进程/线程上下文、控制台（Console）、窗口管理的客户端部分等。由于它拥有 Win32 的核心语义，安全与恶意双方都非常关注它（例如"CVE-2014-? csrss 提权"）。
- **winlogon.exe**：登录进程，处理用户认证、启动 shell（explorer.exe 的 shell 由它派生）、负责安全桌面（Secure Desktop）与 UAC（User Account Control，用户账户控制）提示的提升确认。它是特权进程，也是篡改目标（如"登录后劫持"、"credential provider"）。
- **lsass.exe（Local Security Authority Subsystem，本地安全权威子系统）**：实现 LSA 服务，负责认证、令牌管理、安全策略、域认证、以及 `ntds.dit` / SAM 凭据的访问。**它是凭据转储攻击（Mimikatz）与勒索软件常用目标**；蓝队需在此布局 EDR（如 LSASS 保护、Credential Guard）。
- **services.exe（Service Control Manager，服务控制管理器）**：管理 Windows 服务（Services），维护服务数据库、依赖关系与启停。新增服务是持久化与提权（服务换名、服务二进制替换）的直接入口。
- **System（PID 4）**：内核的系统进程，承载所有内核线程（`SystemThreads`），无用户代码、无用户句柄。EDR 无法像普通进程那样轻易注入到 PID 4，但可通过内核回调观察其线程活动。

### 3.8 SSDT 与系统服务分发 —— 挂钩主战场

SSDT（System Service Descriptor Table，系统服务描述符表）是一个索引数组，把系统调用号映射到内核服务例程地址。EDR 与 Rootkit 都会在此处做文章：

- 恶意驱动把 SSDT 表项从合法地址改成自己的 `MyHookNtXxx` 地址，即可在任意调用该系统服务时先执行恶意逻辑再转发给原函数，实现监控、篡改、反检测。
- 但该技术在 PatchGuard（KPP，Kernel Patch Protection）启用后变得高风险，64 位系统直接修改 SSDT 会触发蓝屏（0xC1 PatchGuard 检测）。因此现代攻击者改用无法被 PatchGuard 直接覆盖检出的合法回调点（如 `ObRegisterCallbacks`、`PsSetLoadImageNotifyRoutine`、minifilter 回调、`NtCreateFile` 前端的 IRP 挂钩）。

安全含义：从防御出发，EDR 既可以使用 patch guard 不可清除的注册回调，也可以裁决以安全驱动的合法方式做"inline hook"（如 Sysmon 采用 ETW/驱动回调）；从红队出发，理解"哪些表可改、哪些会被检测"决定了 Rootkit 载荷的形态。

### 3.9 启动流程（Boot Flow）与可信启动

Windows 的经典启动序列（BIOS 路径）大致是：固件 → 引导扇区（MBR/VBR）或 UEFI → **bootmgr（Boot Manager）** → `winload.exe`（内核加载器）→ 加载 `ntoskrnl.exe`、`hal.dll`、系统驱动 → 进入"内核初始化"阶段：执行体初始化、对象管理器初始化、SSDT 建立、子系统（smss）启动。UEFI 安全启动（Secure Boot）与 **ELAM（Early Launch Anti-Malware，早期启动反恶意软件）** 提供了在早期驱动加载阶段就运行安全过滤的能力，是目前防 Rootkit 引导期注入的机制。

```
 电源 → BIOS/UEFI → MBR/VBR → bootmgr → winload.efi → ntoskrnl.exe 加载
                                                         │
                                          执行体初始化 + 构建对象命名空间
                                                         │
                                                    smss.exe (会话管理器)
                                                    ├─ 分页文件/环境
                                                    ├─ csrss.exe (子服务器)
                                                    └─ winlogon.exe (登录)
                                                           │
                                                     lsass.exe + services.exe
                                                           │
                                                        登录 → explorer.exe
```

### 3.10 现代安全机制与攻防对抗（纵深）

- **PatchGuard（KPP，内核补丁保护）**：x64 系统上由系统随机编排的"哨兵"线程持续校验受保护内核结构的完整性（SSDT、IDT、GDT、部分驱动对象等），被篡改即触发 bugcheck 0x109（SYSTEM_HIVE snafu 或不一致）。这让传统 SSDT hook / DKOM 在 64 位系统变得高风险，也说明"检测-绕过"是动态游戏。
- **Code Integrity（代码完整性）**：KiValidateImageHeader 校验模块签名、驱动强制 KMCS、以及 Hypervisor-protected Code Integrity（HVCI，内核内存保护）使用虚拟化来隔离内核实用户的完整性验证。
- **SMEP/SMAP/Control-flow Guard (CFG)/KASLR**：面向 exploit 开发的缓解，提升利用门槛。
- **ETW（Event Tracing for Windows）**：内嵌的事件追踪机制，edr/blue team 常用 ETW 实时订阅进程、线程、映像、注册表等事件；而攻击者常通过关闭/破坏关键 ETW Provider（如 Microsoft-Windows-Kernel-Process）来削弱监控（"ETW 阻断"）。

## 4. 实战与示例

### 4.1 使用 WinDbg 观察架构（本地/远程内核调试）

```
!process 0 0                        ; 枚举全部进程（ActiveProcessList）
dq nt!PsInitialSystemProcess         ; 读取系统进程 EPROCESS 地址
dt nt!_EPROCESS                      ; 查看 EPROCESS 结构（Token 偏移、ActiveProcessLinks 偏移）
dt nt!_EPROCESS 82xxxxx Token        ; 读取某进程的 Token 字段
!ssdt                                ; 查看 SSDT 表（系统服务描述符表）内容
!idt                                 ; 查看 IDT 表（中断描述符表）布局
!drvobj \Driver\Disk                 ; 查看某个驱动对象的 IRP 分发例程表
!address                             ; 查看当前地址空间布局（用户空间/系统空间分界）
```

这类命令在分析 Rootkit、驱动异常与进程信息泄露时极其常用：通过 `!ssdt` 可见是否有异常地址出现在 SSDT 表中；通过 `dt nt!_EPROCESS Token` 偏移可计算 Token 偏移用于提权 exploit 的 `EPROCESS` 遍历。

### 4.2 使用 PowerShell 检测系统组件与签名

```powershell
# 列出全部内核驱动及其签名状态（排查 BYOVD / 无签名驱动）
Get-CimInstance Win32_SystemDriver |
  ForEach-Object {
    $p = $_.PathName
    if ($p -and (Test-Path $p)) {
      $sig = (Get-AuthenticodeSignature $p).Status
      [PSCustomObject]@{ Name=$_.Name; Signed=$sig; Path=$p }
    }
  } | Format-Table -AutoSize

# 列出可疑的自动启动 / RunOnce（持久化排查）
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute

# 使用 Sysinternals Autoruns 枚举启动/持久化项
autorunsc.exe -c -a * -h -s -m   # CSV 全量导出
```

### 4.3 通过 Native API 直接系统调用（C/C++ 内核驱动约定示例）

前文提到 `Zw*`/`Nt*` 在内核态的差异，下面给出一个常见的驱动注册 IRP 分发、并调用 ZwXxx 的骨架（KMDF/WDM 风格）：

```c
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp);

typedef struct _DEVICE_CONTEXT {
    UNICODE_STRING DosDeviceName;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\MyTestDevice");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\MyTestDevice");

    // 建立 IRP 分发函数指针（攻击者会篡改此处实现窃听）
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = NULL;

    // 创建设备对象并导出符号链（与用户态 CreateFile 对应）
    status = IoCreateDevice(DriverObject,
                 sizeof(DEVICE_CONTEXT),
                 &deviceName,
                 FILE_DEVICE_UNKNOWN,
                 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(deviceObject); return status; }

    // 使用 Zw 体系访问注册表（内核态走系统服务分发）
    // 例如：ZwOpenKey / ZwQueryValueKey 读取配置
    // HANDLE hKey; OBJECT_ATTRIBUTES oa; PUNICODE_STRING keyPath;
    // InitializeObjectAttributes(&oa, keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    // status = ZwOpenKey(&hKey, KEY_READ, &oa);

    DbgPrint("[driver] MyTestDevice loaded.\n");
    return STATUS_SUCCESS;
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
```

配合用户态调用：

```c
// PowerShell / C 中打开该驱动的符号链进行 DeviceIoControl：
// CreateFileW(L"\\\\.\\MyTestDevice", GENERIC_READ|GENERIC_WRITE, 0, NULL,
//            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```

该示例展示了"驱动对象作为一类内核对象、其 IRP 分发表是攻击/防御结合点"这一核心：篡改 `MajorFunction` 或设备设备的 IRP_PENDING 即可劫持任意设备 I/O。

### 4.4 通过 ETW 观察进程/线程/映像活动

```powershell
# 启用内核进程 ETW Provider 并实时观测（蓝队监控进程创建）
logman create trace procmon -p "Microsoft-Windows-Kernel-Process" 0x2 -o procmon.etl
logman start procmon
# ... 运行被监控程序 ...
logman stop procmon
# 用 Windows Performance Analyzer 或 tracerpt 解析 procmon.etl
tracerpt procmon.etl -o procmon.csv -of csv
```

### 4.5 验证 SSDT 是否被篡改（畸形地址检测）

```powershell
# 借助 NirSoft 或 Sysinternals 的 Kernel 工具查看 SSDT 表中是否存在
# 指向非 ntoskrnl 的陌生地址（通常非法改动会指向自定义驱动）。
# 另可用 WinDbg 的 !ssdt Whistler 扩展打印每项的原地址与当前地址之差异。
```

## 5. 常见坑与避坑指南

1. **把"Ring"与"权限"在 Windows 上混同**：Windows 只有 Ring 0/3 两级被使用，且现代缓解（SMEP/SMAP/CFG）已大幅改变 Ring 0 的游刃度。写文章/做利用时不要默认"进 Ring 0 = 完全自由"。
2. **误以为 SSDT hook 是唯一/最佳的 Rootkit 挂钩点**：64 位 PatchGuard 会蓝屏；现代攻击者多用合法注册回调与 minifilter。防御端也不应只盯着 SSDT。
3. **混淆 `Nt*` 与 `Zw*` 的内核语义**：驱动内直接调用 `NtCreateFile` 是函数调用，而调用 `ZwCreateFile` 会重新进入 SSDT 分发——在高 IRQL 处要谨慎；写驱动时混乱会引起死锁。
4. **忽略页面池/缓冲与 IRQL 关系**：在高 IRQL（> DISPATCH_LEVEL）下申请分页内存或调用可能分页的例程（如 `ExAllocatePoolWithTag` 的分页池）会触发 bugcheck；这是内核崩溃数据的常见误因。
5. **盲目相信"签名驱动 = 安全"**：证书过期、泄露、以及 BYOVD 均可使已签名驱动被滥用。签名校验面向"来源可信"，而非"行为可信"。
6. **只监控用户态 API/DLL 挂钩而漏内核侧**：攻击者通过直接系统调用可绕过 ntdll hook；因此 EDR 必须具备内核回调/ETW 层面检测，否则极易被绕过。
7. **PatchGuard 与 KASLR 对动态分析工具的干扰**：内核调试器（WinDbg）会被 PatchGuard 干扰/拒绝某些动作；KASLR 随机化也让旧偏移脚本失效——分析时应读取哨兵符号/重新计算偏移。
8. **把"系统服务"进程直接当 Rootkit 宿主而不考虑其特权意义**：System/PID 4、smss、csrss、lsass 等拥有内核级或特权上下文，是其攻击价值所在；但它们的内部结构（如 csrss 的窗口消息处理）也常被用于提权与反射注入。
9. **忽略启动早期（UEFI/ELAM/Secure Boot）层**：仅聚焦于 Ring 0 驱动防护，而忽略 bootmgr/winload/ELAM 阶段的载荷注入——引导期 Rootkit（Bootkit）可绕过后期检测。
10. **内核逆向/驱动的编译环境不匹配**：驱动必须与目标 Windows 版本、架构（x64）、WDK/WinSxS 一致；用错 SDK/体系会蓝屏或加载失败。调试符号（Public Symbols）过旧时 `dt` 偏移会错位。

## 6. 知识关联

- [[Windows进程与线程管理]] —— 执行体 Ps* 与 EPROCESS/KPROCESS 结构、线程调度与优先级。
- [[Windows内存虚拟化与分页]] —— 内存管理器 Mm*、VAD、页表、工作集与内存保护（DEP/ASLR）。
- [[Windows对象与句柄]] —— 对象管理器 Object Manager、命名空间、句柄表与访问检查。
- [[SSDT与系统调用挂钩]] —— 系统服务分发、SSDT 结构与挂钩/反挂钩实战。
- [[Windows访问令牌与提权]] —— 安全引用监视器 Se*、_TOKEN、权限/特权枚举与提权路径。
- [[Rootkit技术与对抗]] —— DKOM、minifilter 隐藏、注册回调、PKPP 攻防。
- [[Windows驱动开发入门]] —— WDM/KMDF、IRP 处理、DeviceIoControl 通信、签名与加载。
- [[持久化技术概览]] —— Run/RunOnce/注册表/服务/计划任务与 smss 启动期交互。
- [[EDR工作原理与绕过]] —— 挂钩点（SSDT/ETW/回调）、直接系统调用与 ETW 阻断。
- [[内核逆向工程入门]] —— IDA/WinDbg/Windbg 关于内核模块的反汇编、结构体解析与符号。

以上关联以 Windows 架构为轴心，把"进程/内存/对象/访问控制/驱动/持久化/对抗"串成一条从攻击面到防御面的完整链路，便于按主题展开专项研究。

## 7. 参考资料

1. **Microsoft Docs —— Windows 内核架构**（官方）：
   - "Windows kernel" / "Inside the Windows Kernel" 系列：https://learn.microsoft.com/windows-hardware/drivers/kernel/
   - WDK 驱动开发文档（KMDF、IRP、设备栈）：https://learn.microsoft.com/windows-hardware/drivers/
   - "Boot sequence"（启动顺序）：https://learn.microsoft.com/windows-hardware/drivers/
2. **《Windows Internals》**（第 7 版，Mark Russinovich、David Solomon、Alex Ionescu）：官方权威专著，详细覆盖执行体、内核、子系统、SSDT 与对象管理器。中文译本《深入解析 Windows 操作系统》。
3. **Microsoft Learn —— Windows 系统调用/原生 API**：
   - NtDll 系统服务（Syscalls）：https://learn.microsoft.com/windows/win32/api/
   - UNDOCUMENTED NT APIs 参考（SysInternals 创始人的 NT Internals 站点）：https://undocumented.ntinternals.net/
4. **Microsoft Learn —— Windows 安全**：
   - Windows 安全模型与访问控制：https://learn.microsoft.com/windows/security/identity-protection/access-control/
   - Security Descriptor / DACL / SACL：https://learn.microsoft.com/windows/win32/secauthz/access-control
   - Credential Guard / Local Security Authority：https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
5. **Microsoft Learn —— ETW（Event Tracing for Windows）**：
   - ETW 文档：https://learn.microsoft.com/windows/win32/etw/event-tracing-portal
6. **Microsoft Learn —— Windows 内核模式调试（WinDbg）**：
   - Kernel-mode debugging tools：https://learn.microsoft.com/windows-hardware/drivers/debugger/
   - WinDbg 命令参考（!process、!ssdt、!idt）：https://learn.microsoft.com/windows-hardware/drivers/debugger/
7. **MJT (Matthew Graeber) 与实用参考**：
   - "Direct System Calls" / NtTraceSyscall 技术文章（用于日志绕过与内核研究）。
8. **安全社区/paper**：
   - CVE（Common Vulnerabilities and Exposures）关于 Win32k 提权漏洞（如 CVE-2021-1732、CVE-2022-21882）。
   - "Windows Internals" 配套网站（Sysinternals.com）文档与 eBook（PDF 由微软官方提供）：
     https://learn.microsoft.com/sysinternals/
9. **微软符号库（Public Symbols）**：
   - 下载调试符号以便 `dt nt!_EPROCESS` 等结构解析：https://msdl.microsoft.com/download/symbols

> 说明：本文内容综合自微软官方文档、Windows Internals 专著与公开安全研究。文中链接为作者整理的官方入口，实际使用时请以微软当前文档站为准（部分 URL 因版本演进可能有路径微调）。
