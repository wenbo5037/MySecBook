---
title: "进程本质：PCB结构与进程创建流程"
category: "00-基础通用/04-操作系统原理"
tags: [进程, PCB, fork, 操作系统, 调度]
level: 主攻
type: ai-generated
status: 完成
updated: 2025-07-17
---

# 进程本质：PCB结构与进程创建流程

> 本文内容聚焦操作系统基础原理，属于计算机学科通识知识。文中涉及的进程管理、系统调用等均为合法操作系统课程与系统编程实践范畴，未涉及任何攻击性技术。请读者遵守所在机构与国家的法律法规，仅在授权环境中进行实验。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 进程(Process)是操作系统进行资源分配和调度的基本单位，是程序的一次动态执行过程，由代码、数据、堆栈和PCB(Process Control Block)组成 |
| 核心用途 | 实现多道程序并发执行、隔离各程序的地址空间、管理 CPU/内存/文件等资源、支撑 shell 与守护进程等系统架构 |
| 关键参数 | PID(Process ID)、状态(R/S/D/Z/T)、优先级与 nice、父子关系(PPID)、内存映射 mm_struct、文件描述符表 files_struct、信号掩码 |
| 常见风险 | fork 泄漏导致的僵尸进程(Zombie)、D 状态(Uninterruptible Sleep)进程无法 kill、COW 误用带来的内存膨胀、未回收子进程的孤儿进程 |
| 关联知识 | [[02-调度算法：从时间片轮转到CFS与EEVDF]]、[[05-上下文切换：开销来源与实测分析]]、[[10-内核态用户态：特权级与模式切换]] |

## 1. 概述

进程(process)是现代操作系统中最核心的概念之一。理解进程是理解整个操作系统的基础——调度、内存管理、文件系统、IPC 等所有子系统最终都是围绕"如何管理好一堆进程"来设计的。

**进程 vs 程序**：程序(program)是存储在磁盘上的静态指令序列，是一个被动实体(entity)；进程则是程序被加载到内存后由 CPU 执行的动态活动，是一个主动实体。同一份程序可以被加载为多个进程（例如同时开多个编辑器窗口），每个进程拥有独立的地址空间和执行上下文。

| 比较维度 | 程序(Program) | 进程(Process) |
|---------|--------------|--------------|
| 存在性 | 静态，长期驻留磁盘 | 动态，从创建到消亡有生命周期 |
| 组成 | 代码与数据文件 | 程序 + 数据 + 堆栈 + PCB |
| 状态 | 无状态 | 有 运行/就绪/阻塞 等状态 |
| 并发性 | 不具备 | 可与其他进程并发执行 |
| 资源 | 不占用运行资源 | 占用 CPU、内存、I/O 等资源 |

进程的动态性体现在：它经历创建——就绪——运行——阻塞——终止的生命周期，且随调度不断在状态间迁移。这种动态性是理解操作系统调度与并发的基础。

从安全视角看，进程隔离(address space isolation)是操作系统安全模型(protection domain)的基石：一个进程无法直接读取另一个进程的内存，必须通过受控的 IPC 或系统调用才能通信。理解进程结构，也是理解内核后门、提权攻击、恶意软件行为分析的前提。

## 2. 核心原理

进程管理的核心设施是**进程控制块(PROCESS Control Block, PCB)**。PCB 是操作系统为每个进程维护的一份数据结构，记录了操作系统管理该进程所需的全部信息。进程与 PCB 是一一对应的；没有 PCB，进程就不存在。在 Linux 中 PCB 就是 `task_struct`。

```ascii
+-------------------------------------------+
|            进程的生命周期状态机              |
+-------------------------------------------+
       fork()             调度选中           等待事件
创建 ----------> 就绪(Ready) -----> 运行(Running) -----> 阻塞(Blocked)
 |                  ^                          |            |
 |                  |      时间片耗尽/被抢占      |            |
 |                  +--------------------------+            |
 |                                                           |
 |                    wait() 被调度器选中                      |
 +--------------> 终止(Terminated) <-------- 事件就绪((信号唤醒)
                                            阻塞解除
+-------------------------------------------+
```

进程状态迁移的核心：就绪态由调度器决定是否进入运行态；运行态在时间片耗尽或抢占时回到就绪态；运行态遇到需要等待的事件（如 I/O、锁、信号）进入阻塞态，事件就绪后被唤醒回到就绪态。

**进程的生命周期管理需三个配套机制**：
1. 创建机制：fork()/exec()/clone() 系统调用
2. 终止机制：exit() 系统调用 + 父进程 wait() 回收
3. 调度机制：由调度器在就绪队列中挑选下一个运行进程

### 2.1 进程两种关键抽象

内核为进程维护两类核心结构：
- **PCB（task_struct）**：内核中每个进程的唯一描述，包含状态、标识、调度、内存、文件、信号等信息。
- **内存描述符 mm_struct**：描述进程虚拟地址空间的布局，包括代码段、数据段、堆、栈、映射区域等。

进程的内存布局示意：

```ascii
+------------------------+ 0xFFFFFFFF (最高地址，x86-64 用户空间)
|      内核空间          |   （仅内核态可访问）
+------------------------+ 0x00007FFFFFFFFFFF
|      用户栈(向下生长)   |
+------------------------+
|          ↕             |
|      映射区域(mmap)     |
|          ↕             |
+------------------------+
|     运行时堆(向上生长)  |
+------------------------+
|   未初始化数据段 BSS    |
|   已初始化数据段 Data   |
|      文本段 Text        |
+------------------------+ 0x0000000000400000
```

这一布局对理解内存隔离、缓冲区溢出、ASLR(Address Space Layout Randomization)等安全概念至关重要。

## 3. 详细知识点

### 3.1 Linux task_struct（PCB）结构详解

Linux 内核中进程的所有信息封装在 `include/linux/sched.h` 的 `struct task_struct` 中，它是内核中最大的结构之一（约 KB 级）。核心字段分类如下：

#### 3.1.1 进程标识

- `pid_t pid`：进程 ID，在当前命名空间内唯一。
- `pid_t tgid`：线程组 ID，`getpid()` 返回的是 tgid，用于区分进程与线程。
- `pid_t ppid`：父进程 PID。
- `struct task_struct *parent,*real_parent`：指向父进程指针。
- `char comm[TASK_COMM_LEN]`：进程名（默认 16 字节，如 "nginx"）。

#### 3.1.2 进程状态

Linux 进程状态定义在 `task_state_array`（可见于 `fs/proc/array.c`）：

| 状态码 | 含义 | 英文全称 | 典型场景 |
|-------|------|---------|---------|
| R | 运行/就绪 | Running | 正在执行或在可运行队列中 |
| S | 可中断睡眠 | Interruptible Sleep | 等待 I/O、信号可唤醒 |
| D | 不可中断睡眠 | Uninterruptible Sleep | 等待内核操作（如磁盘 I/O），信号无法唤醒 |
| Z | 僵尸 | Zombie | 已终止但未被父进程 wait() 回收 |
| T | 停止 | Stopped | 被 SIGSTOP/SIGTSTP 暂停 |
| t | 跟踪停止 | Tracing stop | 被调试器(ptrace)暂停 |
| X | 正在退出 | Exiting death | 退出过程 |
| I | 空闲内核线程 | Idle | 内核空转（如 kthreadd） |

`sched.h` 中的定义（宏展开后）：
```c
#define TASK_RUNNING        0x0000   /* R */
#define TASK_INTERRUPTIBLE  0x0001   /* S */
#define TASK_UNINTERRUPTIBLE 0x0002  /* D */
#define __TASK_STOPPED      0x0004   /* T */
#define __TASK_TRACED       0x0008   /* t */
#define EXIT_DEAD           0x0010   /* X */
#define EXIT_ZOMBIE         0x0020   /* Z */
```

#### 3.1.3 调度信息

```c
int prio, static_prio, normal_prio;   /* 动态优先级、静态优先级 */
unsigned int rt_priority;              /* 实时优先级 0~99 */
struct sched_entity se;               /* CFS 调度实体（vruntime 等） */
struct sched_rt_entity rt;            /* 实时调度实体 */
struct sched_dl_entity dl;            /* 截止时限调度实体 */
const struct sched_class *sched_class;/* 调度器类 */
```

- `static_prio`：即 nice 值映射（0~139），由 `nice()` 设置。
- `vruntime`：CFS 虚拟运行时间，决定红黑树排序。
- `sched_class`：`stop_sched_class` > `dl_sched_class` > `rt_sched_class` > `fair_sched_class` > `idle_sched_class`。

#### 3.1.4 内存映射 mm_struct

```c
struct mm_struct *mm;    /* 用户空间内存描述符 */
struct mm_struct *active_mm; /* 内核线程的借用 mm */
```

`mm_struct` 包含：
- `pgd`：页全局目录指针（MMU 基址）。
- `mmap`/`mm_rb`：虚存区域(VMA)链表与红黑树。
- `start_code/end_code/start_data/end_data`：代码段与数据段边界。
- `start_brk/brk`：堆起始与当前堆顶。
- `start_stack`：栈起始。

#### 3.1.5 文件描述符表 files_struct

```c
struct files_struct *files;   /* 打开文件表 */
```

`files_struct` 持有 `fdtable`，包含：
- `fd`：指针数组，每个元素指向 `struct file`。
- `close_on_exec`：位图，标记 exec 时需关闭的 fd（O_CLOEXEC）。
- `open_fds`：已打开 fd 位图。

每个 `struct file` 有 `f_pos`（文件偏移）、`f_op`（文件操作函数表）、`f_count`（引用计数）。

#### 3.1.6 信号处理信息

```c
struct signal_struct *signal;  /* 进程级信号 */
struct sighand_struct *sighand;/* 信号处理函数表 */
sigset_t blocked, real_blocked;/* 信号屏蔽集 */
```

`signal` 结构包含信号处理相关字段，是整个进程组共享的；`sighand` 保存每个信号的默认/自定义处理函数。

#### 3.1.7 命名空间

```c
struct nsproxy *nsproxy;  /* 进程命名空间集合 */
```

`nsproxy` 指向五类命名空间：mnt(挂载)、pid(进程)、net(网络)、ipc、uts(主机名)。这就是容器(container)技术隔离的底层基础。

#### 3.1.8 其他关键字段

- `struct cred *cred`：进程凭证（uid/gid、capability），安全模块(SELinux/AppArmor)也依赖它。
- `seccomp`：系统调用过滤器。
- `cgroups`：资源控制组。
- `fs`：文件系统信息（根目录、当前目录）。
- `thread`：线程上下文（栈指针 SP、指令指针 IP、寄存器）。
- `children`/`sibling`：子进程链表、兄弟链表。

### 3.2 进程创建：fork() 写时复制(COW)

#### 3.2.1 fork() 语义

`fork()` 系统调用创建一个与父进程几乎完全相同的子进程：

```c
pid_t fork(void);
```

- 成功时，父进程返回子进程 PID，子进程返回 0。
- 失败返回 -1。
- **子进程从 fork() 返回点继续执行**，而不是从 main 开始。

#### 3.2.2 写时复制(Copy-On-Write, COW)

传统 fork 会完整复制父进程地址空间，开销巨大。现代 Linux 采用 COW：

1. fork 时父进程页表被复制，但内存页**不复制**，改为共享。
2. 所有共享页被标记为**只读**，且页表项(PTe)设置 COW 标志。
3. 任一进程尝试写共享页时，触发**缺页异常(page fault)**。
4. 缺页处理程序复制该物理页，分别映射到两个进程，并去除只读标志。

```ascii
写时复制(COW)缺页处理流程
+------------------+
| 进程P尝试写共享页   |
+------------------+
        | 缺页异常 #PF
        v
+------------------+
| do_wp_page()    |
|  分配新物理页     |
|  复制旧页内容     |
|  更新父子页表项   |
|  恢复可写属性     |
+------------------+
        |
        v
+----------------------------------+
|  P: 指向新页(可写)                |
|  子进程: 指向原页(被改为可写)      |
|  两者不再共享该页                  |
+----------------------------------+
```

COW 的优点：fork 开销大幅降低（只需复制页表和 task_struct），且内存节省显著——尤其对"fork 后立即 exec"的常见模式，COW 使 exec 前完全不需复制用户内存。

#### 3.2.3 fork() 的两种失效机制与 COW 开销

- **fork 后立即 exec**：exec 会丢弃所有用户空间映射，COW 复制的页表被立即丢弃——所以务必 fork 后马上 exec，避免不必要的 COW 页表复制。
- **fork 后大量写**：每个共享页首次写入都会触发一次缺页+复制，产生系统性开销。因此 fork 的"便宜"是相对的，取决于 fork 后写操作的频率。

### 3.3 vfork() 区别

`vfork()` 是 fast-fork，历史遗留：

- 子进程与父进程**共享完整的地址空间**（无 COW 保护），子进程的写操作直接影响父进程。
- 子进程必须立即 `exec()` 或 `_exit()`，否则行为未定义。
- **父进程被阻塞**，直到子进程 exec 或 exit。
- 现代内核中 vfork 主要用于"确保 exec 前的 fork 无 COW 开销"的场景（如 glibc 的 `posix_spawn`）。

```c
// vfork 的正确用法：子进程必须 exec 或 _exit
pid_t pid = vfork();
if (pid == 0) {
    execl("/bin/ls", "ls", NULL);   // 必须 exec
    _exit(127);                     // exec 失败也必须 _exit，不能 return
}
```

由于语义危险，实践中应优先使用 `posix_spawn()` 替代 vfork。

### 3.4 exec() 家族

exec 系列系统调用用一个新的程序镜像**替换**当前进程的代码段、数据段、堆栈等，**PID 不变**：

```c
int execl(const char *path, const char *arg0, ...);
int execlp(const char *file, const char *arg0, ...);
int execle(const char *path, const char *arg0, ..., char *const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[], char *const envp[]);
int execve(const char *pathname, char *const argv[], char *const envp[]); /* 真正的系统调用 */
```

- 前 6 个是 glibc 封装，最终都调用 `execve()`。
- **path 与 file 的区别**：`*p` 版本（execlp/execvp）使用 PATH 环境变量搜索可执行文件。
- exec 成功后**不返回**（成功即整个进程镜像被替换）；失败返回 -1 并设置 errno。

exec 过程中保持不变的资源：PID、PPID、打开且未设 O_CLOEXEC 的文件描述符、信号处理（SIG_IGN 保持，自定义处理恢复默认）、nice 值、当前目录（除非用 chdir）。

### 3.5 clone() 与线程创建

`clone()` 是 Linux 创建进程/线程的统一底层接口：

```c
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...);
```

`flags` 决定父子共享哪些资源：

| flags | 含义 |
|-------|------|
| CLONE_VM | 共享地址空间（线程的关键标志） |
| CLONE_FS | 共享文件系统信息（umask/cwd/root） |
| CLONE_FILES | 共享文件描述符表 |
| CLONE_SIGHAND | 共享信号处理表 |
| CLONE_THREAD | 加入同一线程组（共享 tgid） |
| CLONE_NEWPID/NET... | 创建新命名空间 |

glibc 的 `pthread_create()` 内部通过 `clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|...)` 创建线程。一个进程内的所有线程共享同一个 `mm`，因此**线程之间共享地址空间**，这也是线程间通信高效但需要同步的原因。

### 3.6 进程终止：exit() 与回收

#### 3.6.1 exit() 流程

进程终止的路径：

1. 正常退出：`main` 返回或调用 `exit()`/`_exit()`。
2. 异常终止：收到未被捕获的信号（如 SIGSEGV、SIGKILL）。

`exit()`（glibc 封装）与 `_exit()`（底层 syscall）区别：
- `exit()`：先调用 atexit 注册的清理函数、刷新 stdio 缓冲区，再调用 `_exit()`。
- `_exit()`：直接终止，不刷新 stdio 缓冲区、不调用清理函数。

内核终止流程（`do_exit()`）：
1. 释放用户空间内存映射（mm）。
2. 释放打开的文件描述符。
3. 通知父进程（发送 SIGCHLD）。
4. 将自己挂到**僵尸队列**，等待父进程 wait 回收剩余 PCB。

#### 3.6.2 僵尸进程与孤儿进程

**僵尸进程(Zombie)**：进程已终止，但其 PCB 仍在，只等父进程 `wait()` 读取退出状态后回收。

- 僵尸不占用内存，但占用 PID 和 PCB。
- 若父进程不 wait，僵尸会累积，直到 PID 耗尽。
- PPT：`ps` 中状态为 `Z`。

**孤儿进程(Orphan)**：父进程先于子进程退出，子进程被"过继"给 `PID 1`（init/systemd）作为新父进程。孤儿进程不一定是坏的——init 会负责回收它们。

**问题场景**：父进程在 fork 后直接退出且不 wait 子进程，子进程成为孤儿并持续运行——这有时被用作"守护进程化"技巧，但若配合未处理的 fork，就可能产生僵尸。

#### 3.6.3 wait()/waitpid() 回收进程

```c
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);
```

- `wait()`：阻塞等待**任意**一个子进程终止，返回其 PID，通过 `status` 获取退出信息。
- `waitpid(pid, ...)`：等待指定子进程；`options=WNOHANG` 时非阻塞，`WUNTRACED` 捕获停止。
- 通过 `WIFEXITED(status)`、`WEXITSTATUS(status)`、`WIFSIGNALED(status)`、`WTERMSIG(status)` 宏解析退出状态。

```c
#include <sys/wait.h>
int status;
if (waitpid(pid, &status, 0) == pid) {
    if (WIFEXITED(status))
        printf("exit code: %d\n", WEXITSTATUS(status));
    if (WIFSIGNALED(status))
        printf("killed by signal: %d\n", WTERMSIG(status));
}
```

### 3.7 /proc 文件系统

`/proc` 是伪文件系统，动态反映内核与进程状态：

- `/proc/<pid>/status`：进程状态、内存、凭证、voluntary_ctxt_switches 等。
- `/proc/<pid>/stat`：调度、CPU、内存等原始统计。
- `/proc/<pid>/statm`、`/proc/<pid>/maps`：内存占用与映射。
- `/proc/<pid>/fd/`：打开的文件描述符（符号链接到实际文件）。
- `/proc/<pid>/cmdline`、`/proc/<pid>/environ`：命令行与环境变量。
- `/proc/<pid>/task/`：线程目录（tid）。
- `/proc/<pid>/ns/`：命名空间标识。
- `/proc/loadavg`、`/proc/meminfo`、`/proc/cpuinfo`：系统级信息。

```bash
# 查看某进程状态
cat /proc/1234/status
grep -E '^(State|Pid|PPid|VmRSS|voluntary_ctxt)' /proc/1234/status

# 列出进程打开的 fd
ls -l /proc/1234/fd/

# 统计各进程占用内存排序
ps aux --sort=-%mem | head
```

## 4. 实战与示例

### 4.1 fork + exec + wait() 完整流程（C 语言）

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        /* 子进程：exec 一个外部命令 */
        execlp("ls", "ls", "-l", "/proc", NULL);
        /* 只有 exec 失败才会执行到这里 */
        perror("execlp");
        _exit(127);   /* 必须用 _exit，避免刷新父进程未输出的缓冲区 */
    } else {
        /* 父进程：等待子进程退出并回收 */
        int status;
        pid_t w = waitpid(pid, &status, 0);
        if (w == -1) {
            perror("waitpid");
        }
        if (WIFEXITED(status)) {
            printf("子进程退出码: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("子进程被信号 %d 杀死\n", WTERMSIG(status));
        }
    }
    return 0;
}
```

编译与运行：
```bash
gcc -o fork_demo fork_demo.c
./fork_demo
```

**重点观察**：`_exit()` 而非 `exit()` 在子进程 exec 失败分支中的使用——因为 fork 会复制父进程的 stdio 缓冲区，若用 `exit()` 会把父进程未写出的缓冲数据重复刷新到 stdout。

### 4.2 fork 两次避免僵尸

对于"父进程不关心子进程退出时间"的场景，可采用**中间进程 fork 两次**，让中间子进程立即退出、孙进程过继给 init：

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);

    if (pid == 0) {
        /* 子进程再次 fork，然后自己立即退出 */
        pid_t pid2 = fork();
        if (pid2 < 0) exit(1);
        if (pid2 == 0) {
            /* 孙进程：成为孤儿，过继给 init，被 init 回收 */
            printf("孙进程 PID=%d, PPID=%d\n", getpid(), getppid());
            sleep(5);
            printf("孙进程结束\n");
            _exit(0);
        }
        /* 中间子进程立即退出，孙进程成为孤儿 */
        _exit(0);
    }

    /* 父进程回收中间子进程即可 */
    waitpid(pid, NULL, 0);
    printf("父进程退出\n");
    return 0;
}
```

观察效果：运行后 `ps -ef | grep 孙进程名` 可见孙进程的 PPID 已变成 1（init）。

### 4.3 用 /proc/<pid>/ 字段分析进程状态

```bash
# 找一个 sleep 进程做实验
sleep 300 &
PID=$!
echo "PID=$PID"

# 1) 查看状态：应为 S (sleeping)
cat /proc/$PID/status | grep -E '^(State|Name|Pid|PPid)'

# 2) 查看内存
grep VmRSS /proc/$PID/status

# 3) 查看打开的文件
ls -l /proc/$PID/fd/ | head

# 4) 让进程进入僵尸态实验：用 shell 提前结束其子，然后查看 Z 状态
# 通过手动 kill + 不 wait 制造僵尸
```

手动制造僵尸验证：
```bash
# 脚本：子进程 sleep 后结束，父进程睡眠不回收 → 子进程变僵尸
sleep 1 &          # 子进程
PID=$!
wait $PID || true  # 子进程结束但父进程已退出... 需要更精细控制
```

更直接的僵尸实测：写一个父进程 fork 子进程后故意不 wait，子进程 sleep 5 后退出，观察 `ps -o stat` 显示 `Z`。

### 4.4 D 状态进程排查

D 状态（不可中断睡眠）通常由慢速磁盘 I/O、NFS、等待锁的内核路径引起，`kill -9` 无效。排查方法：

```bash
# 找出所有 D 状态进程
ps -eo pid,ppid,stat,wchan:32,cmd | grep '^ *[0-9]* *[0-9]* D'

# wchan 显示进程在内核中的等待点，帮助定位
cat /proc/<D进程PID>/wchan
cat /proc/<D进程PID>/stack   # 内核栈回溯（需 root）
```

如果 D 状态持续，通常意味着底层块设备或文件系统有问题（如 NFS 挂起、坏盘重试），应从系统层面（dmesg、iostat）排查，而不是试图 kill 进程。

## 5. 常见坑与避坑指南

### 5.1 fork 后没有 wait → 僵尸进程堆积

**现象**：长时间运行的服务进程持续 fork 子任务却从不 wait/waitpid，`ps` 中出现大量 `Z` 进程，最终 PID 耗尽（`fork() 返回 -1`，`Cannot fork`）。
**原因**：子进程已终止但 PCB 未被回收。
**避坑**：
- 父进程必须 wait/waitpid（阻塞或 WNOHANG 轮询）。
- 或安装 SIGCHLD 处理器，在其中 waitpid(‑1, ..., WNOHANG) 批量回收（信号驱动的收割）。
- 或使用 "fork 两次" 让 init 收养孙进程。
- 或直接使用线程池/goroutine 替代 fork。

### 5.2 COW 没有想象的"零开销"

**现象**：父进程 fork 后持有大块内存并持续写，导致大量缺页复制，性能反而比手动 `mmap(MAP_SHARED)` + 共享计数更差。
**原因**：COW 只复制了"页表 + 标记"，没复制物理页，但每次写入被写页面都会触发 page fault 和物理复制。
**避坑**：
- fork 前用 `posix_memalign`/`mmap` 规划共享内存，或 fork 后立即 `exec`。
- 若子进程完全不需要父进程内存，可直接用 `vfork`+`exec` 或 `posix_spawn`。
- 用 `madvise(MADV_WIPEONFORK)` 标记不需要继承的页，让 fork 后这些页安全清零而非 COW。

### 5.3 D 状态进程无法 kill

**现象**：`kill -9 <pid>` 无效，进程卡在 D 状态。
**原因**：进程在内核不可中断路径中（典型是慢速同步 I/O、NFS 不可达、设备驱动持锁），信号无法递送，SIGKILL 也排队等待。
**避坑**：
- 先查 `wchan`/`stack` 定位内核等待点。
- 排查底层存储/NFS/设备状态，解除阻塞。
- 切勿盲目 reboot 生产机；若确因挂载协议失联，可考虑恢复网络后进程自然解除。
- 服务设计中避免在关键路径做同步慢 I/O（改用异步 I/O、io_uring）。

### 5.4 子进程用 exit() 而不用 _exit() 重复刷新缓冲

**现象**：子进程输出内容重复/错乱。
**原因**：fork 复制了父进程 stdio 缓冲区；子进程用 `exit()` 会刷新这份拷贝，与父进程重复输出。
**避坑**：fork 后子进程分支用 `_exit()`；exec 失败的分支也务必用 `_exit()`。

### 5.5 忽略 fork 返回值导致的逻辑混乱

**现象**：fork 后父、子进程都执行了本应只执行一次的业务逻辑。
**原因**：fork 返回两次，未按返回分支编写代码。
**避坑**：严格按 `pid==0`（子）、`pid>0`（父）、`pid<0`（失败）三支编码，并在 fork 后立即可移植 exec 或明确 goto 分支。

### 5.6 进程名 comm 被截断

**现象**：`/proc/<pid>/comm` 或 `ps` 中进程名显示异常短。
**原因**：`comm` 仅 16 字节，超出部分被截断。
**避坑**：程序名不宜过长；或用 `/proc/<pid>/cmdline`（完整命令行）而非 comm 判断身份。恶意软件也常伪造 comm 隐蔽，检查 cmdline 更可靠。

### 5.7 fork 后线程的问题

**现象**：多线程程序中调用 fork，子进程可能死锁，pthread 库调用异常。
**原因**：fork 只复制调用线程，其他线程持有的锁状态被复制但锁的持有者是"消失的线程"，造成死锁。
**避坑**：多线程程序避免直接 fork；必须 fork 时在 fork 前确保无持锁，或使用 `pthread_atfork()` 注册清理回调。

## 6. 知识关联

- [[02-调度算法：从时间片轮转到CFS与EEVDF]]：进程就绪态是如何被调度器挑选进入运行态的，task_struct 中的 sched_class 与 vruntime 是关键输入。
- [[05-上下文切换：开销来源与实测分析]]：进程切换时的 TSS 保存/恢复、TLB/缓存失效开销，正是 COW 与线程共享地址空间的设计动机。
- [[10-内核态用户态：特权级与模式切换]]：fork/exec/exit 都通过系统调用陷入内核，涉及特权级切换的代价。
- [[06-进程间通信：管道消息队列共享内存信号]]：进程隔离后需要 IPC 才能协作。
- [[03-线程模型：内核线程用户线程与混合模型]]：线程是共享地址空间的进程，与进程的本质差异。
- [[08-同步原语：互斥锁自旋锁信号量条件变量]]：进程/线程并发执行的同步基石。

## 7. 参考资料

1. Abraham Silberschatz, Peter Galvin, Greg Gagne. *Operating System Concepts* (第九/十版, "恐龙书"), Wiley. 进程与 PCB 的经典讲解。
2. Andrew S. Tanenbaum, Herbert Bos. *Modern Operating Systems* (第四版), Pearson. 进程状态机与 UNIX 进程模型。
3. Robert Love. *Linux Kernel Development* (第三版), Addison-Wesley. 第 3、4 章详细讲解 task_struct 与进程管理。
4. Linux man pages: `fork(2)`, `vfork(2)`, `execve(2)`, `clone(2)`, `exit(3)`, `_exit(2)`, `wait(2)`, `waitpid(2)`, `proc(5)`.
5. Linux 内核源码：`kernel/fork.c`（`_do_fork`、`copy_process`）、`kernel/exit.c`（`do_exit`）、`include/linux/sched.h`（`task_struct`）。
6. 内核文档：`Documentation/admin-guide/sysrq.rst` 等进程调试相关说明。
7. POSIX 标准：IEEE Std 1003.1-2017, *fork*, *waitpid*, *exec* 接口定义。
