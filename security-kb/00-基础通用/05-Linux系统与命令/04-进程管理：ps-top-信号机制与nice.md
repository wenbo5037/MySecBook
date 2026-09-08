---
title: "进程管理：ps-top-信号机制与nice"
category: "00-基础通用/05-Linux系统与命令"
tags: [ps, top, 进程管理, 信号, nice, 调度]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# 进程管理：ps-top-信号机制与nice

> 本文内容聚焦 Linux 系统的合法进程管理与运维实践，包括进程查看、信号机制、优先级与调度等操作系统常规知识，未涉及任何攻击性技术。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | `ps` 快照式查看进程静态信息；`top` 交互式动态刷新进程性能；信号是内核发给进程的异步事件；nice 是进程优先级偏置，影响 CPU 调度权重 |
| 核心用途 | 排查异常进程与僵尸进程、监控 CPU/内存占用、优雅/强制终止进程、调整进程优先级与调度策略 |
| 关键参数 | ps:`-ef aux -o %cpu --sort`；top:`P M d -b -n`；信号:`SIGKILL SIGTERM SIGSTOP SIGCONT SIGCHLD`；nice:`-n nice renice` |
| 常见风险 | 误 kill 系统进程、僵尸进程无法 kill、SIGKILL 数据丢失、D 状态进程不可杀、nice 值越界混乱、top 交互误按热键 |
| 关联知识 | [[01-进程本质：PCB结构与进程创建流程]]、[[02-调度算法：从时间片轮转到CFS与EEVDF]]、[[06-进程间通信：管道消息队列共享内存信号]] |

## 1. 概述

进程(process)是操作系统资源分配与调度的基本单位。运维与安全人员日常高频操作就是"看进程、管理进程"。这个任务由三大块构成：

1. **查看进程**：`ps`(process status, 静态快照) 与 `top`/`htop`(动态刷新) 等。
2. **信号机制**：Linux 用信号(signal)通知进程事件，`kill` 命令本质就是向进程发送信号，SIGTERM/SIGKILL/SIGSTOP/SIGCONT 等各自语义不同。
3. **优先级与调度**：`nice` 偏置与 `renice` 调整，影响进程在 CFS 调度器中的权重，从而影响 CPU 分配比例。

理解进程管理不仅是日常排障（"这个进程为什么占满 CPU"、"怎么优雅停掉服务"），更是安全分析的基础：
- 排查可疑进程（隐藏进程、高 CPU、未预期的 root 进程）。
- 信号在恶意软件中常被用于控制（如 SIGSTOP 暂停、SIGKILL 终止反调试子进程）。
- 优先级与 cgroup 结合可以限制资源滥用（如勒索挖矿限 CPU）。

下文从底层原理展开，介绍 ps/top 的关键字段、信号机制、nice 与调度关系，并给出安全视角的排查思路。

## 2. 核心原理

### 2.1 ps 与 /proc

ps 本质上是把 `/proc` 中每个进程目录里的信息汇总展示。`/proc/<pid>/` 里的 `status`、`stat`、`statm`、`cmdline` 等文件提供了进程状态、内存、命令行。ps 不同语法（`-ef`、`aux`、BSD/Unix 风格）只是字段选择与输出的差异，底层数据源一致。

- `-e`：所有进程；`-f`：全格式；`aux`：BSD 风格，含 `%CPU %MEM`。
- `-o` 可自定义输出字段，非常灵活。

### 2.2 top 的动态模型

top 周期性（默认约 3 秒）读取 `/proc` 与各 `/proc/<pid>/stat`，刷新汇总统计与每个进程的 CPU 使用率。它读的第一行汇总来自 `/proc/stat`（总体 CPU 计数），进程行来自各 `/proc/<pid>/stat`。

```
/proc/stat ─────────────────► 系统总体 CPU、内存、负载(第一行几栏)
/proc/<pid>/stat, statm ────► 每个进程的 CPU%、MEM%、状态
```

top 交互热键很常用：`P`(按CPU排)、`M`(按内存排)、`d`(改刷新间隔)、`k`(发信号)、`r`(renice)。

### 2.3 信号的处理流程

信号是内核向进程投递的异步通知。进程可以对每个信号设定"处置(disposition)"：

```
信号投递 ──► 进程的信号处置(disposition)
                  │
      ┌───────────┼──────────────┐
      ▼           ▼              ▼
  忽略(ignore)  默认动作(terminate/stop)  自定义handler(用sigaction安装)
```

每个信号有默认动作：多数终止进程(SIGTERM/SIGKILL/SIGSEGV)、SIGSTOP/SIGTSTP暂停、SIGCONT恢复。

关键区分：
- **可捕获(catchable)**信号（如 SIGTERM、SIGINT）：进程可安装 handler 做清理后退出。
- **不可捕获/忽略/屏蔽**信号（SIGKILL、SIGSTOP）：内核直接执行默认动作，进程无法拦截。

### 2.4 nice 与 CFS 权重

在 Linux 的完全公平调度器(CFS)中，`nice` 值(对应内核的 `nice` ≤> weight 映射)决定进程的调度**权重(weight)**。nice 每增加 1，权重约乘以 `1.25`(即 CPU 份额约减少)；nice 范围 `-20`(最高优先级，根用户可"降低"到 -20) 到 `19`(最低)。

- `nice` 值越高，进程剥夺率越大，获得的 CPU 时间越少。
- `renice` 调整**已运行**进程的 nice。
- 只有 root 可以把 nice 降到负值（提高优先级）。

```
调度权重 ----► 在 CFS 红黑树(或 EEVDF 的虚拟截止时间)中选择
nice 每+1 ----► 权重约 *0.8 (delta≈1.25 inverse)，CPU 份额下降
```

相关调度细节见 [[02-调度算法：从时间片轮转到CFS与EEVDF]]。

## 3. 详细知识点

### 3.1 ps 常用命令与字段

```bash
ps -ef                 # 全格式，含 PPID
ps aux                 # BSD 风格，含 CPU%/MEM%
ps -eo pid,ppid,user,%cpu,%mem,stat,cmd --sort=-%cpu   # 自定义并按CPU降序
ps -o pid,lstart,etime,cmd -p <PID>   # 查进程启动时间与运行时长
ps -L -p <PID>         # 列出进程的线程
pgrep -f <pattern>     # 按命令行匹配进程号
pstree -p              # 进程树
```

`STAT` 字段含义：
- `R` 运行、`S` 可中断睡眠、`D` 不可中断睡眠(I/O)、`T` 停止、`Z` 僵尸。
- 附加标志：`+` 前台进程组、`s` 会话首进程、`l` 多线程、`<` 高优先级、`N` 低优先级(nice)。

### 3.2 top 关键列与交互

| 列 | 含义 |
|----|------|
| PID | 进程号 |
| %CPU | CPU 占用率（近一次刷新） |
| %MEM | RSS / 总内存 |
| S | 状态（同 ps） |
| TIME+ | 累计 CPU 时间 |
| NI | nice 值 |
| PR | 内核优先级权重（未必直读） |

交互热键：`P` 按 CPU、`M` 按内存、`d` 刷新间隔、`k` 发信号、`r` renice、`q` 退出、`h` 帮助。批处理模式 `top -b -n 1` 可输出单帧用于脚本。

### 3.3 信号列表

```bash
kill -l        # 列出全部信号
kill -2 PID    # SIGINT，等同 Ctrl+C
```

常用信号（编号与名称关系符合 POSIX）：
- `1` SIGTERM? 不，SIGHUP=1。准确对照如下：

| 编号 | 信号 | 默认动作 | 说明 |
|------|------|----------|------|
| 1 | SIGHUP | 终止 | 挂断/终端关闭；守护进程常重载配置 |
| 2 | SIGINT | 终止 | 终端中断（Ctrl+C） |
| 3 | SIGQUIT | 终止+核心转储 | 终端退出（Ctrl+\） |
| 9 | SIGKILL | 强制终止 | 不可捕获/忽略 |
| 15 | SIGTERM | 终止 | 优雅终止（kill 默认） |
| 17 | SIGCHLD | 忽略 | 子进程状态变化通知父进程 wait |
| 18 | SIGCONT | 继续 | 恢复被暂停进程 |
| 19 | SIGSTOP | 暂停 | 强制暂停，不可捕获/忽略 |
| 20 | SIGTSTP | 暂停 | 终端暂停（Ctrl+Z） |

注：此处信号编号为 Linux/x86 惯例，符合 `kill -l` 输出（待验证目标环境是否一致，通用按编号不依赖跨平台）。

### 3.4 僵尸进程与孤儿进程

- **僵尸(Zombie, Z)**：子进程已退出但父进程未调用 `wait()` 回收，PCB 残留在表中。僵尸**无法用 kill 杀死**（它已死），只能让父进程 wait 或终止父进程（由 init/systemd 收养后回收）。
- **孤儿**：父进程先退出，子进程被 `init`(或 systemd) 收养，通常无害。

排查与处理僵尸：

```bash
ps -eo pid,ppid,stat,cmd | awk '$3 ~ /^Z/'
# 对僵 DEFUNCT 父进程做处理（通知其回收或重启父进程）
```

### 3.5 不可中断睡眠 D 状态

`D`(Uninterruptible sleep) 常见于磁盘 I/O、NFS 卡死、内核锁等待。D 状态进程**既不能在此刻收到信号**，kill 无效，需等 I/O 恢复或重启系统。这是运维在 NFS 挂载出问题时最常见的"杀不死"现象。

### 3.6 信号的安全视角

- 恶意程序可能用 `SIGTRAP`/`SIGSTOP` 干扰调试器；ptrace 与信号有复杂交互。
- 终止反调试：程序常忽略 SIGTRAP，或对 SIGCHLD 做特殊处理导致调试器失败（详见 [[09-调试工具链：strace-ltrace-gdb基础]]）。
- 日志审计：`pkill`/`kill` 可通过 auditd 记录（见 [[13-日志体系：syslog-journald-auditd配置]]）。
- 权限：普通用户只能向自己的进程发信号；向他人进程发信号需同一 UID 或 root，否则 `Operation not permitted`。

### 3.7 nice 与 renice 操作

```bash
nice -n -10 ./heavy_job      # 以更高优先级启动（负nice，需root）
renice -n 15 -p <PID>        # 降低运行中进程优先级
renice -n -5 -p <PID>        # 提高（需root）
nice -19 command             # 以最低优先级运行
```

`renice` 对已运行进程生效，是调整调度权的常用手段。

### 3.8 优雅停机 vs 强制停机

- `kill <PID>` 默认发 SIGTERM，进程可捕获并做清理（保存状态、关连接）。
- `kill -9 <PID>` 发 SIGKILL，内核直接终止，**不做清理**，可能丢数据/损坏文件。
- 生产环境优先 SIGTERM，等待后再用 SIGKILL 兜底。这是"优雅停机"的正确姿势。

## 4. 实战与示例

### 4.1 排查 CPU 占用最高的进程

```bash
ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -10
# 快速定位，怀疑挖矿时常看到陌生进程
```

### 4.2 用 top 交互或批处理监控

```bash
# 单帧批处理
top -b -n 1 | head -20
# 每5秒取样一次，共10次
top -b -d 5 -n 10 > top.log
```

### 4.3 优雅停止并按需强杀

```bash
# 找到进程
pgrep -f 'myapp'
PID=$(pgrep -f 'myapp')
# 先 SIGTERM
kill $PID
sleep 5
# 检查是否还活着，是则 SIGKILL
if kill -0 $PID 2>/dev/null; then kill -9 $PID; fi
```

`kill -0` 只测试进程是否存在而不发真正的信号，是常见的存活探测手法。

### 4.4 处理僵尸进程

```bash
# 找出僵尸
ps -eo pid,ppid,stat,cmd | awk '$3 ~ /^[Zz]/'
# 若父进程是可控服务，重启之；否则等待其 wait 或终止父进程
```

### 4.5 调整优先级限制资源

```bash
# 给某进程降优先级
renice -n 15 -p 12345
# 以低优先级后台运行备份任务
nice -n 19 tar czf /backup.tgz /data &
```

### 4.6 通过信号让守护进程重载配置

很多服务（nginx、sshd）把 SIGHUP 解释为"重载配置"：

```bash
kill -HUP $(cat /var/run/nginx.pid)
```

### 4.7 安全排查：找未预期的高权限进程

```bash
# 找以 root 运行的可疑进程
ps -eo user,pid,cmd | awk '$1=="root" {print}' | grep -v -E '\((systemd|cron|sshd|bash|...)\)' # 示例过滤，实际按环境
# 找监听端口的进程
ss -tlnp | grep -v LISTEN # 方向示意，见网络笔记
```

## 5. 常见坑与避坑指南

| 坑点 | 现象 | 原因 | 规避建议 |
|------|------|------|----------|
| SIGKILL 丢数据 | 服务状态损坏 | -9 不清理 | 先 SIGTERM，再超时兜底 -9 |
| 僵尸杀不掉 | kill 无反应 | 僵尸已死，需 wait | 处理父进程，勿浪费在子进程上 |
| D 状态 kill 无效 | kill 挂起/无效 | 不可中断 I/O | 查 NFS/磁盘，等恢复或重启 |
| 误 kill 系统进程 | 系统异常 | PID 复用/认错 | kill 前 kill -0 + 确认 cmdline，用 pgrep 定位 |
| nice 理解反了 | 以为越大越快 | nice 高=低优先 | 记清：nice 越高CPU份额越少 |
| renice 权限不足 | Operation not permitted | 非 root 不能提高优先级 | 需 root 才能设负 nice |
| 普通用户 kill 不了 | Operation not permitted | 不同 UID | 用 sudo 或确认属主 |
| top 误按热键 | 界面突变/卡住 | 交互热键 | 记好 q 退出，离线用 -b |
| `kill -0` 误判 | 判断进程不存在 | 权限或无该 PID | 结合权限与 cmdline 复核 |
| %CPU 超 100% | 显示>100% | 多线程/多核 | 理解 %CPU 是多核累计 |

## 6. 知识关联

- [[01-进程本质：PCB结构与进程创建流程]]：task_struct 与进程生命周期、僵尸成因的底层解释
- [[02-调度算法：从时间片轮转到CFS与EEVDF]]：nice 值如何映射为调度权重
- [[06-进程间通信：管道消息队列共享内存信号]]：信号在 IPC 中的地位与机制
- [[09-调试工具链：strace-ltrace-gdb基础]]：ptrace、信号与进程调试的安全交互
- [[13-日志体系：syslog-journald-auditd配置]]：kill/pkill 等进程操作的可审计日志
- [[06-权限体系：rwx-ACL-setuid-capabilities]]：发送信号与进程权限的关联

## 7. 参考资料

- man 手册：`man 1 ps`、`man 1 top`、`man 1 kill`、`man 1 nice`、`man 1 renice`、`man 7 signal`、`man 2 kill`
- man 手册：`man 5 proc`（/proc 中进程信息格式）
- 《鸟哥的Linux私房菜 基础学习篇》（第三版），第 13 章 进程管理与 SELinux 入门
- CSAPP《深入理解计算机系统》第 8 章 异常控制流（信号、进程调度、并发）
- 《深入理解LINUX内核》(Understanding the Linux Kernel) 相关调度与进程管理章节
