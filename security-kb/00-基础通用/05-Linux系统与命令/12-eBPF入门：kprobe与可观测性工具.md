---
title: "eBPF入门：kprobe与可观测性工具"
category: "00-基础通用/05-Linux系统与命令"
tags: [eBPF, kprobe, 可观测性, BPF, BCC, bpftool, tracepoint, 安全监控]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# eBPF入门：kprobe与可观测性工具

> 防御视角声明：本篇涉及的eBPF程序编写、kprobe/tracepoint hooking、BCC/bpftool使用等技术，仅用于合法的系统可观测性、性能分析与安全防御研究（如eBPF恶意hook检测、运行时行为审计）。严禁用于未授权的内核hook、数据窃取或绕过安全机制（如利用eBPF进行提权或隐藏恶意行为）。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | Extended Berkeley Packet Filter，Linux内核中运行的沙箱化字节码虚拟机，允许用户态程序安全地在内核上下文中执行自定义逻辑 |
| 核心用途 | 网络数据包过滤（XDP/TC）、内核函数追踪（kprobe/kretprobe）、系统调用审计、安全策略执行（LSM hook）、性能剖析（perf事件）、容器运行时监控 |
| 关键参数 | `bpftool`（BPF对象管理）、`bpftrace`（高级追踪语言）、BCC（Python/C前端）、`/sys/fs/bpf/`（持久化存储）、程序类型（BPF_PROG_TYPE_*）、map类型（BPF_MAP_TYPE_*） |
| 常见风险 | eBPF verifier绕过（提权攻击面）、BPF map内存耗尽、kprobe hook点不稳定（内核版本间符号偏移）、恶意eBPF程序内核持久化 |
| 关联知识 | [[11-内核模块：编写编译与insmod加载]]（eBPF vs LKM对比）、[[04-进程管理：ps-top-信号机制与nice]]（BPF获取进程信息）、[[05-网络命令链：ip-ss-tcpdump-nmap排查实战]]（XDP替代iptables）、[[13-日志体系：syslog-journald-auditd配置]]（BPF日志输出到用户态） |

## 1. 概述

eBPF（Extended Berkeley Packet Filter）是Linux内核自3.18版本（2014年）引入的一项革命性技术。它允许用户态程序在内核中加载并执行经过验证的沙箱化字节码程序，无需修改内核源码或加载内核模块。eBPF已经从最初的网络包过滤工具，演变为Linux可观测性和安全领域的核心基础设施。

与传统的[[11-内核模块：编写编译与insmod加载|内核模块]]相比，eBPF具有根本性的安全优势：所有eBPF程序在加载前都经过内核 verifier（验证器）的严格检查，确保不会导致内核崩溃、不会无限循环、不会越界访问内存。这种"编写即安全"的特性使得eBPF程序可以由非内核开发人员编写，且加载失败时不影响系统稳定性。

eBPF的核心架构包含三个层次：（1）用户态前端——BCC（Python/C）、bpftrace（高级DSL）、libbpf（纯C库）；（2）内核eBPF虚拟机——执行经verifier验证的字节码；（3）钩子点——kprobe/tracepoint（追踪）、XDP/TC（网络）、LSM（安全）、perf_event（性能）等内核事件源。

从安全角度看，eBPF已成为现代Linux安全架构的双刃剑。防御侧利用它实现运行时威胁检测（如Falco、Tetragon）、网络微分段（Cilium）、系统调用过滤（seccomp-bpf）。攻击侧则利用eBPF verifier中的漏洞进行内核提权（CVE-2021-3490等）。理解eBPF的工作原理和安全边界，是现代Linux安全工程师的必备能力。

## 2. 核心原理

### 2.1 eBPF架构全景

```text
用户态                              内核态
+-------------------+              +---------------------------+
|  BCC/bpftrace/    |              |   eBPF Verifier           |
|  libbpf 前端      |  bpf()      |   (安全性验证)             |
|                   | ----------> |           |                 |
|  加载字节码       |  syscall     |    通过  v  拒绝            |
+-------------------+              |   +--------+--------+     |
                                   |   | eBPF Program VM  |     |
                                   |   | (64-bit RISC)    |     |
                                   |   +--------+--------+     |
                                   |            |               |
                                   |   +--------v--------+     |
                                   |   |  Hook Points     |     |
                                   |   |  kprobe/trace    |     |
                                   |   |  XDP/TC/LSM     |     |
                                   |   |  perf_event      |     |
                                   |   +--------+--------+     |
                                   |            |               |
                                   |   +--------v--------+     |
                                   |   |  BPF Maps        |     |
                                   |   |  (共享数据结构)   |     |
                                   |   +-----------------+     |
                                   +---------------------------+
```

### 2.2 eBPF程序类型

eBPF程序必须声明其类型，这决定了它可以挂载到哪些钩子点以及可以调用哪些内核辅助函数（helper functions）：

| 程序类型 | 挂载点 | 典型用途 | 辅助函数限制 |
|----------|--------|----------|-------------|
| BPF_PROG_TYPE_KPROBE | kprobe/kretprobe | 内核函数追踪 | 几乎不受限 |
| BPF_PROG_TYPE_TRACEPOINT | 静态追踪点 | 系统事件追踪 | 受tracepoint参数约束 |
| BPF_PROG_TYPE_XDP | 网络驱动层 | 高性能包处理 | 无内存分配，受限helper |
| BPF_PROG_TYPE_SCHED_CLS | TC ingress/egress | 流量控制 | 中等限制 |
| BPF_PROG_TYPE_LSM | LSM hook点 | 安全策略 | 受LSM框架约束 |
| BPF_PROG_TYPE_PERF_EVENT | perf硬件/软件事件 | 性能剖析 | 中等限制 |
| BPF_PROG_TYPE_CGROUP_SKB | cgroup网络 | 容器网络策略 | 受cgroup约束 |
| BPF_PROG_TYPE_SYSCALL | 系统调用入口 | syscall过滤/修改 | 严格限制 |

### 2.3 eBPF Verifier

eBPF verifier是内核安全的关键防线。它在用户态通过`bpf()`系统调用加载程序时执行静态分析：

```text
Verifier验证过程:
1. 控制流分析 - 确保无不可达代码、无无限循环
2. 寄存器状态跟踪 - 每条指令后跟踪每个寄存器的类型和范围
3. 内存访问验证 - 确保所有内存读写在合法边界内
4. Helper函数调用验证 - 确保只调用已声明的辅助函数
5. BPF-to-BPF函数调用验证 - 递归检查被调用函数
6. 栈溢出检测 - 每个程序最大512字节栈空间
7. 指令数量限制 - 非特权程序最大100万条指令（5.2+内核）
```

验证器拒绝加载时会返回详细错误信息：

```bash
# 查看verifier拒绝原因
sudo bpftool prog load hello.o /sys/fs/bpf/hello
# libbpf: prog 'hello': BPF program is too large: processed 100001 insns
# Error loading object file

# 使用bpf_log_level获取详细验证日志
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 2.4 BPF Map数据结构

BPF Map是eBPF程序（内核态）与用户态程序之间的共享数据结构，也是多个eBPF程序之间通信的机制：

| Map类型 | 键/值结构 | 用途 |
|---------|-----------|------|
| BPF_MAP_TYPE_HASH | 任意/任意 | 通用键值存储，用于统计、缓存 |
| BPF_MAP_TYPE_ARRAY | u32/任意 | 固定大小数组，索引为u32 |
| BPF_MAP_TYPE_PERF_EVENT_ARRAY | 无键/u32 | 向用户态推送事件（不可读取） |
| BPF_MAP_TYPE_RINGBUF | 无键/无值 | 高性能环形缓冲区（5.8+内核） |
| BPF_MAP_TYPE_LRU_HASH | 任意/任意 | 自动LRU淘汰的哈希表 |
| BPF_MAP_TYPE_STACK_TRACE | u32/任意 | 内核栈追踪存储 |
| BPF_MAP_TYPE_LPM_TRIE | 任意/任意 | 最长前缀匹配（IP地址匹配） |

### 2.5 kprobe与tracepoint机制

**kprobe**是动态追踪点，可以附着到几乎任何内核函数的入口（kprobe）或返回点（kretprobe）：

```c
// kprobe的工作原理（内核内部）
// 1. 用户态注册kprobe: 指定目标函数名+偏移
// 2. 内核在目标地址写入断点指令(int3 on x86)
// 3. 执行到该地址时触发断点异常
// 4. 异常处理器调用注册的pre_handler
// 5. 执行完毕后单步执行原指令
// 6. 调用post_handler继续执行
```

**tracepoint**是静态追踪点，预埋在内核源码中，由开发者显式定义：

```c
// 内核中的tracepoint定义（fs/open.c）
TRACE_EVENT(do_sys_open,
    TP_PROTO(int dfd, const char __user *filename, int flags, umode_t mode),
    TP_STRUCT__entry(
        __field(int, dfd)
        __string(filename, filename)
        __field(int, flags)
    ),
    TP_fast_assign(...)
    TP_printk("dfd=%d filename=%s flags=%x", __entry->dfd,
              __get_str(filename), __entry->flags)
);
```

tracepoint比kprobe更稳定——内核版本升级时tracepoint接口通常保持兼容，而kprobe附着的函数名和签名可能改变。

## 3. 详细知识点

### 3.1 BCC：Python + C的eBPF前端

BCC（BPF Compiler Collection）是最早的eBPF高级前端之一，允许用Python编写eBPF工具，C代码作为内核态部分内嵌在Python字符串中：

```python
#!/usr/bin/env python3
# hello_bcc.py - 使用BCC追踪系统调用
from bcc import BPF

# 内核态C代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# 加载BPF程序
b = BPF(text=bpf_text)
b.attach_kprobe(event="do_execveat_common", fn_name="trace_execve")

# 定义输出回调
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"[{event.ts}] pid={event.pid} comm={event.comm.decode()}")

# 注册回调并开始轮询
b["events"].open_perf_buffer(print_event)
print("Tracing execve... Ctrl+C to stop.")
while True:
    b.perf_buffer_poll()
```

```bash
# 安装BCC（Ubuntu/Debian）
sudo apt install bpfcc-tools python3-bpfcc

# BCC工具集（通常以-bcc结尾）
/usr/sbin/execsnoop-bcc     # 追踪新进程创建
/usr/sbin/tcpconnect-bcc    # 追踪TCP连接
/usr/sbin/fileslower-bcc    # 追踪慢文件I/O
/usr/sbin/biolatency-bcc    # 块设备I/O延迟直方图
/usr/sbin/profile-bcc       # CPU性能剖析

# 运行示例
sudo execsnoop-bcc
# PID    COMM    ARGS
# 12345  ls      ls --color=auto
# 12346  cat     cat /etc/passwd
```

### 3.2 bpftrace：一行命令的内核追踪

bpftrace是DTrace的Linux实现，使用简洁的单行脚本语法：

```bash
# 安装bpftrace
sudo apt install bpftrace           # Debian/Ubuntu
sudo dnf install bpftrace           # Fedora/RHEL 8+

# 基本语法: probe /filter/ { action }
# probe类型: kprobe, kretprobe, tracepoint, uprobe, profile, interval

# 追踪所有系统调用
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { printf("pid=%d comm=%s syscall=%d\n", pid, comm, args->id); }'

# 统计系统调用分布
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm, args->id] = count(); }'

# 追踪文件打开
sudo bpftrace -e 'kprobe:vfs_open { printf("pid=%d file=%s\n", pid, comm); }'

# 测量函数执行时间
sudo bpftrace -e 'kprobe:tcp_sendmsg { @start[tid] = nsecs; } kretprobe:tcp_sendmsg /@start[tid]/ { @ns = hist(nsecs - @start[tid]); delete(@start[tid]); }'

# 每秒输出事件计数
sudo bpftrace -e 'tracepoint:syscalls:sys_enter { @++; } interval:s:1 { print(@); clear(@); }'

# 检测异常文件访问
sudo bpftrace -e 'kprobe:vfs_read /comm=="sshd"/ { printf("sshd reading: pid=%d\n", pid); }'
```

### 3.3 bpftool：BPF对象管理瑞士军刀

bpftool是内核自带的BPF管理命令行工具：

```bash
# 列出所有已加载的BPF程序
sudo bpftool prog show
# 1: xdp  name xdp_pass  tag 0123456789abcdef  uid 0
#     loaded_at 2026-09-01T10:00:00+0000  uid 0
#     map_ids 3,4
#     btf_id 123

# 查看程序详细信息（含verifier日志）
sudo bpftool prog show id 1 verbose

# 列出所有BPF map
sudo bpftool map show
# 3: hash  name events  flags 0x0
#     key 4B  value 32B  max_entries 10240  uid 0
#     id 3  locals_for_refs 0

# 查看map内容
sudo bpftool map dump id 3

# 将BPF程序dump为字节码
sudo bpftool prog dump xlated id 1

# 查看JIT编译后的机器码
sudo bpftool prog dump jited id 1

# 从ELF文件加载BPF程序
sudo bpftool prog load hello.o /sys/fs/bpf/hello

# 验证BPF对象文件
sudo bpftool obj dump file hello.o

# 查看BTF（BPF Type Format）信息
sudo bpftool btf show
sudo bpftool btf dump id 1

# Pin BPF程序到bpffs（持久化）
sudo bpftool prog pin id 1 /sys/fs/bpf/my_prog

# 附加XDP程序到网络接口
sudo bpftool net attach xdp id 1 dev eth0
sudo bpftool net detach xdp dev eth0

# 查看网络接口上的BPF程序
sudo bpftool net show dev eth0
```

### 3.4 libbpf与CO-RE：现代化的BPF开发范式

libbpf + CO-RE（Compile Once - Run Everywhere）是目前推荐的eBPF开发方式，解决了BCC运行时编译和kprobe偏移不稳定的问题：

```c
// hello.bpf.c - CO-RE风格的BPF程序
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义BPF map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");

// SEC宏定义程序类型和hook点
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count = bpf_map_lookup_elem(&exec_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&exec_count, &pid, &init_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

```c
// hello.c - 用户态加载器（纯C，使用libbpf）
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int prog_fd, map_fd;

    // 加载并验证BPF对象
    obj = bpf_object__open_file("hello.bpf.obj", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // 加载到内核
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // 获取map fd
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "exec_count"));

    // 读取map数据
    __u32 key = 0, next_key;
    __u64 value;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd, &next_key, &value);
        printf("pid=%u exec_count=%llu\n", next_key, value);
        key = next_key;
    }

    bpf_object__close(obj);
    return 0;
}
```

```bash
# 使用clang编译BPF程序
clang -O2 -target bpf -g -c hello.bpf.c -o hello.bpf.obj

# 使用gcc编译用户态加载器（需要libbpf）
gcc -o hello hello.c -lbpf

# 运行
sudo ./hello
# pid=1234 exec_count=5
# pid=5678 exec_count=12
```

### 3.5 eBPF安全检测与防御

#### 3.5.1 检测恶意eBPF程序

```bash
# 列出所有已加载的BPF程序（关注可疑类型）
sudo bpftool prog show
# 重点检查：
# - BPF_PROG_TYPE_KPROBE 附着到敏感函数（如sys_execve）
# - BPF_PROG_TYPE_LSM 类型程序
# - 不明来源的BPF程序

# 检查BPF程序的owner UID
sudo bpftool prog show | grep "uid 0"  # root拥有的
sudo bpftool prog show | grep -v "uid 0"  # 非root拥有的（可疑）

# 监控BPF加载系统调用
sudo auditctl -a always,exit -F arch=b64 -S bpf -k bpf_load
sudo ausearch -k bpf_load -ts recent

# 检查bpffs挂载点（BPF持久化存储）
mount | grep bpf
# /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime)

# 列出bpffs中的所有pinned对象
sudo bpftool obj pin show /sys/fs/bpf/
```

#### 3.5.2 内核eBPF安全配置

```bash
# 查看内核BPF相关配置
grep BPF /boot/config-$(uname -r)
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_JIT_ALWAYS_ON=y          # 强制JIT编译（安全建议开启）
# CONFIG_BPF_UNPRIV_DEFAULT_OFF=y      # 非特权用户默认禁用BPF（4.4+内核）

# 限制非特权用户使用BPF
sysctl kernel.unprivileged_bpf_disabled=1

# 查看当前BPF内存使用
cat /proc/net/stat/bpf
```

### 3.6 eBPF在安全监控中的典型应用

#### Falco与Tetragon

```bash
# Falco使用eBPF（或内核模块）进行运行时威胁检测
# 安装Falco（使用eBPF驱动）
curl -s https://falco.org/repo/falco-apt-key.asc | sudo apt-key add -
sudo echo "deb https://falco.org/repo/stable stable main" > /etc/apt/sources.list.d/falco.list
sudo apt update && sudo apt install falco

# Falco规则示例：检测异常shell启动
# - rule: Terminal shell in container
#   condition: >
#     container and shell_procs and proc.tty != 0
#   output: >
#     Shell launched in container
#     (user=%user.name container=%container.name shell=%proc.name parent=%proc.pname)
#   priority: WARNING

# Tetragon（Cilium子项目）使用eBPF实现内核级安全策略
# https://github.com/cilium/tetragon
```

#### 网络安全应用

```bash
# XDP（eXpress Data Path）实现高性能DDoS防护
# 替代iptables，直接在网络驱动层处理数据包

# 使用Cilium进行容器网络微分段
# Cilium使用eBPF替代iptables实现网络策略
# 性能对比：Cilium(eBPF) vs kube-proxy(iptables)
#   - 规则数量 > 1000 时，eBPF性能优势明显
#   - iptables O(n)规则匹配 vs eBPF O(1)哈希查找
```

## 4. 实战与示例

### 4.1 实验一：使用bpftrace追踪内核函数

```bash
# 步骤1：确认内核支持eBPF
grep -E 'CONFIG_BPF|CONFIG_BPF_SYSCALL' /boot/config-$(uname -r)
# 应显示CONFIG_BPF=y 和 CONFIG_BPF_SYSCALL=y

# 步骤2：安装bpftrace
sudo apt install bpftrace

# 步骤3：运行追踪
# 追踪所有TCP连接建立
sudo bpftrace -e '
tracepoint:sock:inet_sock_set_state
/args->newstate == 1/
{
    printf("TCP connect: pid=%d comm=%s saddr=%s daddr=%s\n",
           pid, comm,
           ntop(args->saddr), ntop(args->daddr));
}'

# 步骤4：输出示例
# TCP connect: pid=1234 curl saddr=10.0.0.1 daddr=93.184.216.34
# TCP connect: pid=1235 wget saddr=10.0.0.1 daddr=142.250.80.46

# 步骤5：统计每个进程的网络字节数
sudo bpftrace -e '
kprobe:tcp_sendmsg { @bytes[comm] = sum(arg2); }
interval:s:10 { print(@bytes); clear(@bytes); }
'
```

### 4.2 实验二：使用BCC监控进程创建

```bash
# 使用BCC的execsnoop工具追踪新进程
sudo /usr/sbin/execsnoop-bcc

# 输出示例：
# TIME     PID    PPID    COMM    ARGS
# 10:00:01 1234   1000    ls      ls --color=auto /tmp
# 10:00:02 1235   1234    grep    grep -r pattern /etc
# 10:00:03 1236   1000    vim     vim /etc/hosts

# 仅追踪特定进程的子进程
sudo /usr/sbin/execsnoop-bcc -t bash

# 追踪容器中的新进程（Docker）
sudo /usr/sbin/execsnoop-bcc -d
```

### 4.3 实验三：使用bpftool分析系统BPF状态

```bash
# 完整的BPF状态审计脚本
#!/bin/bash
echo "=== BPF Programs ==="
sudo bpftool prog show 2>/dev/null | grep -E "^(id|name|type)"

echo -e "\n=== BPF Maps ==="
sudo bpftool map show 2>/dev/null | grep -E "^(id|type|key|value)"

echo -e "\n=== Pinned BPF Objects ==="
sudo find /sys/fs/bpf -type f 2>/dev/null

echo -e "\n=== Network BPF Attachments ==="
sudo bpftool net show 2>/dev/null

echo -e "\n=== BPF Memory Usage ==="
grep -i bpf /proc/net/stat/bpf 2>/dev/null
```

## 5. 常见坑与避坑指南

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `bpf() call: Operation not permitted` | 非特权用户无权加载BPF程序 | 使用sudo；或设置`kernel.unprivileged_bpf_disabled=0`（不推荐） |
| `cannot attach BPF program: No such process` | kprobe附着的函数不存在 | 用`cat /proc/kallsyms \| grep <函数名>`确认函数存在；不同内核版本函数名可能不同 |
| BCC编译缓慢（每次运行重新编译） | BCC使用LLVM运行时编译C代码 | 切换到libbpf+CO-RE方案（编译一次，到处运行） |
| `R1 must be a pointer to ctx` | BPF verifier类型检查失败 | 确保辅助函数调用的参数类型正确；查看verifier日志定位具体指令 |
| `Backpack too big` 栈溢出 | BPF栈空间限制512字节 | 使用BPF_PERCPU_ARRAY或BPF_MAP_TYPE_PERF_EVENT_ARRAY在用户态聚合数据 |
| kprobe在内核升级后停止工作 | 目标函数名或参数发生变化 | 优先使用tracepoint（更稳定）；或使用CO-RE/BTF自动适配结构体偏移 |
| `libbpf: prog xxx: BPF program is too large` | 超过verifier指令数限制（通常100万条） | 分拆程序；使用BPF-to-BPF函数调用；使用trampoline优化 |
| eBPF map内存无限增长 | map entry未清理导致内存耗尽 | 设置合理的max_entries；使用LRU类型map；用户态定期清理过期条目 |
| `cannot find BTF` | 内核未编译BTF信息 | 安装kernel-btf包；或手动从pahole生成BTF |
| XDP程序加载后网络中断 | XDP程序返回错误丢弃了所有包 | 确保XDP程序在不匹配时返回XDP_PASS；在虚拟机环境测试前先在物理机验证 |

## 6. 知识关联

- [[11-内核模块：编写编译与insmod加载]] — eBPF与LKM的对比：安全性、灵活性、性能
- [[04-进程管理：ps-top-信号机制与nice]] — BPF获取进程创建事件、进程状态追踪
- [[05-网络命令链：ip-ss-tcpdump-nmap排查实战]] — XDP/TC替代iptables实现高性能网络处理
- [[08-systemd：unit文件编写与服务管理]] — BPF工具的systemd服务化部署
- [[09-调试工具链：strace-ltrace-gdb基础]] — eBPF追踪 vs strace/ltrace：性能与功能对比
- [[10-性能排查：vmstat-iostat-perf火焰图实战]] — BPF实现比perf更灵活的性能剖析
- [[13-日志体系：syslog-journald-auditd配置]] — BPF事件输出到日志系统进行长期存储

## 7. 参考资料

1. **BPF and XDP Reference Guide** (kernel.org): https://www.kernel.org/doc/html/latest/bpf/index.html
2. **BCC Documentation**: https://github.com/iovisor/bcc/blob/master/docs/kernel_threadedio.md
3. **bpftrace Reference Guide**: https://github.com/bpftrace/bpftrace/blob/master/docs/reference_guide.md
4. **libbpf-bootstrap** (CO-RE templates): https://github.com/libbpf/libbpf-bootstrap
5. **Brendan Gregg's BPF Performance Tools**: https://www.brendangregg.com/bpf-performance-tools-book.html
6. **eBPF.io** (community resources): https://ebpf.io/
7. **Cilium Documentation** (eBPF networking): https://docs.cilium.io/
8. **Tetragon** (eBPF security observability): https://github.com/cilium/tetragon
9. **Linux man-pages** - `bpf(2)`, `bpftool(8)`: https://man7.org/linux/man-pages/
10. **LWN.net** - "A new kernel-based packet filtering engine": https://lwn.net/Articles/743722/
