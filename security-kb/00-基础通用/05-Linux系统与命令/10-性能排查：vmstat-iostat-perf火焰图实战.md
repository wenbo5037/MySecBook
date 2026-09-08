---
title: "性能排查：vmstat-iostat-perf火焰图实战"
category: "00-基础通用/05-Linux系统与命令"
tags: [vmstat, iostat, perf, 火焰图, 性能排查, Linux系统]
level: 主攻
type: ai-generated
status: 完成
---

# 性能排查：vmstat-iostat-perf火焰图实战

> 本文为合法系统管理与运维研究，旨在帮助运维人员掌握vmstat、iostat、perf三大性能排查工具的原理与实战方法。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | vmstat报告虚拟内存/CPU/IO全局状态；iostat专注块设备IO统计；perf是Linux内核性能计数器框架，支持采样、硬件事件、火焰图生成 |
| 核心用途 | vmstat用于快速判断系统瓶颈类别（CPU/内存/IO）；iostat用于定位磁盘IO瓶颈；perf用于精确分析CPU热点函数和生成火焰图 |
| 关键参数 | vmstat：`1 10`（1秒间隔采10次）；iostat：`-x 1`（扩展模式）；perf：`record -g`, `report`, `script`, `火焰图工具链` |
| 常见风险 | perf需root或CAP_PERFMON权限；perf record会临时禁用内核性能监控导致少量计数不准；火焰图采样过短导致信息不足；vmstat的si/so列不等于swap使用量 |
| 关联知识 | [[04-进程管理：ps-top-信号机制与nice]]、[[09-调试工具链：strace-ltrace-gdb基础]]、[[05-网络命令链：ip-ss-tcpdump-nmap排查实战]] |

## 1. 概述

Linux性能排查遵循"先整体后局部"的原则：

1. **第一层：系统概览**（vmstat）—— 快速判断瓶颈在CPU、内存还是IO
2. **第二层：设备级分析**（iostat）—— 定位具体的磁盘IO瓶颈
3. **第三层：函数级分析**（perf）—— 精确找到热点函数和代码路径

这三个工具形成了一套从宏观到微观的性能排查工具链。掌握它们可以解决90%以上的Linux性能问题。

**性能排查方法论（USE方法）**：

- **U**tilization：资源使用率（CPU、内存、磁盘、网络）
- **S**aturation：资源饱和度（是否有排队/等待）
- **E**rrors：错误数（是否有失败事件）

vmstat覆盖U和S，iostat覆盖U/S/E，perf则可以深入到代码级的U。

## 2. 核心原理

### 2.1 vmstat原理

vmstat（Virtual Memory Statistics）从`/proc/stat`、`/proc/meminfo`、`/proc/diskstats`等内核虚拟文件读取数据，计算差值得到变化率。

```bash
# 基本用法：每1秒采样一次，共采样5次
vmstat 1 5

# 输出示例：
# procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
#  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
#  2  0      0 512345  65432 2345678    0    0    12    34  234  567 15  3 80  2  0
#  1  0      0 500000  65432 2350000    0    0     8    56  345  789 22  5 71  2  0
#  0  0      0 498000  65432 2355000    0    0     4    12  123  345  8  2 89  1  0
```

**各列含义**：

| 列 | 含义 | 健康阈值 |
|----|------|----------|
| r | 等待运行的进程数（运行队列） | > CPU核心数 表示CPU饱和 |
| b | 不可中断睡眠的进程数（通常等IO） | > 0 持续出现 表示IO瓶颈 |
| swpd | 已使用的swap空间（KB） | > 0 说明物理内存不够 |
| si | 从磁盘换入swap的速率（KB/s） | > 0 持续出现 需关注 |
| so | 从swap换出到磁盘的速率（KB/s） | > 0 持续出现 严重内存不足 |
| bi | 块设备读入速率（KB/s） | 视设备能力而定 |
| bo | 块设备写出速率（KB/s） | 视设备能力而定 |
| in | 中断次数/秒 | 突然升高需关注 |
| cs | 上下文切换次数/秒 | > 10万 可能有性能问题 |
| us | 用户空间CPU使用率 | 高=应用代码瓶颈 |
| sy | 内核空间CPU使用率 | 高=系统调用/中断频繁 |
| id | 空闲CPU使用率 | < 10% 需关注 |
| wa | 等待IO的CPU时间 | > 10% 表示IO等待严重 |
| st | 被虚拟机管理程序偷走的CPU时间 | > 0 说明超卖 |

### 2.2 iostat原理

iostat（IO Statistics）从`/proc/diskstats`读取块设备统计信息，计算差值得到吞吐量、IOPS和延迟。

```bash
# 扩展模式，每1秒采样
iostat -x 1

# 输出示例：
# Device            r/s     rkB/s   rrqm/s  %rrqm  r_await  rareq-sz  w/s     wkB/s   wrqm/s  %wrqm  w_await  wareq-sz  d/s  dkB/s   drqm/s  %drqm  d_await  dareq-sz  aqu-sz  %util
# sda              45.00   1800.00   2.00   4.26     1.23    40.00   120.00  24000.00  15.00  11.11     2.45   200.00   0.00    0.00    0.00   0.00     0.00     0.00    0.34  68.50
```

**关键指标解读**：

| 指标 | 含义 | 健康阈值 |
|------|------|----------|
| r/s | 每秒读请求数（IOPS） | 视设备能力：SSD约3-10万，HDD约100-300 |
| w/s | 每秒写请求数 | 同上 |
| rkB/s | 每秒读吞吐量（KB/s） | 视设备带宽 |
| wkB/s | 每秒写吞吐量 | 视设备带宽 |
| r_await | 读请求平均等待时间（ms） | SSD < 1ms，HDD < 10ms |
| w_await | 写请求平均等待时间（ms） | 同上 |
| aqu-sz | 平均队列深度（类似avgqu-sz） | > 1 说明有排队 |
| %util | 设备繁忙百分比 | > 80% 接近饱和；SSD此值参考意义有限 |

**%util的误区**：对于支持并发队列的NVMe SSD和多路径存储，%util=100%不代表带宽用尽。应结合await和吞吐量综合判断。

### 2.3 perf原理

perf是Linux内核内置的性能分析工具，基于内核的perf_event子系统。

**工作原理**：

```text
用户空间（perf工具）
    |
    +-- perf_event_open() 系统调用
    |
内核空间（perf_event子系统）
    |
    +-- 注册硬件性能计数器（PMU）
    |   - CPU cycles（时钟周期）
    |   - Instructions（指令数）
    |   - Cache misses（缓存未命中）
    |   - Branch misses（分支预测失败）
    |
    +-- 注册软件事件
    |   - context-switches（上下文切换）
    |   - page-faults（缺页异常）
    |   - cpu-migrations（CPU迁移）
    |
    +-- 注册内核 tracepoint
    |   - sched:sched_switch
    |   - block:block_rq_issue
    |   - net:net_dev_xmit
    |
    +-- 定时中断采样（基于NMI或PMI）
        - 记录当前IP（指令指针）
        - 记录调用栈（dwarf/frame pointer）
```

**perf record采样流程**：

1. perf通过`perf_event_open()`注册采样事件
2. 内核在每个采样间隔触发PMI（Performance Monitor Interrupt）
3. 内核记录当前进程的IP和调用栈到ring buffer
4. perf工具从ring buffer读取数据写入perf.data文件
5. perf report/script解析perf.data生成报告或火焰图

## 3. 详细知识点

### 3.1 vmstat高级用法

**带时间戳输出**：

```bash
# -t显示时间戳
vmstat -t 1 3

# procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu----- -----timestamp-----
#  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st                 CST
#  0  0      0 485432  43210 1987654    0    0     8    24  187  432  5  2 92  1  0 2026-09-09 10:00:01
```

**宽格式输出**：

```bash
# -w显示宽格式（列名更清晰）
vmstat -w 1 3

# procs -----------------------memory---------------------- ---swap-- -----io---- -system-- ------cpu-----
#  r  b    swpd     free     buff    cache    si   so    bi    bo    in   cs  us sy id wa st
#  0  0       0   485432    43210  1987654     0    0     8    24   187  432   5  2 92  1  0
```

**实战排查思路**：

```bash
# 场景：服务器响应缓慢

# 第一步：快速查看vmstat（看3行数据即可判断）
vmstat 1 3

# 分析路径：
# 如果 r > CPU核数 + wa > 10% → CPU和IO双重瓶颈
# 如果 si/so > 0 → 内存不足，正在使用swap
# 如果 b > 0 持续 → IO阻塞
# 如果 us > 80% → 应用代码CPU密集
# 如果 sy > 50% → 内核态开销大（可能是系统调用过多或锁竞争）
```

### 3.2 iostat高级用法

**扩展模式详解**：

```bash
# -x显示扩展统计信息
iostat -x 1

# -d只显示设备，-p显示分区
iostat -x -p sda 1

# -k以KB为单位，-m以MB为单位
iostat -x -m 1

# 结合特定设备
iostat -x nvme0n1 1
```

**NVMe vs SATA SSD vs HDD的iostat对比**：

```text
# NVMe SSD（高并发低延迟）：
# r/s: 50000+  r_await: 0.05ms  %util: 95%（不代表饱和）

# SATA SSD（中等并发）：
# r/s: 800     r_await: 0.5ms   %util: 75%

# HDD（低并发高延迟）：
# r/s: 150     r_await: 5ms     %util: 90%（接近饱和）
```

**实战排查思路**：

```bash
# 场景：数据库查询慢

# 第一步：查看磁盘IO整体状况
iostat -x 1 5

# 分析路径：
# 如果 await > 10ms（SSD）或 > 50ms（HDD）→ IO延迟过高
# 如果 %util > 90%（HDD）→ 磁盘接近饱和
# 如果 rkB/s + wkB/s 接近设备带宽上限 → 带宽瓶颈
# 如果 r/s + w/s 接近设备IOPS上限 → IOPS瓶颈

# 第二步：结合vmstat确认是否是IO导致的系统问题
vmstat 1 3
# 如果 b > 0 且 wa > 10% → 确认IO是瓶颈
```

### 3.3 perf核心用法

**基础操作**：

```bash
# 记录CPU采样数据（采样频率4000Hz，持续10秒）
perf record -g -F 4000 -- sleep 10

# 附加到运行中的进程
perf record -g -p 12345 -F 1000 -- sleep 30

# 记录所有CPU上的事件
perf record -a -g -F 99 -- sleep 30

# 查看perf报告
perf report

# 交互式操作：
# 上下箭头浏览函数
# Enter展开调用链
# +展开/折叠
# /搜索函数名
# q退出
```

**生成火焰图的完整流程**：

```bash
# 第一步：采集perf数据
perf record -g -F 99 -a -- sleep 30

# 第二步：转换为折叠栈格式
perf script > out.perf-script

# 第三步：使用FlameGraph工具生成SVG
# 克隆FlameGraph工具
git clone https://github.com/brendangregg/FlameGraph.git

# 生成火焰图
./FlameGraph/stackcollapse-perf.pl out.perf-script > out.folded
./FlameGraph/flamegraph.pl out.folded > flamegraph.svg

# 一行命令完成（管道方式）
perf record -g -F 99 -a -- sleep 30 && \
perf script | ./FlameGraph/stackcollapse-perf.pl | \
./FlameGraph/flamegraph.pl > flamegraph.svg
```

**火焰图解读要点**：

```text
火焰图结构：
- X轴：采样数量（不是时间），越宽表示该函数被采样到的次数越多
- Y轴：调用栈深度，底部是入口函数，顶部是实际执行的函数
- 颜色：随机色，无特殊含义（某些变体用颜色表示内核/用户态）

关键解读：
- 宽的"平台"表示CPU时间集中在这个函数中
- 如果某个函数占了很大比例，它就是性能热点
- 纵向的调用链表示函数调用关系
- 火焰图中每个方块的宽度 = 该函数在采样期间被采样到的比例
```

**perf其他实用功能**：

```bash
# 查看硬件性能计数器
perf stat -d ./myapp

# 输出示例：
# Performance counter stats for './myapp':
#     1,234.56 msec task-clock
#            12      context-switches
#             3      cpu-migrations
#           234      page-faults
# 4,567,890,123      cycles
# 8,901,234,567      instructions    #    1.95  insn per cycle
# 1,234,567,890      branches
#    23,456,789      branch-misses   #    1.90% of all branches

# 监控特定事件
perf stat -e cache-misses,cache-references,dTLB-load-misses ./myapp

# 记录特定tracepoint事件
perf record -e sched:sched_switch -a -- sleep 5

# 追踪系统调用
perf trace -p 12345
```

### 3.4 综合性能排查方法论

**USE方法的工具映射**：

```text
资源         | Utilization       | Saturation           | Errors
-------------|-------------------|----------------------|---------
CPU          | vmstat (us+sy)    | vmstat (r列)         | perf stat (hardware errors)
Memory       | vmstat (free/cache)| vmstat (si/so)      | dmesg (OOM killer)
Disk IO      | iostat (%util)    | iostat (aqu-sz)     | iostat (errors in /proc/diskstats)
Network      | sar -n DEV        | ifconfig (overruns)  | ifconfig (errors)
```

**性能排查决策树**：

```text
系统响应缓慢
    |
    +---> vmstat 1 5
    |     |
    |     +---> r > CPU核数, us+sy > 80%?
    |     |     |   YES -> CPU瓶颈 -> perf record -g -> 火焰图
    |     |     |   NO  -> 检查IO
    |     |
    |     +---> b > 0, wa > 10%?
    |     |     |   YES -> IO瓶颈 -> iostat -x 1 -> 定位设备
    |     |     |   NO  -> 检查内存
    |     |
    |     +---> si/so > 0?
    |           |   YES -> 内存不足 -> free -h / top -> OOM风险
    |           |   NO  -> 检查网络/应用逻辑
    |
    +---> 进一步深入...
          |
          +---> CPU瓶颈: perf record -> 火焰图 -> 定位热点函数
          +---> IO瓶颈: iostat -x -> 优化查询/添加SSD/调整IO调度器
          +---> 内存: free -h -> 优化内存使用/增加物理内存
```

### 3.5 内核级性能追踪

**ftrace简介**：

```bash
# 查看可用的tracepoint
ls /sys/kernel/debug/tracing/events/

# 启用特定事件
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable

# 查看追踪输出
cat /sys/kernel/debug/tracing/trace_pipe

# 使用trace-cmd简化操作
trace-cmd record -e sched_switch sleep 5
trace-cmd report | head -20
```

**BPF和现代性能工具**：

```bash
# 使用bpftrace进行动态追踪
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'

# 使用bcc工具
/usr/share/bcc/tools/execsnoop    # 追踪新进程创建
/usr/share/bcc/tools/opensnoop    # 追踪文件打开
/usr/share/bcc/tools/biolatency   # 块IO延迟直方图
/usr/share/bcc/tools/tcpconnect   # 追踪TCP连接
```

## 4. 实战与示例

### 4.1 排查Web服务器CPU飙高

```bash
# 场景：Nginx worker进程CPU使用率达到100%

# 第一步：确认CPU状况
vmstat 1 3
# procs --memory-- ---swap-- -----io---- -system-- ------cpu-----
#  r  b   swpd   free   cache   si   so    bi    bo   in   cs us sy id wa
#  4  0      0 234567 5678901    0    0     4    12  4567 8901 95  3  1  1

# 分析：us=95%，r=4，CPU在用户态处理请求。us+sy=98%几乎无空闲。

# 第二步：用perf采集CPU采样（10秒）
perf record -g -F 99 -p $(pgrep -f "nginx: worker") -- sleep 10

# 第三步：生成火焰图
perf script | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > nginx-cpu.svg

# 第四步：分析火焰图
# 发现大量CPU时间集中在ngx_http_parse_uri函数 → 解析器有性能问题
# 进一步分析发现该函数被循环调用 → 配置中某个规则导致正则回溯
```

### 4.2 排查数据库IO瓶颈

```bash
# 场景：MySQL查询响应时间从10ms涨到500ms

# 第一步：查看磁盘IO
iostat -x 1 5
# Device  r/s   rkB/s  rrqm/s  r_await  w/s   wkB/s  wrqm/s  w_await  aqu-sz  %util
# sda    250    8000    45      2.5     180   36000    120     45.2    38.5   99.2%

# 分析：w_await=45.2ms，aqu-sz=38.5，%util=99.2%。写延迟极高，队列深度大。

# 第二步：确认系统级影响
vmstat 1 3
#  r  b   swpd   free   cache   si   so    bi    bo   in   cs us sy id wa
#  1  8      0 123456 8765432    0    0    32  1200  3456 7890 15 12  8 65

# 分析：b=8（8个进程等待IO），wa=65%，确认IO是主要瓶颈。

# 第三步：定位IO来源
iotop -o -d 1
# Total DISK READ:  45.00 M/s | Total DISK WRITE:  32.00 M/s
#   PID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN     IO>    COMMAND
# 12345 be/4  mysql      30.00 M/s    25.00 M/s  0.00 %  78.50 %  mysqld

# 结论：mysqld是IO主要来源，需要优化查询或升级存储。
```

### 4.3 排查内存不足问题

```bash
# 场景：应用频繁OOM Killed

# 第一步：查看内存状况
free -h
#               total        used        free      shared  buff/cache   available
# Mem:           16Gi       14Gi       200Mi       512Mi       1.5Gi       800Mi
# Swap:         4.0Gi       3.8Gi       200Mi

# 第二步：用vmstat确认swap活动
vmstat 1 5
#  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa
#  0  2  3900000 180000  12000  1200000 2048  4096   64  256  567  890 20  8 55 17

# 分析：si=2048KB/s，so=4096KB/s。swap持续高频率换入换出，系统严重抖动（thrashing）。

# 第三步：查找内存大户
ps aux --sort=-%mem | head -10
# USER   PID  %CPU %MEM    VSZ    RSS TTY  STAT START  TIME COMMAND
# mysql 1234  15.0 45.0 18234567 7340032 ?   Sl   08:00  50:00 /usr/sbin/mysqld
# java  5678  25.0 30.0 12345678 4915200 ?  Sl   08:05  80:00 java -jar app.jar

# 结论：mysqld占45%，java占30%，两者合计占75%。需要增加内存或优化配置。
```

### 4.4 perf stat快速性能对比

```bash
# 场景：优化代码前后对比性能

# 优化前
perf stat -d ./myapp_before
#  1,234.56 msec task-clock
#  4,567,890,123      cycles
#  8,901,234,567      instructions    #    1.95  insn per cycle
#     23,456,789      branch-misses   #    1.90% of all branches

# 优化后
perf stat -d ./myapp_after
#    890.12 msec task-clock           # 减少28%
#  3,456,789,012      cycles          # 减少24%
# 10,123,456,789      instructions    #    2.93  insn per cycle  # IPC提升50%
#     12,345,678      branch-misses   #    1.02% of all branches # 分支预测改善

# 对比：IPC从1.95提升到2.93，分支预测失败率从1.90%降到1.02%
```

### 4.5 综合排查脚本模板

```bash
#!/bin/bash
# 快速性能诊断脚本
echo "=== 系统概览 ==="
uptime
echo ""

echo "=== 内存状态 ==="
free -h
echo ""

echo "=== vmstat 采样（5次） ==="
vmstat 1 5
echo ""

echo "=== 磁盘IO状态 ==="
iostat -x 1 3
echo ""

echo "=== CPU密集进程（top 10） ==="
ps aux --sort=-%cpu | head -11
echo ""

echo "=== 内存密集进程（top 10） ==="
ps aux --sort=-%mem | head -11
echo ""

echo "=== 网络连接状态 ==="
ss -s
echo ""
```

## 5. 常见坑与避坑指南

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| vmstat第一行数据是累计值不是瞬时值 | 第一行是系统启动以来的平均值，从第二行开始才是采样间隔内的数据 | 使用vmstat 1 N时忽略第一行输出 |
| iostat %util=100%但系统正常 | NVMe/RAID设备支持高并发队列，%util不等于饱和 | 结合await和吞吐量综合判断，不单独依赖%util |
| perf report显示"no symbols" | 二进制文件未包含调试符号 | 编译时加 `-g` 选项，或使用 `perf report --symfs` 指定符号路径 |
| 火焰图全是"unknown" | 采样栈回溯失败 | 检查 `/proc/sys/kernel/kptr_restrict`，设为0允许读取内核符号；确保perf.data包含栈信息 |
| perf record被安全策略阻止 | ptrace_scope或seccomp禁止了perf_event_open | `echo 0 > /proc/sys/kernel/yama/ptrace_scope`（需root）；容器需 `--cap-add=PERFMON` |
| vmstat的si/so不等于实际swap使用量 | si/so是速率（KB/s），不是总量 | 查看 `free -h` 的swap行或 `swapon -s` 获取总量 |
| iostat无法显示NVMe分区统计 | 旧版iostat不识别NVMe设备名 | 升级sysstat版本，或使用 `iostat -p /dev/nvme0n1` |
| perf.data文件过大 | 采样频率过高或时间过长 | 降低 `-F` 频率（推荐99或999），缩短采样时间 |
| 火焰图中"perf_map"相关函数干扰 | JVM等运行时动态生成代码的符号映射 | 确保 `PERF_MAP_OPTIONS=dump` 已设置，或在火焰图中过滤掉这些条目 |
| 多容器环境vmstat数据不准确 | vmstat显示的是宿主机全局数据 | 使用 `cgroup` 限制的容器内查看对应cgroup的统计信息 |

## 6. 知识关联

- [[04-进程管理：ps-top-信号机制与nice]]：vmstat的r列（运行队列）与进程调度直接相关；perf stat中的context-switches与进程切换机制呼应
- [[09-调试工具链：strace-ltrace-gdb基础]]：perf的tracepoint机制与strace的ptrace机制形成互补——strace适合单进程细粒度追踪，perf适合全局采样分析
- [[05-网络命令链：ip-ss-tcpdump-nmap排查实战]]：网络性能排查需要perf的net tracepoint与tcpdump/tss统计配合
- [[06-权限体系：rwx-ACL-setuid-capabilities]]：perf需要CAP_PERFMON能力或root权限，容器环境需要特殊授权
- [[13-日志体系：syslog-journald-auditd配置]]：性能事件的日志化与journald的结构化日志配合，可实现性能事件的长期追踪

## 7. 参考资料

- **man手册**：`man vmstat`（虚拟内存统计）、`man iostat`（IO统计）、`man perf`（perf工具集总览）、`man perf-record`（采样记录）、`man perf-stat`（性能计数器统计）、`man perf-report`（报告分析）
- **《BPF Performance Tools》**：Brendan Gregg，性能排查方法论圣经，含USE方法和大量实战案例
- **《Systems Performance》**（第2版）：Brendan Gregg，系统性能分析方法论专著
- **FlameGraph工具**：https://github.com/brendangregg/FlameGraph — Brendan Gregg的火焰图工具集
- **Linux性能可观测性工具**：https://www.brendangregg.com/linuxperf.html — 性能工具速查表
- **perf官方文档**：https://perf.wiki.kernel.org/index.php/Tutorial — Linux内核perf教程
- **sysstat项目**：https://github.com/sysstat/sysstat — iostat/vmstat/sar等工具的源码和文档
- **《Linux Kernel Development》**（第3版）：Robert Love，详解内核调度器、cgroups和perf_event子系统
