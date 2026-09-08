---
title: "Socket通信模型与epoll实现机制"
category: "00-基础通用/04-操作系统原理"
tags: [socket, epoll, 网络IO, 高并发, 操作系统]
level: 主攻
type: ai-generated
status: 完成
updated: 2025-07-17
---

# Socket通信模型与epoll实现机制

> **合规声明**：本文内容用于 Socket 网络编程、IO 多路复用与高并发服务器设计的合法工程研究。文中涉及的网络编程、epoll 用法、状态机分析均为防御性/开发性用途。严禁利用本文技术实施未授权端口扫描、DDoS、数据窃取或网络攻击。服务端程序的开发与部署请遵守当地法律、所在组织安全政策与服务条款。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | Socket 是对网络通信端点的文件抽象；epoll 是 Linux 高效的 IO 多路复用机制 |
| 核心用途 | 网络服务端并发连接处理、高性能事件驱动服务器（nginx/redis） |
| 关键参数 | 监听队列 backlog、epoll_wait 超时、ET/LT 模式、EPOLLEXCLUSIVE 防惊群 |
| 常见风险 | 惊群、ET 漏事件、fd 泄漏、TIME_WAIT 堆积、阻塞 accept 丢连接 |
| 关联知识 | [[13-IO模型演进：select-poll-epoll-io_uring]]、[[06-进程间通信：管道消息队列共享内存信号]]、[[05-TCP状态机与TIME_WAIT调优]] |

---

## 1. 概述

**Socket（套接字）** 是操作系统向应用层提供的网络通信抽象。它的核心设计哲学是 **"一切皆文件"（Everything is a File）**：在网络通信中，每个连接端点都是一个文件描述符（file descriptor, fd），可以用 `read`/`write`/`close` 等统一文件 IO 接口操作，只是底层由网络协议栈（TCP/UDP/IP）驱动，而不是磁盘驱动。这一抽象让"网络读写"与"文件读写"在系统调用层面统一，也让人多路复用（select/poll/epoll）可以一视同仁地管理"连接"与"打开的文件"。

一个典型的服务端 TCP Socket 生命周期：

```text
socket() ──▶ bind() ──▶ listen() ──▶ accept() ──▶ read()/write() ──▶ close()
   创建端点    绑定地址    开始监听     接受连接       数据交换          释放
              (IP:port)   (backlog)   (返回新fd)
```

Socket 每次 accept 返回一个新的 fd 代表已建立连接，与监听的 `listenfd` 相互独立。一个进程可以持有成百上千个连接 fd（理论上限受 fd 数量与内存约束），这正是高性能并发服务器的前提。Linux 下每个进程默认 fd 上限是 1024（`ulimit -n`），高并发前务必调大到 65535 以上。

**epoll** 诞生于 Linux 2.6，是 `select`/`poll` 之后第三代 IO 多路复用机制。它解决了两大历史痛点：

1. `select` 的 fd 上限 `FD_SETSIZE=1024`，且每次都要线性扫描全量集合；
2. `select`/`poll` 每次调用都要把整个 fd 集合从用户态拷贝到内核态，复杂度 O(n) 随连接数线性膨胀。

epoll 用 **红黑树 + 就绪链表 + mmap** 实现了 O(1) 的就绪检测，成为 Linux 高并发服务器的基石。nginx、Redis、libevent、Node.js 的底层事件循环、大量网关都用它。事件驱动模型本身，也直接呼应了 [[05-上下文切换：开销来源与实测分析]] 中"减少切换次数"的优化思想——一个线程用 epoll 管住所有连接，而不是为每个连接开一个线程。

在连接模型上要纠正一个常见误解：**"连接数"不等于"线程数"**。使用 epoll 后，十万连接只需要几十个线程，甚至单线程就能承接——CPU 资源只在"有数据要读写"的瞬间被消耗，空闲连接只占一个 fd 与内核中的少量内存。这就是事件驱动（event-driven）与阻塞式（blocking）两种模型最大的分野。因此衡量一个服务能否支撑高并发，看的不是"连接/线程比"，而是"每个就绪事件的处理时长"与"事件循环是否被阻塞"。若 handler 里出现耗时操作（磁盘、锁、sleep），事件循环会被"抬住"，整个服务的吞吐瞬间垮掉——这是所有基于 epoll 框架的通用铁律。

本节作为 [[13-IO模型演进：select-poll-epoll-io_uring]] 的姊妹篇，重点深入 Socket 抽象、TCP 状态映射、以及 epoll 的内核实现细节。掌握本节之后，读 nginx worker 模型、Redis 单线程事件循环的源码都会有"原来如此"的体验。

---

## 2. 核心原理

### 2.1 Socket 抽象与"一切皆文件"

Unix 把 I/O 设备抽象为文件描述符。Socket 内核中有 `struct socket → struct sock` 对应一个通信端点，用户态通过 int fd 引用。所有 fd 共享统一的 file 操作接口：

| 操作 | 含义 |
|------|------|
| socket(AF_INET, SOCK_STREAM, 0) | 创建 fd（地址族、类型、协议） |
| bind(fd, &sockaddr, len) | 绑定本地 IP:port，客户端 read 写之前必做 |
| listen(fd, backlog) | 进入监听态，backlog 为"已建立待 accept"队列上限 |
| accept(fd, &cliaddr, &len) | 从 accept 队列取出一个连接，返回新 fd |
| connect(fd, &srvaddr, len) | 主动发起连接（客户端） |
| read/write/recv/send | 数据传输 |
| shutdown(fd, how) | 半关闭某个方向（关读/关写/全关） |
| close(fd) | fd 引用计数 -1，归零才真正释放 |

注意：`listen` 的 backlog 参数在 Linux 上会被 clamp 到 `net.core.somaxconn`（默认 4096）；`backlog` 实际控制的是**已完成三次握手、等待 accept 的队列长度**，与之并列的还有 SYN 半连接队列（由 `net.ipv4.tcp_max_syn_backlog` 控制）。这两个队列一旦满，新连接会被内核直接丢弃或回 RST——在高并发突刺场景，backlog 太小是"连接被拒"的隐形元凶。

### 2.2 TCP 状态机与 Socket API 的映射

TCP 有 11 个状态（RFC 793），它们与 socket API 调用关系如下：

```text
                    ┌─────────────┐
                    │   CLOSED    │
                    └──────┬──────┘
                 socket()  │  connect()
                    ┌──────▼──────┐
      ┌─ SYN_SENT ─┤            ├─ LISTEN ──┐
      │  (connect) │            │ (listen)  │
      │            └──┬─────────┘           │
      │               ▼                     ▼
      └─────── SYN_RECEIVED ──────── accept() ─ at ESTABLISHED
                            │
                      ┌─────▼─────┐
                      │ESTABLISHED│  ← 读写数据
                      └─────┬─────┘
               close() ─────┴───── close()
                   │              │
          ┌───────▼───┐    ┌─────▼────┐
          │ FIN_WAIT1 │    │ CLOSE_WAIT│
          └───────┬───┘    └─────┬────┘
                  │              │
          ┌───────▼───┐    ┌─────▼────┐
          │ FIN_WAIT2 │    │  LAST_ACK │
          └───────┬───┘    └─────┬────┘
                  │              │
                  └───┬──────────┘
                      ▼
              ┌─────────────┐
              │  TIME_WAIT  │  (2*MSL≈60s)
              └──────┬──────┘
                     │
              ┌──────▼─────┐
              │   CLOSED   │
              └────────────┘
```

- **LISTEN**：`listen()` 之后。
- **ESTABLISHED**：三次握手完成，连接从 SYN 半连接队列转入 accept 队列，`accept()` 返回新 fd。
- **CLOSE_WAIT**：收到对端 FIN，但本端还没 `close()`。*进程不 close、REPLACEMENT fd 挂 CLOSE_WAIT，是典型的 fd 泄漏症状*——实际排查时，CLOSE_WAIT 持续增长几乎必然意味着代码漏了 close。
- **TIME_WAIT**：主动关闭方在收到 FIN 后停留 2×MSL（约 60 秒），用于兜底最后一个 ACK 丢失与旧报文失效。高并发短连接下 TIME_WAIT 多是正常现象，无脑调整反而破坏连接语义，详见 [[05-TCP状态机与TIME_WAIT调优]]。

### 2.3 阻塞 IO 与 thread-per-connection 的局限

默认情况下，`read`/`accept` 是**阻塞（blocking）**的：`read` 无数据时线程阻塞挂起，`accept` 无连接时阻塞等待。因此最简单可靠的服务端模式是"一连接一线程"：

```c
while (1) {
    int cfd = accept(listenfd, NULL, NULL);   /* 阻塞等连接 */
    pthread_create(&t, NULL, handle, &cfd);   /* 每连接一线程 */
}
```

问题在连接数上了规模之后立刻暴露：

```text
连接数 1万  → 需要 1万 个线程
            → 每个线程默认栈 8MB 虚拟内存  → 内存爆炸
            → 海量线程上下文切换           → 见 [[05-上下文切换]]
            → 线程调度风暴、cache 全部失效
```

**阻塞 + 线程池无法支撑高并发**的根本原因是：资源（线程、栈、切换）随连接数**线性增长**，而连接大多是空闲的。解决方案是把"阻塞等待"换成"事件通知"——一个线程管所有连接，谁有数据就处理谁，这便是 IO 多路复用。

### 2.4 非阻塞 IO：EAGAIN 与 EWOULDBLOCK

用 `fcntl(fd, F_SETFL, ... | O_NONBLOCK)` 把 fd 设为非阻塞：

- `read`/`accept` 没有数据/连接时**立即返回 -1**，`errno = EAGAIN`（POSIX 上 `EWOULDBLOCK` 与 `EAGAIN` 同值）。
- 程序用"是否 EAGAIN"判断"现在没事可做"，稍后再来——实现不阻塞的轮询基础。

```c
int flags = fcntl(fd, F_GETFL, 0);
fcntl(fd, F_SETFL, flags | O_NONBLOCK);
ssize_t n = read(fd, buf, sizeof(buf));
if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    /* 现在没数据，稍后再读 */
}
```

非阻塞只是"轮询的基础"。如果程序自己 while 循环重 EAGAIN 试，就是忙轮询（busy polling），CPU 被白白空转。所以非阻塞 fd 必须配合**事件通知**机制（select/poll/epoll）告诉我们"什么时候去读"，这就是 IO 多路复用的意义。三者中只有 epoll 具备真正的"就绪事件"能力，select/poll 本质仍是轮询。

---

## 3. 详细知识点

### 3.1 select → poll → epoll 的演进

| 维度 | select | poll | epoll |
|------|--------|------|-------|
| fd 上限 | FD_SETSIZE=1024（编译期固定） | 无上限 | 无上限 |
| 集合表示 | fd_set 位图 | pollfd 数组 | 内核维护 |
| 每次调用拷贝 | 全量 fd_set（用户↔内核） | 全量 pollfd 数组 | 增删改单个 fd |
| 就绪检测 | 线性扫描全部 | 线性扫描全部 | 红黑树 + 就绪链表，O(1) |
| 就绪结果 | 需自行 FD_ISSET 遍历 | 需遍历 revents | 直接返回就绪 fd |
| 阻塞语义 | 每次调用都阻塞 | 每次调用都阻塞 | epoll_wait 可等可不等 |

```c
/* select：每次要把整个 fd_set 传入，最大 1024 */
fd_set rset;
FD_ZERO(&rset);
FD_SET(listenfd, &rset);
select(listenfd + 1, &rset, NULL, NULL, &tv);
/* 之后逐个 FD_ISSET 检查——O(n) 且把 set 从用户态拷进内核 */
```

select 的 `do_select()` 每次都要把集合拷贝进内核、遍历所有 fd 调用 poll 回调，O(n)。连接过万时，仅这套往返拷贝与线性扫描就足以拖垮 CPU。poll 去掉了 1024 上限，但依旧每次全量拷贝 + 线性扫描。

### 3.2 epoll 使用三部曲

```c
#include <sys/epoll.h>

/* 1. 创建 epoll 实例（返回 epfd） */
int epfd = epoll_create(1024);   /* 参数已忽略，>0 即可 */

/* 2. 登记/修改/删除关注的事件 */
struct epoll_event ev;
ev.events = EPOLLIN;             /* 关注的事件 */
ev.data.fd = fd;                 /* 用户数据：常是 fd，可放指针 */
epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);   /* ADD/MOD/DEL */

/* 3. 等待就绪事件 */
struct epoll_event events[128];
int n = epoll_wait(epfd, events, 128, -1);   /* -1 永久阻塞 */
for (int i = 0; i < n; i++) {
    if (events[i].events & EPOLLIN) {
        int ready_fd = events[i].data.fd;
        /* 处理 ready_fd 的可读 */
    }
}
```

关键概念：

- **就绪事件 vs 全量事件**：`epoll_wait` 只返回**就绪**的 fd（有数据/可写），不需要把 N 个 fd 集合每次都放进内核。这是与 select/poll 的本质差异。
- **LT（Level Triggered，水平触发）**（默认）：只要 fd 还有可读数据，`epoll_wait` 就会重复返回。允许分批读，编程宽容。
- **ET（Edge Triggered，边缘触发）**：只在状态"无→有"的**跳变沿**通知一次；要求一次把数据读完（读到 EAGAIN），否则剩余数据"卡住"不再通知。ET 更高效（减少重复唤醒），但要求严格的读循环。

```text
LT 模式：fd 有数据就一直上报
    数据到达 ──▶ [有数据] ─▶ epoll_wait 返回
                ─▶ 未读完，下次 epoll_wait 仍返回  ← 重复唤醒
ET 模式：只在边沿上报一次
    数据到达 ──▶ [跳变沿] ─▶ epoll_wait 返回一次
                ─▶ 未读完 ╳ 不再上报  ← 必须一次读尽（读到 EAGAIN）
```

### 3.3 epoll 内部实现：红黑树 + 就绪链表 + mmap

epoll 在内核（`fs/eventpoll.c`）中有两个核心数据结构：

1. **红黑树（rbtree）**：存所有被 `epoll_ctl` 登记监视的 fd，O(log n) 增删改，避免每次全量扫描。
2. **就绪链表（rdllist）**：存"当前有事件"的 fd。事件到达时，网络协议栈回调 `ep_poll_callback` 把 fd 挂进链表；`epoll_wait` 只摘就绪项，O(1)。
3. **epfd 本身**：`epoll_create` 通过 `anon_inode_getfd` 创建的一个匿名 inode fd 实现。

```text
           用户态 epoll_ctl(ADD/MOD/DEL)
        ──────────────────────────▶
        │
        ▼
   ┌──────────────────────────────────┐
   │  内核 eventpoll 对象 (epfd)        │
   │                                  │
   │  红黑树 rbtree    就绪链表 rdllist │
   │  ┌─────┐┌─────┐  ┌─────┐┌─────┐  │
   │  │fd1  ││fd2  │  │fd3  ││fd5  │  │
   │  └─────┘└─────┘  └─────┘└─────┘  │
   │  (所有被监视fd)   (有事件待取的fd)  │
   └─────────────────┬────────────────┘
        │数据到达       ▲ ep_poll_callback
        ▼              │
   ┌──────────────────────────────────┐
   │  网络协议栈（tcp/udp）            │
   │  数据就绪 → 回调通知 eventpoll    │
   └──────────────────────────────────┘
```

**mmap 的应用**：Linux 上 epoll 返回的事件数组通过 mmap 让内核与用户态共享就绪队列，减少一次复制（`epoll_wait` 返回就绪 fd 时尽量少拷贝）。这个优化在事件密集时至关重要。

### 3.4 epoll 事件类型速查

| 事件 | 含义 |
|------|------|
| EPOLLIN | 可读（有数据 / 对端关闭 / 有新连接等 accept） |
| EPOLLOUT | 可写（发送缓冲有空间） |
| EPOLLERR | 出错 |
| EPOLLHUP | 挂断（对端关闭本端未关） |
| EPOLLRDHUP | 对端关闭写端（半关闭） |
| EPOLLET | 边缘触发 |
| EPOLLONESHOT | 一次性触发，事件后自动从集合移除 |
| EPOLLEXCLUSIVE | 惊群缓解：只唤醒一个等待者 |

### 3.5 epoll 与 nginx / redis / libevent 的关系

- **nginx**：worker 进程用 epoll 驱动事件循环（`ngx_epoll_module.c`），管理海量连接；EPOLLET + 非阻塞 IO，配合 `EPOLLEXCLUSIVE` 或锁避免 accept 惊群。
- **redis**：单线程事件循环基于自研 `ae.c`，Linux 上用 `ae_epoll.c` 包装 epoll，处理所有客户端 socket 命令。
- **libevent / libev**：跨平台事件库，Linux 后端用 epoll，把 ET/LT 差异封装成统一 API。

它们的共同模式是 **事件循环（event loop）**：

```text
while (1) {
    int n = epoll_wait(epfd, events, N, timeout);
    for (i in 0..n)  handle(events[i]);   /* 分发回调 */
}
```

### 3.6 Socket 选项速查（工程高频项）

| 选项 | 用途 | 坑 |
|------|------|----|
| SO_REUSEADDR | 允许端口立刻复用（服务端重启快） | 配合 SO_REUSEPORT 使用时要理解语义 |
| SO_REUSEPORT | 多进程同时 bind 同端口，内核负载均衡 | 惊群常见替代方案 |
| TCP_NODELAY | 禁用 Nagle 算法，小包立即发 | 交互型应用应关闭 |
| SO_KEEPALIVE | 空闲时发探测包维持连接 | 默认 2h，参数在 sysctl `tcp_keepalive_*` |
| SO_RCVBUF/SNDBUF | 收发缓冲大小 | 过大浪费内存 |
| SO_LINGER | 控制 close 行为（LINGER=0 发 RST） | 乱用会丢未发数据 |
| SO_TIMEOUT/超时 | 收发超时 | 区分阻塞与轮询语义 |

`listen` 的 accept 队列与 SYN 队列，`TCP_NODELAY` 与 Nagle，`SO_LINGER` 与 RST——这些细节直接决定线上服务的连接质量，是面试与实际调优的题库核心。

### 3.7 io_uring 简介（下一代异步 IO）

**io_uring**（Linux 5.1+）是内核为高性能 IO 推出的新一代异步机制：

- **SQ（Submission Queue，提交队列）与 CQ（Completion Queue，完成队列）**：无锁 ring buffer，与应用直接 mmap 共享，提交/完成都不进逐条 syscall。
- **异步批处理 + 零拷贝**：一次提交多条读写，内核批量执行，减少内核态切换；支持 `splice`/`sendfile` 零拷贝路径。
- **与 epoll 对比**：epoll 仍是"事件通知"——真正 read/write 还要逐条走 syscall；io_uring 把提交与完成都异步批量化，削减 syscall 与切换。

```text
epoll 模式：  epoll_wait(通知) → read(数据，syscall) → write(数据，syscall)
io_uring：    SQ 提交 [read, write] → 内核异步执行 → CQ 返回结果
              （无逐条 syscall，批量异步 + 事件驱动）
```

io_uring 在 NVMe 直连、数据库 IO、以及需要极高吞吐的网关场景逐渐普及；但其异步读写要求对 fd 生命周期与 SO_OOM 等边界状态格外小心，工程复杂度比 epoll 高一个台阶——这也是 nginx/redis 先守住 epoll、逐步迁移 io_uring 的原因。

---

## 4. 实战与示例

### 4.1 C 语言 epoll echo server（完整可运行）

```c
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define MAX_EVENTS 128
#define PORT 8080

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int main(void) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listenfd, 128);
    set_nonblock(listenfd);

    int epfd = epoll_create(1024);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = listenfd};
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

    struct epoll_event evs[MAX_EVENTS];
    char buf[4096];

    while (1) {
        int n = epoll_wait(epfd, evs, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == listenfd) {                     /* 新连接 */
                int cfd;
                while ((cfd = accept(listenfd, NULL, NULL)) >= 0) {
                    set_nonblock(cfd);
                    struct epoll_event ce = {.events = EPOLLIN, .data.fd = cfd};
                    epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ce);
                }
            } else {                                  /* 已连接可读 */
                ssize_t r = read(fd, buf, sizeof(buf));
                if (r > 0) {
                    write(fd, buf, r);                /* 原样回显 */
                } else {                              /* 0=关闭, <0=错误 */
                    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                }
            }
        }
    }
    return 0;
}
```

```bash
$ gcc -O2 -o echoserver echoserver.c
$ ./echoserver &
$ echo "hi" | nc localhost 8080
hi
```

要点：listenfd 与连接 fd 都在 epoll 中管理；用**非阻塞 listenfd** 并在循环里 `while ((cfd = accept(...)) >= 0)` 取尽所有新连接——这是避免"epoll_wait 返回后只 accept 一次而丢弃链接"的标准姿势。连接 fd 读到 0 或出错必须 DEL + close，否则泄漏。

### 4.2 Python asyncio 底层原理：事件循环

Python 的 `asyncio` 在 Linux 底层 `_selector.py` 使用 `selectors.EpollSelector` 实现事件循环：

```python
import asyncio

async def handle(reader, writer):
    data = await reader.read(100)         # 挂起，等 epoll 通知可读
    print(f"收到: {data.decode()}")
    writer.write(data)
    await writer.drain()                  # 等待可写
    writer.close()

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 8080)
    async with server:
        await server.serve_forever()      # 底层: epoll_wait 循环

asyncio.run(main())
```

`await reader.read()` 的语义：read 无数据时协程挂起，事件循环把该协程注册进 epoll；当 `epoll_wait` 返回该 fd 可读，再恢复相应协程。**协程 + epoll 的组合**正是 Python 单进程承接上万连接的原理。同样，Go 的 netpoller、Node.js 的 libuv，在 Linux 上都以 epoll 为底座——这是"语言不同、底座相同"的典型例子。

### 4.3 压测与状态观测

```bash
# 观察连接状态分布
$ ss -tan state established | wc -l
$ ss -tan state time-wait | wc -l
$ ss -tan state close-wait | wc -l

# 压测：100 并发 × 10000 请求
$ ab -n 10000 -c 100 http://127.0.0.1:8080/
# 或 wrk
$ wrk -t4 -c1000 -d10s http://127.0.0.1:8080/
```

`ss -tan` 的状态分布是体检表：`CLOSE_WAIT` 大量堆积 = 服务端漏 close；`TIME_WAIT` 飙升 = 大量短连接主动关闭方；`SYN_SENT` 大量 = 连接建立异常或遭扫描。

### 4.4 用 perf 验证 epoll 的 O(1) 行为

```bash
# 对比不同连接规模下的 spend
$ perf stat -e syscalls:sys_enter_epoll_wait syscalls:sys_enter_epoll_ctl ./echoserver
```

在 100 与 10000 连接下，若 epoll 每轮 `epoll_wait` 只返回就绪 fd，则 syscall 次数不随连接规模线性增长——这就是 O(1) 的实证。而 select 实现会呈现明显的线性上升，两份数据放一起即是对"演进合理性"的最好解释。

---

## 5. 常见坑与避坑指南

### 坑 1：epoll 惊群（Thundering Herd）

**症状**：多进程/多线程都 `epoll_wait` 监听同一 listenfd，一个新连接到达，**所有**等待者都被唤醒，但只有 1 个 accept 成功，其余空转（产生大量无谓调度）。

**根因**：Linux < 4.5 时，多个等待者对同一 fd 的事件会被全部唤醒（水平触发唤醒语义）。

**解决**：
- 现代 Linux 用 `EPOLLEXCLUSIVE` 标志，保证同一事件只唤醒其中一个等待者。
- nginx 的经典做法：worker 抢锁或 `SO_REUSEPORT` 让各 worker 分别 bind 同端口，内核负责分配连接。

```c
ev.events = EPOLLIN | EPOLLEXCLUSIVE;   /* 只唤醒一个 */
epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
```

### 坑 2：ET 模式漏事件

**症状**：ET 下偶发"数据到了但没被处理"、连接卡死、吞吐骤降。

**根因**：ET 每次只在边沿通知一次；若没在一次 `epoll_wait` 返回后把 fd 数据**全部读完（读到 EAGAIN）**，剩余数据不再触发通知。

**解决**：ET 下 read 必须循环到 `EAGAIN/EWOULDBLOCK` 为止；或者干脆用 LT（默认），代价只是多一点重复唤醒。**新手默认 LT**，追求极致性能且有纪律的团队再用 ET。

### 坑 3：文件描述符泄漏（fd leak → CLOSE_WAIT 堆积）

**症状**：`ss` 显示 CLOSE_WAIT 持续增长，`/proc/<pid>/fd` 数量爆涨，最终新连接耗光 fd（Too many open files）。

**根因**：对端 FIN 到达后，本端进入 CLOSE_WAIT，但代码没有对该连接 fd 执行 `close`/`epoll_ctl(DEL)`——通常是把"连接读取出错"的清理路径漏写了。

**解决**：读写返回 0 或出错必须唯一走"DEL + close"清理出口；用类封装 fd（RAII）；上线前用 `lsof -p` 与 `ss` 巡检 CLOSE_WAIT 基线。**每个 close 路径都要自测**。

### 坑 4：阻塞 accept 与 epoll 混用丢连接

**症状**：并发突刺时 accept 到一半卡住、后续事件不响应。

**根因**：listenfd 未设非阻塞，而 `accept` 阻塞等待；epoll_wait 返回"有连接"事件后，只 accept 一次就跳出，导致多个待处理连接排队并被后续事件饿死。

**解决**：listenfd 与连接 fd 都设 `O_NONBLOCK`；在事件处理里 `while ((cfd = accept(listenfd,...)) >= 0)` 取尽；对每个新 cfd 也设非阻塞并登记进 epoll。

### 坑 5：SO_LINGER=0 导致 RST 而非 FIN

**症状**：主动 close 的客户端"以为正常关闭"，服务端却收到 RST，数据丢失。

**根因**：`SO_LINGER` 置 `(on=1, linger=0)` 时 close 直接发 RST 而非优雅 FIN；未发完的数据被丢弃。此选项常被误用于"解决 TIME_WAIT"。

**解决**：不要为了消 TIME_WAIT 而乱开 LINGER=0；优雅关闭用默认 FIN 语义，TIME_WAIT 是正常的协议退出成本。若确需"秒关"，也要接受丢尾部数据的风险。

### 坑 6：Nagle 与延迟 ACK 叠加导致的交互延迟

**症状**：交互型应用（小包来回）延迟突然涨几十毫秒，吞吐不高但延迟爆炸。

**根因**：Nagle（攒小包）与对端 delayed ACK（40ms）相互等待形成死锁状延迟——经典"Naggle + delayed ACK"陷阱。

**解决**：对交互请求（登录、命令、RPC）设置 `TCP_NODELAY` 关闭 Nagle；大的流式传输保留默认即可。

### 坑 7：iptables/firewalld 规则误伤本地 loopback

**症状**：本地服务间 AF_INET 通信被防火墙拦（连 127.0.0.1 也失败），`ss -tan` 显示 SYN_SENT 累积。

**根因**：防火墙规则覆盖了 loopback 接口。这也是很多人被误导去"调 TCP 参数"却无效的典型场景。

**解决**：同机通信优先用 AF_UNIX（不进 IP 栈、天然绕过 netfilter 的大部分路径）；若必须用 127.0.0.1，放行 `lo` 接口。排查时先 `iptables -L`/`nft list ruleset`。

---

## 6. 知识关联

- [[13-IO模型演进：select-poll-epoll-io_uring]]：本文是 epoll 层面的深入展开，与之构成"演进全景"，含 io_uring 对比。
- [[06-进程间通信：管道消息队列共享内存信号]]：AF_UNIX 与网络 Socket 同族，是本机高性能通信的兄弟篇。
- [[05-TCP状态机与TIME_WAIT调优]]：Socket 编程的 TCP 层基础，CLOSE_WAIT/TIME_WAIT 的技术依托。
- [[10-内核态用户态：特权级与模式切换]]：read/write/epoll 都经过内核态，理解模式切换成本。
- [[05-上下文切换：开销来源与实测分析]]：线程池模式因上下文切换无法支撑高并发，是 epoll 存在的根本动机。
- [[08-同步原语：互斥锁自旋锁信号量条件变量]]：多线程/多进程共享 accept 与连接处理时的锁同步与惊群治理。
- [[04-协程原理：用户态调度与栈管理]]：协程 + epoll 是现代高并发（Go/Node/asyncio）的两大支柱。

---

## 7. 参考资料

1. Stevens, W. R., Fenner, B., Rudoff, A. M. *UNIX Network Programming, Vol. 1*, 3rd ed., Addison-Wesley, 2003. — Socket API 权威。
2. RFC 793 — *Transmission Control Protocol*, IETF, 1981. — TCP 状态机与 11 状态。
3. Kerrisk, M. *The Linux Programming Interface*, No Starch Press, 2010. — epoll、socket、inet 章节。
4. Linux man-pages：`socket(2)`, `bind(2)`, `listen(2)`, `accept(2)`, `connect(2)`, `epoll_create(2)`, `epoll_ctl(2)`, `epoll_wait(2)`, `SO_REUSEPORT(7)`, `tcp(7)`, `unix(7)`, `ss(8)`, `ab(1)`, `wrk(1)`.
5. Linux 内核源码：`fs/eventpoll.c`（epoll 实现）、`net/ipv4/tcp.c`、`net/unix/af_unix.c`.
6. nginx 源码：`src/event/modules/ngx_epoll_module.c`（EPOLLEXCLUSIVE、ET 用法）。
7. Redis 源码：`src/ae_epoll.c`.
8. Axboe, J. "io_uring and networking"（io_uring 作者系列博客）。— io_uring 机制与 epoll 对比。
9. Silberschatz, A. et al. *Operating System Concepts*, 10th ed., Wiley, 2018. — IO 系统与并发服务器章节。