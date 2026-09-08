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
| 常见风险 | 惊群、ET 漏事件、fd 泄漏、TIME_WAIT 堆积、iptables 误伤 AIO |
| 关联知识 | [[13-IO模型演进：select-poll-epoll-io_uring]]、[[06-进程间通信：管道消息队列共享内存信号]]、[[05-TCP状态机与TIME_WAIT调优]] |

---

## 1. 概述

**Socket（套接字）** 是操作系统向应用层提供的网络通信抽象。它的核心设计哲学是 **"一切皆文件"（Everything is a File）**：在网络通信中，每个连接端点都是一个文件描述符（file descriptor, fd），可以用 `read`/`write`/`close` 等统一文件 IO 接口操作，只是底层由网络协议栈（TCP/UDP/IP）驱动，而不是磁盘驱动。

一个典型的服务端 TCP Socket 生命周期：

```text
socket() ──▶ bind() ──▶ listen() ──▶ accept() ──▶ read()/write() ──▶ close()
   创建端点    绑定地址     开始监听    接受连接      数据交换        释放
                (IP:port)    (backlog)  (返回新fd)
```

Socket 每次 accept 返回一个新的 fd 代表已建立连接，与监听的 `listenfd` 相互独立。一个进程可以持有成百上千个连接 fd，这正是高性能并发服务器的前提。

**epoll** 诞生于 Linux 2.6，是 `select`/`poll` 之后第三代 IO 多路复用机制。它解决了两大历史痛点：

1. `select` 的 fd 上限 `FD_SETSIZE=1024`，且每次都要线性扫描全量集合；
2. `select`/`poll` 每次调用都要把整个 fd 集合从用户态拷贝到内核态，O(n) 复杂度随连接数线性膨胀。

epoll 用 **红黑树 + 就绪链表 + mmap** 实现了 O(1) 的就绪检测，成为 Linux 高并发服务器的基石。nginx、Redis、libevent、Node.js 的底层循环、很多网关都用它。

本节作为 [[13-IO模型演进：select-poll-epoll-io_uring]] 的姊妹篇，重点深入 Socket 抽象、TCP 状态映射、以及 epoll 的内核实现细节。

---

## 2. 核心原理

### 2.1 Socket 抽象与"一切皆文件"

Unix 把 I/O 设备抽象为文件描述符。Socket 同样如此：内核中 `struct socket → struct sock` 对应一个通信端点，用户态通过 int fd 引用它。所有 fd 共享统一的 file 操作接口：

| 操作 | 含义 |
|------|------|
| socket(AF_INET, SOCK_STREAM, 0) | 创建 fd，AF=地址族，type=流/报 |
| bind(fd, &sockaddr, len) | 绑定本地 IP:port |
| listen(fd, backlog) | 进入监听态，backlog 为排队连接数上限 |
| accept(fd, &cliaddr, &len) | 接受等待队列中的第一个连接，返回新 fd |
| connect(fd, &srvaddr, len) | 主动发起连接（客户端） |
| read/write/recv/send | 数据传输 |
| close(fd) | 关闭 fd（引用计数-1） |
| shutdown(fd, how) | 关闭某方向（半关闭） |

注意事项：backlog 在 Linux 中由 `net.core.somaxconn`（默认 4096）和 `net.ipv4.tcp_max_syn_backlog` 共同约束；`listen` 的 backlog 参数实际会被 clamp 到 somaxconn。

### 2.2 TCP 状态机与 Socket API 的映射

TCP 连接的有 11 个状态（RFC 793），它们与 socket API 调用关系如下：

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
- **ESTABLISHED**：三次握手完成，`accept()` 从 SYN 队列转移到 accept 队列后返回。
- **CLOSE_WAIT**：收到对端 FIN，但本端还没 `close()`——*进程没 close，fd 一直挂在 CLOSE_WAIT，是典型的 fd 泄漏症状*。
- **TIME_WAIT**：主动关闭方在收到 FIN 后停留 2×MSL（约 60 秒），用于处理最后一个 ACK 丢失与旧报文失效。详见 [[05-TCP状态机与TIME_WAIT调优]]。

### 2.3 阻塞 IO 与线程池的局限

默认情况下，`read`/`accept` 是阻塞的（blocking）：

- `read(fd, buf, n)`：若 fd 无数据，线程阻塞挂起，直到有数据来。
- `accept(listenfd, ...)`：若无新连接，阻塞直到有连接。

**"一连接一线程"（thread-per-connection）** 的模式在大并发下撑不住：

```text
连接数 1万  → 需要 1万 个线程  →  每个线程栈 8MB 虚拟内存  →  内存爆炸
                                  →  海量线程上下文切换（见 05-上下文切换）
                                  →  cache 污染、调度风暴
```

这正是"阻塞 + 线程池"无法支撑高并发的根本原因：内存与上下文切换开销随连接数线性增长。解决方案是把 IO 从"一个线程管一个连接"改为"一个线程管所有连接"，即 IO 多路复用。

### 2.4 非阻塞 IO：EAGAIN 与 EWOULDBLOCK

用 `fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)` 把 fd 设成非阻塞：

- `read`/`accept` 若没有数据/连接，**立即返回 -1**，`errno` 设为 `EAGAIN`（在 POSIX 上 `EWOULDBLOCK` 与 `EAGAIN` 同值）。
- 程序通过"这次是否 EAGAIN"来判断"现在没东西可读，下次再来"，从而实现不阻塞的轮询。

```c
int flags = fcntl(fd, F_GETFL, 0);
fcntl(fd, F_SETFL, flags | O_NONBLOCK);
ssize_t n = read(fd, buf, sizeof(buf));
if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    /* 现在没数据，稍后再读 */
}
```

非阻塞只是"轮询的基础"，如果程序自己去 while 循环 EAGAIN 重试，就是忙轮询（busy polling），CPU 被白白空转。所以非阻塞 fd 必须配合**事件通知**机制（select/poll/epoll）来告诉我们"什么时候去读"，这就是 IO 多路复用的意义。

---

## 3. 详细知识点

### 3.1 select → poll → epoll 的演进

| 维度 | select | poll | epoll |
|------|--------|------|-------|
| fd 上限 | FD_SETSIZE=1024（编译期固定） | 无上限 | 无上限 |
| 集合表示 | fd_set 位图 | pollfd 数组 | 内核维护 |
| 每次调用拷贝 | 全量 fd_set（用户↔内核） | 全量 pollfd 数组 | 只增删改单个 fd |
| 就绪检测 | 线性扫描全部 | 线性扫描全部 | 红黑树+就绪链表，O(1) |
| 就绪结果 | 需自行 bit 遍历 | 需遍历 revents | 直接返回就绪 fd |
| 阻塞 | 每次调用都阻塞 | 每次调用都阻塞 | 首次可阻塞，之后增量 |

```c
/* select：每次要把整个 fd_set 传入 */
fd_set rset;
FD_ZERO(&rset);
FD_SET(listenfd, &rset);
select(listenfd + 1, &rset, NULL, NULL, &tv);
/* 之后要逐个 FD_ISSET 检查 */
```

select 的内核实现 `do_select()` 每次都要把集合从用户态 copy 进来、遍历所有 fd 调用 poll 回调，O(n)；且 FD_SETSIZE 1024 固定，无法突破。

### 3.2 epoll 使用三部曲

```c
#include <sys/epoll.h>

/* 1. 创建 epoll 实例（返回 epfd） */
int epfd = epoll_create(1024);   /* 参数在新内核已忽略，>0 即可 */

/* 2. 登记/修改/删除关注的事件 */
struct epoll_event ev;
ev.events = EPOLLIN;             /* 感兴趣的事件 */
ev.data.fd = fd;                 /* 用户数据：通常是 fd，可以是任意 */
epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);   /* ADD/MOD/DEL */

/* 3. 等待就绪事件 */
struct epoll_event events[128];
int n = epoll_wait(epfd, events, 128, -1);   /* -1 永久阻塞 */
for (int i = 0; i < n; i++) {
    if (events[i].events & EPOLLIN) {
        int ready_fd = events[i].data.fd;
        /* 处理 ready_fd 的可读/可写 */
    }
}
```

关键概念：

- **就绪事件 vs 全量事件**：`epoll_wait` 只返回**有数据/可写的 fd**（就绪事件），不需要应用的 N 个 fd 都被拷贝进内核。
- **LT（Level Triggered，水平触发）**（默认）：只要 fd 还有可读数据，`epoll_wait` 就会重复返回它。可以不分批读完。
- **ET（Edge Triggered，边缘触发）**：只在状态从"无→有"的**跳变沿**通知一次；要求一次性把数据读完（读 EAGAIN 为止），否则剩余数据"卡住"不再通知。ET 模式更高效（避免重复唤醒），但要求编程严格。

ET vs LT 示意图：

```text
LT 模式：fd 有数据就一直上报
    数据到达 ──▶ [有数据] ─▶ epoll_wait 返回
                ─▶ 未读完，下次 epoll_wait 仍返回  ← 重复唤醒
ET 模式：只在边沿上报一次
    数据到达 ──▶ [跳变沿] ─▶ epoll_wait 返回一次
                ─▶ 未读完 ╳ 不再上报  ← 必须一次读尽（读 EAGAIN）
```

### 3.3 epoll 内部实现：红黑树 + 就绪链表 + mmap

epoll 在内核中（`fs/eventpoll.c`）有两个核心数据结构：

1. **红黑树（rbtree）**：存所有被 `epoll_ctl` 登记监视的 fd。为 O(log n) 的增删改提供支撑，避免每次检查全量集合。
2. **就绪链表（rdllist）**：存"当前有事件"的 fd。事件发生（数据到达）时，驱动（如网络协议栈 tcp 层）回调 `ep_poll_callback` 把 fd 加入链表；`epoll_wait` 只取链表头部就绪项，O(1)。
3. **eventpoll 对象**：`ep_create` 创建的匿名 fd（通过 `anon_inode_getfd`），也就是 epfd。

```text
        用户态 epoll_ctl(ADD/MOD/DEL)
        ──────────────────────────▶
        │
        ▼
   ┌───────────────────────────────┐
   │  内核 eventpoll 对象 (epfd)     │
   │                              │
   │  红黑树 rbtree                │   就绪链表 rdllist
   │  ┌────┐ ┌────┐              │   ┌────┐ ┌────┐
   │  │fd1 │ │fd2 │ ◀──ep_ctl     │   │fd3 │ │fd5 │ ←有事件的
   │  │item│ │item│               │   │    │ │    │
   │  └────┘ └────┘              │   └────┘ └────┘
   │  (所有被监视的fd)             │   (就绪等待epoll_wait取)
   └───────────────────────────────┘
        │            ▲
        │ 数据到达     │ ep_poll_callback
        ▼            │
   ┌───────────────────────────────┐
   │  网络协议栈（tcp/udp）          │
   │  数据就绪 → 回调通知 epoll      │
   └───────────────────────────────┘
```

**mmap 的应用**：epoll 的 `struct epoll_event` 就绪数组通过 `mmap` 映射到用户态（`epoll_wait` 返回就绪项），避免内核→用户态的一次复制。这也是 epoll 高效的原因之一（虽然现代 Linux 对就绪 fd 的拷贝已很小）。

### 3.4 epoll 事件类型

| 事件 | 含义 |
|------|------|
| EPOLLIN | 可读（有数据 / 对端关闭 / 新连接 accept） |
| EPOLLOUT | 可写（发送缓冲有空间） |
| EPOLLERR | 出错 |
| EPOLLHUP | 挂断（对端关闭） |
| EPOLLRDHUP | 对端关闭写端（半关闭，Linux 2.6.17+） |
| EPOLLET | 边缘触发 |
| EPOLLONESHOT | 一次性触发，事件后自动从集合移除 |
| EPOLLEXCLUSIVE | 惊群缓解：只唤醒一个等待者 |

### 3.5 epoll 与 nginx / redis / libevent 的关系

- **nginx**：单进程（worker）用 epoll 驱动事件循环，管理大量连接；EPOLLET + 非阻塞 IO + 各 worker 监听同一 listenfd。
- **redis**：单线程事件循环基于 `ae.c`，底层在 Linux 用 epoll（`ae_epoll.c`），处理 socket 的命令请求。
- **libevent / libev**：跨平台事件库，Linux 后端用 epoll，包装成统一 API，屏蔽 ET/LT 差异。

它们都遵循 **事件循环（event loop）** 模式：

```text
while (1) {
    int n = epoll_wait(epfd, events, N, timeout);
    for (i in 0..n)  handle(events[i]);   /* 分发回调 */
}
```

### 3.6 io_uring 简介（下一代 IO）

**io_uring**（Linux 5.1+）是内核为高性能 IO 推出的新一代异步机制：

- **SQ（Submission Queue，提交队列）与 CQ（Completion Queue，完成队列）**：设计为无锁 ring buffer，与应用直接共享（mmap），提交/完成都不进 syscall。
- **异步批处理 + 零拷贝**：把 syscall 开销降到接近零，支持 `splice`/`sendfile` 等零拷贝路径。
- **与 epoll 对比**：epoll 仍是"事件通知"，真正 read/write 还是要 syscall；io_uring 把提交和完成都异步化、批量化，减少内核态切换与拷贝。详见 [[13-IO模型演进：select-poll-epoll-io_uring]]。

```text
epoll 模式：  epoll_wait(通知) → read(数据，syscall) → write(数据，syscall)
io_uring：    SQ 提交 [read, write] → 内核异步执行 → CQ 返回结果
              （无逐次 syscall，批量异步）
```

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

要点：listenfd 与连接 fd 都在 epoll 中管理；用非阻塞 accept（while 循环取尽所有新连接）是避免"误触"丢连接的标准做法。

### 4.2 Python asyncio 底层原理：事件循环

Python 的 `asyncio` 在 Linux 底层 `_selector.py` 用 `selectors.DefaultSelector()`（Linux 为 `EpollSelector`）实现事件循环：

```python
import asyncio

async def handle(reader, writer):
    data = await reader.read(100)         # 挂起，等 epoll 通知可读
    print(f"收到: {data.decode()}")
    writer.write(data)                    # 回显
    await writer.drain()                  # 等待可写
    writer.close()

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 8080)
    async with server:
        await server.serve_forever()      # 底层: epoll_wait 循环

asyncio.run(main())
```

`await reader.read()` 的语义：read 无数据时协程挂起，事件循环把该协程注册进 epoll；当 `epoll_wait` 返回该 fd 可读，再恢复相应协程。**协程 + epoll 的组合**正是因为底层还是 epoll，才使得 Python 一个进程能承接上万连接。

### 4.3 高并发连接测试：`ab` / `wrk` / `netstat`

```bash
# 观察 TIME_WAIT / ESTABLISHED / CLOSE_WAIT 分布
$ ss -tan state established | wc -l
$ ss -tan state time-wait | wc -l
$ ss -tan state close-wait | wc -l

# 压测：100 并发 × 10000 请求
$ ab -n 10000 -c 100 http://127.0.0.1:8080/
# 或用 wrk
$ wrk -t4 -c1000 -d10s http://127.0.0.1:8080/
```

`ss -tan` 看状态分布，`CLOSE_WAIT` 大量堆积=代码没 close，是最常见的服务端 fd 泄漏信号。

---

## 5. 常见坑与避坑指南

### 坑 1：epoll 惊群（Thundering Herd）

**症状**：多进程/多线程都 `epoll_wait` 监听同一 listenfd，一个新连接到达，**所有**进程都被唤醒，但只有 1 个能 accept 成功，其余空转。

**根因**：Linux < 4.5 时，多个进程对同一 fd 的 epoll_wait 在事件到来时会被全部唤醒（level-triggered wakeup）。

**解决**：
- 现代 Linux 用 `EPOLLEXCLUSIVE`（2.6.28+）标志，保证只唤醒一个等待者。
- nginx 的做法：只有 master 或特定 worker 持锁 accept，或用 `SO_REUSEPORT` 让各 worker 分别监听同端口。

```c
ev.events = EPOLLIN | EPOLLEXCLUSIVE;   /* 只唤醒一个 */
epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
```

### 坑 2：ET 模式漏事件

**症状**：ET 下偶发"数据到了但没被处理"、连接卡死。

**根因**：ET 只通知一次；若没在一次 `epoll_wait` 返回后把 fd 的可读数据**全部读完（到 EAGAIN）**，剩余数据不再触发。

**解决**：ET 下 read 必须循环到 `EAGAIN/EWOULDBLOCK` 才停；或者干脆用 LT 模式（更省心，只是唤醒多一点）。连接多而事件稀疏时，优先 LT；追求极致性能且能严格编程，再考虑 ET。

### 坑 3：文件描述符泄漏（fd leak，CLOSE_WAIT 堆积）

**症状**：`ss` 显示 CLOSE_WAIT 不断增长，`/proc/<pid>/fd` 里 fd 数爆涨，最终客户端连接失败。

**根因**：对端 close 后（FIN），本端进了 CLOSE_WAIT，但代码没对连接 fd 执行 `close`/`epoll_ctl(DEL)`。

**解决**：每次 read 返回 0 或错误时必须 `epoll_ctl(EPOLL_CTL_DEL)` + `close(fd)`；用 RAII/析构自动 close；监控服务端 CLOSE_WAIT 数量。整个事件循环的 fd 生命周期要严谨管理。

### 坑 4：SO_REUSEADDR / TIME_WAIT 调优过度

**症状**：服务端口被 TIME_WAIT 占满导致 bind 失败，或无脑开 SO_REUSEPORT 引发问题。

**解决**：服务端 `SO_REUSEADDR` 允许快速重启；高并发短连接下 TIME_WAIT 正常，别盲目调 `tcp_tw_reuse`（会破坏连接语义）；合理复用长连接减少 TIME_WAIT。详见 [[05-TCP状态机与TIME_WAIT调优]]。

### 坑 5：阻塞 accept 与 epoll 混用的数据丢失

**症状**：某些连接 accept 不到，或 accept 返回但不完整。

**根因**：用阻塞的 `accept` 搭配非阻塞 fd；或一个 `epoll_wait` 回来只 accept 一个连接（accept 是阻塞的会卡住后续事件）。

**解决**：将 listenfd 设为**非阻塞**，并在 epoll_wait 返回后在循环里 `while ((cfd = accept(listenfd,NULL,NULL)) >= 0)` 取尽所有新连接；对每个 cfd 也设非阻塞。

---

## 6. 知识关联

- [[13-IO模型演进：select-poll-epoll-io_uring]]：本文是该主题在 epoll 层面的深入展开，与之配合掌握完整的 IO 模型演进与 io_uring 对比。
- [[06-进程间通信：管道消息队列共享内存信号]]：AF_UNIX 与网络 Socket 同族，构成同机/跨机完整通信图谱。
- [[05-TCP状态机与TIME_WAIT调优]]：Socket 编程的 TCP 层基础，处理 TIME_WAIT/CLOSE_WAIT。
- [[10-内核态用户态：特权级与模式切换]]：read/write/epoll 都经过内核态，理解切换成本。
- [[05-上下文切换：开销来源与实测分析]]：线程池模式因上下文切换无法支撑高并发，是 epoll 存在的根本动机。
- [[08-同步原语：互斥锁自旋锁信号量条件变量]]：多线程/多进程共享 accept 与连接处理时的锁同步。
- [[04-协程原理：用户态调度与栈管理]]：协程 + epoll 是现代高并发（Node/Go/asyncio）的两大支柱。

---

## 7. 参考资料

1. Stevens, W. R., Fenner, B., Rudoff, A. M. *UNIX Network Programming, Vol. 1: The Sockets Networking API*, 3rd ed., Addison-Wesley, 2003. — Socket API 权威。
2. RFC 793 — *Transmission Control Protocol*, IETF, 1981. — TCP 状态机与 11 状态。
3. Kerrisk, M. *The Linux Programming Interface*, No Starch Press, 2010. — epoll、socket、inetaddr 章节。
4. Linux man-pages：`socket(2)`, `bind(2)`, `listen(2)`, `accept(2)`, `connect(2)`, `epoll_create(2)`, `epoll_ctl(2)`, `epoll_wait(2)`, `SO_REUSEPORT(7)`, `unix(7)`, `ss(8)`.
5. Linux 内核源码：`fs/eventpoll.c`（epoll 实现）、`net/ipv4/tcp.c`, `net/unix/af_unix.c`.
6. nginx 官方文档与源码：`src/event/modules/ngx_epoll_module.c`.
7. Redis 源码：`src/ae_epoll.c`.
8. Axboe, J. "io_uring and networking in 2023"（io_uring 作者博客）及 `include/uapi/linux/io_uring.h`. — io_uring 机制说明。
9. Silberschatz, A. et al. *Operating System Concepts*, 10th ed., Wiley, 2018. — IO 系统与并发服务器章节。
