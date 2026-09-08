---
title: "目录结构与FHS规范：一切皆文件"
category: "00-基础通用/05-Linux系统与命令"
tags: [Linux, FHS, 目录结构, 文件系统, 挂载]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# 目录结构与FHS规范：一切皆文件

> 本文内容聚焦 Linux 系统的合法系统管理与运维实践，包括目录结构、文件系统层次标准(FHS)、挂载与文件抽象机制等常规系统管理知识，属于操作系统学科的通用内容，未涉及任何攻击性技术。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 目录是文件名到 inode 的映射表；FHS即Filesystem Hierarchy Standard，规定 Linux 系统根目录下各级目录的用途与内容的规范标准 |
| 核心用途 | 统一各发行版目录布局、便于软件打包与多用户协作、规定可共享与不可共享、可变与静态数据的存放位置、理解系统启动与排障 |
| 关键参数 | 根目录 `/`、挂载点、chroot、`/etc` 配置、`/var` 可变数据、`/proc` 与 `/sys` 虚拟文件系统、rpath 与可执行文件搜索路径 |
| 常见风险 | 挂载点权限滥用、`/tmp` 目录竞态、`/proc` 信息泄露、`noexec` 配置不当、绑定挂载与 chroot 逃逸、硬链接计数困惑 |
| 关联知识 | [[14-文件系统原理：inode目录项与日志机制]]、[[06-权限体系：rwx-ACL-setuid-capabilities]] |

## 1. 概述

"一切皆文件"(Everything is a file)是 Unix/Linux 设计的核心哲学之一。它指的是：在 Linux 中，普通文件、目录、设备、管道、socket、进程信息、系统状态等几乎一切实体，都被抽象为"文件"这一统一接口，通过统一的`open/read/write/close`等系统调用进行访问。这一抽象极大简化了编程模型，也让各种命令可以统一地作用于不同的对象之上。

而"目录结构与FHS规范"则回答"文件放在哪里"的问题。FHS(Filesystem Hierarchy Standard)由 Linux Foundation 维护，规定了根目录下各目录的用途、内容与命名，目标是保证不同发行版之间目录布局的一致性，从而让软件能够跨发行版安装与运行，也让运维人员熟悉不同系统上的文件位置。

需要区分两件事：
- **"一切皆文件"**是内核提供的抽象机制（VFS 虚拟文件系统 + 各种特殊文件系统）。
- **FHS** 是用户空间约定的目录布局规范（纯约定，不强制）。

理解目录结构不仅是系统管理员的入门课，更是安全分析的基础——恶意软件常把自己藏在`/tmp`、`/dev/shm`、`/var/tmp`等目录；被植入的后门常替换或新增`/usr/bin`下的可执行文件；特权升级路径往往依赖挂载点权限或 setuid 文件。因此下文会大量结合安全视角来分析每个目录。

## 2. 核心原理

### 2.1 目录的本质：文件名到 inode 的映射表

在 Linux 中，目录本身也是一种"文件"，不过它的内容是"条目(entry)"的列表。每个条目记录了两部分信息：**文件名**与 **inode 编号**。真正的文件数据（权限、所有者、数据块位置）存储在 inode 中。

```
目录 /home 的内容（概念示意）
+--------------+----------------+
|  文件名       |  inode号        |
+--------------+----------------+
|      .       |      2         |
|      ..      |      1         |
|     alice    |   23654        |
|     bob      |   23877        |
+--------------+----------------+
```

- `.` 指当前目录自身，`..` 指父目录。
- inode 号是文件系统内的唯一编号；通过 inode 找到对应的 inode 结构，即可读取文件的元数据与数据块。
- 多个文件名可以指向同一个 inode，这就是"硬链接(hard link)"。硬链接本质是目录中的多个条目公用一个 inode。

### 2.2 挂载：把文件系统"接"进目录树

"一切皆文件"的物理载体是文件系统。内核通过**挂载(mount)**操作，把一块逻辑卷（磁盘分区、CD、网络文件系统等）挂载到目录树的某个挂载点上，从而让该文件系统的内容在该目录下可见。

```
+--------------------------------------------------+
|              目录树（单一根）                        |
|  /（根文件系统）                                   |
|    +-- /etc                                     |
|    +-- /home  <---- 挂载点，挂载了独立的 home 分区  |
|    +-- /proc  <---- 挂载点，挂载了 procfs 虚拟系统  |
|    +-- /tmp                                     |
+--------------------------------------------------+
```

- 挂载前目录下原有的内容会被"遮蔽(hidden)"。
- 挂载点本身可以是任何目录，但规范约定使用空目录。
- 支持 `bind` 绑定挂载（把某目录再挂到另一处）与 `mount --move` 移动挂载。

### 2.3 虚拟文件系统与"一切皆文件"

用户看到的"文件"分两类：
- **真实文件系统**：ext4、xfs、btrfs、ntfs 等，数据落盘。
- **虚拟文件系统**：proc、sysfs、tmpfs、devtmpfs、cgroup 等，数据由内核动态生成，不落盘，但通过文件接口暴露。

`/proc` 与 `/sys` 是"一切皆文件"哲学的典型代表——进程信息、CPU 信息、内核参数都以文件形式暴露，可以用`cat`直接读取，用`echo`写入修改。

## 3. 详细知识点

### 3.1 FHS 规定的核心目录速览

| 目录 | 用途 | 文件类型/示例 | 是否允许卸载 |
|------|------|---------------|--------------|
| `/` | 根，所有文件的起点 | 根文件系统本身 | 否 |
| `/bin` | 基本用户命令（单用户模式也需） | `ls, cp, mv, bash` | 可与/usr 合并 |
| `/sbin` | 系统管理命令 | `mount, fdisk, reboot` | 可与/usr 合并 |
| `/usr/bin` | 大部分用户命令 | 各种软件二进制 | 与 / 分开的独立分区 |
| `/usr/sbin` | 非关键系统命令 | `httpd 的管理工具` | 同上 |
| `/usr/local` | 系统管理员本地安装的软件 | `/usr/local/bin` 等 | 是 |
| `/etc` | 主机特定的配置文件 | `passwd, fstab, sshd_config` | 否 |
| `/home` | 用户主目录 | `/home/alice` | 是 |
| `/root` | root 用户主目录 | 只有 root 可读 | 否 |
| `/var` | 可变数据（运行时产生的） | 日志、缓存、邮件、锁文件 | 是 |
| `/tmp` | 临时文件 | 系统重启可能被清空 | 否（通常是 tmpfs） |
| `/proc` | 进程与内核信息（虚拟） | `cpuinfo, meminfo, pid/` | 虚拟 |
| `/sys` | 设备、驱动、内核参数（虚拟） | `class/, block/` | 虚拟 |
| `/dev` | 设备文件 | 块设备、字符设备 | 是（devtmpfs） |
| `/run` | 系统运行时信息（tmpfs） | pid 文件、socket | 虚拟/tmpfs |
| `/boot` | 内核与引导加载程序文件 | `vmlinuz-*, grub2/` | 是 |
| `/mnt` | 临时挂载点 | 通常为空 | 是 |
| `/media` | 可移动介质自动挂载点 | `/media/cdrom` | 是 |
| `/opt` | 第三方/可选软件包 | `/opt/xxx` | 是 |
| `/srv` | 系统服务的服务数据 | web/ftp 数据 | 是 |

### 3.2 /bin、/sbin、/usr/bin、/usr/local/bin 的区别

这是一个经典困惑点。历史上有 `/usr` 独立分区、`/` 分区很小的做法，因此出现分工。现代发行版（Fedora、Ubuntu、Debian）普遍做了 `/usr` 合并（usrmerge），`/bin`、`/sbin` 成为指向 `/usr/bin`、`/usr/sbin` 的符号链接。

从安全视角关注：
- PATH 顺序决定优先执行哪个同名命令。如果 PATH 中用户可控的目录（如`.`或`~/bin`）排在系统目录之前，攻击者可能放置同名木马导致命令劫持。应检查系统 PATH。
- `/usr/local/bin` 优先级常高于 `/usr/bin`，被入侵后攻击者常把恶意二进制丢进`/usr/local/bin`伪装成后门。

### 3.3 /etc 配置文件

`/etc` 存放主机特定配置。关键文件包括：

| 文件 | 用途 |
|------|------|
| `/etc/passwd` | 用户账户信息（现代系统不存密码，密码在 shadow） |
| `/etc/shadow` | 加密后的密码哈希与策略 |
| `/etc/group` | 组信息 |
| `/etc/fstab` | 开机自动挂载表 |
| `/etc/hosts` | 静态主机名解析 |
| `/etc/resolv.conf` | DNS 服务器配置 |
| `/etc/ssh/sshd_config` | SSH 服务端配置 |
| `/etc/sudoers` | sudo 授权规则 |
| `/etc/crontab` | 周期性任务 |
| `/etc/systemd/system/` | 用户/自定义 systemd 单元 |

安全提示：`/etc/passwd` 必须是世界可读（getent 需要），但真实密码哈希在`/etc/shadow`（仅 root 可读）。如果发现 `/etc/shadow` 能被普通用户读取，属于严重配置错误。

### 3.4 /proc 虚拟文件系统

`/proc` 挂载了 procfs，以文件形式暴露内核运行时信息。

```
/proc/<pid>/        每个运行中进程一个目录
/proc/<pid>/cmdline 进程启动命令行（以 \0 分隔）
/proc/<pid>/environ 进程环境变量
/proc/<pid>/status  进程状态、内存、权限（含uid/gid）
/proc/<pid>/fd/     进程打开的文件描述符符号链接
/proc/<pid>/maps    进程内存映射（对内存取证/ASLR分析重要）
/proc/<pid>/root    指向进程根目录（chroot 逃逸点）
/proc/cpuinfo       CPU 信息
/proc/meminfo       内存信息
/proc/loadavg       负载均值
/proc/sys/...       内核 tunable（可写，如禁用ASLR、IP转发）
```

安全视角：
- `/proc/<pid>/environ` 可能泄露进程环境变量中的敏感信息（如数据库密码、密钥），普通用户只能读自己的进程。
- `/proc/sys/kernel/randomize_va_space` 控制 ASLR，写入 0 可关闭（需权限）。
- `/proc/sys/net/ipv4/ip_forward` 控制 IP 转发，被攻陷主机常被打开以做横向代理。
- 从 `/proc/<pid>/root` 可以访问进程视角的根目录，这是检测 chroot/jail 逃逸的关键点。

### 3.5 /sys 与/设备 sysfs

`/sys` 挂载 sysfs，以层级目录结构反映内核抽象的设备模型（总线、驱动、设备），常与 `udev` 交互。

```
/sys/class/net/eth0/  以太网接口属性
/sys/block/sda/       块设备
/sys/devices/        设备树
```

`/dev` 使用 devtmpfs + udev 动态管理设备节点，例如 `/dev/sda`、`/dev/tty0`、`/dev/null`、`/dev/zero`、`/dev/random`、`/dev/urandom`。

安全提示：`/dev/shm`（临时共享内存，tmpfs）常在内存文件系统上，权限默认 1777，常被攻击者用作 payload 存放区（因为不落盘、避开 AV 扫描）。运维应关注 `/dev/shm` 的可执行权限配置。

### 3.6 chroot 与挂载边界

chroot 把进程的根目录更改为指定目录，常用于容器早期实现或隔离测试环境。**chroot 并不等同于安全隔离**：
- 如果 chroot 内还有 mount、mknod、ptrace 能力，或可用 open 祖先目录的 fd，可能逃逸。
- 现代容器使用 namespaces + cgroups + capability 双层隔离，比 chroot 安全得多。

dangerous point：对挂载过来的目录若设置了 `exec`，则 /tmp 可执行;若关闭 `noexec`，则可执行。运维用 `mount -o noexec /tmp` 提高安全，但注意有些软件依赖 /tmp 执行。

### 3.7 /var 与日志

> `/var` 存放运行时可变数据，最典型的是日志。日志体系详细内容见 [[13-日志体系：syslog-journald-auditd配置]]。

```
/var/log/            日志目录
/var/log/messages    通用系统日志（部分发行版）
/var/log/secure      安全认证日志（RHEL系）
/var/log/auth.log    认证日志（Debian系）
```

"一切皆文件"体现在：日志文件可以被轮转(logrotate)、被 grep 检索、被 tail 跟踪，都是用文件机制统一处理。

## 4. 实战与示例

### 4.1 查看目录结构

```bash
# 查看根目录下的目录
ls -l /
# 递归查看一棵目录树（限制深度2，避免刷屏）
tree -L 2 /etc
# 只看目录
find / -maxdepth 1 -type d | sort
```

### 4.2 查看挂载点与文件系统

```bash
# 查看当前挂载表
mount
# 查看文件系统使用率
df -h
# 查看某路径所在文件系统类型
stat -f /etc
# 查看 inode 使用率
df -i
```

输出示例（`df -h`）：

```text
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2       120G   62G   52G  55% /
/dev/sda1       976M  180M  731M  21% /boot
tmpfs           7.7G     0  7.7G   0% /dev/shm
```

### 4.3 查看 inode 与硬链接

```bash
# 查看 inode 号与链接计数
ls -li /etc/passwd
stat /etc/hosts
# 创建硬链接
ln /tmp/a.txt /tmp/b.txt
ls -li /tmp/a.txt /tmp/b.txt   # 两个条目 inode 相同
```

### 4.4 新增挂载与绑定挂载

```bash
# bind 挂载：把某个目录再挂到另一处
mount --bind /home/alice /mnt/backup
# 重新挂载，去掉可执行权限（安全加固 /tmp）
mount -o remount,noexec /tmp
# 卸载
umount /mnt/backup
```

### 4.5 通过 /proc 排障

```bash
# 查看系统负载与内存
cat /proc/loadavg
cat /proc/meminfo
# 查看某进程命令行（PID 1234）
cat /proc/1234/cmdline | tr '\0' ' '
# 查看进程打开的文件
ls -l /proc/1234/fd/
# 查看内核 ASLR 设置（0=关闭,1=部分,2=完全）
cat /proc/sys/kernel/randomize_va_space
```

## 5. 常见坑与避坑指南

| 坑点 | 现象 | 原因 | 规避建议 |
|------|------|------|----------|
| 挂载点有旧内容 | 挂载后看不到旧文件 | 挂载会遮蔽原目录内容 | 挂载前清空目录，或用临时目录 |
| 误删整个文件系统 | `rm -rf /*` 灾难 | 未注意路径、变量为空时 `rm -rf $DIR/` | 绝不裸用 `rm -rf /`，先 `echo $DIR` 确认，用 `set -u` |
| `df -h` 显示空间满但实际没满 | 磁盘报满但删文件无效 | 进程仍持有已删除文件的 fd，空间未释放 | `lsof +L1` 找到并 kill 占用进程 |
| `ls -l` 权限 `d` 与 `-` 混淆 | 分不清文件与目录 | 第一个字符 d 表示目录 | 用 `stat` 或 `file` 确认 |
| inode 用尽 | `No space left on device` 但 df 正常 | 小文件过多耗尽 inode | `df -i` 检查，`find ... -delete` 清理 |
| PATH 被劫持 | 命令执行异常/木马 | PATH 含用户可控目录 | 固定 PATH，`command -v` 确认路径 |
| /tmp 可执行 | 攻击者可执行 payload | /tmp 未设 noexec | `mount -o noexec /tmp`（注意兼容性） |
| chroot 误当安全边界 | 认为 chroot 隔离了文件 | chroot 不隔离能力与 fd | 用容器/namespace，勿依赖 chroot 安全 |

## 6. 知识关联

- [[14-文件系统原理：inode目录项与日志机制]]：目录的本质、inode 与硬链接的底层机制
- [[13-日志体系：syslog-journald-auditd配置]]：/var/log 日志文件的管理与审计
- [[06-权限体系：rwx-ACL-setuid-capabilities]]：文件权限如何在目录结构中生效
- [[05-网络命令链：ip-ss-tcpdump-nmap排查实战]]：/proc 与 /sys 在网络排障中的配合
- [[15-内核内存管理：伙伴系统与slab分配器]]：从 `/proc/meminfo` 到内存子系统细节

## 7. 参考资料

- Filesystem Hierarchy Standard 官方文档:https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html（Linux Foundation）
- man 手册：`man hier`（Linux 目录层级说明）
- 《鸟哥的Linux私房菜 基础学习篇》（第三版），第 4 章 文件与目录管理、第 5 章 Linux 磁盘与文件系统管理
- CSAPP《深入理解计算机系统》第 10 章 系统级 I/O（"一切皆文件"的接口抽象）
- man 手册：`man 5 proc`（/proc 文件系统官方手册）
- man 手册：`man 8 mount`、`man 8 df`、`man 1 stat`
