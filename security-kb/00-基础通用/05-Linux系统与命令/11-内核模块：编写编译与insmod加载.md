---
title: "内核模块：编写编译与insmod加载"
category: "00-基础通用/05-Linux系统与命令"
tags: [内核模块, insmod, LKM, 驱动, Makefile, kernel, rootkit检测]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# 内核模块：编写编译与insmod加载

> 防御视角声明：本篇涉及的内核模块编程、insmod/rmmod加载卸载、内核符号导出等技术，仅用于合法的系统开发、驱动编写与安全防御研究（如LKM rootkit检测、内核完整性校验）。严禁用于未授权的内核篡改、后门植入或绕过安全机制。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | Loadable Kernel Module（LKM），可在运行时动态加载到内核地址空间的二进制代码段，与内核共享同一地址空间和特权级 |
| 核心用途 | 设备驱动开发、文件系统扩展、网络过滤钩子、安全监控（syscall hook检测）、内核调试探针 |
| 关键参数 | `insmod`（加载）、`rmmod`（卸载）、`lsmod`（列出）、`modprobe`（自动依赖加载）、`modinfo`（模块信息）、`/proc/modules` |
| 常见风险 | 内核崩溃（oops/panic）、内存泄露无法回收、符号冲突、rootkit持久化、模块签名绕过（需Secure Boot配合） |
| 关联知识 | [[06-权限体系：rwx-ACL-setuid-capabilities]]（capabilities与模块加载权限）、[[08-systemd：unit文件编写与服务管理]]（模块自动加载配置）、[[04-进程管理：ps-top-信号机制与nice]]（内核线程与模块进程关系） |

## 1. 概述

Linux内核采用单体内核（Monolithic Kernel）架构，但通过可加载内核模块（Loadable Kernel Module，LKM）机制实现了模块化的扩展能力。内核模块是可以在系统运行时动态加载到内核地址空间的共享代码，它与静态编译进内核镜像的代码拥有完全相同的特权级和内存访问权限——运行在Ring 0（x86_64上的最高特权级）。

LKM机制的核心价值在于：开发者无需重新编译和重启整个内核即可扩展功能。一个编写不当的模块可以瞬间导致内核崩溃（kernel panic），而一个恶意模块则可以完全控制系统——这使得内核模块开发既是系统编程的巅峰，也是安全攻防的核心战场。

从安全防御角度看，理解LKM机制是检测和防御rootkit的基础。攻击者常用的持久化手段之一就是编写内核模块实现syscall table hook、隐藏进程/文件、绕过SELinux/AppArmor等。防御者需要掌握模块签名验证、`/proc/modules`监控、`finit_module`系统调用审计等手段来建立纵深防御。

内核模块的生命周期由内核的模块加载子系统管理。当`insmod`用户态工具发起加载请求时，内核通过`sys_init_module`系统调用（或更新的`finit_module`）接收模块的ELF镜像，执行重定位、符号解析，然后调用模块注册的初始化函数完成注册。卸载时则调用清理函数并释放资源。

## 2. 核心原理

### 2.1 内核模块的ELF结构

内核模块本质上是一个经过特殊编译的ELF（Executable and Linkable Format）可重定位目标文件。与普通用户态共享库不同，模块文件使用`.ko`（Kernel Object）扩展名，其ELF结构包含以下关键节：

```text
$ modprobe --dump-modversions ./hello.ko
0x00000000  CRC32
0x00000001  vermagic

$ readelf -S hello.ko
Section Headers:
  [Nr] Name              Type            Address  Offset   Size
  [ 0]                   NULL            00000000 00000000 000000
  [ 1] .text             PROGBITS        00000000 00000040 000034
  [ 2] .rela.text        RELA            00000000 00000348 000018
  [ 3] .data             PROGBITS        00000000 00000074 000004
  [ 4] .bss              NOBITS          00000000 00000078 000004
  [ 5] .rodata           PROGBITS        00000000 0000007c 000010
  [ 6] .modinfo          PROGBITS        00000000 0000008c 000078
  [ 7] .exit.text        PROGBITS        00000000 00000104 00000e
  ...
```

`.modinfo`节存储模块的元数据（作者、许可证、vermagic版本匹配字符串等）；`.init.text`和`.exit.text`分别存储初始化和清理函数的代码。内核在加载时会将这些代码段映射到内核地址空间的`vmalloc`区域。

### 2.2 模块加载流程

当用户执行`insmod hello.ko`时，完整的调用链如下：

```text
用户态: insmod hello.ko
  -> open("hello.ko", O_RDONLY)  打开模块文件
  -> mmap()                       将文件映射到用户空间
  -> syscall(SYS_finit_module, fd, params, flags)
      或 SYS_init_module(uaddr, len, params)
内核态:
  -> finit_module()               系统调用入口
  -> load_module()                核心加载函数
     -> verify_elf()              验证ELF格式完整性
     -> sanity_check_modinfo()    检查模块元数据
     -> find_module()             检查是否已加载（同名去重）
     -> copy_module_from_user()   从用户空间拷贝模块镜像
     -> load_core()               加载核心ELF节
     -> parse_parms()             解析模块参数
     -> resolve_symbols()         解析外部内核符号引用
     -> relocate()                执行地址重定位
     -> complete_formation()      完成模块结构体初始化
     -> do_init_module()          调用 module_init() 注册的函数
  -> 模块注册成功，出现在 /proc/modules
```

### 2.3 符号导出与依赖

内核通过`EXPORT_SYMBOL`宏将函数和变量导出为全局符号，供其他模块使用：

```c
// 导出符号供所有模块使用（含GPL模块和非GPL模块）
EXPORT_SYMBOL(function_name);

// 仅导出给声明了GPL许可证的模块
EXPORT_SYMBOL_GPL(function_name);
```

`modprobe`工具在加载模块时会自动解析`/lib/modules/$(uname -r)/modules.dep`文件中的依赖关系链，递归加载所需依赖模块。而`insmod`是"裸"加载器，不会处理依赖，需要手动按顺序加载。

### 2.4 模块签名与Secure Boot

从Linux 4.5开始，内核支持模块签名验证（CONFIG_MODULE_SIG）。启用后，每个`.ko`文件必须包含有效的数字签名，否则拒绝加载：

```bash
# 检查模块是否已签名
$ modinfo hello.ko | grep signer
signer:         Build time asymptotic kernel signing key

# 检查内核是否启用模块签名强制
$ cat /proc/config.gz | gunzip | grep MODULE_SIG_FORCE
CONFIG_MODULE_SIG_FORCE=y
```

当Secure Boot启用时，模块签名链必须最终回溯到UEFI数据库中的信任根，否则`insmod`会返回`Operation not permitted`。

## 3. 详细知识点

### 3.1 最小内核模块的编写

一个最基本的内核模块只需要实现两个函数——初始化函数和清理函数：

```c
// hello.c - 最小内核模块示例
#include <linux/init.h>      // __init, __exit 宏
#include <linux/module.h>    // MODULE_LICENSE, module_init, module_exit
#include <linux/kernel.h>   // printk

// 模块初始化函数，insmod时调用
static int __init hello_init(void)
{
    printk(KERN_INFO "hello: module loaded, pid=%d\n", current->pid);
    return 0;  // 返回0表示成功，非0表示加载失败
}

// 模块清理函数，rmmod时调用
static void __exit hello_exit(void)
{
    printk(KERN_INFO "hello: module unloaded\n");
}

// 使用module_init/module_exit宏注册入口点
module_init(hello_init);
module_exit(hello_exit);

// 必须声明许可证，否则加载时产生WARNING
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Researcher");
MODULE_DESCRIPTION("Minimal kernel module example");
MODULE_VERSION("1.0");
```

关键细节：
- `__init`宏将初始化函数放入`.init.text`节，执行完毕后内核自动释放该段内存
- `__exit`宏标记清理函数，如果模块编译进内核（非LKM），该函数会被丢弃
- `MODULE_LICENSE("GPL")`是必要的，缺少它会导致`tainted kernel`标记，并且无法使用`EXPORT_SYMBOL_GPL`导出的符号
- `printk`使用内核日志级别（KERN_INFO对应数字6），可通过`dmesg`查看输出

### 3.2 Makefile编写规则

内核模块的编译依赖Kbuild系统（Kernel Build System），不能使用普通的gcc直接编译：

```makefile
# Makefile - 单模块编译（外置模块方式）
# 指向正在运行的内核源码树路径
KDIR ?= /lib/modules/$(shell uname -r)/build

# 当前源码目录
PWD := $(shell pwd)

# 默认目标
obj-m := hello.o

# 若模块由多个源文件组成（如 mymod 由 a.c 和 b.c 编译）
# obj-m := mymod.o
# mymod-objs := a.o b.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a
```

`obj-m`表示将`hello.c`编译为模块（`.m`是module的意思）。如果使用`obj-y`则表示编译进内核镜像。Kbuild系统会自动处理CFLAGS、依赖追踪、符号表生成等复杂工作。

对于多文件模块，需要先列出目标模块名，再用`xxx-objs`列出组成对象文件：

```makefile
# 多文件模块编译示例
obj-m := rootkit_detector.o
rootkit_detector-objs := detector.o net_filter.o proc_monitor.o
```

### 3.3 insmod/rmmod/modprobe命令详解

#### insmod - 手动加载模块

```bash
# 基本用法：加载模块
sudo insmod /path/to/hello.ko

# 带参数加载（模块必须声明module_param）
sudo insmod hello.ko verbose=1 threshold=100

# 查看加载结果
dmesg | tail -5
# [12345.678] hello: module loaded, pid=1234

# 查看模块是否在内核中
cat /proc/modules | grep hello
# hello 16384 0 - Live 0xffffffffc0a10000

# 查看模块详细信息
modinfo /path/to/hello.ko
# filename:       /path/to/hello.ko
# license:        GPL
# description:    Minimal kernel module example
# author:         Security Researcher
# vermagic:       5.15.0-generic SMP mod_unload
```

#### rmmod - 卸载模块

```bash
# 基本卸载（模块名不带.ko后缀）
sudo rmmod hello

# 强制卸载正在使用的模块（危险操作）
sudo rmmod -f hello

# 查看模块引用计数（为0才能安全卸载）
lsmod | grep hello
# hello    16384  0
#                       ^-- 引用计数为0
```

#### modprobe - 智能加载（推荐）

```bash
# 自动解析依赖并加载
sudo modprobe hello

# 卸载时自动清理依赖
sudo modprobe -r hello

# 查看模块依赖关系
modprobe --show-depends hello

# 黑名单禁止自动加载（写入配置文件）
echo "blacklist malicious_module" | sudo tee /etc/modprobe.d/blacklist.conf

# 强制禁用某个模块（即使被依赖也拒绝加载）
install bad_module /bin/false
```

### 3.4 模块参数机制

内核模块可以通过`module_param`宏接受用户态传入的参数，这是模块配置的重要机制：

```c
#include <linux/moduleparam.h>

static int threshold = 10;
module_param(threshold, int, 0644);
MODULE_PARM_DESC(threshold, "Detection threshold (default: 10)");

static char *action = "log";
module_param(action, charp, 0600);
MODULE_PARM_DESC(action, "Action on detection: log|block|alert");

static int modes[4] = {1, 2, 3, 4};
module_param_array(modes, int, NULL, 0644);
MODULE_PARM_DESC(modes, "Operating modes array");
```

参数权限位的含义：
- `0644`：所有者可读写，其他只读（可在`/sys/module/<name>/param/`中查看/修改）
- `0600`：仅所有者可读写
- `0444`：只读（加载后不可修改）
- `0000`：不暴露到sysfs（仅加载时指定）

```bash
# 加载时传参
sudo insmod hello.ko threshold=50 action="block"

# 运行时查看参数（如果权限允许）
cat /sys/module/hello/parameters/threshold
# 50

# 运行时修改参数（如果权限允许且模块处理了变更通知）
echo 100 > /sys/module/hello/parameters/threshold
```

### 3.5 内核模块的内存与地址

内核模块运行在内核地址空间，其内存布局与用户态程序截然不同：

```bash
# 查看已加载模块的内核地址
cat /proc/modules
# hello 16384 0 - Live 0xffffffffc0a10000
# nf_conntrack 176128 3 nf_nat,xt_conntrack,nf_conntrack, Live 0xffffffffc0700000

# 查看内核符号表（需要CONFIG_KALLSYMS=y）
cat /proc/kallsyms | grep hello_init
# ffffffffc0a10010 T hello_init  [hello]

# 查看模块内存使用
cat /sys/module/hello/sections/.text
# 0xffffffffc0a10000
```

模块使用`vmalloc`区域分配内存（不是`kmalloc`），这意味着：
- 模块的代码和静态数据在`vmalloc`区域，不与内核镜像共享地址空间
- 这也是为什么模块可以被卸载——卸载时整个`vmalloc`区域的映射可以被释放

### 3.6 模块安全加固技术

#### 3.6.1 模块签名验证

```bash
# 查看内核模块签名配置
grep MODULE_SIG /boot/config-$(uname -r)
# CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE=y
# CONFIG_MODULE_SIG_SHA256=y

# 生成自签名密钥对（用于私有模块签名）
openssl req -new -x509 -newkey rsa:2048 -keyout kernel_key.pem \
  -out kernel_cert.pem -days 365 -nodes \
  -subj "/CN=Module Signing Key/"

# 使用内核提供的签名工具（scripts/sign-file）
./scripts/sign-file sha256 kernel_key.pem kernel_cert.pem hello.ko
```

#### 3.6.2 模块加载审计

```bash
# 监控模块加载事件（通过auditd）
auditctl -w /usr/sbin/insmod -p x -k module_load
auditctl -w /usr/sbin/modprobe -p x -k module_load
auditctl -a always,exit -F arch=b64 -S init_module -k kernel_module
auditctl -a always,exit -F arch=b64 -S finit_module -k kernel_module

# 查询审计日志
ausearch -k module_load --start today
```

#### 3.6.3 sysctl加固参数

```bash
# 禁止未签名模块加载（与内核编译选项配合）
# 以下参数需在内核编译时启用 CONFIG_MODULE_SIG_FORCE

# 查看tainted kernel状态（非0表示加载了非GPL或第三方模块）
cat /proc/sys/kernel/tainted
# 0  -- 干净内核
# 1  -- 加载了非GPL模块
# 4096 -- 加载了外部模块

# 限制模块加载能力（通过capabilities）
# CAP_SYS_MODULE 是加载内核模块所需的capability
# 通常仅root拥有此capability，可通过secComp进一步限制
```

## 4. 实战与示例

### 4.1 实验一：从零构建并加载模块

```bash
# 步骤1：确认内核头文件已安装
dpkg -l | grep linux-headers-$(uname -r)   # Debian/Ubuntu
rpm -q kernel-devel-$(uname -r)             # RHEL/CentOS

# 步骤2：创建模块源码目录
mkdir -p ~/kernel-mod/hello && cd ~/kernel-mod

# 步骤3：编写hello.c（见3.1节）

# 步骤4：编写Makefile（见3.2节）

# 步骤5：编译
make
# make -C /lib/modules/5.15.0-generic/build M=/root/kernel-mod modules
#   CC [M] /root/kernel-mod/hello.o
#   MODPOST /root/kernel-mod/Module.symvers
#   CC [M] /root/kernel-mod/hello.mod.o
#   LD [M] /root/kernel-mod/hello.ko

# 步骤6：验证模块
file hello.ko
# hello.ko: ELF 64-bit LSB relocatable, x86-64, ...

modinfo hello.ko
# filename:       /root/kernel-mod/hello.ko
# license:        GPL
# vermagic:       5.15.0-generic SMP mod_unload

# 步骤7：加载模块
sudo insmod hello.ko

# 步骤8：验证
dmesg | tail -3
# [67890.123] hello: module loaded, pid=5678

cat /proc/modules | grep hello
# hello 16384 0 - Live 0xffffffffc0a10000

# 步骤9：卸载模块
sudo rmmod hello
dmesg | tail -1
# [67891.456] hello: module unloaded
```

### 4.2 实验二：创建带参数的安全监控模块

```c
// monitor.c - 进程创建监控模块
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>

static int verbose = 0;
module_param(verbose, int, 0644);
MODULE_PARM_DESC(verbose, "Enable verbose logging (0/1)");

static int __init monitor_init(void)
{
    printk(KERN_INFO "monitor: process monitor loaded (verbose=%d)\n", verbose);
    printk(KERN_INFO "monitor: current task=%s pid=%d\n",
           current->comm, current->pid);
    return 0;
}

static void __exit monitor_exit(void)
{
    printk(KERN_INFO "monitor: process monitor unloaded\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Process creation monitor module");
```

```makefile
# Makefile
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m := monitor.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

### 4.3 检测可疑内核模块

```bash
# 列出所有已加载模块及其来源（Live=运行中, Deleted=已卸载）
lsmod

# 查看模块是否通过签名验证
dmesg | grep -i "module verification failed"
# 如果出现此消息，说明有未签名模块被加载——高度可疑

# 检查模块的tainted状态
cat /proc/sys/kernel/tainted
# 非0值需关注：1=非GPL, 4096=外部模块

# 使用kmod工具检查模块依赖
modprobe --show-depends <模块名>

# 监控模块加载系统调用（使用auditd）
sudo auditctl -a always,exit -F arch=b64 -S finit_module -k module_load
sudo ausearch -k module_load -ts recent

# 使用falcon等工具持续监控
# (Linux Audit + osquery 可以记录模块加载事件)
```

## 5. 常见坑与避坑指南

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `insmod: ERROR: could not insert module: Required key not available` | Secure Boot启用且模块未签名 | 用`mokutil`注册自签名密钥，或关闭Secure Boot（不推荐） |
| `insmod: Invalid module format` | 模块vermagic与当前内核版本不匹配 | 用`modinfo hello.ko | grep vermagic`检查，确保内核头版本与运行内核一致 |
| `Unknown symbol in module` | 模块引用了未导出的内核符号 | 用`dmesg`查看缺失符号名，检查是否需要`EXPORT_SYMBOL`，或检查模块是否在正确的内核树编译 |
| `rmmod: ERROR: Module hello is in use` | 模块被其他模块引用或有活跃用户 | 用`lsmod`检查引用计数，确保无依赖后再卸载；`rmmod -f`强制卸载（危险） |
| 加载后`tainted kernel`变为非0 | 加载了非GPL模块或签名无效模块 | 确保`MODULE_LICENSE("GPL")`声明，检查模块签名完整性 |
| `make`时报 `No rule to make target 'modules'` | KDIR路径错误或内核头未安装 | 确认`/lib/modules/$(uname -r)/build`存在，安装对应内核头文件包 |
| 模块加载成功但`dmesg`无输出 | 日志级别过低被过滤 | 使用`printk(KERN_ERR ...)`或`dmesg -n 8`提升控制台日志级别 |
| 卸载模块后内核oops | 清理函数中释放了仍在使用的资源 | 确保`__exit`函数中撤销所有`__init`中的操作，检查引用计数 |
| `modprobe`找不到模块 | `/lib/modules/$(uname -r)/modules.dep`未生成 | 运行`sudo depmod -a`重新生成模块依赖数据库 |
| 编译时报 `stack Protector` 警告 | 内核编译选项CONFIG_STACKPROTECTOR与模块不匹配 | 确保模块编译时的gcc选项与内核一致（Kbuild会自动处理） |

## 6. 知识关联

- [[01-目录结构与FHS规范：一切皆文件]] — `/lib/modules/`目录结构与模块存储位置
- [[04-进程管理：ps-top-信号机制与nice]] — 模块进程（kthread）与用户态进程的关系
- [[06-权限体系：rwx-ACL-setuid-capabilities]] — CAP_SYS_MODULE capability与模块加载权限控制
- [[08-systemd：unit文件编写与服务管理]] — 通过systemd自动加载模块（systemd-modules-load.service）
- [[09-调试工具链：strace-ltrace-gdb基础]] — 使用strace跟踪insmod系统调用过程
- [[12-eBPF入门：kprobe与可观测性工具]] — eBPF作为内核模块的现代替代方案，更安全更灵活
- [[13-日志体系：syslog-journald-auditd配置]] — 模块加载日志的记录与审计

## 7. 参考资料

1. **Linux Kernel Documentation** - Loadable Kernel Module HOWTO: https://www.kernel.org/doc/html/latest/driver-api/index.html
2. **The Linux Kernel Module Programming Guide** (Chaos Calmer): https://tldp.org/LDP/lkmpg/2.6/html/
3. **Linux man-pages** - `insmod(8)`, `rmmod(8)`, `modprobe(8)`, `modinfo(8)`: https://man7.org/linux/man-pages/
4. **kernel.org** - Documentation/admin-guide/modules.rst: https://www.kernel.org/doc/html/latest/admin-guide/modules.html
5. **LWN.net** - "Module signing" 系列文章: https://lwn.net/Articles/585095/
6. **LWN.net** - "The life of a loadable kernel module": https://lwn.net/Articles/258188/
7. **redhat.com** - "What are kernel modules": https://www.redhat.com/sysadmin/kernel-modules
8. **kmod project** - Module loading tools: https://git.kernel.org/pub/scm/libs/kmod/kmod.git
9. **auditd documentation** - Linux Audit System: https://man7.org/linux/man-pages/man8/auditctl.8.html
10. **Secure Boot and Module Signing** - UEFI.org MOK: https://docs.kernel.org/driver-api/module_signing.html
