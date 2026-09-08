---
title: "权限体系：rwx-ACL-setuid-capabilities"
category: "00-基础通用/05-Linux系统与命令"
tags: [rwx, ACL, setuid, capabilities, 权限, sudo, chown, chmod, 安全]
level: 主攻
type: ai-generated
status: 完成
---

# 权限体系：rwx-ACL-setuid-capabilities

> 本文为合法系统管理与运维研究，从防御视角剖析 Linux 权限体系中的 setuid 提权、ACL 绕过和 capabilities 精细化控制机制，帮助安全人员理解攻击面并构建纵深防御策略。理解这些机制的目的是为了更安全地配置和审计系统，而非进行未授权操作。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | rwx 是传统的 Unix 三级权限模型（owner/group/other）；ACL 是 POSIX Access Control List，提供超出三级的细粒度权限控制；setuid 是特殊文件权限位，允许执行者以文件属主身份运行；capabilities 是内核级的细粒度特权分解机制，替代传统的 root 全能模型 |
| 核心用途 | 文件与目录的访问控制（rwx/ACL）、以特权身份执行特定程序（setuid/capabilities）、sudo 提权审计、容器安全中的 capabilities drop |
| 关键参数 | chmod: u+s, g+s, o+t, 4755, 2755, 1777; chown; setfacl: -m, -x, -b, -R; getfacl; getcap; setcap; capsh; sudo: -l, -u, visudo; lsattr: +s, +i |
| 常见风险 | setuid root 程序的缓冲区溢出可导致本地提权；ACL 权限膨胀导致最小权限原则失效；capabilities 未正确 drop 导致容器逃逸；sudo 配置不当（NOPASSWD、ALL）等同于 root 沦陷 |
| 关联知识 | [[01-目录结构与FHS规范：一切皆文件]], [[04-进程管理：ps-top-信号机制与nice]], [[08-systemd：unit文件编写与服务管理]] |

## 1. 概述

Linux 权限体系是一个多层叠加的安全模型，从基础到高级依次为：传统的 rwx 三级权限 -> 特殊权限位（setuid/setgid/sticky bit） -> POSIX ACL -> Linux Capabilities -> SELinux/AppArmor 强制访问控制。每一层都是对前一层的补充和细化，而非替代。

理解权限体系对安全从业者至关重要。每一次本地提权漏洞的利用，本质上都是对权限模型的某种突破或滥用：setuid 程序中的缓冲区溢出让攻击者获得 root shell；拥有 CAP_NET_RAW 能力的进程可以伪造 ARP 包进行中间人攻击；不当的 ACL 配置可能让低权限用户读取敏感文件。

本文从防御视角出发，系统性地剖析每一层权限机制的原理、配置和潜在风险，帮助安全人员建立「权限即攻击面」的意识，并掌握最小权限原则的落地实践。

## 2. 核心原理

### 2.1 传统 rwx 三级权限模型

Linux 每个文件/目录关联一个 UID（属主）和 GID（属组），权限分三组各三位：

```text
文件类型 | 属主权限 | 属组权限 | 其他用户权限
   -    |  r w x  |  r w x  |    r w x
```

- **r (read)**：文件=读取内容；目录=列出内容（ls）
- **w (write)**：文件=修改内容；目录=创建/删除/重命名子项（需同时有 x）
- **x (execute)**：文件=作为程序执行；目录=进入该目录（cd）

目录的 x 权限极其关键：没有 x 权限的目录，即使有 w 权限也无法在其中创建文件，且无法访问目录内文件的 inode 信息（即使知道文件名）。`ls -l` 显示目录内文件属性需要 r+x，`stat` 查看单个文件只需对该文件路径上每个目录有 x 权限。

### 2.2 特殊权限位

#### setuid (SUID)

当可执行文件设置了 setuid 位（chmod u+s 或 chmod 4xxx），任何用户执行该文件时，进程的有效用户 ID（EUID）变为文件的属主 UID。典型例子：

```bash
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root 68208 ... /usr/bin/passwd
#          ^ s 表示 setuid 位
```

passwd 命令需要 root 权限修改 /etc/shadow，但不应给所有用户 root shell，因此通过 setuid 让普通用户以 root 身份运行 passwd 程序的特定功能。

安全风险：如果 setuid root 程序存在缓冲区溢出、格式化字符串、竞争条件等漏洞，攻击者可以注入 shellcode 或利用 ROP 链，以 root 身份执行任意代码。历史上著名的本地提权漏洞如 CVE-2021-4034（pkexec PwnKit）就是利用了 setuid 程序中的漏洞。

#### setgid (GID)

类似 setuid，但设置的是进程的有效组 ID（EGID）。在目录上设置 setgid 位意味着在该目录下创建的文件会继承目录的 GID 而非创建者的主组，这对团队协作目录非常有用。

#### sticky bit

目录上的 sticky bit（chmod +t 或 chmod 1xxx）确保只有文件属主、目录属主或 root 才能删除目录内的文件。典型例子是 /tmp 目录：

```bash
ls -ld /tmp
# drwxrwxrwt 15 root root 4096 ... /tmp
#                          ^ t 表示 sticky bit
```

### 2.3 POSIX ACL

传统 rwx 模型只能为一个用户和一个组设置权限。当需要为多个用户或多个组分别设置不同权限时，ACL 提供了扩展能力。

ACL 条目类型：
- **user::rwx**：属主权限（等同于传统 owner 权限）
- **user:username:rwx**：为特定用户设置权限
- **group::rwx**：属组权限（等同于传统 group 权限）
- **group:groupname:rwx**：为特定组设置权限
- **mask::rwx**：ACL 掩码，限制所有命名用户和命名组的最大有效权限
- **other::rwx**：其他用户权限

关键概念：**有效权限 = ACL 条目权限 AND mask**。即使为用户 alice 设置了 rwx，如果 mask 是 r-x，则 alice 的有效权限仅为 r-x。

### 2.4 Linux Capabilities

传统 Unix 权限模型将特权操作简化为「是否为 root」的二元判断。这导致了一个严重问题：为了执行一个小的特权操作（如绑定 80 端口），进程必须拥有完整的 root 权限，而一旦被利用，攻击者将获得系统完全控制权。

Linux Capabilities（从 Linux 2.2 内核引入，2.6.25 起完善）将 root 的「全能」拆分为约 41 个独立的能力单元，每个能力控制一类特定的特权操作：

- CAP_NET_RAW：使用原始套接字（ping、tcpdump）
- CAP_NET_BIND_SERVICE：绑定 1024 以下端口
- CAP_SYS_ADMIN：大量系统管理操作（mount、namespace 创建等）
- CAP_SYS_PTRACE：ptrace 其他进程（调试、注入）
- CAP_DAC_OVERRIDE：绕过文件权限检查
- CAP_SETUID / CAP_SETGID：修改进程 UID/GID
- CAP_NET_ADMIN：网络管理（路由、防火墙规则）
- CAP_SYS_MODULE：加载/卸载内核模块
- CAP_SYS_RAWIO：直接 I/O 端口操作

capabilities 附加到进程而非用户。一个非 root 用户可以被授予特定的 capability，从而只拥有完成其功能所需的最小特权。

## 3. 详细知识点

### 3.1 rwx 权限的精确语义与八进制表示

#### 3.1.1 权限的八进制计算

```bash
r=4, w=2, x=1
# rwx = 4+2+1 = 7
# r-x = 4+0+1 = 5
# r-- = 4+0+0 = 4

chmod 755 script.sh    # rwxr-xr-x
chmod 644 config.txt   # rw-r--r--
chmod 700 private_dir  # rwx------
chmod 600 id_rsa       # rw-------
```

#### 3.1.2 umask 与默认权限

新建文件的默认权限 = 666 - umask（文件无 x，因为需要显式 chmod +x）
新建目录的默认权限 = 777 - umask

```bash
# 查看当前 umask
umask
# 0022 表示新建文件 644，新建目录 755

# 设置 umask（仅当前 shell 会话生效）
umask 0077  # 新建文件 600，新建目录 700

# 在 /etc/profile 或 ~/.bashrc 中永久设置
```

#### 3.1.3 目录权限的特殊性

```bash
# 场景：文件 rwx 但所在目录权限不同
mkdir secret
chmod 700 secret
echo "password=123" > secret/data.txt
chmod 644 secret/data.txt

# 普通用户无法看到目录内容（无目录 r）
# 但如果知道文件名，可以通过完整路径访问（无目录 x 则不行）

# 验证：无目录 x 权限时
chmod 600 secret      # rw-------
# 此时无法 cd 进入，也无法 stat 目录内的文件
# 但如果文件本身有 world readable 权限且通过硬链接等方式可访问...
```

目录权限组合的实际效果：

| 目录权限 | r | w | x | 能否 ls | 能否 cd | 能否 stat 内部已知文件 | 能否创建/删除文件 |
|----------|---|---|---|---------|---------|----------------------|-------------------|
| rwx------ | Y | Y | Y | Y | Y | Y | Y（仅属主） |
| r-x------ | N | N | Y | N | Y | Y | N |
| rw------- | Y | Y | N | Y | N | N | N |
| ---rwx--- | N | N | Y | N | Y | N | Y（需对文件有写） |
| --------- | N | N | N | N | N | N | N |

### 3.2 setuid 审计与安全加固

#### 3.2.1 发现系统中的 setuid 文件

```bash
# 查找所有 setuid 文件
find / -perm -4000 -type f 2>/dev/null

# 查找 setuid 或 setgid 文件
find / -perm /6000 -type f 2>/dev/null

# 更高效的查找（使用 -perm 的精确匹配）
find / -perm -u=s -type f 2>/dev/null

# 使用 locate 加速
locate --regex '/[^/]*s[^/]*$' | xargs ls -la 2>/dev/null | grep '^...s'
```

#### 3.2.2 常见 setuid 程序及风险评估

```bash
# 典型的 setuid root 程序（Debian/Ubuntu 系统示例）
ls -la /usr/bin/passwd      # 修改密码（/etc/shadow）
ls -la /usr/bin/sudo        # 提权执行命令
ls -la /usr/bin/su          # 切换用户
ls -la /usr/bin/chsh        # 修改登录 shell
ls -la /usr/bin/chfn        # 修改 finger 信息
ls -la /usr/bin/newgrp      # 切换组
ls -la /usr/bin/gpasswd     # 修改组密码
ls -la /usr/bin/mount       # 挂载文件系统
ls -la /usr/bin/umount      # 卸载文件系统
ls -la /usr/bin/ping        # 发送 ICMP 包
ls -la /usr/bin/crontab     # 管理 crontab
ls -la /usr/sbin/umount.nfs # NFS 卸载
ls -la /usr/lib/openssh/ssh-keysign  # SSH 主机密钥签名

# 风险评估：不必要的 setuid 程序应当移除
# 例如：如果系统不需要 mount/umount 的 setuid，可以：
sudo chmod u-s /usr/bin/mount
sudo chmod u-s /usr/bin/umount
```

#### 3.2.3 setuid 程序的执行流程与安全检查点

当一个 setuid 程序被 execve() 执行时：

1. 内核检查文件的 setuid 位
2. 如果设置了 setuid 且文件属主是 root，进程的 EUID 变为 0
3. 进程获得 root 的所有 capabilities（在非文件系统能力模式下）
4. 程序代码开始以 root 身份运行

安全加固手段：
- 使用 nosuid 挂载选项阻止文件系统上的 setuid 生效：`mount -o nosuid /dev/sdb1 /data`
- 使用 capabilities 替代 setuid（见 3.4 节）
- 对 setuid 程序进行代码审计和 fuzzing
- 使用 seccomp 限制 setuid 程序可用的系统调用

### 3.3 POSIX ACL 详解

#### 3.3.1 ACL 操作命令

```bash
# 查看文件/目录的 ACL
getfacl file.txt

# 设置 ACL（-m 修改，-b 清除所有 ACL）
setfacl -m u:alice:rwx file.txt       # 为 alice 用户设置 rwx
setfacl -m g:devteam:rx shared_dir/   # 为 devteam 组设置 rx
setfacl -m u:bob:--- secret.txt       # 显式拒绝 bob 访问
setfacl -m m::rx file.txt            # 设置 ACL 掩码

# 递归设置（目录及其子项）
setfacl -R -m u:alice:rwx shared_dir/

# 设置默认 ACL（影响新创建的文件）
setfacl -d -m g:devteam:rx shared_dir/

# 删除特定 ACL 条目
setfacl -x u:alice file.txt

# 清除所有 ACL（恢复传统权限）
setfacl -b file.txt

# 从文件恢复 ACL
setfacl --restore=acl_backup.txt
```

#### 3.3.2 ACL 输出解读

```bash
getfacl file.txt
# 输出：
# # file: file.txt
# # owner: root
# # group: root
# user::rwx
# user:alice:rwx          # named user entry
# user:bob:---            # named user entry (explicit deny)
# group::r-x              # owning group
# group:devteam:r-x       # named group entry
# mask::rwx               # ACL mask
# other::r-x

# ls -l 显示 ACL 标记
ls -l file.txt
# -rw-rwx---+ 1 root root 128 ... file.txt
#                             ^ + 表示有 ACL 条目
```

#### 3.3.3 ACL 常见陷阱

**陷阱一：mask 导致有效权限降低**

```bash
setfacl -m u:alice:rwx file.txt
setfacl -m m::r-x file.txt     # mask 只有 rx
getfacl file.txt
# user:alice:rwx               # ACL 条目是 rwx
# mask::r-x                     # mask 是 r-x
# 有效权限 = rwx AND r-x = r-x  # alice 实际只有 rx！
```

**陷阱二：修改传统权限会重置 ACL mask**

```bash
chmod g+w file.txt    # 这会修改 ACL mask！
# 因为传统 group 权限位在有 ACL 时实际控制的是 mask
# 所以 chmod g+w 会把 mask 改为包含 w
```

**陷阱三：ACL 不继承扩展属性**

复制文件时使用 cp -p 保留权限但不保留 ACL。需要使用 `cp --preserve=all` 或 `getfacl ... | setfacl --restore=-` 来保留 ACL。

#### 3.3.4 ACL 安全审计

```bash
# 查找所有有 ACL 的文件
getfacl -R /etc 2>/dev/null | grep -B1 "user:[^:]*:[^-r]*w" | grep "^# file:"

# 查找过于宽泛的 ACL 条目
find / -name '*.txt' -exec getfacl {} \; 2>/dev/null | grep "other::r"

# 审计 setfacl 的使用（通过 auditd）
auditctl -w /usr/bin/setfacl -p x -k acl-change
ausearch -k acl-change
```

### 3.4 Linux Capabilities 体系

#### 3.4.1 查看进程的 capabilities

```bash
# 查看当前 shell 的 capabilities
cat /proc/self/status | grep Cap
# CapPrm: 00000000a80425fb  # Permitted
# CapEff: 00000000a80425fb  # Effective
# CapBnd: 0000003fffffffff  # Bounding
# CapAmb: 0000000000000000  # Ambient

# 解码十六进制为可读名称
capsh --decode=00000000a80425fb

# 或使用 python3
python3 -c "import subprocess; result=subprocess.run(['capsh','--decode=00000000a80425fb'],capture_output=True,text=True); print(result.stdout)"
# CapPrm: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_admin,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep

# 查看指定进程的 capabilities
cat /proc/<PID>/status | grep Cap
```

#### 3.4.2 Capabilities 的四套集合

每个进程维护四套 capabilities 集合：

- **Permitted (CapPrm)**：进程可以使用的 capabilities 超集。新进程继承自父进程。只有在此集合中的 capability 才能被提升到 Effective。
- **Effective (CapEff)**：当前实际生效的 capabilities。内核在执行特权操作时检查此集合。
- **Bounding (CapBnd)**：capability 的上限。任何新 capability 都不能超过此集合。用于限制子进程的 capability 范围。
- **Ambient (CapAmb)**：非特权进程执行 setuid 二进制时保留的 capabilities（Linux 4.3+ 引入）。

#### 3.4.3 设置文件 capabilities

```bash
# 为可执行文件设置 capability
setcap cap_net_bind_service=+ep /usr/local/bin/myserver
# 效果：myserver 启动后拥有绑定低端口的能力，无需 setuid root

# 查看文件 capabilities
getcap /usr/local/bin/myserver
# /usr/local/bin/myserver cap_net_bind_service=ep

# 添加多个 capabilities
setcap cap_net_bind_service,cap_net_raw=+ep /usr/local/bin/myserver

# 移除文件 capabilities
setcap -r /usr/local/bin/myserver

# 递归设置（危险！谨慎使用）
setcap -r /usr/local/bin/
```

#### 3.4.4 使用 capsh 管理 capabilities

```bash
# 以特定 capabilities 运行命令
capsh --caps="cap_net_raw+eip" -- -c 'ping -c 1 8.8.8.8'

# 丢弃所有 capabilities 以非特权模式运行
capsh --drop=all -- -c 'whoami'  # 可能输出 nobody 或报错

# 查看当前 shell 的完整 capability 状态
capsh --print

# 利用 ambient capabilities 在非特权 shell 中赋予子进程能力
capsh --addamb=cap_net_raw -- -c 'ping -c 1 8.8.8.8'
```

#### 3.4.5 Capabilities 在容器安全中的应用

Docker/Kubernetes 容器安全与 capabilities 的关系至关重要：

```bash
# Docker 默认赋予容器的 capabilities（--cap-default）
# CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FSETID, CAP_FOWNER,
# CAP_MKNOD, CAP_NET_RAW, CAP_SETGID, CAP_SETUID,
# CAP_SETFCAP, CAP_SETPCAP, CAP_NET_BIND_SERVICE,
# CAP_SYS_CHROOT, CAP_KILL, CAP_AUDIT_WRITE

# 删除所有 capabilities 并仅添加需要的
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Kubernetes 中配置 capabilities
# securityContext:
#   capabilities:
#     drop: ["ALL"]
#     add: ["NET_BIND_SERVICE", "SYS_TIME"]

# 高危 capabilities（不应授予容器）：
# CAP_SYS_ADMIN   -> 可以 mount、创建 namespace，是容器逃逸的关键跳板
# CAP_SYS_PTRACE  -> 可以 ptrace 其他进程
# CAP_SYS_MODULE  -> 可以内核模块注入
# CAP_NET_ADMIN   -> 可以修改网络配置、路由表
# CAP_DAC_OVERRIDE -> 可以绕过文件权限
```

### 3.5 sudo 提权与审计

#### 3.5.1 sudo 配置基础

sudo 通过 /etc/sudoers 文件（必须使用 visudo 编辑）控制提权规则：

```bash
# sudoers 文件格式
# 用户 主机=(运行身份) 命令
root    ALL=(ALL:ALL)   ALL
alice   ALL=(ALL)       /usr/bin/systemctl restart nginx, /usr/bin/tail -f /var/log/*
bob     ALL=(root)      NOPASSWD: /usr/bin/apt-get update

# 组授权
%devteam ALL=(ALL) /usr/bin/docker, /usr/bin/kubectl
%sudo   ALL=(ALL:ALL)  ALL

# 常用 sudo 命令
sudo -l                    # 列出当前用户的 sudo 权限
sudo -u www-data bash      # 以 www-data 身份执行
sudo -E env                # 保留环境变量执行
```

#### 3.5.2 sudo 安全风险与加固

```bash
# 风险配置示例（应避免）
alice ALL=(ALL) NOPASSWD: ALL          # 等同于给 alice root
bob ALL=(ALL) ALL                      # 需要密码但可执行任何命令
%dba ALL=(ALL) /usr/bin/vi             # vi 可以通过 :!sh 获得 root shell
dev ALL=(ALL) /usr/bin/docker run *    # 可以通过 docker mount 宿主机目录

# 加固原则：
# 1. 限制可执行的命令（白名单）
# 2. 禁止 NOPASSWD（除非自动化场景且命令受限）
# 3. 避免授予可交互式 shell 的命令（vi、less、man 等）
# 4. 使用 command 参数限制参数
# 5. 使用 ! 否定关键字排除危险命令
admin ALL=(ALL) /usr/bin/systemctl restart *, !/usr/bin/systemctl restart sshd
```

#### 3.5.3 sudo 提权攻击手法

```bash
# 1. 利用可编辑的配置文件提权
# 如果 sudo 允许 vim/vi/less/cat/ftp 等：
sudo vim          # :!sh 或 :!bash
sudo less         # !sh
sudo ftp          # !sh
sudo man vim      # !sh
sudo awk 'BEGIN{system("/bin/sh")}'
sudo python -c 'import os; os.execl("/bin/sh","sh","-p")'

# 2. 利用 find 提权
sudo find / -exec /bin/sh \;
sudo find / -exec /bin/bash \; 

# 3. 利用环境变量注入
# 如果 sudoers 中有 env_keep+=LD_PRELOAD 或 LD_LIBRARY_PATH
# 可以创建恶意 .so 文件进行提权

# 4. 利用路径注入
# 如果 sudo 配置了相对路径或未使用 FULL_PATH
```

### 3.6 文件不可变属性与特殊属性

```bash
# 查看文件扩展属性
lsattr file.txt

# 设置不可修改属性（即使 root 也不能删除或修改）
chattr +i file.txt    # 设置 immutable
chattr -i file.txt    # 移除

# 设置仅追加属性（只能追加内容，不能修改已有内容）
chattr +a log.txt     # 常用于日志文件防篡改
chattr -a log.txt

# 其他属性
chattr +s file.txt    # 安全删除（用0覆盖）
chattr +u file.txt    # undelete（保留删除数据以便恢复）
chattr +c file.txt    # 自动压缩
```

## 4. 实战与示例

### 4.1 安全基线审计脚本

```bash
#!/bin/bash
# 安全审计脚本：检查权限配置异常

echo "=== setuid/setgid 文件审计 ==="
find / -perm /6000 -type f 2>/dev/null | while read f; do
    echo "[AUDIT] $f $(ls -la $f)"
done

echo ""
echo "=== world-writable 目录审计 ==="
find / -type d -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | while read d; do
    echo "[WARN] World-writable: $d"
done

echo ""
echo "=== ACL 条目审计 ==="
getfacl -R /etc 2>/dev/null | grep -B1 "user:[^:]*:[^-r]*w" | grep "^# file:" | while read line; do
    echo "[AUDIT] ACL write: $line"
done

echo ""
echo "=== capabilities 文件审计 ==="
find / -type f -exec getcap {} + 2>/dev/null | grep -v "^$"

echo ""
echo "=== sudo 配置审计 ==="
if [ -f /etc/sudoers ]; then
    grep -v '^#' /etc/sudoers | grep -v '^$' | grep -i 'NOPASSWD\|ALL'
fi

echo ""
echo "=== 不可变文件检查 ==="
find /etc -exec lsattr {} + 2>/dev/null | grep '\.i'
```

### 4.2 最小权限实践：Web 服务器加固

```bash
# 1. 创建专用用户
sudo useradd -r -s /usr/sbin/nologin -d /var/www/html www-run

# 2. 设置目录权限
sudo chown -R www-run:www-run /var/www/html
sudo chmod 750 /var/www/html

# 3. 使用 capabilities 替代 setuid
sudo setcap cap_net_bind_service=+ep /usr/sbin/nginx
# 之后 nginx 可以绑定 80/443 端口而无需 root

# 4. 在 systemd unit 中限制 capabilities
# [Service]
# User=www-run
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# AmbientCapabilities=CAP_NET_BIND_SERVICE
# NoNewPrivileges=true
# ProtectSystem=strict
# ProtectHome=true

# 5. 对上传目录设置 ACL
setfacl -d -m g:www-run:rw /var/www/uploads
setfacl -m o::--- /var/www/uploads
```

### 4.3 容器 capabilities 精细化配置

```bash
# 查看容器默认 capabilities
docker run --rm alpine sh -c 'cat /proc/1/status | grep Cap'

# 最小化容器 capabilities
docker run -d \
  --name web \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --cap-add=CHOWN \
  --cap-add=SETGID \
  --cap-add=SETUID \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid \
  -p 8080:80 \
  nginx:alpine

# 验证容器 capabilities
docker exec web cat /proc/1/status | grep Cap
# 对比 drop 前后的 capabilities 差异
```

## 5. 常见坑与避坑指南

| 坑点 | 表现 | 原因 | 解决方案 |
|------|------|------|----------|
| chmod +x 无效 | 文件仍然无法执行 | 文件系统挂载了 noexec 选项 | 检查 `mount | grep noexec`，使用 `remount,exec` |
| setuid 位无效 | 执行时不以 root 运行 | 文件系统挂载了 nosuid，或文件系统不支持（如 FAT32/NFS） | 使用 `mount | grep nosuid` 检查，NFS 需要 `noexec` 配合 root_squash |
| ACL 权限不生效 | 用户仍无法访问 | mask 限制了有效权限 | 用 `getfacl` 检查 mask，使用 `setfacl -m m::rwx` 调整 |
| ACL 被 chmod 重置 | ACL 条目丢失 | `chmod g+xxx` 会修改 mask | 使用 `setfacl` 替代 `chmod` 管理组权限 |
| capabilities 不继承 | 子进程丢失 capability | ambient capabilities 未设置，或进程 setuid 执行时被清除 | 使用 `capsh --addamb` 或 systemd 的 `AmbientCapabilities=` |
| sudo vi 获得 root | 通过 :!sh 提权 | vi/less/man 等允许执行外部命令 | sudoers 中使用 `!` 排除：`!ALL`，或使用 `SETENV` 关键字限制 |
| cp 不保留 ACL | 复制后 ACL 权限丢失 | cp -p 不保留 ACL | 使用 `cp --preserve=all` 或 `getfacl/setfacl` 备份恢复 |
| NFS 权限映射混乱 | NFS 客户端看到的权限不正确 | root_squash/all_squash/uid 映射配置 | 理解 NFS 的 squash 机制，服务端和客户端 uid/gid 需一致 |
| chattr +i 后无法删除 | rm 报 Operation not permitted | 文件设置了 immutable 属性 | `chattr -i` 移除后再删除，root 也受此限制 |
| /tmp 权限不对 | 所有用户无法创建临时文件 | /tmp 缺少 sticky bit 或权限过严 | `chmod 1777 /tmp` 恢复 |

## 6. 知识关联

- [[01-目录结构与FHS规范：一切皆文件]]：理解 Linux「一切皆文件」哲学是理解 rwx 权限的基础，/proc 和 /sys 的权限控制直接影响系统可观测性
- [[04-进程管理：ps-top-信号机制与nice]]：capabilities 附加到进程而非用户，理解进程的 UID/EUID/RUID/SUID 等多个身份概念与 capabilities 的交互关系
- [[05-网络命令链：ip-ss-tcpdump-nmap排查实战]]：CAP_NET_RAW 控制 tcpdump 和 ping 的能力，CAP_NET_ADMIN 控制 ip 命令的路由修改能力
- [[08-systemd：unit文件编写与服务管理]]：systemd unit 文件中的 User=、CapabilityBoundingSet=、AmbientCapabilities= 是服务最小权限配置的关键
- [[11-内核模块：编写编译与insmod加载]]：CAP_SYS_MODULE 控制内核模块加载，insmod/rmmod 需要此 capability
- [[13-日志体系：syslog-journald-auditd配置]]：auditd 可以监控 setuid 文件的执行、capability 的变更、sudo 的使用等安全事件

## 7. 参考资料

- **man 手册**：`man 1 chmod`, `man 1 chown`, `man 2 chdir`, `man 7 capabilities`, `man 5 sudoers`, `man 1 setfacl`, `man 1 getfacl`, `man 8 setcap`, `man 8 getcap`, `man 1 capsh`
- **Linux Capabilities 文档**：https://man7.org/linux/man-pages/man7/capabilities.7.html
- **POSIX ACL 文档**：https://www.gnu.org/software/libc/manual/html_node/Access-Control.html
- **Docker 安全 - Capabilities**：https://docs.docker.com/engine/reference/run/#cap-add
- **《鸟哥的Linux私房菜》- 权限与文件系统管理**：http://linux.vbird.org/linux_basic/0410filemanager.php
- **《Linux程序设计》**（Neil Matthew & Richard Stones）：文件权限与进程权限的系统性讲解
- **CWE-250: Execution with Unnecessary Privileges**：MITRE 对过度权限风险的分类
- ** CIS Benchmark**：Linux 发行版安全基线中的 setuid/capabilities 审计建议
