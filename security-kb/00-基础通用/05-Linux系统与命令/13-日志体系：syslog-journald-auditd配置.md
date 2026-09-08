---
title: "日志体系：syslog-journald-auditd配置"
category: "00-基础通用/05-Linux系统与命令"
tags: [syslog, journald, auditd, rsyslog, 日志安全, 日志转发, 合规审计]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# 日志体系：syslog-journald-auditd配置

> 防御视角声明：本篇涉及的syslog配置、journald持久化、auditd审计规则编写、日志转发与远程存储等技术，仅用于合法的系统运维、安全监控与合规审计。严禁用于日志伪造、日志清洗（log washing）、抗取证攻击或破坏审计完整性。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | Linux日志体系由三层组成：传统syslog/rsyslog（应用日志）、systemd-journald（结构化二进制日志）、auditd（内核级审计日志），三者协同构成完整的可观测性与合规基础 |
| 核心用途 | 应用故障排查、安全事件调查（DFIR）、合规审计（PCI-DSS/SOC2/等保）、入侵检测、日志集中收集（SIEM接入） |
| 关键参数 | `rsyslog.conf`（syslog配置）、`journald.conf`（journal配置）、`auditctl`/`auditd.conf`（审计配置）、`journalctl`（journal查询）、facility/priority过滤、远程转发 |
| 常见风险 | 日志被篡改/删除、日志空间耗尽（DoS）、日志明文传输泄露、时区/时钟跳变导致日志时序混乱、日志延迟导致检测窗口扩大 |
| 关联知识 | [[11-内核模块：编写编译与insmod加载]]（内核模块加载事件的审计记录）、[[12-eBPF入门：kprobe与可观测性工具]]（eBPF事件输出到日志系统）、[[08-systemd：unit文件编写与服务管理]]（journald与systemd集成）、[[06-权限体系：rwx-ACL-setuid-capabilities]]（auditd权限与capability控制） |

## 1. 概述

Linux日志体系是系统可观测性的基石，也是安全防御的核心基础设施。一个设计良好的日志架构需要回答四个关键问题：发生了什么（事件内容）、何时发生（时间戳）、谁干的（用户/进程）、影响了什么（资源/对象）。

现代Linux系统的日志体系由三个层次构成：

**第一层：syslog/rsyslog** — 传统的文本日志系统，遵循RFC 3164/RFC 5424标准。应用程序通过`openlog()`/`syslog()` C库函数或直接写入`/dev/log` socket将消息发送到syslog daemon。rsyslog是syslog-ng的替代品，目前是大多数发行版的默认syslog daemon，支持TCP/UDP/TLS远程转发、数据库写入、复杂的过滤规则。

**第二层：systemd-journald** — systemd引入的结构化二进制日志系统。所有通过`sd_journal_print()`、`printf`到stderr的输出、内核`printk`消息都会被journald收集。journal使用二进制格式存储，支持结构化字段、快速索引查询、按时间/优先级/进程过滤。journal可以配置为易失性（仅内存）或持久化（写入`/var/log/journal/`）。

**第三层：auditd** — 内核级审计框架。通过Linux Audit子系统捕获系统调用级别的安全相关事件（文件访问、权限变更、进程创建、网络连接等）。auditd是唯一能提供完整证据链的日志源，是合规审计（PCI-DSS要求6个月审计日志保留）的核心组件。

从安全防御角度看，日志体系面临三重威胁：（1）可用性威胁——攻击者删除日志以掩盖痕迹；（2）完整性威胁——篡改日志条目或时间戳；（3）机密性威胁——明文传输的日志被窃听。防御策略包括日志远程转发（不可本地删除）、只读存储（append-only）、数字签名（auditd日志签名）、加密传输（TLS syslog）、NTP时间同步（防止时钟篡改）。

## 2. 核心原理

### 2.1 Syslog协议与消息格式

Syslog消息遵循RFC 5424结构化格式：

```text
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

示例：
<134>1 2026-09-01T10:30:00.123Z webserver nginx 1234 - - - Started worker process
```

PRI（Priority）= Facility * 8 + Severity，共8bit编码了消息来源和严重级别：

**Facility（来源）：**

| 值 | 名称 | 用途 |
|----|------|------|
| 0 | kern | 内核消息 |
| 1 | user | 用户级消息 |
| 2 | mail | 邮件系统 |
| 3 | daemon | 系统守护进程 |
| 4 | auth | 认证/授权 |
| 5 | syslog | syslog内部 |
| 6 | lpr | 打印机 |
| 7 | news | 新闻组 |
| 8 | uucp | UUCP |
| 10 | authpriv | 私有认证 |
| 11 | cron | cron/at |
| 16-23 | local0-local7 | 本地自定义 |

**Severity（级别）：**

| 值 | 名称 | 描述 |
|----|------|------|
| 0 | emerg | 系统不可用 |
| 1 | alert | 需要立即处理 |
| 2 | crit | 严重条件 |
| 3 | err | 错误 |
| 4 | warning | 警告 |
| 5 | notice | 正常但重要 |
| 6 | info | 信息性 |
| 7 | debug | 调试 |

### 2.2 rsyslog架构

```text
应用程序
    |
    v
[应用] -> openlog()/syslog() -> /dev/log (Unix socket)
    |
    v
rsyslogd (核心引擎)
    |
    +-- 输入模块 (imuxsock, imklog, imudp, imtcp, imfile)
    |
    +-- 规则引擎 (解析/过滤/路由)
    |   |
    |   +-- 解析器 (RSyslog Advanced Format Parser)
    |   +-- 过滤器 (property-based, scripted)
    |   +-- 输出模块 (omfile, omfwd, ommysql, ommongodb, omelasticsearch)
    |
    +-- 输出目标
        +-- 本地文件 (/var/log/syslog, /var/log/auth.log, ...)
        +-- 远程主机 (TCP/UDP/TLS)
        +-- 数据库 (MySQL, PostgreSQL)
        +-- SIEM (Splunk, ELK, Graylog)
```

### 2.3 systemd-journald架构

```text
内核 printk()
    |
    v
/dev/kmsg (内核日志设备)
    |
    v
systemd-journald ----+----> /dev/log (Unix socket接收应用日志)
    |                 +----> stdout/stderr (systemd服务日志)
    |                 +----> Audit netlink (auditd事件)
    |
    v
Journal 文件 (二进制)
    |
    +-- /run/log/journal/  (易失性，内存中)
    +-- /var/log/journal/  (持久化，磁盘上)
    
查询接口:
    +-- journalctl (命令行)
    +-- sd-journal API (程序接口)
    +-- /var/log/journal/*/system.journal (直接读取)
```

Journal文件使用内存映射（mmap）和追加写入（append-only）设计，提供O(1)的日志追加性能和高效的索引查询。每个条目包含时间戳、PID、UID、进程名、syslog facility、syslog identifier、message等结构化字段。

### 2.4 Linux Audit子系统

```text
用户态应用
    |
    v
系统调用 (syscall)
    |
    v
内核 Audit 子系统
    |
    +-- syscall审计规则匹配
    |   +-- 审计类型: SYSCALL, PATH, EXECVE, USER, ANOM_*
    |   +-- 过滤条件: -F uid=, -F arch=, -F success=
    |
    v
Audit 消息队列 (内核缓冲区)
    |
    v
auditd (用户态daemon)
    |
    +-- /var/log/audit/audit.log (主日志文件)
    +-- 远程转发 (audisp-remote)
    +-- 日志轮转 (auditd - rotate)
```

审计事件使用ARC（Audit Record Canonical）格式：

```text
type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 success=yes exit=0
a0=7ffd12345678 a1=7ffd12345680 a2=7ffd12345690 a3=0 items=1 ppid=1234 pid=5678
auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000
fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/usr/bin/bash" key=(null)
type=PATH msg=audit(1234567890.123:456): item=0 name="/usr/bin/bash" inode=12345
dev=dm-0 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0
cap_fi=0 cap_fe=0 cap_fver=0
```

## 3. 详细知识点

### 3.1 rsyslog配置详解

主配置文件位于`/etc/rsyslog.conf`，额外规则放在`/etc/rsyslog.d/*.conf`：

```bash
# /etc/rsyslog.conf 主配置文件

# 全局指令
$FileOwner root
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0027

# 模块加载
$ModLoad imuxsock    # 本地Unix socket输入
$ModLoad imklog      # 内核日志输入
$ModLoad imudp       # UDP syslog输入（可选）
$ModLoad imtcp       # TCP syslog输入（可选）

# 远程转发规则
# 转发所有emerg以上级别到远程服务器
*.* @@192.168.1.100:514     # @@ = TCP, @ = UDP

# 仅转发auth相关日志
auth,authpriv.* @@192.168.1.100:514

# 使用队列缓冲远程转发（防丢）
$ActionResumeRetryCount -1
$ActionQueueSize 100000
$ActionQueueDiskQueueSize 2G
$ActionQueueFileName fwd_queue
*.* @@192.168.1.100:514;RSYSLOG_SyslogProtocol23Format

# 本地日志规则
kern.*                          /var/log/kern.log
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          /var/log/syslog
cron.*                          /var/log/cron.log
local0.*                        /var/log/app.log

# 紧急消息写入所有终端
*.emerg                         :omusrmsg:*

# 日志模板（RFC 5424格式）
template(name="RFC5424" type="string"
    string="<%pri%>%proto-version% %timestamp:::date-rfc3339% %hostname% %app-name% %procid% %msgid% %structured-data% %msg%\n")

# 使用TLS加密转发（推荐）
$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca-cert.pem
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
$ActionSendStreamDriverPermittedPeer logserver.example.com
```

### 3.2 systemd-journald配置

主配置文件位于`/etc/systemd/journald.conf`：

```ini
# /etc/systemd/journald.conf

[Journal]
# 存储模式: volatile(仅内存), persistent(仅磁盘), auto(有/var/log/journal则持久化), none(禁用)
Storage=persistent

# 日志保留策略
SystemMaxUse=4G            # 最大磁盘使用
SystemMaxFileSize=128M     # 单个journal文件最大
MaxRetentionSec=6month     # 保留时间
MaxFileSec=1day            # 每个文件最大时间跨度
MinFreeSec=512M            # 保留的最小空闲空间

# 压缩策略
Compress=yes               # 压缩旧journal文件

# 同步策略
SyncIntervalSec=5s         # 同步间隔（默认5s）
RateLimitIntervalSec=30s   # 速率限制窗口
RateLimitBurst=10000       # 窗口内最大条目数

# 转发到rsyslog
ForwardToSyslog=yes        # 同时转发到syslog（兼容性）

# 认证日志
ForwardToKMsg=no
ForwardToConsole=no
ForwardToWall=yes
```

```bash
# journald管理命令
# 查看journal磁盘使用
journalctl --disk-usage
# Archived and active journals take up 256.0M in the file system.

# 手动触发journal轮转
sudo journalctl --rotate

# 清理旧日志（保留最近7天）
sudo journalctl --vacuum-time=7d

# 清理旧日志（保留1GB）
sudo journalctl --vacuum-size=1G

# 验证journal文件完整性
journalctl --verify
```

### 3.3 auditd配置与规则编写

主配置文件`/etc/audit/auditd.conf`：

```ini
# /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log
log_format = ENRICHED          # 启用增强格式（包含进程上下文）
log_group = adm
write_logs = yes
priority_boost = 4
flush = INCREMENTAL_ASYNC      # 异步增量刷新（性能最佳）
freq = 50                      # 每50条刷新一次
num_logs = 10                  # 保留日志文件数
max_log_file = 50              # 单个日志文件最大MB
max_log_file_action = ROTATE   # 超限时动作
name_format = HOSTNAME         # 主机名格式

# 网络远程转发
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
distribute_network = no
```

审计规则配置（`/etc/audit/rules.d/audit.rules`或通过`auditctl`）：

```bash
# /etc/audit/rules.d/audit.rules - 审计规则示例

# 删除所有现有规则（谨慎使用）
-D

# 设置缓冲区大小（默认8KB，高流量系统需要更大）
-b 8192

# 失败模式（1= printk, 2= panic, 0=忽略）
-f 1

# 监控文件访问
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# 监控命令执行
-w /usr/bin/su -p x -k priv escalation
-w /usr/bin/sudo -p x -k priv escalation
-w /usr/bin/passwd -p x -k password_change
-w /usr/sbin/useradd -p x -k user_management
-w /usr/sbin/userdel -p x -k user_management

# 监控内核模块加载
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_load
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module -k module_load
-a always,exit -F arch=b64 -S finit_module -k module_load

# 监控网络配置变更
-w /etc/hosts -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config

# 监控cron任务
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# 监控登录事件
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# 监控系统调用（高风险syscall）
-a always,exit -F arch=b64 -S execve -C uid!=aid -F auid>=1000 -F auid!=4294967295 -k exec
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink,rmdir -F auid>=1000 -F auid!=4294967295 -k file_deletion

# 使规则不可变（auditd运行后无法修改，需要重启才能更改）
-e 2
```

```bash
# auditctl即时管理
# 查看当前规则
sudo auditctl -l

# 添加规则
sudo auditctl -w /etc/ssh/sshd_config -p war -k sshd_config

# 查看审计日志
sudo ausearch -k module_load --start today
# time->Mon Sep  1 10:00:00 2026
# type=SYSCALL ... comm="modprobe" exe="/sbin/modprobe"
# type=PATH ... name="/lib/modules/5.15.0/kernel/drivers/..."

# 按时间范围搜索
sudo ausearch -ts 2026-09-01 10:00:00 -te 2026-09-01 11:00:00

# 按用户搜索
sudo ausearch -ua 1000

# 生成审计报告
sudo aureport --summary
sudo aureport --auth          # 认证报告
sudo aureport --login         # 登录报告
sudo aureport --failed        # 失败事件
sudo aureport --file --summary  # 文件访问Top统计
```

### 3.4 journalctl查询语法

journalctl是查询systemd journal的命令行工具，功能强大但语法需要掌握：

```bash
# 基本查询
journalctl                          # 所有日志
journalctl -e                       # 跳到末尾
journalctl -f                       # 实时跟踪（类似tail -f）
journalctl -n 50                    # 最近50条

# 按优先级过滤（0=emerg 到 7=debug）
journalctl -p err                   # 仅err及以上
journalctl -p warning..err          # warning到err范围

# 按时间过滤
journalctl --since "2026-09-01 10:00:00"
journalctl --since "1 hour ago"
journalctl --since "yesterday" --until "today"

# 按单元（unit）过滤
journalctl -u nginx.service
journalctl -u nginx.service -u php-fpm.service
journalctl -u nginx --since "1 hour ago"

# 按进程/PID过滤
journalctl _PID=1234
journalctl _UID=1000
journalctl _COMM=sshd              # 按命令名过滤

# 按内核消息过滤
journalctl -k                      # 等同于dmesg
journalctl -k -p err               # 内核错误

# 输出格式控制
journalctl -o json                 # JSON格式（适合日志收集）
journalctl -o json-pretty          # 格式化JSON
journalctl -o verbose              # 所有字段
journalctl -o cat                  # 仅消息（无时间戳前缀）
journalctl -o short-iso            # ISO 8601时间格式

# 持久化状态查看
journalctl --disk-usage
journalctl --header                # 查看journal文件头信息
journalctl --verify                # 验证journal文件完整性

# 与grep组合使用（注意：先获取再过滤，性能更佳）
journalctl -u sshd --output=json | jq '.[] | select(.MESSAGE | test("Failed"))'
```

### 3.5 日志安全加固

#### 3.5.1 远程日志（防本地删除）

```bash
# rsyslog TCP远程转发
# 接收端配置（/etc/rsyslog.conf）
$ModLoad imtcp
$InputTCPServerRun 514
template(name="RemoteLogs" type="string"
    string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?RemoteLogs

# 发送端配置
$ModLoad imudp
*.* @@192.168.1.100:514;RSYSLOG_SyslogProtocol23Format
```

#### 3.5.2 日志只读保护

```bash
# 使用auditd监控日志文件被修改
-w /var/log/syslog -p wa -k log_tampering
-w /var/log/auth.log -p wa -k log_tampering
-w /var/log/audit/audit.log -p wa -k log_tampering

# 使用chattr设置不可变属性（防止删除/修改）
sudo chattr +a /var/log/auth.log          # append-only
sudo chattr +i /var/log/audit/audit.log   # 完全不可变（auditd需要特殊配置）
```

#### 3.5.3 日志加密传输

```bash
# 使用stunnel为syslog添加TLS加密
# /etc/stunnel/syslog-client.conf
[syslog-tls]
client = yes
accept = 127.0.0.1:6514
connect = 192.168.1.100:6514
cert = /etc/ssl/certs/client.pem
key = /etc/ssl/private/client.key
CAfile = /etc/ssl/certs/ca.pem

# rsyslog原生TLS配置
$DefaultNetstreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
*.* @@192.168.1.100:6514
```

#### 3.5.4 时间同步（防时钟篡改）

```bash
# 确保NTP同步（防止日志时序被篡改）
timedatectl status
# NTP service: active

# 使用chrony（推荐）
sudo apt install chrony
sudo systemctl enable --now chrony
chronyc tracking
# System time : 0.000001234 seconds fast of NTP time

# 强制时间同步策略
# /etc/chrony/chrony.conf
server ntp.example.com iburst
makestep 1.0 3        # 启动后3次大步调整（超过1秒立即修正）
rtcsync               # 同步RTC硬件时钟
```

## 4. 实战与示例

### 4.1 实验一：构建企业级日志收集架构

```text
架构设计：
应用服务器 x N ----> 日志收集服务器 ----> SIEM/ELK
   |                    |
   +-- rsyslog          +-- rsyslog (TLS接收)
   +-- journald         +-- Logstash/Filebeat
   +-- auditd           +-- Elasticsearch
                        +-- Kibana/Grafana
```

```bash
# 服务器端：配置rsyslog接收远程日志
# /etc/rsyslog.d/remote.conf
module(load="imtcp")
module(load="imudp")

input(type="imtcp" port="514" address="0.0.0.0")

template(name="RemoteHost" type="string"
    string="/var/log/remote/%HOSTNAME%/messages.log")
template(name="RemoteHostAuth" type="string"
    string="/var/log/remote/%HOSTNAME%/auth.log")

if $fromhost-ip != '127.0.0.1' then {
    action(type="omfile" dynaFile="RemoteHost")
    if $syslogfacility-text == 'auth' or $syslogfacility-text == 'authpriv' then {
        action(type="omfile" dynaFile="RemoteHostAuth")
    }
}

# 客户端：配置rsyslog转发所有日志
# /etc/rsyslog.d/forward.conf
$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca-cert.pem
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
$ActionSendStreamDriverPermittedPeer logserver.internal

# 队列配置（防丢）
$ActionResumeRetryCount -1
$ActionQueueType LinkedList
$ActionQueueFileName forward_queue
$ActionQueueMaxDiskSpace 256M
$ActionQueueSaveOnShutdown on
$ActionQueueTimeoutEnqueue 0

*.* @@logserver.internal:6514;RSYSLOG_SyslogProtocol23Format
```

### 4.2 实验二：auditd检测可疑活动

```bash
# 场景：检测暴力破解SSH密码

# 步骤1：创建审计规则
sudo auditctl -w /var/log/auth.log -p rwa -k auth_log
sudo auditctl -a always,exit -F arch=b64 -S open -F dir=/var/log -F success=0 -k log_access_fail

# 步骤2：模拟攻击并分析
# 查找短时间内多次失败的登录尝试
sudo ausearch -k auth_log --start today | \
    grep "Failed password" | \
    awk '{print $NF}' | \
    sort | uniq -c | sort -rn | head -10
#   147 from 192.168.1.50
#    89 from 10.0.0.100

# 步骤3：自动阻止（结合fail2ban）
# auditd检测 -> 自定义脚本 -> fail2ban/iptables封禁

# 场景：检测sudo提权
sudo auditctl -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/sudo -k sudo_usage
sudo ausearch -k sudo_usage --start today -i
# type=EXECVE ... a0="sudo" a1="rm" a2="-rf" a3="/var/log"
#          ^^^ 检测到用sudo执行危险命令
```

### 4.3 实验三：日志完整性监控

```bash
# 使用aide（Advanced Intrusion Detection Environment）监控日志文件完整性
sudo apt install aide

# 配置监控日志目录
# /etc/aide/aide.conf
/var/log/admin = p+i+n+u+g+s+b+m+c+sha256
/var/log/audit = p+i+n+u+g+s+b+m+c+sha256
/etc/rsyslog.conf = p+i+n+u+g+s+b+m+c+sha256

# 初始化数据库
sudo aideinit

# 定期检查
sudo aide --check

# 使用inotifywait实时监控日志变更
sudo apt install inotify-tools
inotifywait -m -r -e modify,delete,move /var/log/audit/
# /var/log/audit/ MODIFY audit.log
# /var/log/audit/ DELETE old-audit.log
#            ^^^ 告警：日志被删除
```

## 5. 常见坑与避坑指南

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `journalctl` 查询极慢（大journal） | journal文件超过10GB | 设置`SystemMaxUse`和`MaxRetentionSec`限制大小；定期`journalctl --vacuum-size=1G` |
| rsyslog远程转发丢失日志 | 网络抖动或接收端不可用 | 启用磁盘队列（`$ActionQueueFileName`），设置`$ActionResumeRetryCount -1` |
| `auditd`日志文件快速增长占满磁盘 | 审计规则过宽或未配置轮转 | 精细化审计规则（减少`-w`覆盖范围），设置`max_log_file=50`和`max_log_file_action=ROTATE` |
| 时区不一致导致日志时间混乱 | 服务器时区配置不一致 | 统一使用UTC（`timedatectl set-timezone UTC`），确保NTP同步 |
| `auditctl`规则加载后`ausearch`搜索不到 | `-e 2`（不可变模式）阻止了规则修改 | 规则变更需在`-e 2`之前完成，或重启auditd |
| journald `RateLimitBurst`限制导致日志丢失 | 短时间大量日志触发速率限制 | 调高`RateLimitIntervalSec`和`RateLimitBurst`，或关闭速率限制（不推荐） |
| `rsyslog` `TCP`传输比`UDP`更可靠但更慢 | TCP有连接开销，UDP无保证 | 高可靠性场景用TCP/TLS；低延迟场景用UDP；生产环境推荐TCP+队列 |
| `audit.log`权限被修改导致auditd写入失败 | 文件权限或SELinux策略问题 | 检查`/var/log/audit/audit.log`权限为`0600`，owner为`root:root` |
| `journalctl -f` 输出大量噪音 | 日志级别过低 | 使用`-p warning`过滤低优先级；按unit过滤`-u <service>` |
| 日志轮转后`auditd`不重新打开日志 | `auditd`使用文件描述符保持打开 | 使用`augenrules --reload`或`service auditd rotate`触发轮转 |

## 6. 知识关联

- [[08-systemd：unit文件编写与服务管理]] — journald作为systemd核心组件，unit文件中`StandardOutput=journal`将服务日志路由到journald
- [[06-权限体系：rwx-ACL-setuid-capabilities]] — auditd的`CAP_AUDIT_CONTROL`/`CAP_AUDIT_WRITE` capability需求，日志文件权限模型
- [[04-进程管理：ps-top-信号机制与nice]] — 日志daemon进程管理，auditd/rsyslog的进程优先级调整
- [[05-网络命令链：ip-ss-tcpdump-nmap排查实战]] — 远程日志传输的网络配置，TCP/UDP端口514/6514
- [[11-内核模块：编写编译与insmod加载]] — 内核模块加载事件的audit记录（`finit_module` syscall审计）
- [[12-eBPF入门：kprobe与可观测性工具]] — eBPF事件通过ring buffer/perf event输出，可路由到日志系统长期存储
- [[01-目录结构与FHS规范：一切皆文件]] — `/var/log/`目录结构与FHS日志规范

## 7. 参考资料

1. **rsyslog Documentation**: https://www.rsyslog.com/doc/
2. **systemd-journald man page**: https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html
3. **Linux Audit System**: https://www.kernel.org/doc/html/latest/audit/index.html
4. **auditd man page**: https://man7.org/linux/man-pages/man8/auditd.8.html
5. **auditctl man page**: https://man7.org/linux/man-pages/man8/auditctl.8.html
6. **journalctl man page**: https://man7.org/linux/man-pages/man1/journalctl.1.html
7. **RFC 5424** - The Syslog Protocol: https://tools.ietf.org/html/rfc5424
8. **CIS Benchmarks** - Linux logging requirements: https://www.cisecurity.org/cis-benchmarks
9. **PCI-DSS v4.0** - Requirement 10: Logging and Monitoring: https://www.pcisecuritystandards.org/
10. **LWN.net** - "The Linux audit system": https://lwn.net/Articles/630251/
