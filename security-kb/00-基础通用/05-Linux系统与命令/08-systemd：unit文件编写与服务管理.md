---
title: "systemd：unit文件编写与服务管理"
category: "00-基础通用/05-Linux系统与命令"
tags: [systemd, unit文件, 服务管理, Linux系统]
level: 主攻
type: ai-generated
status: 完成
---

# systemd：unit文件编写与服务管理

> 本文为合法系统管理与运维研究，旨在帮助系统管理员正确编写unit文件、管理服务生命周期并加固服务安全。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | systemd是Linux系统的初始化系统和系统服务管理器，以并行方式启动服务，通过unit文件声明服务资源和依赖关系 |
| 核心用途 | 服务（.service）、挂载（.mount）、Socket（.socket）、定时器（.timer）等资源的声明式配置与生命周期管理 |
| 关键参数 | `[Service]`段：Type/ExecStart/Restart/RestartSec；`[Install]`段：WantedBy/RequiredBy；`[Unit]`段：After/Requires/Wants |
| 常见风险 | 服务以root身份运行导致提权面扩大、ExecStart路径被篡改、PrivateTmp未启用导致共享命名空间、缺少ProtectSystem/ProtectHome |
| 关联知识 | [[04-进程管理：ps-top-信号机制与nice]]、[[06-权限体系：rwx-ACL-setuid-capabilities]]、[[13-日志体系：syslog-journald-auditd配置]] |

## 1. 概述

systemd从Linux内核完成初始化后接管用户空间的整个系统生命周期。它是PID 1进程，负责：

- **服务管理**：启动、停止、重启、状态查询等生命周期操作
- **依赖解析**：基于unit文件中的Requires/After/Wants声明构建依赖图，支持并行启动
- **资源控制**：通过cgroups实现CPU份额、内存上限、IO带宽限制
- **安全加固**：命名空间隔离、能力裁剪、系统调用过滤等安全特性
- **日志管理**：与journald深度集成，提供结构化日志查询
- **定时任务**：.timer单元替代cron实现基于事件的定时调度

systemd相比传统SysV init的优势在于：

1. 启动速度快——通过依赖图并行启动无依赖关系的服务
2. 配置统一——所有服务配置统一为unit文件格式
3. 生命周期精确——通过cgroup跟踪进程树，避免僵尸进程
4. 安全特性丰富——内置多种安全沙箱能力

## 2. 核心原理

### 2.1 Unit文件结构

每个unit文件由三个段组成，顺序固定：

```ini
[Unit]
# 依赖声明与元数据
Description=My Application
After=network-online.target
Requires=network-online.target
Wants=postgresql.service

[Service]
# 服务运行配置
Type=simple
ExecStart=/usr/bin/myapp --config /etc/myapp/config.yml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=myapp
Group=myapp
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/myapp

[Install]
# 安装配置（何时启用该unit）
WantedBy=multi-user.target
```

**Unit文件搜索优先级**（从高到低）：

1. `/etc/systemd/system/` — 管理员手动配置，优先级最高
2. `/run/systemd/system/` — 运行时动态生成的unit
3. `/usr/lib/systemd/system/` — 软件包自带的默认unit

### 2.2 Service Type详解

`Type=`决定systemd如何判断服务已成功启动：

| Type | 判断逻辑 | 适用场景 |
|------|----------|----------|
| `simple` | ExecStart进程启动即视为就绪 | 前台运行的守护进程（默认值） |
| `forking` | 进程fork后父进程退出即视为就绪 | 传统daemon（通过fork+daemon模式） |
| `oneshot` | ExecStart所有命令执行完毕即视为就绪 | 初始化脚本、一次性任务 |
| `notify` | 进程通过sd_notify()主动通知就绪 | 支持systemd通知协议的现代应用 |
| `dbus` | 进程获取指定D-Bus名称即视为就绪 | D-Bus激活的服务 |
| `exec` | ExecStart命令成功执行（文件可执行）即视为就绪 | systemd 240+，比simple更精确 |

### 2.3 依赖关系模型

systemd有两种依赖类型：

- **Requires**：硬依赖。被依赖的unit失败，本unit也失败。适合有严格先后顺序的场景。
- **Wants**：软依赖。被依赖的unit失败不影响本unit。适合可选组件。
- **After**：顺序依赖。本unit在指定unit之后启动（但不自动启动指定unit）。
- **Before**：反向顺序依赖。本unit在指定unit之前启动。

关键组合模式：

```ini
# 模式一：需要且必须在其之后
Requires=database.service
After=database.service

# 模式二：可选依赖，建议在其之后
Wants=cache.service
After=cache.service

# 模式三：仅控制顺序（不建立依赖关系）
After=network-online.target
```

### 2.4 生命周期状态机

systemd服务有以下关键状态转换：

```text
inactive (dead) --[Start]--> active (running) --[Stop]--> inactive (dead)
                      |                                      ^
                      +--[Restart]--> inactive (dead) --------+
                      |                                      ^
                      +--[Reload]--> active (running) --------+
```

`Restart=`的取值决定了失败后的自动重启行为：

- `no`：不自动重启（默认）
- `on-success`：仅在退出码为0时重启
- `on-failure`：退出码非0或被信号杀死时重启
- `on-abnormal`：被信号杀死或超时时重启
- `on-abort`：仅被未捕获信号杀死时重启
- `always`：无论如何都重启

## 3. 详细知识点

### 3.1 Service类型与进程模型

**Type=simple下的ExecStart**：systemd直接管理ExecStart启动的进程。若进程退出，服务进入inactive状态。

**Type=forking下的进程模型**：ExecStart启动的进程必须fork出守护进程后退出。systemd通过监控主进程退出来判断服务启动完成。典型用法：

```ini
[Service]
Type=forking
ExecStart=/usr/sbin/nginx
PIDFile=/run/nginx.pid
```

`PIDFile=`告诉systemd去哪里读取守护进程的PID，用于进程跟踪。注意systemd只在`Type=forking`时使用PIDFile。

**Type=oneshot的多命令执行**：oneshot类型允许多个ExecStart按顺序执行：

```ini
[Service]
Type=oneshot
ExecStart=/usr/bin/mkdir -p /var/lib/myapp
ExecStart=/usr/bin/chown myapp:myapp /var/lib/myapp
ExecStart=/usr/bin/myapp --migrate
RemainAfterExit=yes
```

`RemainAfterExit=yes`使oneshot执行完后状态变为active（而非inactive），这样后续的Stop命令才有效。

**Type=notify的精确就绪检测**：应用通过`sd_notify(0, "READY=1")`主动通知systemd就绪。这是最精确的启动检测方式，适合启动耗时不确定的服务。需在C代码中调用或使用`systemd-notify`命令：

```bash
#!/bin/bash
/usr/bin/myapp &
APP_PID=$!
# 模拟就绪通知
systemd-notify --pid=$APP_PID READY=1
wait $APP_PID
```

### 3.2 安全加固配置

systemd提供了丰富的安全沙箱特性，可以大幅减小服务的攻击面：

```ini
[Service]
# 以非特权用户运行
User=myapp
Group=myapp

# 禁止获取新能力
CapabilityBoundingSet=
AmbientCapabilities=

# 文件系统保护
ProtectSystem=strict        # /usr, /boot, /etc 只读
ProtectHome=true            # /home, /root, /run/user 不可见
ReadWritePaths=/var/lib/myapp /var/log/myapp

# 命名空间隔离
PrivateTmp=true             # 独立的 /tmp
PrivateDevices=true         # 禁止访问物理设备
PrivateNetwork=true         # 禁止网络访问（仅限不需要网络的服务）
ProtectKernelTunables=true  # 禁止修改 /proc, /sys
ProtectKernelModules=true   # 禁止加载内核模块
ProtectControlGroups=true   # 禁止修改 cgroups
RestrictNamespaces=true     # 禁止创建新命名空间
RestrictSUIDSGID=true       # 禁止设置SUID/SGID

# 系统调用过滤
SystemCallFilter=@system-service  # 仅允许系统服务常用syscall
SystemCallArchitectures=native    # 仅允许本机架构

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=2G
CPUQuota=200%
```

**各安全选项的审计视角**：

- `User=` / `Group=`：若缺少此项，服务以root运行，任何服务漏洞均可直接提权
- `ProtectSystem=strict`：防止服务篡改系统文件，是安全基线的必选项
- `PrivateTmp=true`：防止通过共享`/tmp`进行符号链接攻击（symlink attack）
- `CapabilityBoundingSet=`：裁剪Linux capabilities，即使服务被攻破也无法获得敏感能力
- `SystemCallFilter=`：通过seccomp过滤系统调用，是纵深防御的关键层

### 3.3 Socket激活与按需启动

systemd支持socket激活（socket activation），允许服务在收到连接时才启动，节省系统资源：

**服务端unit文件**：

```ini
# /etc/systemd/system/myapp.socket
[Unit]
Description=MyApp Socket

[Socket]
ListenStream=8080
Accept=no

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=MyApp Service
Requires=myapp.socket

[Service]
Type=simple
ExecStart=/usr/bin/myapp
FileDescriptorStoreMax=10

[Install]
WantedBy=multi-user.target
```

socket激活的工作流程：

1. systemd先启动socket监听，文件描述符3绑定到8080端口
2. 有连接到达时，systemd启动service，并将fd3传递给服务进程
3. 服务进程通过sd_listen_fds()获取继承的socket fd

这种模式的好处：服务可以无缝升级——先启动新版本，旧版本优雅退出，期间连接不丢失。

### 3.4 Timer定时器

systemd Timer可以替代cron实现更灵活的定时任务：

```ini
# /etc/systemd/system/backup.timer
[Unit]
Description=Daily Backup Timer

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=300
Persistent=true
Unit=backup.service

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/backup.service
[Unit]
Description=Daily Backup

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup.sh
```

**常用时间表达式**：

| 表达式 | 含义 |
|--------|------|
| `OnCalendar=hourly` | 每小时 |
| `OnCalendar=daily` | 每天0点 |
| `OnCalendar=*-*-* 02:30:00` | 每天2:30 |
| `OnCalendar=Mon *-*-* 09:00:00` | 每周一9:00 |
| `OnBootSec=5min` | 启动后5分钟 |
| `OnUnitActiveSec=1h` | 上次激活后1小时 |

`Persistent=true`确保错过的执行在下次系统启动时补执行。`RandomizedDelaySec`添加随机延迟防止多机同时执行。

### 3.5 Drop-in覆盖机制

不要修改软件包自带的unit文件（升级会被覆盖）。正确做法是使用drop-in覆盖：

```bash
# 创建drop-in目录
systemctl edit myapp.service
# 这会打开编辑器，写入：
# [Service]
# Restart=always
# RestartSec=3
```

实际创建的文件是 `/etc/systemd/system/myapp.service.d/override.conf`。也可以手动创建：

```bash
mkdir -p /etc/systemd/system/myapp.service.d/
cat > /etc/systemd/system/myapp.service.d/override.conf << 'EOF'
[Service]
Restart=on-failure
RestartSec=5
MemoryMax=1G
EOF
systemctl daemon-reload
```

### 3.6 Journald日志集成

服务日志自动被journald收集，可通过以下方式查看：

```bash
# 查看指定服务的日志
journalctl -u myapp.service -f

# 查看最近100行
journalctl -u myapp.service -n 100

# 查看指定时间段
journalctl -u myapp.service --since "2026-09-01" --until "2026-09-08"

# 查看启动相关日志
journalctl -b -u myapp.service

# 按优先级过滤（0=emerg, 7=debug）
journalctl -u myapp.service -p err
```

在unit文件中配置日志输出：

```ini
[Service]
StandardOutput=journal
StandardError=journal
SyslogIdentifier=myapp
```

## 4. 实战与示例

### 4.1 编写一个完整的Web服务unit

以下是一个生产级Nginx反向代理的systemd配置：

```ini
# /etc/systemd/system/nginx-proxy.service
[Unit]
Description=Nginx Reverse Proxy
Documentation=https://nginx.org/en/docs/
After=network-online.target
Wants=network-online.target
Requires=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID

# 重启策略
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=5

# 安全加固
User=www-data
Group=www-data
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

# 资源限制
LimitNOFILE=65536
LimitNPROC=512

# 输出日志到journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nginx-proxy

[Install]
WantedBy=multi-user.target
```

### 4.2 服务生命周期操作命令

```bash
# 启用服务（创建开机自启链接）
systemctl enable nginx-proxy.service

# 立即启动
systemctl start nginx-proxy.service

# 查看状态
systemctl status nginx-proxy.service

# 查看服务详细属性
systemctl show nginx-proxy.service

# 查看服务的依赖树
systemctl list-dependencies nginx-proxy.service

# 停止并禁用
systemctl disable --now nginx-proxy.service

# 重新加载配置（不重启服务）
systemctl reload nginx-proxy.service

# 重载unit文件（修改unit文件后必须执行）
systemctl daemon-reload

# 强制重启
systemctl restart nginx-proxy.service

# 查看服务日志
journalctl -u nginx-proxy.service -f
```

### 4.3 调试unit文件语法

```bash
# 验证unit文件语法
systemd-analyze verify nginx-proxy.service

# 查看服务启动耗时
systemd-analyze blame

# 按时间排序的服务启动耗时
systemd-analyze blame | head -20

# 查看关键链启动路径
systemd-analyze critical-chain nginx-proxy.service

# 分析安全特性是否生效
systemd-analyze security nginx-proxy.service

# 查看cgroup资源使用
systemctl status nginx-proxy.service
# 输出中会显示 Tasks: X, Memory: Xmax, CPUWeight: X
```

### 4.4 使用systemd-run临时运行一次性任务

```bash
# 运行一次性任务（使用 transient unit）
systemd-run --unit=daily-cleanup \
  --on-calendar="*-*-* 03:00:00" \
  /usr/local/bin/cleanup.sh

# 运行带资源限制的临时任务
systemd-run --unit=mem-test \
  --scope \
  --property=MemoryMax=500M \
  /usr/bin/stress --vm 1 --vm-bytes 400M

# 查看临时任务状态
systemctl status daily-cleanup.service
journalctl -u daily-cleanup.service
```

## 5. 常见坑与避坑指南

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 修改unit文件后不生效 | 未执行daemon-reload | 每次修改unit文件后必须 `systemctl daemon-reload` |
| 服务启动后立即退出 | ExecStart路径错误或权限不足 | 先用 `systemd-analyze verify` 检查，再用 `journalctl -u` 查看错误日志 |
| Restart=always不生效 | 超出了StartLimitBurst限制 | 检查 `StartLimitBurst` 和 `StartLimitIntervalSec` 配置 |
| 服务无法绑定端口 | 缺少CAP_NET_BIND_SERVICE能力 | 添加 `AmbientCapabilities=CAP_NET_BIND_SERVICE` |
| 修改安全选项后服务无法启动 | ProtectSystem=strict导致写操作失败 | 添加 `ReadWritePaths=` 显式允许需要写入的路径 |
| Type=forking服务状态显示inactive | PIDFile路径不正确或进程未正确fork | 确认PIDFile指向正确的pid文件，且服务确实会fork |
| ExecStart中的环境变量未展开 | systemd不继承shell环境变量 | 使用 `Environment=` 或 `EnvironmentFile=` 显式声明 |
| Timer不触发执行 | 时间表达式格式错误或unit未启用 | 用 `systemctl list-timers` 检查，确认timer和service均已enable |
| 非root用户编辑unit被拒绝 | systemd-unit路径权限问题 | 使用 `systemctl edit` 而非直接编辑文件 |
| 服务kill信号未正确传递 | systemd默认发送SIGTERM，但应用期望SIGQUIT | 在ExecStop中显式指定信号：`ExecStop=/bin/kill -s QUIT $MAINPID` |

## 6. 知识关联

- [[04-进程管理：ps-top-信号机制与nice]]：systemd的Restart策略和KillSignal涉及进程信号机制
- [[06-权限体系：rwx-ACL-setuid-capabilities]]：systemd的CapabilityBoundingSet和AmbientCapabilities直接控制Linux capabilities
- [[07-Shell脚本编程：变量展开与子shell陷阱]]：ExecStart中的变量展开遵循systemd规则，非shell规则
- [[13-日志体系：syslog-journald-auditd配置]]：systemd服务日志通过journald收集，StandardOutput配置决定日志去向
- [[01-目录结构与FHS规范：一切皆文件]]：unit文件的搜索路径遵循systemd的层级优先级约定

## 7. 参考资料

- **man手册**：`man systemd.unit`（unit文件语法）、`man systemd.service`（服务配置）、`man systemd.exec`（执行环境配置）、`man systemd.timer`（定时器）、`man systemd.socket`（socket激活）、`man systemd-analyze`（分析工具）
- **官方文档**：https://www.freedesktop.org/software/systemd/man/ — systemd官方man页面在线版
- **systemd.io**：https://systemd.io/ — systemd项目官网，含HOWTO和最佳实践
- **《Linux Performance Optimization》**：Brendan Gregg，涵盖systemd启动性能分析方法
- **《systemd in Practice》**：Community Wiki，https://wiki.archlinux.org/title/Systemd — Arch Wiki中的systemd页面，内容详实
- **《Linux System Programming》**（第2版）：Robert Love，讲解sd_notify()等systemd API的底层机制
