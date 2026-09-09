---
type: 网络安全主题
难度: 高级
前置知识: "[[01-002-x86-64汇编与栈帧基础]]"
对应语言等级: 精通级
status: Active
related_to:
  - "[[二进制安全]]"
---

# 01-007 利用保护机制：NX、ASLR、PIE、Canary 与 RELRO

## 基础信息
- 难度：高级
- 前置知识：[[01-002-x86-64汇编与栈帧基础]]、[[01-003-ELF文件格式与链接机制]]
- 对应语言等级：精通级

## 核心原理

现代 Linux 系统通过「纵深防御」在编译期、加载期与运行期叠加了五类主要防护。攻击者视角下，这些机制共同决定了每一步利用必须满足的约束（constraint）：栈不可执行则无法直接跳转到 shellcode；代码段地址随机则固定地址的 ret2text 失效；返回地址有 canary 校验则必须先泄露或逐字节爆破；GOT 只读则无法改写 GOT 实现 hook。理解这些机制的**实现位置与可绕过条件**，是编写真实可利用样本的前提。

防护的落地分层：**编译器**（GCC/Clang）负责插入 canary 校验、生成 PIC/PIE 代码、标记栈区属性；**内核**（Linux）在响应 `randomize_va_space` 时执行地址空间布局随机化；**动态链接器**（glibc 的 ld.so）负责抢占 GOT 的 RELRO 落地与重定位。每一层的开关都可以通过编译选项、程序头标记或 sysctl 单独控制，因此实战中「逐个确认防护现状」是第一步。

## 技术要点

### NX（No-eXecute）与 W^X

- 原理：x86-64 页表项（PTE）第 63 位为 NX 位（AMD 实现，Intel 采用类似方案随 EMT64/IA-32e 引入），将此位置 1 后该页只能读/写、不可执行，CPU 页表遍历时即拒绝取指（#PF 类型为 instruction fetch）。Linux 把栈、堆、匿名映射区统一定义为不可执行。意外灾难的是，若程序要求可执行栈仍可通过 `execstack` 工具恢复（PAX_RETPOLINE? 不，paX 无关）——因此检查实际标记比默认假设重要。
- 编译控制：`gcc -z execstack` 在 GNU_STACK 程序头置 `RWE` 标记；`-z noexecstack`（默认）置 `RW`。可执行栈标记由内核与 ld.so 读取，标记为不可执行的栈在 glibc 启动时就对 mmap 区应用原子。用 `readelf -l` 查看 `GNU_STACK` 段即可确认。
- 绕过条件：只要能被 `mprotect` 改回可执行（`PROT_EXEC`），就可以把 shellcode 所在页变成可执行——经典 ret2libc/ret2syscall 正是「不执行注入数据」的替代方案。所以 NX 本身**不阻止控制流劫持**，只阻止「跳进数据页执行」。

### ASLR（Address Space Layout Randomization）

- 实现：Linux 通过内核 `mmap_rnd_bits`/`mmap_rnd_bytes` 与文件映射随机化，将 mmap 基址、栈基址、DTV/线程栈、堆（brk）基址在进程启动时随机化。sysctl 参数 `kernel.randomize_va_space`：`0` 关闭、`1` 仅随机 mmap/栈（堆仍固定）、`2`（默认）完整随机含 brk 堆。其权威定义位于内核文档 `admin-guide/sysctl/kernel.rst`。
- 影响范围：**ET_DYN（PIE 动态可执行文件）的代码段/数据段基址也随机**；而 ET_EXEC（非 PIE）的可执行文件基址固定为链接时地址（传统 0x400000）。现代发行版（如 Ubuntu 20.04+）默认 `-pie` 编译。
- 关闭方法（实验环境）：`setarch -R ./vuln`（设置 `personality(ADDR_NO_RANDOMIZE)`）、GDB 内 `set disable-randomization on`、或 sysctl 置 0。注意 GDB 默认会关掉 ASLR，否则现场调试地址不稳定。
- 绕过：**相对偏移固定**。PIE 下虽然绝对基址随机，但指令相对偏移不变，可用 `getauxval(AT_BASE)`、动态链接器 `.bss` 数据、或部分覆盖（partial overwrite）来修正。只随机化基址而非其内部相对布局是 ASLR 的根本局限。

### PIE（Position Independent Executable）

- 原理：与位置无关代码（PIC）同样适用于可执行文件本身。GCC 用 `-fPIE -pie` 生成、链接器 `-pie` 将其链接为 ET_DYN。加载后所有绝对地址都要经过 GOT/相对基址计算，配合 ASLR 达到「每次运行基址不同」。
- 判断：`readelf -h ./prog` 中 `Type: DYN (Position-Independent Executable file)` 即 PIE，`Type: EXEC` 则是非 PIE（基址固定）。`checksec`（pwntools/checksec.sh/GEF）给出直观汇总。
- 关闭：`gcc -no-pie`。CTF 与教材为降低门槛常常关闭，但真实二进制几乎都是 PIE。
- 绕过：不需要 ROP 重定位 gadget 时可以 ret2plt（PLT 跳转由动态链接器解析绝对地址，本身与基址无关）；需要精确地址时泄露基址（一遍 leak → 计算 delta → 重算目标）。

### Stack Canary（栈金丝雀）

- 原理：函数序跋插入检查值。GCC 在函数入口从线程局部存储 `fs:0x28`（x86-64：`%fs` 段基址指向 TLS，偏移 0x28 处为 stack guard）取随机值存入栈上 Canary 槽，返回前与 `fs:0x28` 比对，不一致即调用 `__stack_chk_fail`（GCC 自动链接，默认 SIGABRT 并打印 `*** stack smashing detected ***`）。Canary 最低字节固定为 `\x00`，利用字符串拷贝函数（strcpy 等）天然无法直接读到，形成第一道屏障。
- 编译控制：`-fstack-protector`（仅对含较大的缓冲数组与其
它危险函数的函数插樫）、`-fstack-protector-all`（所有函数）、`-fstack-protector-strong`（Ubuntu 默认，含 `local数组/地址引用` 等）、`-fno-stack-protector`（关闭）。`-fstack-clash-protection` 针对栈冲突（stack clash, CVE-2017-1000364 系）在栈增长处插被探测页。
- 绕过条件：1) **泄露 canary**后原样回填（leak 通常来自格式化字符串或多重溢出）；2) **fork 后 canary 相同**（TLS 随进程复制，可在每次响应前爆破 1 字节，但会触发 __stack_chk_fail 造成一次进程崩溃，与 fork 容忍崩溃的服务结合）；3) 覆盖返回地址上游的超大溢出直接整段覆写包括 canary 上方区域（仍会失败于返回校验）；4) 在**覆盖返回地址之前**的位置一般无法写（越过 canary 与 RBP），但若溢出终点在返回地址之上（如覆盖到函数序言的保存区上一大片）仍受校验限制。

### RELRO（RELocation Read-Only）

- 两种级别：**partial RELRO**（`-z relro`，非默认？实际 GCC 默认 partial）把 `.got` 中的非重定位部分（`.got.plt` 之前）置只读；**full RELRO**（`-z relro -z now`）将全部 GOT 在启动早期重定位结束后置只读（所以 `now` 全量立即绑定）。判读：`readelf -l` 中 GNU_RELRO LOAD 段的 Read 位，或 checksec。
- 影响：partial 下 `.got.plt` 可写 → 覆盖 GOT 指到 system/one-gadget 的经典手法可行；full 下 GOT 只读，只能改函数指针、vtable、environ 或直接攻击返回地址。ret2dlresolve 攻击依赖 partial RELRO 时才可行（需要篡改 `.rela.plt`？实际是把伪造的动态链接数据结构指向可控内存），full RELRO 下失去该路径。

### 汇总与判读工具

checksec 系工具读 ELF 程序头与段并输出 `NX enabled / PIE enabled / Canary found / RELRO: Full` 等。pwntools `checksec('./prog')` 输出字节对应串。gef/gdb `checksec` 同理。示例输出：`RELRO: Partial RELRO / Stack canary: Canary found / NX: NX enabled / PIE: PIE enabled`。

## 实践示例

环境：Ubuntu 20.04 LTS x86_64、GCC 9.4.0、binutils 2.34、pwntools 4.11.0。

以一个含溢出的规范样例演示五类防护的开关与判读：

```c
// vuln.c
#include <stdio.h>
#include <string.h>

void vuln(char *s) {
    char buf[64];
    strcpy(buf, s);   // 无边界拷贝
    puts(buf);
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
```

编译四种配置：

```bash
gcc -o vuln_default vuln.c                 # 发行版默认（全开）
gcc -fno-stack-protector -o vuln_lax vuln.c
gcc -no-pie -o vuln_nopie vuln.c
gcc -z execstack -fno-stack-protector -o vuln_legacy vuln.c
```

判读：

```bash
readelf -l vuln_default | grep -E "GNU_STACK|GNU_RELRO"
readelf -h vuln_default | grep Type          # DYN = PIE
checksec --file=vuln_default                 # checksec.sh
python3 -c "from pwn import *; print(checksec('vuln_default'))"
```

`vuln_default` 预期为全开（Canary found、NX enabled、PIE enabled、Full RELRO），`vuln_legacy` 为部分关闭（可执行栈）。再做一次给系统化的验证：用 `setarch -R` 关 ASLR 前后观察同一 PIE 程序两次运行的 `info proc mappings`（gdb/gef 的 vmmap）基址差：

```bash
gdb -q ./vuln_default -ex "set disable-randomization off" -ex "start" \
    -ex "info proc mappings" -ex quit
gdb -q ./vuln_default -ex "set disable-randomization off" -ex "start" \
    -ex "info proc mappings" -ex quit   # 两次基址不同
```

两次输面的 `Start Addr`（.text 段）不同即验证 ASLR+PIE 生效。

## 常见问题与误区

- 误区一：以为 ASLR = 所有地址都随机。实际上非 PIE 程序代码段固定、brk 堆在 `randomize_va_space=1` 时也固定；且 PIE 下**相对偏移不变**，这恰是多数利用的精算基础。
- 误区二：以为 canary 每次运行都不同，无法爆破。canary 存在 TLS，`fork` 出的子进程从父进程复制 TLS，**一次中父子 canary 相同**；配合 fork 型服务可逐字节爆破（每字节 256 试，失败即崩溃，子进程重启）。
- 误区三：混淆 partial/full RELRO 对 GOT 写的效力。partial 的 `.got.plt` 可写，GOT 覆盖（overwrite GOT）可行；full RELRO 后 GOT 只读，必须转向改写函数指针或返回地址。拿到二进制先 checksec 再定利用路径，否则把时间花在不可能的路线上。
- 注意：仅可在本人授权环境（本地编译漏洞程序、CTF 平台、授权靶场）中做关防护/越对抗实验。

## 参考来源
- GCC Options（`-fstack-protector*`、`-z execstack`、`-fPIE/-pie/-no-pie`） - 官方文档 - https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html
- GNU ld manual（`-z noexecstack`、`-z relro`、`-z now`） - 官方文档 - https://sourceware.org/binutils/docs/ld/Options.html
- Linux kernel sysctl doc（`randomize_va_space`） - 官方文档 - https://docs.kernel.org/admin-guide/sysctl/kernel.html
- pwntools checksec 文档 - 开源项目 - https://github.com/Gallopsled/pwntools
- checksec.sh - 开源项目 - https://github.com/slimm609/checksec.sh
- System V ABI AMD64（NXC? 架构无关，栈与映射属性约定） - 权威标准 - https://gitlab.com/x86-psABIs/x86-64-ABI

## 合规声明
本文仅用于授权安全测试与学习研究，未经授权对他人系统进行测试属于违法行为。