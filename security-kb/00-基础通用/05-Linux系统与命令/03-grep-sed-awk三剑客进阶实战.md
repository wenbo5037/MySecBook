---
title: "grep-sed-awk三剑客进阶实战"
category: "00-基础通用/05-Linux系统与命令"
tags: [grep, sed, awk, 正则, 文本三剑客]
level: 主攻
type: ai-generated
status: 完成
updated: 2026-09-08
---

# grep-sed-awk三剑客进阶实战

> 本文内容聚焦 Linux 系统合法文本处理与日志分析技术，属于系统运维与数据处理通用技能，未涉及任何攻击性技术。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | `grep` 按正则匹配行并输出；`sed` 流编辑器按行读入、按地址与替换规则修改；`awk` 面向行的编程语言，按字段切分并支持条件、循环、统计 |
| 核心用途 | 日志检索与关键字告警、文本批量替换、按字段提取/统计、ETL-like 数据处理、awk 写统计脚本、sed 做原地缓存替换 |
| 关键参数 | grep:`-E -P -o -v -l -r -c -A -B -i`；sed:`-n -i -e s/.../`；awk:`-F -v NR NF FS print $1` |
| 常见风险 | 正则贪婪/回溯DoS、未`-i`备份导致不可逆替换、awk 未初始化变量、grep 基本/扩展正则混淆、二进制文件误判、locale 影响排序与比较 |
| 关联知识 | [[02-文件与文本命令精讲：find-xargs-sort-uniq]]、[[07-Shell脚本编程：变量展开与子shell陷阱]]、[[13-日志体系：syslog-journald-auditd配置]] |

## 1. 概述

grep、sed、awk 常被称为 Unix/Linux 的"文本处理三剑客"。它们共同构成了命令行处理文本的核心能力：

- **grep**（Global Regular Expression Print）：定位"哪一行匹配"。
- **sed**（Stream Editor）：逐行处理与修改，擅长替换、删除、插入、提取区间。
- **awk**：以字段为中心的编程语言，擅长按列处理、统计、格式化输出、复杂条件逻辑。

三者配合管道可以完成从"找"到"改"到"算"的完整数据流：

```
日志文件 ──► grep 过滤出关心的行 ──► sed 清洗/替换字段 ──► awk 按列统计与求和
```

对运维与安全分析而言，三剑客是日志挖掘（log mining）、告警提取、指标聚合的基础。文章会穿插真实日志分析示例（nginx access log、系统日志），并强调正则安全（ReDoS）、不可逆替换、编码与 locale 等常见坑。

三剑客各自的设计哲学不同：grep 是"过滤器"，专注于行匹配；sed 是"编辑器"，专注流式修改；awk 是"小语言"，具备完整控制流。理解三者的边界，才能选择最合适的工具。

## 2. 核心原理

### 2.1 grep 的处理模型

grep 逐行读取输入流，把每一行与给定正则表达式匹配，匹配的行(默认)输出。它内部有一套正则引擎（BRE/ERE/PCRE），不同类型用不同参数启用。

```
输入行 ──► 正则引擎匹配 ──► 匹配? ──► 是：输出该行(或-l/-c等) / 否：丢弃
```

### 2.2 sed 的流式处理模型

sed 是一行一行的"流编辑器"：读入一行到模式空间(pattern space)，执行脚本中的命令(按地址与条件)，输出处理结果，再读下一行。

```
读入一行 ──► 放入模式空间 ──► 依次执行地址匹配的命令(替换/删除/打印) ──► 输出 ──► 下一行
```

sed 的"地址"决定命令作用于哪些行：行号、正则、范围、最后一行`$`。

### 2.3 awk 的记录与字段模型

awk 在整个输入文件中维护隐式状态：每条"记录"(record，默认是一行，可用 RS 改)分隔为多个"字段"(field，默认空白分隔，可用 FS 改)。每读一条记录执行一遍 pattern 与 action。

```
记录(默认一行)
  ┌────────────┬───────────┬───────────┐
  │  $1 字段     │  $2 字段    │   $3 字段   │
  └────────────┴───────────┴───────────┘
  NR=行号(全局) FNR=当前文件行号 NF=字段数 $0=整行
```

awk 具备 BEGIN(处理前)、END(处理后)、if/while/for、自定义函数、多维数组((awk4) 下标数组，ar) 等能力，实际上是一门小型编程语言。

## 3. 详细知识点

### 3.1 grep 的参数与正则选择

| 参数 | 作用 |
|------|------|
| `-E` | 扩展正则(ERE)，`+ ? | () {}` 不再需要转义 |
| `-P` | PCRE 兼容正则（Perl 风格），支持非贪婪、前瞻 |
| `-o` | 只输出匹配到的部分（而非整行） |
| `-v` | 反向匹配（输出不匹配的行） |
| `-l` / `-L` | 只输出含/不含匹配的文件名 |
| `-c` | 只输匹配行数 |
| `-r` / `-R` | 递归搜索目录 |
| `-i` | 忽略大小写 |
| `-n` | 输出行号 |
| `-A/-B/-C N` | 匹配行后/前/前后N行上下文 |
| `-x` | 整行匹配 |
| `--include=PAT` | 递归时只搜指定文件名模式 |

正则差异：默认是 BRE（basic），`+ ? | ()` 需转义；`-E` 是 ERE，无需转义；`-P` 支持非贪婪`+?`与前瞻`(?=...)`。

### 3.2 sed 的核心命令与地址

常用命令：

| 命令 | 作用 |
|------|------|
| `s/old/new/g` | 替换，`g` 全局、默认只替换每行第一个 |
| `d` | 删除匹配行 |
| `p` | 打印（通常配合 `-n` 抑制默认输出） |
| `a\` / `i\` | 行后/行前插入文本 |
| `c\` | 整行替换 |
| `=` | 输出行号 |

地址形式：
- 行号：`3`、`1,5`、`1~2`(奇数行)、`$`(最后一行)
- 正则：`/pattern/`、`/start/,/end/`(范围)
- 组合：`/pat/p`、`2,/pat/d`

`-i` 原地修改（直接改文件），务必先用无 `-i` 的版本测试。`-i.bak` 可备份。

### 3.3 awk 的内建变量与编程结构

内建变量：
- `NR`：已读总记录数；`FNR`：当前文件记录数
- `NF`：当前记录字段数
- `FS`：字段分隔符（可用 -F 或 FS 设置，支持正则）
- `RS`：记录分隔符（默认换行）
- `$0`：整行；`$1..$N`：各字段；`$(NF)`：最后字段

action 结构：
- `BEGIN { }`：读文件前执行
- `pattern { action }`：对每条匹配记录
- `END { }`：全部读完后执行

字段分隔支持正则，例如用 `:` 分隔 passwd：`awk -F':' '{print $1}' /etc/passwd`

### 3.4 awk 常用的内置函数

- 字符串：`length(s)`、`substr(s,start,len)`、`index(s,t)`、`split(s,a,sep)`、`tolower/toupper`
- 数值：`int(x)`、`sqrt`、`sin/cos`、`rand()/srand()`
- 格式化：`printf`、`sprintf`
- 判断/数组：`in` 操作符、`delete a[k]`

awk 数组下标其实是字符串，所以 `arr[$1]++` 用第一列的值做键实现计数，这正是日志统计的核心技法。

### 3.5 三剑客组合与管道

典型日志分析管道：

```bash
awk '{print $9}' access.log | sort | uniq -c | sort -rn | head -5
```

这里 awk 负责取值、sort+uniq 去重计数、sort 排 TOP。该模式在 [[02-文件与文本命令精讲：find-xargs-sort-uniq]] 有详细展开。

## 4. 实战与示例

### 4.1 grep 综合实战

```bash
# 非贪婪提取：只取 IP 段（PCRE）
grep -oP '\d{1,3}(\.\d{1,3}){3}' access.log | head
# 带上下文
grep -A2 -B1 'ERROR' app.log
# 递归只搜代码文件、含函数
grep -rni --include='*.py' 'def main' src/
# 统计匹配行数
grep -c '401' access.log
# 反向排除
grep -v '^#' /etc/ssh/sshd_config
```

### 4.2 sed 替换实战

```bash
# 替换（先测试不写 -i）
sed 's/foo/bar/g' input.txt
# 原地修改并备份
sed -i.bak 's/old/new/' config.conf
# 只改第3行
sed '3s/old/new/' file
# 删除第5到10行
sed '5,10d' file
# 打印第1到第5行
sed -n '1,5p' file
# 用正则范围抽日志区间
sed -n '/ERROR/,$p' app.log
```

### 4.3 awk 统计实战

```bash
# 输出第1列用户，第3列UID（passwd）
awk -F':' '{print $1, $3}' /etc/passwd
# 计算某列之和/均值
awk '{sum+=$5} END {print "sum="sum, "avg="sum/NR}' file
# 统计日志状态码计数
awk '{cnt[$9]++} END {for (c in cnt) print c, cnt[c]}' access.log
# 条件求和（金额超过100的行）
awk '$2 > 100 {total+=$2} END {print total}' sales.txt
# printf 格式化
awk -F',' '{printf "%s\t%5.2f\n", $1, $2}' data.csv
# 行号与字段
awk '{print NR": "$1}' file | head
```

### 4.4 组合实例：提取并统计 5xx 错误与来源 IP

```bash
# 假设 access.log 列为：IP 时间 请求 状态码 大小
awk '$4 ~ /^5/ {src[$1]++} END {for (i in src) print src[i], i}' access.log | sort -rn | head -10
```

### 4.5 实际演示输出

对一段 nginx access log 演示：

```text
192.168.1.5 - - [09/Sep/2026:10:00:01] "GET /api HTTP/1.1" 200 512
192.168.1.5 - - [09/Sep/2026:10:00:02] "GET /api HTTP/1.1" 404 180
10.0.0.3   - - [09/Sep/2026:10:00:03] "GET /admin HTTP/1.1" 500 0
```

```bash
awk '$9 == 500 {print $1}' access.log       # 出 500 的 IP
# 输出
# 10.0.0.3
```

## 5. 常见坑与避坑指南

| 坑点 | 现象 | 原因 | 规避建议 |
|------|------|------|----------|
| sed -i 误改 | 文件内容被破坏 | 未先测试 | 先无 -i 演练，用 -i.bak 备份，改前 diff |
| 正则贪婪爆栈 | grep/sed 卡死或慢 | 复杂 PCRE 导致回溯（ReDoS） | 用非贪婪 `+?`，限制输入，避免嵌套回溯 |
| BRE/ERE 混淆 | `+` 被当字面量 | 用默认 BRE 未 -E | 记清楚默认 BRE，必要时加 -E/-P |
| awk 变量未初始化 | 结果 NaN/0 | 隐式变量默认 0/空 | 显式初始化，理解 BEGIN 作用 |
| awk 用 NR 但对多文件混淆 | 行号不对 | NR 是全局计数 | 多文件用 FNR |
| uniq 依赖 sort | 去重不全 | uniq 只去相邻 | 先 sort 再 uniq |
| grep 二进制文件 | "Binary file ... matches" | 文件含 NUL | 加 `-a`（当文本）/`-I`（忽略二进制） |
| locale 影响 sort | 排序顺序诡异 | 受 LC_ALL 影响 | `LC_ALL=C sort ...` 得到稳定字节序 |
| 转义地狱 | 正则失效 | shell/引号/正则多重转义 | 用单引号包正则，必要时 -E/-P 简化 |
| `-o` 与整行混用 | 提取结果不一致 | 误解 -o 语义 | 明确要 `-o`(片段) 还是默认(整行) |

## 6. 知识关联

- [[02-文件与文本命令精讲：find-xargs-sort-uniq]]：三剑客常与 find/sort/uniq 串成管道
- [[07-Shell脚本编程：变量展开与子shell陷阱]]：命令替换、grep 赋值、awk 与 shell 变量传递的坑
- [[13-日志体系：syslog-journald-auditd配置]]：日志检索、告警规则中 grep/awk 的实际应用
- [[10-性能排查：vmstat-iostat-perf火焰图实战]]：用管道统计性能指标时的文本处理配合
- [[01-目录结构与FHS规范：一切皆文件]]：/var/log 与 /proc 文本信息的处理基础

## 7. 参考资料

- GNU grep 官方文档：https://www.gnu.org/software/grep/manual/
- GNU sed 官方文档：https://www.gnu.org/software/sed/manual/
- GNU awk (gawk) 官方文档：https://www.gnu.org/software/gawk/manual/
- man 手册：`man 1 grep`、`man 1 sed`、`man 1 awk`、`man 1 gawk`
- 《鸟哥的Linux私房菜 基础学习篇》（第三版），第 12 章 正则表达式
- 《The AWK Programming Language》(Aho, Kernighan, Weinberger) 经典原书
- CSAPP《深入理解计算机系统》附录中对命令行数据处理工具的关联理解（可选）
