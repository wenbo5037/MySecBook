---
type: Article
status: 已发布
module: "[[模块01：计算机组成原理]]"
---

# [01-22] Cache映射方式与缓存行

## 版本信息
- 文档版本：v1.0
- 更新日期：2026-09-09
- 适用工具版本：Linux perf、GCC 13+、Python 3.11+

## 难度级别
中级

## 前置知识
- [[01-21 局部性原理与存储层次]]：局部性与层次

## 学习目标
1. 能描述直接映射、组相联、全相联三种 Cache 结构
2. 能计算 tag/index/offset 位划分
3. 能分析 cache 行大小、容量与相联度对命中率的影响

## 核心内容

### 概念与原理

Cache 把主存划分为定长**缓存行（cache line）**（通常 64 字节）。地址被分为三部分：**tag（标志）**、**index（索引）**、**offset（块内偏移）**。由 index 决定行槽位，tag 判断命中（是否是该槽存的地址），offset 选取字节。

三种映射：
- **直接映射（direct-mapped）**：每个 index 只有一个槽，简单但冲突多。
- **组相联（set-associative）**：每组多个路，冲突分摊到 n 路（n-way）。
- **全相联（fully associative）**：任意地址可放任意槽，命中最好但比较硬件贵。

### 技术细节

#### 位划分公式
若 Cache 容量 C、行大小 L、路数 A：
- 组数 S = C/(L·A)，index 用 `log2(S)` 位；
- offset 用 `log2(L)` 位；
- 其余高地址位为 tag。

例：64KB，64B 行，4 路 → 组数=256，index=8 位，offset=6 位，tag=地址高 64-14 位（对 64 位地址）。

#### 替换与写入
LRU/pseudo-LRU 换行；写回（write-back）vs 写直达（write-through）影响一致与性能（与[[01-23 MESI]]、[[02-19]]相关）。

#### 冲突与别名
直接映射下多个映射到同一组的地址引发**冲突缺失（conflict miss）**，一步态数组 stride 访问极易触发（见实验）。

### 代码/命令示例

Python 模拟直接映射 cache 的 tag/index 计算：

```python
def cache_bits(addr, cap=64*1024, line=64, ways=1):
    off = line.bit_length()-1
    sets = cap//(line*ways)
    idx = sets.bit_length()-1
    return addr & ((1<<idx)-1), (addr>>idx) & ((1<<(64-idx-off))-1), addr & ((1<<off)-1)

idx, tag, off = cache_bits(0x7fff_ff00)
print(idx, hex(tag), off)
```

### 工具与环境
- Linux perf - https://perf.wiki.kernel.org/
- 缓存行检测（`getconf LEVEL1_DCACHE_LINESIZE`）

## 实战案例（不少于全文30%篇幅）

### 案例1：stride 冲突制造 Cache Thrashing
- 场景描述：用 `2^k` 步长访问使多个地址映射到同一组，制造冲突看到缓存退化。
- 环境准备：Linux + gcc
- 操作步骤：
  1. 分配 `arr[256*1024]`，按 `i += 4096`（对齐到 64B 行对应 index 冲突）累加。
  2. 与随机stride 访问对比 `time`/perf。
  3. 改循环顺序（i+=1 自然序）对比。
- 预期结果：`2^k` 大步长命中率低、明显变慢；自然序快。
- 关键分析：直接映射的冲突路径解释了“不要用 2 幂步长遍历大数组”的经验，也可用于侧信道（见Flush+Reload思想）。

### 案例2：用 `getconf` 查看并用 perf 验证行大小
- 场景描述：用 getconf 取 L1 行大小，并与 perf 的 cache-misses 关联。
- 环境准备：Linux
- 操作步骤：
  1. `getconf LEVEL1_DCACHE_LINESIZE`（常见 64）。
  2. 比较 stride=64 与 stride=63 的访问次数/耗时。
- 预期结果：64 对齐处 cache 行为差异暴露行边界影响。
- 关键分析：行大小与预取行说明空间局部性的粒度，62/63 差异解释预取机制，为后续性能调优打底。

## 实验指南
1. 案例1 的 stride 实验并记录 miss。
2. 案例2 的 getconf/perf 验证。
3. 选做：用 Go 或 C 实现 stride=2^14 矩阵乘对比 blocking 优化。

## 常见误区与陷阱
1. 混淆 index 与 tag：index 是槽位，tag 是校验。
2. 认为全相联最常用：成本太高，商用为组相联折中。
3. 忽略组数与相联度的 tradeoff：多了相联度更少冲突但比较成本高。
4. 把 cache 行当 word：行含多个字，含空间局部性。

## 相关CVE/漏洞编号
- CVE-2017-5753/5754 - Cache 行为作为侧信道 - https://nvd.nist.gov/vuln/detail/CVE-2017-5753
- 深入见[[01-24 推测执行漏洞Spectre与Meltdown]]。

## 安全参考
- Patterson & Hennessy《计算机组成与设计》Cache 小节 - 教材 - ISBN: 978-0128203316
- Intel 优化手册 Chapter 3 - 官方文档
- Hill & Smith "Evaluating Associativity in CPU Caches" IEEE TC 1989 - 论文

## 延伸阅读
- Drepper《What Every Programmer Should Know About Memory》Cache 章节
- Cache side-channel 综述（如 Osvik 论文）

## 练习题
1. [基础] 计算给定 Cache 参数的 index/tag/offset 位数。
2. [进阶] 解释为什么大步长 2^k 遍历导致冲突。
3. [挑战] 用 strided access 构造一个可被观测的 cache 计时侧信道示例（理论）。

## 进度标记
- [ ] 已学习
- [ ] 已完成实验
- [ ] 已完成练习