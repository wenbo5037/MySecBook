---
type: Article
status: 已发布
module: "[[模块01：计算机组成原理]]"
---

# [01-24] 推测执行漏洞Spectre与Meltdown

## 版本信息
- 文档版本：v1.0
- 更新日期：2026-09-09
- 适用工具版本：Linux 内核 4.14+、gcc、Python 3.11+（含 PoC 演示）

## 难度级别
专家

## 前置知识
- [[01-12 控制冒险与分支预测]]：分支预测与 BTB
- [[01-22 Cache映射方式与缓存行]]：cache 计时与 flush
- [[01-14 乱序执行与寄存器重命名]]：乱序与提交

## 学习目标
1. 能区分 Spectre（乱序/训练）（variant 1/2）与 Meltdown（乱序读内核）的机制差异
2. 能复述隐蔽信道（cache timing + 训练）的基本构想
3. 能列举缓解方案（KPTI、retpoline、硬件屏障）及其代价

## 核心内容

### 概念与原理

2018 年 1 月，Kocher 等宣布 **Spectre** 与 Lipp 等宣布 **Meltdown**。两者都利用 CPU **推测/乱序执行**把“本不该执行/读取”的数据付之时间可观测的副效应（cache）。

- **Meltdown（CVE-2017-5754）**：允许用户态读取内核内存。机制：乱序执行把内核页内容带进 cache 后再检查权限；检查虽失败返回，但 cache 已污染，可用 Flush+Reload 计时恢复。
- **Spectre（CVE-2017-5753/5754，variant 1/2）**：通过训练分支预测器/BTB，诱导 CPU 推测性地执行攻击者选择的路径，把越界（或秘密）数据用于索引 cache 行，再计时探测。variant 1 为条件分支越界；variant 2 为目标注入（BTB 污染）。

核心掩体是**分支训练 + 缓存计时隐蔽信道**。

### 技术细节

#### Meltdown 步骤（概念）
1. flush 探测数组 cache。
2. `raise(0)； if (x) ...` 之类真实权限检查，但处理器在检查前乱序执行下一条未决 load（内核地址 → cache）。
3. 用探测数组按秘密字节索引的内存行，随后 Flush+Reload 计时确定哪个行被加载。

#### Spectre variant1 示例
```c
// 加法：只演示概念性代码
if (x < array1_size)        // 被训练为 T（错）
    y = array2[array1[x] * 4096];   // 越界 x 控制 cache 痕迹
```

#### 缓解
- **KPTI（KAISER）**：用户/内核页表隔离，消除 Meltdown（Linux 4.14.11+）。
- **Retpoline**：用返回指令替换间接跳转，阻止 BTB 注毒（编译器支持）。
- **硬件屏障**：猜测消除指令（如 `lfence`）；后续 CPU（如 HSW+微码）在 user 切换时冲刷推测状态。
- 各缓解有性能代价（KPTI 曾引起 syscall 延迟稳定增幅）。

#### 检测面
- 侧信道测量必须高精度（RDTSC/`clflush`）。
- 官方 PoC 与后续变体（variant 3a/4、L1TF、MDS）进一步证明。

### 代码/命令示例

以下仅作**教学性概念演示**，不构成可复用攻击代码；所有内容重点标注合规声明。

```python
# 伪代码演示"训练预测器→计时探测"的抽象结构（不实现攻击）
# 1) 训练 if(cond) 分支向 T 方向
# 2) 触发越界路径使秘密字节影响 cache 行
# 3) rdtsc 计时逐行 probe 确定 cache 残留
# 仅供授权安全教学环境
```

### 工具与环境
- 官方论文附 PoC：https://meltdownattack.com/
- Linux 内核文档 / CVE 页面
- 工具：`spectre-meltdown-checker`（GitHub，speed47） - https://github.com/speed47/spectre-meltdown-checker

## 实战案例（不少于全文30%篇幅）

### 案例1：用官方检查器查看本机缓解状态
- 场景描述：在自有 Linux 上运行 spectre-meltdown-checker 查看 CVE 与缓解。
- 环境准备：Linux（KPTI/微码版本可能影响结果）
- 操作步骤：
  1. 克隆 speed47/spectre-meltdown-checker。
  2. `./spectre-meltdown-checker.sh`，观察 variant1/2、Meltdown、KPTI、retpoline 状态。
  3. 对比未更新内核（历史 VM）的状态。
- 预期结果：较新系统报告已缓解；旧内核未缓解项被列出。
- 关键分析：把理论研究与系统实际防护状态对接，是评估漏洞面与运维动作的第一步。

### 案例2：CVE 研究——读取官方公告与 PoC 结构
- 场景描述：分析 meltdownattack.com 提供的 PoC 结构（fixed vs 不受信任读取）以理解原理。
- 环境准备：浏览器 + 官方 PoC（授权研究）
- 操作步骤：
  1. 阅读 PoC 主循环：`clflush`、`scaled= ...`、计时函数。
  2. 对照论文图 3 理解读写顺序。
  3. 记录关键变量（training、offset、probe array）。
- 预期结果：理解到攻击是“制造被推测读取的机会+事后计时恢复”。
- 关键分析：PoC 是研究副产品，目的在于理解硬件行为，而不是制造攻击工具——这正是安全研究（Vs 防御）的立场。

### 案例3：概念性 Covert Channel 演示（授权沙箱，非攻击代码）
- 场景描述：用两个受控进程验证“cache 时序可传信”这一前提。
- 环境准备：Linux + 授权隔离环境
- 操作步骤：
  1. 发送进程写某 cache 行；接收进程用 Flush+Reload 感知命中/缺失。
  2. 串行传输几个 bit；记录每 bit 时间差异。
  3. 关闭共享（关键回到不可共享）以说明攻击面前提。
- 预期结果：时序能可靠区分 0/1（在隔离沙箱、授权环境内）。
- 关键分析：这句话是理解 Spectre/Meltdown 的必要前提；但仅证明“cache 可通信”，不构成漏洞利用。

## 实验指南
1. 在**授权、隔离**环境中运行案例1/2（检查器只读，PoC 仅阅读结构）。
2. 案例3 的 covert channel 需授权虚拟环境（严禁现实目标测试）。
3. 建议在本地 VM + 快照下进行，遵守《网络安全法》与授权测试方针。

## 常见误区与陷阱
1. 把 Meltdown 与 Spectre 混为一谈：机制不同（特权检查 vs 训练预测器）。
2. 认为“回滚=已删除”：推测执行留下的 cache 时间痕迹不可回滚。
3. 低估缓解代价：KPTI/retpoline 都有性能开销。
4. 在未授权系统上验证：这是违法风险，仅限授权与研究环境。

## 相关CVE/漏洞编号
- CVE-2017-5753 (Spectre V1) - https://nvd.nist.gov/vuln/detail/CVE-2017-5753
- CVE-2017-5715 (Spectre V2) - https://nvd.nist.gov/vuln/detail/CVE-2017-5715
- CVE-2017-5754 (Meltdown/Spectre V3) - https://nvd.nist.gov/vuln/detail/CVE-2017-5754
- CVE-2018-3639 (V4, SSB) - https://nvd.nist.gov/vuln/detail/CVE-2018-3639
- 后续 MDS（CVE-2019-11091 等）可作延伸

## 安全参考
- Kocher et al. "Spectre Attacks: Exploiting Speculative Execution", IEEE S&P 2019 - 论文 - https://spectreattack.com/spectre.pdf
- Lipp et al. "Meltdown: Reading Kernel Memory from User Space", USENIX Security 2018 - 论文 - https://meltdownattack.com/meltdown.pdf
- Linux kernel KPTI/KAISER commits 与 retpoline 文档 - https://www.kernel.org/
- AMD/Intel 微码缓解指南（官方文档）

## 延伸阅读
- Gruss et al. "Another Flush+Reload" 及 MDS/L1TF 系列
- Google Project Zero "Reading privileged memory with a side-channel" 笔记
- 《Speculative Execution and Side Channels》综述（USENIX/CACM）

## 练习题
1. [基础] 用一两句话区分 Meltdown 与 Spectre。
2. [进阶] 画出 Spectre V1 的“训练→触发→计时恢复”三段式流程。
3. [挑战] 解释为什么 KPTI 可缓解 Meltdown 但对 Spectre 效果有限。

## 进度标记
- [ ] 已学习
- [ ] 已完成实验
- [ ] 已完成练习