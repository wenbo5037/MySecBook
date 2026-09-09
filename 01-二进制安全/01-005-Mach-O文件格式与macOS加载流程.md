---
type: 网络安全主题
难度: 中级
前置知识: "[[01-001-二进制安全概览与学习路线]]"
对应语言等级: 精通级
status: Active
related_to:
  - "[[二进制安全]]"
  - "[[01-004-PE文件格式与Windows加载流程]]"
---

# 01-005 Mach-O 文件格式与 macOS 加载流程

## 基础信息
- 难度：中级
- 前置知识：[[01-001-二进制安全概览与学习路线]]
- 对应语言等级：精通级

## 核心原理

Mach-O（Mach Object）是 macOS/iOS 的可执行文件格式，规范由 Apple 维护（旧版《Mach-O File Format Reference》）。与 PE/ELF 的「节表 + 头部固定字段」不同，Mach-O 的核心是 **load commands（加载命令）**：头部只给出命令的数量与总大小，所有结构（段、符号、依赖库、入口、代码签名）都以变长命令链表形式声明。解析 Mach-O 的顺序是：`Fat 头（可选）→ Mach-O 头 → load commands → segment/section 数据`。

通用二进制（Universal Binary / Fat）一个特殊点：文件头 magic 为 `0xCAFEBABE`（FAT_MAGIC），内部按大端序记录多个 Mach-O slice，分别对应不同的 CPU 架构（如 x86_64 与 arm64），`lipo -thin` 可提取单个架构。

## 技术要点

- magic 字节：`MH_MAGIC`（`0xFEEDFACE`，32 位大端）、`MH_MAGIC_64`（`0xFEEDFACF`，64 位大端）。磁盘上按小端存储时表现为 `CE FA ED FE`（32 位）与 `CF FA ED FE`（64 位）。`file` 命令即据此识别架构。
- Mach-O 头（mach_header_64）：`cputype`（x86_64 为 `CPU_TYPE_X86_64` 0x01000007，arm64 为 `CPU_TYPE_ARM64` 0x0100000C）、`cpusubtype`、`filetype`（`MH_EXECUTE` 0x2、`MH_DYLIB` 0x6、`MH_BUNDLE` 0x8、`MH_DYLINKER` 0x7）、`ncmds`、`sizeofcmds`、`flags`、64 位保留字段 `reserved`。
- segment（段）命令：`LC_SEGMENT_64`（0x19）。每段含 16 字节段名（`__TEXT`、`__DATA`、`__LINKEDIT` 等）、`vmaddr`、`vmsize`、`fileoff`、`filesize`、`maxprot`、`initprot`（初始读/写/执行权限）、`nsects`（节数量）。段内节名以双下划线前缀：`__text`、`__stubs`、`__const`、`__data`、`__common`、`__la_symbol_ptr`（延迟绑定符号指针表）、`__got`。
- 常用 load command：`LC_SYMTAB`（0x2，符号表）、`LC_DYSYMTAB`（0xB，动态链接符号信息）、`LC_DYLD_INFO_ONLY`（0x80000022，导出/绑定/重定位数据）、`LC_MAIN`（0x80000028，main 入口）、`LC_LOAD_DYLIB`（0xC，依赖的动态库）、`LC_CODE_SIGNATURE`（0x1D）、`LC_ENCRYPTION_INFO_64`（0x2C，App Store 加密标志）。
- 动态链接：由 **dyld**（Apple 动态链接器）完成。外部函数通过 `__TEXT,__stubs` 与 `__DATA,__la_symbol_ptr` 表实现**惰性绑定**，首次调用才查找到真实地址并写入指针表，`dyld` 同时负责 ASLR 下的 rebase（chain 或传统 `__LINKEDIT` 重定位）。
- 代码签名：Mach-O 末尾附有 `__LC_CODE_SIGNATURE` 引导的 Code Directory（基于 Apple Code Signing 规范）；Apple Silicon 上每条 arm64 指令需签名校验（AMFI + AMFID），未签名内核模块不可加载。

## 实践示例

环境：macOS 14（arm64）、LLVM 16（clang）、Command Line Tools。

对任意已编译程序查看架构、load commands 与依赖：

```bash
file ./hello            # 输出架构（arm64 / x86_64）与类型
otool -hl ./hello       # 头 + load commands 摘要
otool -l ./hello        # 全部 load commands（段、节、签名）
otool -L ./hello        # 依赖的动态库（LC_LOAD_DYLIB）
otool -tV ./hello       # 反汇编 __TEXT,__text
nm ./hello              # 符号表
```

涉及通用二进制：

```bash
lipo -info ./hello      # 列出内嵌架构
lipo -thin arm64 -output hello_arm64 ./hello
```

`otool -l` 输出的 `cmd LC_SEGMENT_64` 段内可以看到 `initprot vmprot = r-x/r/x` 之类的权限矩阵，直接反映 NX 与写执行分离的实现（Apple 平台的强制 W^X）。

## 常见问题与误区

- 误区一：把 magic 直接看作文件内容。magic 按主机字节序存储，小端机器上看到的字节流是 `CF FA ED FE`（64 位），按数值 `0xFEEDFACF` 判断才是架构魔数。
- 误区二：混淆 segment 与 section。segment 是段（含权限属性，对应 ELF 的 program header 语义），section 是段内小节（对应 ELF 的 section header 语义）；`__TEXT` 段权限为 r-x，`__DATA` 段为 rw-。
- 误区三：认为 x86 的经验可直接迁移。Apple Silicon 上强制 W^X、代码签名、Pointer Authentication (PAC)，曾经在 Linux x64 上通用的「注入 shellcode」思路在 macOS arm64 默认配置下不可直接复用。

## 参考来源
- Mach-O File Format Reference（Apple Developer Archive） - 官方文档 - https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html
- otool(1) 与 lipo(1) 手册页 - 官方文档 - https://www.manpagez.com/man/1/otool/
- Jonathan Levin《Mac OS X and iOS Internals》（ISBN 978-1118057650） - 经典教材

## 合规声明
本文仅用于授权安全测试与学习研究，未经授权对他人系统进行测试属于违法行为。