---
type: 网络安全主题
难度: 中级
前置知识: "[[01-001-二进制安全概览与学习路线]]"
对应语言等级: 精通级
status: Active
related_to:
  - "[[二进制安全]]"
  - "[[01-003-ELF文件格式与链接机制]]"
---

# 01-004 PE 文件格式与 Windows 加载流程

## 基础信息
- 难度：中级
- 前置知识：[[01-001-二进制安全概览与学习路线]]
- 对应语言等级：精通级

## 核心原理

PE（Portable Executable）是 Microsoft Windows 平台的可执行文件格式，由 COFF（Common Object File Format）演化而来，官方规范收录于微软发布的《PE Format》文档。与 Linux 的 ELF 类似，PE 也是一种「分节映射进内存」的格式，但它保留了 DOS 兼容头、采用了与内存页粒度分离的两种对齐（FileAlignment 与 SectionAlignment），并依赖 Windows Loader（ntdll 中的加载逻辑）在进程创建时填充 IAT（Import Address Table）。

理解 PE 的关键是先区分两层视角：**文件偏移（File Offset）** 与 **虚拟地址（RVA/VA）**。磁盘上的节（Section）按 FileAlignment（典型 0x200）对齐存储，加载到内存后则按 SectionAlignment（典型 0x1000）页对齐映射，因此「节内数据的文件偏移」与「节内数据在内存中的 RVA」需要换算：`RVA = VA - ImageBase`，且 `RVA_to_Offset` 依赖节表的 VirtualAddress 与 PointerToRawData 差值。分析器（如 Ghidra、pefile）正是通过节表完成这种双向映射。

## 技术要点

PE 文件的解析顺序为：**DOS 头 → NT 头（签名 + COFF 头 + 可选头）→ 节表 → 各节数据**。

- DOS 头（IMAGE_DOS_HEADER，64 字节）：以 `MZ`（0x5A4D）开头，偏移 0x3C 处的 `e_lfanew` 字段指向 PE 签名位置。
- PE 签名：`PE\0\0`（0x00004550），位于 e_lfanew 指示的地址。
- COFF 头（IMAGE_FILE_HEADER，20 字节）：关键字段 `Machine`（0x014C 为 x86，0x8664 为 x64）、`NumberOfSections`、`SizeOfOptionalHeader`、`Characteristics`（位 0x2000 表示 DLL）。
- 可选头（IMAGE_OPTIONAL_HEADER）：x86 为 0x10B（PE32），x64 为 0x20B（PE32+）。关键字段：`ImageBase`（x86 默认 0x00400000，x64 默认 0x0000000140000000）、`SectionAlignment`、`FileAlignment`、`AddressOfEntryPoint`（Entry Point 的 RVA）、`SizeOfImage`、`Subsystem`（2 为 GUI，3 为 CUI）、`DllCharacteristics`（位 0x0040 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` 表示支持 ASLR），以及 16 项的 `DataDirectory` 数组。
- DataDirectory 常用索引：0 = Export、1 = Import、2 = Resource、5 = BaseReloc、6 = Debug、12 = IAT。
- 节表（Section Table，每项 40 字节）：`VirtualSize`、`VirtualAddress`（节的 RVA）、`SizeOfRawData`、`PointerToRawData`（文件偏移）、`Characteristics`（0x20000000 可执行、0x40000000 可读、0x80000000 可写）。典型节：`.text` 代码、`.rdata` 只读数据与导入/导出表、`.data` 可读写数据、`.pdata`（x64 异常展开表）、`.rsrc` 资源、`.reloc` 基址重定位表。

**导入表（Import Table）**：DataDirectory[1] 指向一组 `IMAGE_IMPORT_DESCRIPTOR`，每条含 `OriginalFirstThunk`（INT）、`Name`（DLL 名 RVA）、`FirstThunk`（IAT）。加载时 Loader 先投递 `IMAGE_BIND_INFO` 解析延迟绑定，常规情况下逐项查找到函数地址并写入 IAT；INT 与 IAT 内的序号位（最高位）区分按序号导入与按名称导入。

**导出表（Export Table）**：`IMAGE_EXPORT_DIRECTORY` 含函数名表、序号表与地址表（EAT），DLL 通过它在运行时暴露 API；函数可同时按名称与序号被引用。

**基址重定位（Base Reloc）**：启用 ASLR（`/DYNAMICBASE`）后，映像可能被加载到非默认 ImageBase，绝对地址指令（x86 的 `mov eax,0x401000`）无法使用，因此 `.reloc` 节保存了所有需要修正的位置。x86 用 `IMAGE_REL_BASED_HIGHLOW`（类型 3），x64 用 `IMAGE_REL_BASED_DIR64`（类型 10），Loader 按新基址差值重写这些 DWORD/QWORD。

**加载流程**：进程被创建时，ntdll 先为进程申请 `SizeOfImage` 大小的内存块，按节表逐个将节从文件拷贝到 `ImageBase + VirtualAddress` 处，随后处理导入表（加载依赖 DLL 并解析 IAT）、应用重定位，执行 `TLS 回调`，最后跳转到 `AddressOfEntryPoint`（通常是 CRT 初始化 → `main` → `ExitProcess`）。

## 实践示例

环境：Windows 11 x64、Python 3.11、pefile 2023.2.7、dumpbin 来自 Visual Studio Build Tools。

用 pefile 解析 x64 目录程序（例如 `C:\Windows\System32\notepad.exe`），快速提取关键字段：

```python
import pefile
pe = pefile.PE(r"C:\Windows\System32\notepad.exe")
print(hex(pe.FILE_HEADER.Machine))            # 0x8664 -> x64
print(hex(pe.OPTIONAL_HEADER.ImageBase))      # 0x140000000
print(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print(hex(pe.OPTIONAL_HEADER.DllCharacteristics))
for sec in pe.sections:
    print(sec.Name.strip(b"\x00").decode(), hex(sec.VirtualAddress))
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.name:
            print(dll, imp.name.decode())
```

命令行验证（dumpbin 需在 VS 开发者命令提示符中）：

```cmd
dumpbin /headers notepad.exe
dumpbin /imports notepad.exe
dumpbin /exports kernel32.dll
dumpbin /relocations notepad.exe
```

`/headers` 输出 DOS/COFF/Optional 头与节表全字段；`/imports` 展示每个依赖 DLL 及其符号；`/relocations` 展示 .reloc 的分页重定位项。

## 常见问题与误区

- 误区一：认为节的文件偏移等于内存地址。节在磁盘按 FileAlignment 对齐、在内存按 SectionAlignment（页）对齐，必须通过节表换算 RVA 与文件偏移，直接相加必然出错。
- 误区二：混淆「RVA」与「VA」。RVA 是相对 ImageBase 的偏移，VA 是绝对虚拟地址；x64 默认基址为 0x140000000，调试与逆向时先确认当前基址是否为默认值（ASLR 关闭时才相等）。
- 误区三：忽略导入表解析方向。IAT 在运行时被改写，静态分析（如 Ghidra）看到的多是 INT（OriginalFirstThunk）内容；动态调试时 IAT 里才是已解析的真实函数地址。

## 参考来源
- Microsoft PE Format Specification - 官方文档 - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- pefile（Ero Carrera）源码头注释与 README - 开源项目 - https://github.com/erocarrera/pefile
- Microsoft Windows Internals, Part 1（Russinovich, Solomon, Ionescu）ISBN 978-0133986411 - 经典教材

## 合规声明
本文仅用于授权安全测试与学习研究，未经授权对他人系统进行测试属于违法行为。