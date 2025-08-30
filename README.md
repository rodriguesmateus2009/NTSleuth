# 🔍 NTSleuth

<div align="center">

![NTSleuth Banner](https://img.shields.io/badge/NTSleuth-Windows%20Syscall%20Hunter-purple?style=for-the-badge&logo=windows&logoColor=white)

[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)](https://github.com/xaitax/NTSleuth/releases)
[![Platform](https://img.shields.io/badge/Platform-ARM64%20%7C%20x64%20%7C%20x86-orange?style=for-the-badge)](https://github.com/xaitax/NTSleuth)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-green?style=for-the-badge)](LICENSE)
[![C++](https://img.shields.io/badge/C++-20-red?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)

**Comprehensive Windows Syscall Extraction & Analysis Framework**

*Discover every syscall. Resolve every parameter. Map the undocumented.*

If you find this research valuable, I'd appreciate a coffee:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

</div>

---

## ⚠️ Early Development Notice

> **Important**: This project is in early development. While functional and tested on multiple systems, it certainly has bugs and edge cases that haven't been discovered yet. I'm actively working on improvements and welcome feedback! Despite its early stage, I hope NTSleuth proves helpful for your Windows internals research and reverse engineering projects.
>
> Please report any issues you encounter - your feedback helps make this tool better for everyone!

## 🎯 What is NTSleuth?

NTSleuth is an advanced Windows syscall extraction and analysis framework that automatically discovers, documents, and analyzes system calls across all Windows architectures. It's a comprehensive reverse engineering tool that provides deep insights into Windows internals with high accuracy.

### 🚀 Key Achievements

- **2,400+ Syscalls Extracted** - Complete coverage of ntdll.dll and win32u.dll
- **1,100+ Function Signatures** - Integrated PHNT database from System Informer
- **3 Architectures Supported** - Native ARM64, x64, and x86 analysis
- **100% Automated** - From extraction to parameter resolution
- **< 4 Second Extraction** - Lightning-fast analysis engine

## ✨ Core Features

### 🔬 Syscall Extraction Engine
- **Multi-Architecture Disassembly** - ARM64 (SVC), x64 (SYSCALL), x86 (INT 2E/SYSENTER)
- **Complete Module Coverage** - ntdll.dll, win32u.dll, and WOW64 variants
- **Stub Analysis** - Extracts and analyzes syscall stub bytes
- **Alias Detection** - Identifies Nt/Zw function relationships
- **True Syscall Verification** - Distinguishes actual syscalls from regular exports

### 🧠 Advanced Parameter Resolution
- **PHNT Database Integration** - 1,100+ authoritative function signatures
- **SAL Annotation Support** - Complete _In_, _Out_, _Inout_, _opt_ preservation
- **Multi-Method Resolution**:
  - Primary: PHNT database lookup
  - Secondary: Pattern-based matching
  - Tertiary: Assembly code analysis
  - Quaternary: Heuristic inference
  - Quinary: Cross-reference learning
- **Confidence Scoring** - Reliability ratings for each resolution (0.0-1.0)

### 📊 Output Formats
- **JSON Export** - Structured data with complete metadata
- **C/C++ Headers** - Ready-to-use header files with prototypes
- **Interactive Lookup** - Query individual syscalls with rich formatting
- **Documentation Links** - Direct references to ntdoc.m417z.com

### 🛠️ Professional Features
- **Symbol Resolution** - Automatic PDB download from Microsoft Symbol Server
- **Local Caching** - Intelligent cache management for symbols and PHNT data
- **Offline Mode** - Works without internet after initial cache population

## 📸 Screenshots

```
    ███   ██ ████████ ███████ ██      ███████ ██   ██ ████████ ██  ██
    ████  ██    ██    ██      ██      ██      ██   ██    ██    ██  ██
    ██ ██ ██    ██    ███████ ██      █████   ██   ██    ██    ███████
    ██  ████    ██         ██ ██      ██      ██   ██    ██    ██  ██
    ██   ███    ██    ███████ ███████ ███████  ██████    ██    ██  ██


  +===================================================================+
  |  Windows Syscall Extraction & Automated Parameter Resolution Tool |
  |                 ARM64 | x64 | x86 Syscall Analysis                |
  |               v1.0.0 by Alexander Hagenah • @xaitax               |
  +===================================================================+

[*] INITIALIZATION

[+] Initializing NtSleuth Engine...
[+] Output directory: output
[+] Symbol cache: cache\symbols

[*] PARAMETER DATABASE

[+] Loading PHNT database for parameter resolution...
[+] PHNT database initialized with 1109 function signatures

[*] SYSCALL EXTRACTION

[+] Extracting syscalls from system modules...

[*] PARAMETER RESOLUTION

[+] Resolving parameters from PHNT database...
[+] Resolved parameters for 1103 syscalls from PHNT

[*] EXTRACTION RESULTS

> System Information
  * Target OS: 10.0.26220.5770 (ARM64)
  * Build: 26220.5770

> Syscall Statistics
  * Total syscalls found: 2461
    -> ntdll.dll: 978 total
    -> win32u.dll: 1483 total

> Performance Metrics
  * Extraction time: 402 ms

[*] SAVING RESULTS

[+] JSON output saved to: output/syscalls.json
[+] C header saved to: output/syscalls.h

NTSleuth has successfully extracted all syscalls!
Happy hunting!
```

## 🚀 Installation

### Option 1: Download Pre-built Binaries

Download the latest release for your architecture from the release page.

> **Note**: Binaries are statically linked and don't require Visual C++ Redistributables

### Option 2: Build from Source

#### Prerequisites
- Windows 10/11 (any architecture)
- Visual Studio 2019+ with C++ workload
- CMake 3.20+

#### Quick Build
```bash
git clone https://github.com/xaitax/NTSleuth.git
cd NTSleuth
build.bat
```

#### Manual Build
```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## 💻 Usage

### Basic Extraction
```bash
# Extract all syscalls with default settings
ntsleuth.exe

# Extract with full parameter resolution
ntsleuth.exe --auto-params

# High-confidence parameter resolution only
ntsleuth.exe --auto-params --param-confidence 0.9
```

### Syscall Lookup
```bash
# Query specific syscall information
ntsleuth.exe --lookup NtCreateProcess
```

**Example Output:**
```
    ███   ██ ████████ ███████ ██      ███████ ██   ██ ████████ ██  ██
    ████  ██    ██    ██      ██      ██      ██   ██    ██    ██  ██
    ██ ██ ██    ██    ███████ ██      █████   ██   ██    ██    ███████
    ██  ████    ██         ██ ██      ██      ██   ██    ██    ██  ██
    ██   ███    ██    ███████ ███████ ███████  ██████    ██    ██  ██


  +===================================================================+
  |  Windows Syscall Extraction & Automated Parameter Resolution Tool |
  |                 ARM64 | x64 | x86 Syscall Analysis                |
  |               v1.0.0 by Alexander Hagenah • @xaitax               |
  +===================================================================+


======================================================================
  SYSCALL INFORMATION: NtCreateProcess
======================================================================

[Module]        ntdll.dll
[Number]        0xC0 (192)
[RVA]           0x1C40
[Return Type]   NTSTATUS
[Convention]    stdcall
[Is Syscall]    Yes

[Parameters]
----------------------------------------------------------------------
  [0] PHANDLE              ProcessHandle        [_Out_]
  [1] ACCESS_MASK          DesiredAccess        [_In_]
  [2] PCOBJECT_ATTRIBUTES  ObjectAttributes     [_In_opt_]
  [3] HANDLE               ParentProcess        [_In_]
  [4] BOOLEAN              InheritObjectTable   [_In_]
  [5] HANDLE               SectionHandle        [_In_opt_]
  [6] HANDLE               DebugPort            [_In_opt_]
  [7] HANDLE               TokenHandle          [_In_opt_]

[Function Signature]
----------------------------------------------------------------------
  NTSTATUS stdcall NtCreateProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle
  );

[Stub Bytes] (first 32 bytes)
----------------------------------------------------------------------
  01 18 00 d4 c0 03 5f d6 00 00 00 00 00 00 00 00
  21 18 00 d4 c0 03 5f d6 00 00 00 00 00 00 00 00

[Documentation]
----------------------------------------------------------------------
  https://ntdoc.m417z.com/ntcreateprocess
  (Detailed parameter documentation and usage examples)

======================================================================
```

### Advanced Options

| Option | Description |
|--------|-------------|
| `--auto-params` | Enable advanced parameter resolution |
| `--param-confidence <n>` | Set minimum confidence (0.0-1.0) |
| `--no-ntdll` | Skip ntdll.dll extraction |
| `--no-win32u` | Skip win32u.dll extraction |
| `--wow64` | Extract WOW64 (32-bit) syscalls |
| `--no-symbols` | Skip symbol download |
| `--no-cache` | Disable cache usage |
| `--format <type>` | Output format: json, header, both |
| `--lookup <name>` | Query specific syscall |
| `--clear-cache` | Clear all caches |
| `-v, --verbose` | Enable verbose logging |

## 📁 Output Formats

### JSON Format
Complete syscall metadata with full fidelity:

```json
    {
      "calling_convention": "stdcall",
      "is_true_syscall": true,
      "module": "ntdll.dll",
      "name": "NtCreateProcessEx",
      "parameters": [
        {
          "is_const": false,
          "is_input": false,
          "is_optional": false,
          "is_output": true,
          "is_pointer": true,
          "name": "ProcessHandle",
          "sal_annotation": "_Out_",
          "type": "PHANDLE"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": false,
          "is_output": false,
          "is_pointer": false,
          "name": "DesiredAccess",
          "sal_annotation": "_In_",
          "type": "ACCESS_MASK"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": true,
          "is_output": false,
          "is_pointer": true,
          "name": "ObjectAttributes",
          "sal_annotation": "_In_opt_",
          "type": "PCOBJECT_ATTRIBUTES"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": false,
          "is_output": false,
          "is_pointer": false,
          "name": "ParentProcess",
          "sal_annotation": "_In_",
          "type": "HANDLE"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": false,
          "is_output": false,
          "is_pointer": false,
          "name": "Flags",
          "sal_annotation": "_In_",
          "type": "ULONG"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": true,
          "is_output": false,
          "is_pointer": false,
          "name": "SectionHandle",
          "sal_annotation": "_In_opt_",
          "type": "HANDLE"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": true,
          "is_output": false,
          "is_pointer": false,
          "name": "DebugPort",
          "sal_annotation": "_In_opt_",
          "type": "HANDLE"
        },
        {
          "is_const": false,
          "is_input": true,
          "is_optional": true,
          "is_output": false,
          "is_pointer": false,
          "name": "TokenHandle",
          "sal_annotation": "_In_opt_",
          "type": "HANDLE"
        },
        {
          "is_const": false,
          "is_input": false,
          "is_optional": true,
          "is_output": false,
          "is_pointer": false,
          "name": "Reserved",
          "sal_annotation": "_Reserved_",
          "type": "ULONG"
        }
      ],
      "return_type": "NTSTATUS",
      "rva": 5392,
      "stub_bytes": "a10900d4c0035fd60000000000000000c10900d4c0035fd60000000000000000",
      "syscall_number": 77
    },
```

### C Header Format
Ready-to-compile header with all syscall definitions:

```c
// Auto-generated by NTSleuth v1.0.0
// Total syscalls: 2461

#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

// Syscall numbers for ntdll.dll
#define SYSCALL_NUMBER_NTCREATEPROCESSEX 0x4D

/* Syscall #0x4D */
typedef NTSTATUS (NTAPI *pfnNtCreateProcessEx)(
    PHANDLE* ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES* ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved
);

// ... continues for all syscalls
#endif // _SYSCALLS_H_
```

## 🏗️ Architecture

### Technical Stack
- **Language**: C++20 with modern STL
- **Disassembler**: Zydis (multi-architecture support)
- **JSON**: nlohmann/json
- **Build System**: CMake 3.20+
- **CI/CD**: GitHub Actions

### How It Works

1. **Module Loading** - Loads target system libraries (ntdll.dll, win32u.dll)
2. **Export Enumeration** - Enumerates all exported functions
3. **Disassembly** - Analyzes function prologues for syscall instructions
4. **Number Extraction** - Extracts syscall numbers from instruction operands
5. **Symbol Resolution** - Downloads and parses PDB files for metadata
6. **PHNT Integration** - Matches functions with PHNT database entries
7. **Parameter Resolution** - Multi-method parameter type inference
8. **Output Generation** - Formats data as JSON/C headers

## 🤝 Contributing

Contributions are always welcome!

## 📜 License

BSD 3-Clause License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **[System Informer](https://github.com/winsiderss/systeminformer)** - PHNT headers
- **[Zydis](https://github.com/zyantific/zydis)** - Disassembly engine
- **[ntdoc.m417z.com](https://ntdoc.m417z.com)** - Syscall documentation
- **Windows Internals Community** - Research and knowledge

## 🌟 Star History

If you find NTSleuth useful, please consider giving it a star! It helps others discover the tool.

---

<div align="center">

**Built with ❤️ for the Windows internals community**
![Visitors](https://visitor-badge.laobi.icu/badge?page_id=xaitax.ntsleuth)


*"Mapping the undocumented, one syscall at a time"*

</div>
