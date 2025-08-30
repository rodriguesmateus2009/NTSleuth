// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <memory>

namespace WinSyscall
{

    // Architecture types
    enum class Architecture
    {
        Unknown = 0,
        x86,
        x64,
        ARM64
    };

    // Module types
    enum class ModuleType
    {
        NtDll,
        Win32u,
        NtDllWow64
    };

    // Calling conventions
    enum class CallingConvention
    {
        Stdcall,
        Fastcall,
        Cdecl,
        Thiscall,
        Unknown
    };

    // Parameter information
    struct Parameter
    {
        std::string name;
        std::string type;
        bool is_pointer = false;
        bool is_const = false;
        bool is_optional = false;

        // SAL annotations
        bool is_input = true;       // _In_
        bool is_output = false;     // _Out_
        std::string sal_annotation; // Full SAL annotation (e.g., "_In_opt_")
    };

    // Syscall information
    struct Syscall
    {
        std::string name;                  // Function name (e.g., "NtCreateFile")
        uint32_t syscall_number = 0;       // System call number (SSN)
        std::string return_type;           // Return type
        std::vector<Parameter> parameters; // Function parameters
        CallingConvention calling_convention = CallingConvention::Stdcall;
        bool is_true_syscall = true;     // Has syscall/svc instruction
        std::string alias_of;            // If this is an alias (e.g., Zw -> Nt)
        std::string module_name;         // Source module
        uint64_t rva = 0;                // Relative virtual address
        std::vector<uint8_t> stub_bytes; // Raw stub bytes for analysis
    };

    // OS Build information
    struct OSBuildInfo
    {
        uint32_t major_version = 0;
        uint32_t minor_version = 0;
        uint32_t build_number = 0;
        uint32_t revision = 0;
        std::string version_string;
        Architecture architecture = Architecture::Unknown;
        bool is_wow64 = false;
    };

    // Module information
    struct ModuleInfo
    {
        std::string name;
        std::string path;
        ModuleType type;
        uint64_t base_address = 0;
        uint32_t size = 0;
        std::string pdb_path;
        std::string pdb_guid;
        uint32_t pdb_age = 0;
    };

    // Symbol information
    struct SymbolInfo
    {
        std::string name;
        uint64_t address = 0;
        uint32_t size = 0;
        std::string demangled_name;
        bool is_export = false;
        bool is_forward = false;
        std::string forward_name;
    };

    // Extraction results
    struct ExtractionResult
    {
        OSBuildInfo os_info;
        std::vector<ModuleInfo> modules;
        std::vector<Syscall> syscalls;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        uint64_t extraction_time_ms = 0;
    };

    // Configuration options
    struct ExtractionConfig
    {
        bool extract_ntdll = true;
        bool extract_win32u = true;
        bool extract_wow64 = false;
        bool download_symbols = true;
        bool use_symbol_cache = true;
        bool verbose_logging = false;
        bool extract_non_syscalls = false; // Also extract functions without syscall/svc
        std::string symbol_cache_path = "cache\\symbols";
        std::string output_directory = "output";
        std::string symbol_server = "https://msdl.microsoft.com/download/symbols";
    };

}
