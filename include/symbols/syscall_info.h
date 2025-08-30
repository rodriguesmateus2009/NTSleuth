// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace windows_arm64_analyzer
{
    namespace symbols
    {

        // Structure to hold syscall information
        struct SyscallInfo
        {
            std::string name;                // Function name (e.g., "NtCreateFile")
            uint32_t syscall_number;         // Syscall number
            std::vector<uint8_t> stub_bytes; // Raw bytes of the syscall stub
            uintptr_t address;               // Virtual address of the function
            std::string module;              // Module name (e.g., "ntdll.dll")
            size_t rva;                      // Relative virtual address
            std::string return_type;         // Return type (usually NTSTATUS)
            std::string calling_convention;  // Calling convention
            bool is_true_syscall;            // Whether this is a true syscall or wrapper
            std::string alias_of;            // If this is an alias (e.g., Zw* -> Nt*)

            // Parameter information (may be empty if not resolved)
            struct Parameter
            {
                std::string type; // Parameter type
                std::string name; // Parameter name
                bool is_optional; // Whether parameter is optional
                bool is_output;   // Whether parameter is output
            };
            std::vector<Parameter> parameters;

            // Default constructor
            SyscallInfo() : syscall_number(0), address(0), rva(0), is_true_syscall(true) {}

            // Constructor with basic info
            SyscallInfo(const std::string &n, uint32_t num, const std::string &mod = "ntdll.dll")
                : name(n), syscall_number(num), module(mod), address(0), rva(0),
                  return_type("NTSTATUS"), calling_convention("stdcall"), is_true_syscall(true) {}

            // Check if this is a Zw* function
            bool IsZwFunction() const
            {
                return name.find("Zw") == 0;
            }

            // Check if this is an Nt* function
            bool IsNtFunction() const
            {
                return name.find("Nt") == 0;
            }

            // Get the corresponding Nt* name for a Zw* function
            std::string GetNtName() const
            {
                if (IsZwFunction())
                {
                    return "Nt" + name.substr(2);
                }
                return name;
            }

            // Get the corresponding Zw* name for an Nt* function
            std::string GetZwName() const
            {
                if (IsNtFunction())
                {
                    return "Zw" + name.substr(2);
                }
                return name;
            }
        };

    }
}
