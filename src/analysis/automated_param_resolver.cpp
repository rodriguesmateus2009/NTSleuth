// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "analysis/automated_param_resolver.h"
#include "utils/logger.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <regex>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <set>
#include <mutex>
#include "analysis/phnt_database.h"

// Forward declaration for detailed pattern lookup
namespace windows_arm64_analyzer
{
    namespace analysis
    {
        SyscallSignature GetDetailedPattern(const std::string &function_name);

        // Global PHNT database instance (singleton) - define with external linkage
        std::shared_ptr<PHNTDatabase> g_phnt_database = nullptr;
        std::mutex g_phnt_mutex;

        // Initialize PHNT database (call once at startup)
        bool InitializePHNTDatabase()
        {
            std::lock_guard<std::mutex> lock(g_phnt_mutex);
            if (!g_phnt_database)
            {
                g_phnt_database = std::make_shared<PHNTDatabase>();
                return g_phnt_database->Initialize();
            }
            return true;
        }
    }
}

namespace windows_arm64_analyzer
{
    namespace analysis
    {

        // ARM64 registers for parameter passing
        static const std::vector<std::string> ARM64_PARAM_REGS = {
            "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"};

        // x64 registers for parameter passing
        static const std::vector<std::string> X64_PARAM_REGS = {
            "RCX", "RDX", "R8", "R9" // First 4 params in registers, rest on stack
        };

        // Common Windows types and their patterns
        struct TypePattern
        {
            std::regex pattern;
            ParamType type;
            std::string type_name;
        };

        static const std::vector<TypePattern> COMMON_TYPE_PATTERNS = {
            {std::regex(R"(.*[Hh]andle.*)"), ParamType::Handle, "HANDLE"},
            {std::regex(R"(.*UNICODE_STRING.*)"), ParamType::UnicodeString, "PUNICODE_STRING"},
            {std::regex(R"(.*OBJECT_ATTRIBUTES.*)"), ParamType::ObjectAttributes, "POBJECT_ATTRIBUTES"},
            {std::regex(R"(.*IO_STATUS_BLOCK.*)"), ParamType::IoStatusBlock, "PIO_STATUS_BLOCK"},
            {std::regex(R"(.*ACCESS_MASK.*)"), ParamType::AccessMask, "ACCESS_MASK"},
            {std::regex(R"(.*LARGE_INTEGER.*)"), ParamType::LargeInteger, "PLARGE_INTEGER"},
            {std::regex(R"(.*SIZE_T.*)"), ParamType::Size, "SIZE_T"},
            {std::regex(R"(.*ULONG.*)"), ParamType::Ulong, "ULONG"},
            {std::regex(R"(.*BOOLEAN.*)"), ParamType::Boolean, "BOOLEAN"}};

        // Known syscall patterns based on function name
        struct SyscallPattern
        {
            std::regex name_pattern;
            std::vector<std::string> param_types;
            std::string return_type;
        };

        static const std::vector<SyscallPattern> KNOWN_SYSCALL_PATTERNS = {
            // File operations
            {std::regex(R"(Nt(Create|Open)File)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "PIO_STATUS_BLOCK",
              "PLARGE_INTEGER", "ULONG", "ULONG", "ULONG", "ULONG", "PVOID", "ULONG"},
             "NTSTATUS"},

            // Process operations
            {std::regex(R"(NtCreateProcessEx)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "HANDLE",
              "ULONG", "HANDLE", "HANDLE", "HANDLE", "ULONG"},
             "NTSTATUS"},

            {std::regex(R"(NtCreateProcess)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "HANDLE",
              "BOOLEAN", "HANDLE", "HANDLE", "HANDLE"},
             "NTSTATUS"},

            {std::regex(R"(NtOpenProcess)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "PCLIENT_ID"},
             "NTSTATUS"},

            // Thread operations
            {std::regex(R"(Nt(Create|Open)Thread(Ex)?)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "HANDLE",
              "PCLIENT_ID", "PCONTEXT", "PINITIAL_TEB", "BOOLEAN"},
             "NTSTATUS"},

            // Memory operations
            {std::regex(R"(Nt(Allocate|Free)VirtualMemory)"),
             {"HANDLE", "PVOID*", "ULONG_PTR", "PSIZE_T", "ULONG", "ULONG"},
             "NTSTATUS"},

            // Registry operations
            {std::regex(R"(Nt(Create|Open|Query)Key(Ex)?)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "ULONG",
              "PUNICODE_STRING", "ULONG", "PULONG"},
             "NTSTATUS"},

            // Event operations
            {std::regex(R"(Nt(Create|Open|Set)Event)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "EVENT_TYPE", "BOOLEAN"},
             "NTSTATUS"},

            // Mutex operations
            {std::regex(R"(Nt(Create|Open|Release)Mutant)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "BOOLEAN"},
             "NTSTATUS"},

            // Section operations
            {std::regex(R"(Nt(Create|Open|Map)Section)"),
             {"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "PLARGE_INTEGER",
              "ULONG", "ULONG", "HANDLE"},
             "NTSTATUS"},

            // Token operations
            {std::regex(R"(Nt(Open|Query|Set)Token)"),
             {"HANDLE", "ACCESS_MASK", "PHANDLE"},
             "NTSTATUS"},

            // Security operations
            {std::regex(R"(Nt(Query|Set)SecurityObject)"),
             {"HANDLE", "SECURITY_INFORMATION", "PSECURITY_DESCRIPTOR", "ULONG", "PULONG"},
             "NTSTATUS"}};

        // Debug tracer implementation
        class AutomatedParamResolver::DebugTracer
        {
        public:
            DebugTracer() : process_handle_(nullptr), thread_handle_(nullptr) {}

            bool AttachToProcess(DWORD process_id)
            {
                process_handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
                return process_handle_ != nullptr;
            }

            bool SetBreakpoint(uintptr_t address)
            {
                if (!process_handle_)
                    return false;

                // Read original byte
                BYTE original_byte;
                if (!ReadProcessMemory(process_handle_, (LPVOID)address, &original_byte, 1, nullptr))
                {
                    return false;
                }

                // Store original byte
                breakpoints_[address] = original_byte;

                // Write INT3 (0xCC) breakpoint
                BYTE int3 = 0xCC;
                return WriteProcessMemory(process_handle_, (LPVOID)address, &int3, 1, nullptr) != 0;
            }

            bool RemoveBreakpoint(uintptr_t address)
            {
                auto it = breakpoints_.find(address);
                if (it == breakpoints_.end())
                    return false;

                // Restore original byte
                return WriteProcessMemory(process_handle_, (LPVOID)address, &it->second, 1, nullptr) != 0;
            }

            std::vector<uintptr_t> GetRegisterValues()
            {
                std::vector<uintptr_t> values;
                if (!thread_handle_)
                    return values;

                CONTEXT context;
                context.ContextFlags = CONTEXT_ALL;

                if (GetThreadContext(thread_handle_, &context))
                {
#if defined(_M_ARM64) || defined(_ARM64_)
                    // ARM64 registers X0-X7 for parameters
                    values.push_back(context.X0);
                    values.push_back(context.X1);
                    values.push_back(context.X2);
                    values.push_back(context.X3);
                    values.push_back(context.X4);
                    values.push_back(context.X5);
                    values.push_back(context.X6);
                    values.push_back(context.X7);
#elif defined(_M_AMD64) || defined(_M_X64) || defined(_WIN64)
                    // x64 registers RCX, RDX, R8, R9
                    values.push_back(context.Rcx);
                    values.push_back(context.Rdx);
                    values.push_back(context.R8);
                    values.push_back(context.R9);
#elif defined(_M_IX86) || defined(_X86_) || defined(_M_ARM)
                    // x86 and 32-bit ARM use stack-based calling convention
                    // Parameters are on the stack, not in registers
                    // For now, we'll return an empty vector
                    LOG_DEBUG("Stack-based parameter passing not yet implemented for this architecture");
#else
                    // Unknown architecture
                    LOG_WARNING("Unknown architecture for parameter extraction");
#endif
                }

                return values;
            }

            ~DebugTracer()
            {
                if (process_handle_)
                {
                    CloseHandle(process_handle_);
                }
                if (thread_handle_)
                {
                    CloseHandle(thread_handle_);
                }
            }

        private:
            HANDLE process_handle_;
            HANDLE thread_handle_;
            std::map<uintptr_t, BYTE> breakpoints_;
        };

        AutomatedParamResolver::AutomatedParamResolver()
            : confidence_threshold_(0.7),
              debug_tracer_(std::make_unique<DebugTracer>())
        {

            // Enable all detection methods by default
            enabled_methods_[DetectionMethod::AssemblyAnalysis] = true;
            enabled_methods_[DetectionMethod::HeuristicMatching] = true;
            enabled_methods_[DetectionMethod::RegisterAnalysis] = true;
            enabled_methods_[DetectionMethod::CrossReference] = true;
            enabled_methods_[DetectionMethod::DynamicTracing] = false; // Disabled by default (requires admin)
            enabled_methods_[DetectionMethod::FuzzTesting] = false;    // Disabled by default (potentially dangerous)

            // Initialize statistics
            stats_ = {};

            // Initialize known patterns
            InitializeKnownPatterns();
        }

        AutomatedParamResolver::~AutomatedParamResolver() = default;

        void AutomatedParamResolver::InitializeKnownPatterns()
        {
            // Convert static patterns to internal format
            for (const auto &pattern : KNOWN_SYSCALL_PATTERNS)
            {
                KnownPattern kp;
                kp.name_pattern = ""; // Store pattern string representation
                kp.return_type = pattern.return_type;
                kp.confidence_boost = 0.3; // Boost confidence when matching known pattern

                // Convert parameter types
                for (const auto &param : pattern.param_types)
                {
                    // Map string types to ParamType enum
                    if (param.find("HANDLE") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::Handle);
                    }
                    else if (param.find("UNICODE_STRING") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::UnicodeString);
                    }
                    else if (param.find("OBJECT_ATTRIBUTES") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::ObjectAttributes);
                    }
                    else if (param.find("IO_STATUS_BLOCK") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::IoStatusBlock);
                    }
                    else if (param.find("ACCESS_MASK") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::AccessMask);
                    }
                    else if (param.find("LARGE_INTEGER") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::LargeInteger);
                    }
                    else if (param.find("SIZE_T") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::Size);
                    }
                    else if (param.find("ULONG") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::Ulong);
                    }
                    else if (param.find("BOOLEAN") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::Boolean);
                    }
                    else if (param[0] == 'P' || param.find("*") != std::string::npos)
                    {
                        kp.param_types.push_back(ParamType::Pointer);
                    }
                    else
                    {
                        kp.param_types.push_back(ParamType::Integer);
                    }
                }

                known_patterns_.push_back(kp);
            }
        }

        SyscallSignature AutomatedParamResolver::ResolveSyscallParameters(
            const std::string &function_name,
            uint32_t syscall_number,
            const uint8_t *stub_bytes,
            size_t stub_size,
            uintptr_t function_address)
        {

            // Suppress individual syscall resolution messages
            // LOG_INFO("Resolving parameters for syscall: " + function_name);

            // Check cache first
            auto cached = signature_cache_.find(function_name);
            if (cached != signature_cache_.end())
            {
                LOG_DEBUG("Using cached signature for " + function_name);
                return cached->second;
            }

            std::vector<SyscallSignature> candidates;

            // First, check for exact pattern match in detailed database
            auto detailed = GetDetailedPattern(function_name);
            if (detailed.confidence > 0.0)
            {
                LOG_DEBUG("Found exact pattern match for " + function_name);
                signature_cache_[function_name] = detailed;
                stats_.resolved_fully++;
                stats_.total_syscalls++;
                return detailed;
            }

            // Otherwise, try different detection methods
            if (enabled_methods_[DetectionMethod::AssemblyAnalysis])
            {
                auto sig = AnalyzeAssemblyPattern(function_name, stub_bytes, stub_size);
                if (!sig.parameters.empty())
                {
                    sig.detection_method = "AssemblyAnalysis";
                    candidates.push_back(sig);
                }
            }

            if (enabled_methods_[DetectionMethod::HeuristicMatching])
            {
                auto sig = MatchHeuristicPatterns(function_name, syscall_number);
                if (!sig.parameters.empty())
                {
                    sig.detection_method = "HeuristicMatching";
                    candidates.push_back(sig);
                }
            }

            if (enabled_methods_[DetectionMethod::RegisterAnalysis])
            {
                auto sig = AnalyzeRegisterUsage(stub_bytes, stub_size);
                if (!sig.parameters.empty())
                {
                    sig.detection_method = "RegisterAnalysis";
                    candidates.push_back(sig);
                }
            }

            if (enabled_methods_[DetectionMethod::CrossReference])
            {
                auto sig = CrossReferencePatterns(function_name);
                if (!sig.parameters.empty())
                {
                    sig.detection_method = "CrossReference";
                    candidates.push_back(sig);
                }
            }

            if (enabled_methods_[DetectionMethod::DynamicTracing] && function_address)
            {
                auto sig = TraceSyscallDynamically(function_name, syscall_number);
                if (!sig.parameters.empty())
                {
                    sig.detection_method = "DynamicTracing";
                    candidates.push_back(sig);
                }
            }

            // Combine results from multiple methods
            SyscallSignature final_signature;
            if (!candidates.empty())
            {
                final_signature = CombineResults(candidates);
                final_signature.function_name = function_name;

                // Verify if confidence is high enough
                if (final_signature.confidence >= confidence_threshold_)
                {
                    // Optionally verify through testing
                    if (enabled_methods_[DetectionMethod::FuzzTesting])
                    {
                        final_signature.is_verified = VerifySignature(final_signature, syscall_number);
                    }

                    // Cache the result
                    signature_cache_[function_name] = final_signature;

                    // Update statistics
                    stats_.resolved_fully++;
                }
                else
                {
                    stats_.resolved_partially++;
                }
            }
            else
            {
                // Create minimal signature
                final_signature.function_name = function_name;
                final_signature.return_type = "NTSTATUS";
                final_signature.parameter_count = 0;
                final_signature.confidence = 0.0;
                final_signature.detection_method = "Failed";
                stats_.failed++;
            }

            stats_.total_syscalls++;
            return final_signature;
        }

        SyscallSignature AutomatedParamResolver::AnalyzeAssemblyPattern(
            const std::string &function_name,
            const uint8_t *stub_bytes,
            size_t stub_size)
        {

            SyscallSignature signature;
            signature.function_name = function_name;
            signature.return_type = "NTSTATUS";

            // Detect architecture and analyze accordingly
#ifdef _ARM64_
            signature.parameters = AnalyzeARM64Parameters(stub_bytes, stub_size);
#else
            signature.parameters = AnalyzeX64Parameters(stub_bytes, stub_size);
#endif

            signature.parameter_count = signature.parameters.size();
            signature.confidence = signature.parameter_count > 0 ? 0.6 : 0.0;

            return signature;
        }

        std::vector<DetectedParameter> AutomatedParamResolver::AnalyzeARM64Parameters(
            const uint8_t *code,
            size_t size)
        {

            std::vector<DetectedParameter> params;

            // ARM64 analysis: Look for register usage patterns before SVC
            // Parameters are passed in X0-X7 registers

            // Simple pattern: look for MOV/LDR instructions targeting X0-X7
            for (size_t i = 0; i < size && i < 64; i += 4)
            {
                if (i + 4 > size)
                    break;

                uint32_t insn = *reinterpret_cast<const uint32_t *>(code + i);

                // Check for MOV to parameter registers (simplified)
                // MOV Xn, Xm: 0xAA0003E0 | (m << 16) | (n << 0)
                if ((insn & 0xFFE0FFE0) == 0xAA0003E0)
                {
                    uint32_t dest_reg = insn & 0x1F;
                    if (dest_reg < 8)
                    {
                        // Found parameter register being set
                        DetectedParameter param;
                        param.index = dest_reg;
                        param.type = ParamType::Unknown;
                        param.name = "param" + std::to_string(dest_reg);

                        // Try to infer type based on patterns
                        if (dest_reg == 0)
                        {
                            // First parameter is often a handle or pointer
                            // Note: function_name not available here, using heuristic
                            param.type = ParamType::Pointer;
                            param.is_output = param.type == ParamType::Pointer;
                        }

                        params.push_back(param);
                    }
                }

                // Check for LDR to parameter registers
                // LDR Xn, [Xm, #imm]: 0xF9400000 | (imm << 10) | (m << 5) | n
                if ((insn & 0xFFC00000) == 0xF9400000)
                {
                    uint32_t dest_reg = insn & 0x1F;
                    if (dest_reg < 8)
                    {
                        DetectedParameter param;
                        param.index = dest_reg;
                        param.type = ParamType::Pointer; // LDR typically loads pointers
                        param.name = "param" + std::to_string(dest_reg);
                        params.push_back(param);
                    }
                }

                // Check for SVC instruction - stop analyzing after this
                if ((insn & 0xFFE0001F) == 0xD4000001)
                {
                    break;
                }
            }

            // Remove duplicates and sort by index
            std::sort(params.begin(), params.end(),
                      [](const DetectedParameter &a, const DetectedParameter &b)
                      {
                          return a.index < b.index;
                      });

            params.erase(std::unique(params.begin(), params.end(),
                                     [](const DetectedParameter &a, const DetectedParameter &b)
                                     {
                                         return a.index == b.index;
                                     }),
                         params.end());

            return params;
        }

        std::vector<DetectedParameter> AutomatedParamResolver::AnalyzeX64Parameters(
            const uint8_t *code,
            size_t size)
        {

            std::vector<DetectedParameter> params;

            // x64 analysis: Look for register usage patterns
            // Parameters are passed in RCX, RDX, R8, R9, then stack

            // Look for MOV instructions to parameter registers
            for (size_t i = 0; i < size && i < 64; i++)
            {
                if (i + 3 > size)
                    break;

                // MOV RCX, ... : 48 89 C9 or 48 8B C9
                if (code[i] == 0x48 && (code[i + 1] == 0x89 || code[i + 1] == 0x8B))
                {
                    uint8_t modrm = code[i + 2];
                    // uint8_t reg = (modrm >> 3) & 0x07;  // Currently unused
                    uint8_t rm = modrm & 0x07;

                    // Check if targeting a parameter register
                    if (rm == 1)
                    { // RCX
                        DetectedParameter param;
                        param.index = 0;
                        param.type = ParamType::Unknown;
                        param.name = "param0";
                        params.push_back(param);
                    }
                    else if (rm == 2)
                    { // RDX
                        DetectedParameter param;
                        param.index = 1;
                        param.type = ParamType::Unknown;
                        param.name = "param1";
                        params.push_back(param);
                    }
                }

                // MOV R8, ... : 49 89 C0 or 4C 8B C0
                if ((code[i] == 0x49 || code[i] == 0x4C) && i + 2 < size)
                {
                    if (code[i + 1] == 0x89 || code[i + 1] == 0x8B)
                    {
                        DetectedParameter param;
                        param.index = 2;
                        param.type = ParamType::Unknown;
                        param.name = "param2";
                        params.push_back(param);
                    }
                }

                // MOV R9, ... : 49 89 C1 or 4C 8B C9
                if ((code[i] == 0x49 || code[i] == 0x4C) && i + 2 < size)
                {
                    if ((code[i + 1] == 0x89 || code[i + 1] == 0x8B) && (code[i + 2] & 0x07) == 1)
                    {
                        DetectedParameter param;
                        param.index = 3;
                        param.type = ParamType::Unknown;
                        param.name = "param3";
                        params.push_back(param);
                    }
                }

                // Check for SYSCALL instruction (0F 05) - stop analyzing after this
                if (i + 1 < size && code[i] == 0x0F && code[i + 1] == 0x05)
                {
                    break;
                }
            }

            // Remove duplicates and sort
            std::sort(params.begin(), params.end(),
                      [](const DetectedParameter &a, const DetectedParameter &b)
                      {
                          return a.index < b.index;
                      });

            params.erase(std::unique(params.begin(), params.end(),
                                     [](const DetectedParameter &a, const DetectedParameter &b)
                                     {
                                         return a.index == b.index;
                                     }),
                         params.end());

            return params;
        }

        SyscallSignature AutomatedParamResolver::MatchHeuristicPatterns(
            const std::string &function_name,
            uint32_t /*syscall_number*/)
        {

            SyscallSignature signature;
            signature.function_name = function_name;
            signature.return_type = "NTSTATUS";

            // Try to match against known patterns
            for (const auto &pattern : KNOWN_SYSCALL_PATTERNS)
            {
                if (std::regex_match(function_name, pattern.name_pattern))
                {
                    // Found a match!
                    LOG_DEBUG("Matched " + function_name + " to known pattern");

                    size_t idx = 0;
                    for (const auto &param_type : pattern.param_types)
                    {
                        DetectedParameter param;
                        param.index = idx++;
                        param.type_name = param_type;

                        // Infer parameter properties with better type mapping
                        if (param_type == "PHANDLE")
                        {
                            param.type = ParamType::Pointer;
                            param.is_output = (param.index == 0);
                        }
                        else if (param_type == "PCOBJECT_ATTRIBUTES" || param_type == "POBJECT_ATTRIBUTES")
                        {
                            param.type = ParamType::ObjectAttributes;
                            param.is_optional = true;
                        }
                        else if (param_type[0] == 'P' && param_type != "PVOID")
                        {
                            param.type = ParamType::Pointer;
                            param.is_output = (param.index == 0 && function_name.find("Create") != std::string::npos);
                        }
                        else if (param_type.find("HANDLE") != std::string::npos)
                        {
                            param.type = ParamType::Handle;
                        }
                        else if (param_type.find("ACCESS_MASK") != std::string::npos)
                        {
                            param.type = ParamType::AccessMask;
                        }
                        else if (param_type.find("UNICODE_STRING") != std::string::npos)
                        {
                            param.type = ParamType::UnicodeString;
                        }
                        else if (param_type.find("OBJECT_ATTRIBUTES") != std::string::npos)
                        {
                            param.type = ParamType::ObjectAttributes;
                        }
                        else if (param_type.find("BOOLEAN") != std::string::npos)
                        {
                            param.type = ParamType::Boolean;
                        }
                        else if (param_type.find("ULONG") != std::string::npos)
                        {
                            param.type = ParamType::Ulong;
                        }
                        else if (param_type.find("CLIENT_ID") != std::string::npos)
                        {
                            param.type = ParamType::Pointer;
                        }
                        else
                        {
                            param.type = ParamType::Unknown;
                        }

                        // Generate parameter name based on function and position
                        if (function_name == "NtCreateProcessEx")
                        {
                            // Specific names for NtCreateProcessEx
                            switch (idx - 1)
                            {
                            case 0:
                                param.name = "ProcessHandle";
                                break;
                            case 1:
                                param.name = "DesiredAccess";
                                break;
                            case 2:
                                param.name = "ObjectAttributes";
                                break;
                            case 3:
                                param.name = "ParentProcess";
                                break;
                            case 4:
                                param.name = "Flags";
                                break;
                            case 5:
                                param.name = "SectionHandle";
                                break;
                            case 6:
                                param.name = "DebugPort";
                                break;
                            case 7:
                                param.name = "TokenHandle";
                                break;
                            case 8:
                                param.name = "Reserved";
                                break;
                            default:
                                param.name = "param" + std::to_string(idx - 1);
                            }
                            // Set optional flags correctly
                            param.is_optional = (idx - 1 == 2 || idx - 1 >= 5);
                        }
                        else if (function_name == "NtCreateFile")
                        {
                            // Specific names for NtCreateFile
                            switch (idx - 1)
                            {
                            case 0:
                                param.name = "FileHandle";
                                break;
                            case 1:
                                param.name = "DesiredAccess";
                                break;
                            case 2:
                                param.name = "ObjectAttributes";
                                break;
                            case 3:
                                param.name = "IoStatusBlock";
                                break;
                            case 4:
                                param.name = "AllocationSize";
                                break;
                            case 5:
                                param.name = "FileAttributes";
                                break;
                            case 6:
                                param.name = "ShareAccess";
                                break;
                            case 7:
                                param.name = "CreateDisposition";
                                break;
                            case 8:
                                param.name = "CreateOptions";
                                break;
                            case 9:
                                param.name = "EaBuffer";
                                break;
                            case 10:
                                param.name = "EaLength";
                                break;
                            default:
                                param.name = "param" + std::to_string(idx - 1);
                            }
                            param.is_optional = (idx - 1 == 4 || idx - 1 >= 9);
                        }
                        else if (function_name == "NtOpenProcess")
                        {
                            switch (idx - 1)
                            {
                            case 0:
                                param.name = "ProcessHandle";
                                break;
                            case 1:
                                param.name = "DesiredAccess";
                                break;
                            case 2:
                                param.name = "ObjectAttributes";
                                break;
                            case 3:
                                param.name = "ClientId";
                                break;
                            default:
                                param.name = "param" + std::to_string(idx - 1);
                            }
                            param.is_optional = (idx - 1 == 2);
                        }
                        else
                        {
                            // Generic parameter naming
                            switch (param.type)
                            {
                            case ParamType::Handle:
                                if (param.is_output)
                                {
                                    param.name = (function_name.find("Process") != std::string::npos) ? "ProcessHandle" : (function_name.find("Thread") != std::string::npos) ? "ThreadHandle"
                                                                                                                      : (function_name.find("File") != std::string::npos)     ? "FileHandle"
                                                                                                                      : (function_name.find("Key") != std::string::npos)      ? "KeyHandle"
                                                                                                                      : (function_name.find("Section") != std::string::npos)  ? "SectionHandle"
                                                                                                                      : (function_name.find("Token") != std::string::npos)    ? "TokenHandle"
                                                                                                                                                                              : "Handle";
                                }
                                else
                                {
                                    param.name = "Handle";
                                }
                                break;
                            case ParamType::AccessMask:
                                param.name = "DesiredAccess";
                                break;
                            case ParamType::ObjectAttributes:
                                param.name = "ObjectAttributes";
                                break;
                            case ParamType::UnicodeString:
                                param.name = "ObjectName";
                                break;
                            case ParamType::IoStatusBlock:
                                param.name = "IoStatusBlock";
                                break;
                            default:
                                param.name = "param" + std::to_string(idx - 1);
                            }
                        }

                        signature.parameters.push_back(param);
                    }

                    signature.parameter_count = signature.parameters.size();
                    signature.confidence = 0.85; // High confidence for known patterns
                    signature.return_type = pattern.return_type;

                    return signature;
                }
            }

            // If no exact match, try to infer from function name components
            std::vector<DetectedParameter> inferred_params;

            // Common patterns in syscall names
            if (function_name.find("Create") != std::string::npos ||
                function_name.find("Open") != std::string::npos)
            {
                // These typically have: PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES as first 3 params
                DetectedParameter handle_param;
                handle_param.index = 0;
                handle_param.type = ParamType::Pointer;
                handle_param.type_name = "PHANDLE";
                handle_param.name = "Handle";
                handle_param.is_output = true;
                inferred_params.push_back(handle_param);

                DetectedParameter access_param;
                access_param.index = 1;
                access_param.type = ParamType::AccessMask;
                access_param.type_name = "ACCESS_MASK";
                access_param.name = "DesiredAccess";
                inferred_params.push_back(access_param);

                DetectedParameter obj_attr_param;
                obj_attr_param.index = 2;
                obj_attr_param.type = ParamType::ObjectAttributes;
                obj_attr_param.type_name = "POBJECT_ATTRIBUTES";
                obj_attr_param.name = "ObjectAttributes";
                inferred_params.push_back(obj_attr_param);
            }

            if (function_name.find("Query") != std::string::npos)
            {
                // Query functions typically have: HANDLE, InfoClass, Buffer, BufferSize, ReturnLength
                DetectedParameter handle_param;
                handle_param.index = 0;
                handle_param.type = ParamType::Handle;
                handle_param.type_name = "HANDLE";
                handle_param.name = "Handle";
                inferred_params.push_back(handle_param);

                DetectedParameter info_class_param;
                info_class_param.index = 1;
                info_class_param.type = ParamType::Integer;
                info_class_param.type_name = "ULONG";
                info_class_param.name = "InformationClass";
                inferred_params.push_back(info_class_param);

                DetectedParameter buffer_param;
                buffer_param.index = 2;
                buffer_param.type = ParamType::Pointer;
                buffer_param.type_name = "PVOID";
                buffer_param.name = "Buffer";
                buffer_param.is_output = true;
                inferred_params.push_back(buffer_param);
            }

            if (function_name.find("Set") != std::string::npos)
            {
                // Set functions typically have: HANDLE, InfoClass, Buffer, BufferSize
                DetectedParameter handle_param;
                handle_param.index = 0;
                handle_param.type = ParamType::Handle;
                handle_param.type_name = "HANDLE";
                handle_param.name = "Handle";
                inferred_params.push_back(handle_param);

                DetectedParameter info_class_param;
                info_class_param.index = 1;
                info_class_param.type = ParamType::Integer;
                info_class_param.type_name = "ULONG";
                info_class_param.name = "InformationClass";
                inferred_params.push_back(info_class_param);

                DetectedParameter buffer_param;
                buffer_param.index = 2;
                buffer_param.type = ParamType::Pointer;
                buffer_param.type_name = "PVOID";
                buffer_param.name = "Buffer";
                inferred_params.push_back(buffer_param);
            }

            signature.parameters = inferred_params;
            signature.parameter_count = inferred_params.size();
            signature.confidence = inferred_params.empty() ? 0.0 : 0.5;

            return signature;
        }
        SyscallSignature AutomatedParamResolver::CrossReferencePatterns(
            const std::string &function_name)
        {

            SyscallSignature signature;
            signature.function_name = function_name;
            signature.return_type = "NTSTATUS";

            // Cross-reference with similar function names
            std::vector<std::string> similar_functions;

            // Look for functions with similar prefixes/suffixes
            std::string prefix = function_name.substr(0, function_name.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2));

            for (const auto &cached : signature_cache_)
            {
                if (cached.first != function_name && cached.first.find(prefix) == 0)
                {
                    similar_functions.push_back(cached.first);
                }
            }

            // If we found similar functions, use their signatures as a base
            if (!similar_functions.empty())
            {
                auto &similar = signature_cache_[similar_functions[0]];
                signature.parameters = similar.parameters;
                signature.parameter_count = similar.parameter_count;
                signature.confidence = 0.4; // Lower confidence for cross-referenced

                LOG_DEBUG("Cross-referenced " + function_name + " with " + similar_functions[0]);
            }

            return signature;
        }

        SyscallSignature AutomatedParamResolver::AnalyzeRegisterUsage(
            const uint8_t *stub_bytes,
            size_t stub_size)
        {

            SyscallSignature signature;
            signature.return_type = "NTSTATUS";

            // Count unique register references to estimate parameter count
            std::set<int> used_registers;

#ifdef _ARM64_
            // ARM64: Look for X0-X7 usage
            for (size_t i = 0; i < stub_size && i < 64; i += 4)
            {
                if (i + 4 > stub_size)
                    break;

                uint32_t insn = *reinterpret_cast<const uint32_t *>(stub_bytes + i);

                // Check various instruction patterns that use registers
                // This is simplified - real implementation would be more comprehensive

                // Check for register in bits 0-4 (Rd/Rt)
                int reg = insn & 0x1F;
                if (reg < 8)
                    used_registers.insert(reg);

                // Check for register in bits 5-9 (Rn)
                reg = (insn >> 5) & 0x1F;
                if (reg < 8)
                    used_registers.insert(reg);

                // Check for register in bits 16-20 (Rm)
                reg = (insn >> 16) & 0x1F;
                if (reg < 8)
                    used_registers.insert(reg);
            }
#else
            // x64: Look for RCX, RDX, R8, R9 usage
            for (size_t i = 0; i < stub_size && i < 64; i++)
            {
                if (stub_bytes[i] == 0x48 || stub_bytes[i] == 0x49 || stub_bytes[i] == 0x4C)
                {
                    // REX prefix found, next byte might reference a register
                    if (i + 1 < stub_size)
                    {
                        uint8_t next = stub_bytes[i + 1];
                        // Simplified check - would need full x64 decoder for accuracy
                        if (next >= 0x89 && next <= 0x8B)
                        {
                            used_registers.insert(0); // Assume at least one parameter
                        }
                    }
                }
            }
#endif

            // Create parameters based on register usage
            for (int reg : used_registers)
            {
                DetectedParameter param;
                param.index = reg;
                param.type = ParamType::Unknown;
                param.type_name = "PVOID";
                param.name = "param" + std::to_string(reg);
                signature.parameters.push_back(param);
            }

            signature.parameter_count = signature.parameters.size();
            signature.confidence = signature.parameter_count > 0 ? 0.4 : 0.0;

            return signature;
        }

        SyscallSignature AutomatedParamResolver::TraceSyscallDynamically(
            const std::string &function_name,
            uint32_t /*syscall_number*/)
        {

            SyscallSignature signature;
            signature.function_name = function_name;
            signature.return_type = "NTSTATUS";

            // This would require admin privileges and process creation
            // For safety, we'll return an empty signature in this implementation
            // A real implementation would:
            // 1. Create a test process
            // 2. Set breakpoints on the syscall
            // 3. Invoke with test parameters
            // 4. Analyze register/stack state

            LOG_WARNING("Dynamic tracing not fully implemented for safety reasons");
            signature.confidence = 0.0;

            return signature;
        }

        SyscallSignature AutomatedParamResolver::CombineResults(
            const std::vector<SyscallSignature> &candidates)
        {

            if (candidates.empty())
            {
                return SyscallSignature();
            }

            if (candidates.size() == 1)
            {
                return candidates[0];
            }

            // Combine multiple signatures using voting/consensus
            SyscallSignature combined = candidates[0];

            // Find the signature with highest confidence
            double max_confidence = 0.0;
            size_t best_idx = 0;

            for (size_t i = 0; i < candidates.size(); i++)
            {
                if (candidates[i].confidence > max_confidence)
                {
                    max_confidence = candidates[i].confidence;
                    best_idx = i;
                }
            }

            combined = candidates[best_idx];

            // Boost confidence if multiple methods agree
            int agreement_count = 0;
            for (const auto &candidate : candidates)
            {
                if (candidate.parameter_count == combined.parameter_count)
                {
                    agreement_count++;
                }
            }

            if (agreement_count > 1)
            {
                double new_confidence = combined.confidence + 0.1 * agreement_count;
                combined.confidence = (new_confidence > 1.0) ? 1.0 : new_confidence;
                combined.detection_method = "Combined";
            }

            // Merge parameter details from all candidates
            for (size_t i = 0; i < combined.parameters.size(); i++)
            {
                for (const auto &candidate : candidates)
                {
                    if (i < candidate.parameters.size())
                    {
                        // If this candidate has a more specific type, use it
                        if (combined.parameters[i].type == ParamType::Unknown &&
                            candidate.parameters[i].type != ParamType::Unknown)
                        {
                            combined.parameters[i].type = candidate.parameters[i].type;
                            combined.parameters[i].type_name = candidate.parameters[i].type_name;
                        }

                        // If this candidate has a better name, use it
                        if (combined.parameters[i].name.find("param") == 0 &&
                            candidate.parameters[i].name.find("param") != 0)
                        {
                            combined.parameters[i].name = candidate.parameters[i].name;
                        }
                    }
                }
            }

            return combined;
        }

        bool AutomatedParamResolver::VerifySignature(
            const SyscallSignature & /*signature*/,
            uint32_t /*syscall_number*/)
        {

            // This would perform actual testing of the syscall
            // For safety, we return false in this implementation
            // A real implementation would:
            // 1. Create safe test parameters
            // 2. Invoke the syscall
            // 3. Check for crashes/errors
            // 4. Validate results

            LOG_WARNING("Signature verification not fully implemented for safety");
            return false;
        }

        std::map<std::string, SyscallSignature> AutomatedParamResolver::ResolveAllSyscalls(
            const std::vector<symbols::SyscallInfo> &syscalls)
        {

            std::map<std::string, SyscallSignature> results;

            LOG_INFO("Starting automated parameter resolution for " + std::to_string(syscalls.size()) + " syscalls...");

            size_t processed = 0;
            for (const auto &syscall : syscalls)
            {
                auto signature = ResolveSyscallParameters(
                    syscall.name,
                    syscall.syscall_number,
                    syscall.stub_bytes.data(),
                    syscall.stub_bytes.size(),
                    syscall.address);

                results[syscall.name] = signature;

                processed++;
                if (processed % 100 == 0)
                {
                    // Progress logging suppressed for cleaner output
                    // LOG_INFO("Processed syscalls: " + std::to_string(processed) + "/" + std::to_string(syscalls.size()));
                }
            }

            LOG_INFO("Parameter resolution complete. Resolved: " + std::to_string(stats_.resolved_fully) +
                     ", Partial: " + std::to_string(stats_.resolved_partially) +
                     ", Failed: " + std::to_string(stats_.failed));

            return results;
        }

        void AutomatedParamResolver::EnableMethod(DetectionMethod method, bool enable)
        {
            enabled_methods_[method] = enable;
            LOG_DEBUG("Detection method changed");
        }

        // PatternEngine implementation
        std::vector<ParamType> PatternEngine::InferFromName(const std::string &function_name)
        {
            std::vector<ParamType> types;

            // Analyze function name for clues
            if (function_name.find("File") != std::string::npos)
            {
                types.push_back(ParamType::Handle);           // File handle
                types.push_back(ParamType::AccessMask);       // Access rights
                types.push_back(ParamType::ObjectAttributes); // Object attributes
            }

            if (function_name.find("Process") != std::string::npos)
            {
                types.push_back(ParamType::Handle);     // Process handle
                types.push_back(ParamType::AccessMask); // Access rights
            }

            if (function_name.find("Thread") != std::string::npos)
            {
                types.push_back(ParamType::Handle);     // Thread handle
                types.push_back(ParamType::AccessMask); // Access rights
            }

            if (function_name.find("Token") != std::string::npos)
            {
                types.push_back(ParamType::Handle); // Token handle
            }

            if (function_name.find("Memory") != std::string::npos ||
                function_name.find("Virtual") != std::string::npos)
            {
                types.push_back(ParamType::Handle);  // Process handle
                types.push_back(ParamType::Pointer); // Base address
                types.push_back(ParamType::Size);    // Size
            }

            return types;
        }

        ParamType PatternEngine::MatchPattern(const std::string &text)
        {
            if (std::regex_match(text, std::regex(HANDLE_PATTERN)))
            {
                return ParamType::Handle;
            }
            if (std::regex_match(text, std::regex(POINTER_PATTERN)))
            {
                return ParamType::Pointer;
            }
            if (std::regex_match(text, std::regex(STRING_PATTERN)))
            {
                return ParamType::UnicodeString;
            }
            if (std::regex_match(text, std::regex(SIZE_PATTERN)))
            {
                return ParamType::Size;
            }
            if (std::regex_match(text, std::regex(ACCESS_PATTERN)))
            {
                return ParamType::AccessMask;
            }

            return ParamType::Unknown;
        }

        // SyscallFuzzer implementation
        SyscallFuzzer::FuzzResult SyscallFuzzer::FuzzSyscall(
            uint32_t /*syscall_number*/,
            size_t /*max_params*/)
        {

            FuzzResult result = {};

            // Safety check - don't fuzz destructive syscalls
            // This is a simplified implementation for safety

            LOG_WARNING("Syscall fuzzing not yet implemented");
            result.crashed = false;
            result.status = 0xC0000001; // STATUS_UNSUCCESSFUL
            result.param_count_hint = 0;

            return result;
        }

        NTSTATUS SyscallFuzzer::InvokeSyscallSafely(
            uint32_t /*syscall_number*/,
            void ** /*params*/,
            size_t /*param_count*/)
        {

            // This would invoke the syscall with exception handling
            // Not implemented yet

            return 0xC0000001; // STATUS_UNSUCCESSFUL
        }
    }
}
