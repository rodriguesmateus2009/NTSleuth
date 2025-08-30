// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "analysis/automated_param_resolver.h"
#include "analysis/phnt_database.h"
#include "utils/logger.h"
#include <regex>
#include <map>
#include <mutex>

namespace windows_arm64_analyzer
{
    namespace analysis
    {

        // Global PHNT database instance (defined in automated_param_resolver.cpp)
        extern std::shared_ptr<PHNTDatabase> g_phnt_database;
        extern std::mutex g_phnt_mutex;

        // Extended syscall pattern database with accurate parameter information
        struct DetailedSyscallPattern
        {
            std::string function_name;
            struct ParamInfo
            {
                std::string type;
                std::string name;
                bool is_const;
                bool is_optional;
                bool is_output;
                bool is_reserved;
            };
            std::vector<ParamInfo> params;
            std::string return_type;
        };

        // Comprehensive database of known syscall signatures
        static const std::vector<DetailedSyscallPattern> DETAILED_SYSCALL_PATTERNS = {
            // Process Management
            {"NtCreateProcessEx", {
                                      {"PHANDLE", "ProcessHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, // _In_opt_ PCOBJECT_ATTRIBUTES
                                      {"HANDLE", "ParentProcess", false, false, false, false},
                                      {"ULONG", "Flags", false, false, false, false},         // PROCESS_CREATE_FLAGS_*
                                      {"HANDLE", "SectionHandle", false, true, false, false}, // _In_opt_
                                      {"HANDLE", "DebugPort", false, true, false, false},     // _In_opt_
                                      {"HANDLE", "TokenHandle", false, true, false, false},   // _In_opt_
                                      {"ULONG", "Reserved", false, false, false, true}        // _Reserved_ JobMemberLevel
                                  },
             "NTSTATUS"},

            {"NtCreateProcess", {{"PHANDLE", "ProcessHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"HANDLE", "ParentProcess", false, false, false, false}, {"BOOLEAN", "InheritObjectTable", false, false, false, false}, {"HANDLE", "SectionHandle", false, true, false, false}, {"HANDLE", "DebugPort", false, true, false, false}, {"HANDLE", "ExceptionPort", false, true, false, false}}, "NTSTATUS"},

            {"NtOpenProcess", {{"PHANDLE", "ProcessHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, false, false, false}, {"PCLIENT_ID", "ClientId", true, true, false, false}}, "NTSTATUS"},

            {"NtTerminateProcess", {{"HANDLE", "ProcessHandle", false, true, false, false}, {"NTSTATUS", "ExitStatus", false, false, false, false}}, "NTSTATUS"},

            // Thread Management
            {"NtCreateThread", {{"PHANDLE", "ThreadHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"HANDLE", "ProcessHandle", false, false, false, false}, {"PCLIENT_ID", "ClientId", false, false, true, false}, {"PCONTEXT", "ThreadContext", true, false, false, false}, {"PINITIAL_TEB", "InitialTeb", true, false, false, false}, {"BOOLEAN", "CreateSuspended", false, false, false, false}}, "NTSTATUS"},

            {"NtCreateThreadEx", {{"PHANDLE", "ThreadHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"HANDLE", "ProcessHandle", false, false, false, false}, {"PVOID", "StartRoutine", false, false, false, false}, {"PVOID", "Argument", false, true, false, false}, {"ULONG", "CreateFlags", false, false, false, false}, {"SIZE_T", "ZeroBits", false, false, false, false}, {"SIZE_T", "StackSize", false, false, false, false}, {"SIZE_T", "MaximumStackSize", false, false, false, false}, {"PPS_ATTRIBUTE_LIST", "AttributeList", true, true, false, false}}, "NTSTATUS"},

            // File Operations
            {"NtCreateFile", {{"PHANDLE", "FileHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, false, false, false}, {"PIO_STATUS_BLOCK", "IoStatusBlock", false, false, true, false}, {"PLARGE_INTEGER", "AllocationSize", true, true, false, false}, {"ULONG", "FileAttributes", false, false, false, false}, {"ULONG", "ShareAccess", false, false, false, false}, {"ULONG", "CreateDisposition", false, false, false, false}, {"ULONG", "CreateOptions", false, false, false, false}, {"PVOID", "EaBuffer", false, true, false, false}, {"ULONG", "EaLength", false, false, false, false}}, "NTSTATUS"},

            {"NtOpenFile", {{"PHANDLE", "FileHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, false, false, false}, {"PIO_STATUS_BLOCK", "IoStatusBlock", false, false, true, false}, {"ULONG", "ShareAccess", false, false, false, false}, {"ULONG", "OpenOptions", false, false, false, false}}, "NTSTATUS"},

            {"NtReadFile", {{"HANDLE", "FileHandle", false, false, false, false}, {"HANDLE", "Event", false, true, false, false}, {"PIO_APC_ROUTINE", "ApcRoutine", false, true, false, false}, {"PVOID", "ApcContext", false, true, false, false}, {"PIO_STATUS_BLOCK", "IoStatusBlock", false, false, true, false}, {"PVOID", "Buffer", false, false, true, false}, {"ULONG", "Length", false, false, false, false}, {"PLARGE_INTEGER", "ByteOffset", true, true, false, false}, {"PULONG", "Key", false, true, false, false}}, "NTSTATUS"},

            {"NtWriteFile", {{"HANDLE", "FileHandle", false, false, false, false}, {"HANDLE", "Event", false, true, false, false}, {"PIO_APC_ROUTINE", "ApcRoutine", false, true, false, false}, {"PVOID", "ApcContext", false, true, false, false}, {"PIO_STATUS_BLOCK", "IoStatusBlock", false, false, true, false}, {"PVOID", "Buffer", true, false, false, false}, {"ULONG", "Length", false, false, false, false}, {"PLARGE_INTEGER", "ByteOffset", true, true, false, false}, {"PULONG", "Key", false, true, false, false}}, "NTSTATUS"},

            // Memory Management
            {"NtAllocateVirtualMemory", {{"HANDLE", "ProcessHandle", false, false, false, false}, {"PVOID*", "BaseAddress", false, false, true, false}, {"ULONG_PTR", "ZeroBits", false, false, false, false}, {"PSIZE_T", "RegionSize", false, false, true, false}, {"ULONG", "AllocationType", false, false, false, false}, {"ULONG", "Protect", false, false, false, false}}, "NTSTATUS"},

            {"NtFreeVirtualMemory", {{"HANDLE", "ProcessHandle", false, false, false, false}, {"PVOID*", "BaseAddress", false, false, true, false}, {"PSIZE_T", "RegionSize", false, false, true, false}, {"ULONG", "FreeType", false, false, false, false}}, "NTSTATUS"},

            {"NtProtectVirtualMemory", {{"HANDLE", "ProcessHandle", false, false, false, false}, {"PVOID*", "BaseAddress", false, false, true, false}, {"PSIZE_T", "RegionSize", false, false, true, false}, {"ULONG", "NewProtect", false, false, false, false}, {"PULONG", "OldProtect", false, false, true, false}}, "NTSTATUS"},

            // Registry Operations
            {"NtCreateKey", {{"PHANDLE", "KeyHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, false, false, false}, {"ULONG", "TitleIndex", false, false, false, false}, {"PUNICODE_STRING", "Class", true, true, false, false}, {"ULONG", "CreateOptions", false, false, false, false}, {"PULONG", "Disposition", false, true, true, false}}, "NTSTATUS"},

            {"NtOpenKey", {{"PHANDLE", "KeyHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, false, false, false}}, "NTSTATUS"},

            {"NtQueryValueKey", {{"HANDLE", "KeyHandle", false, false, false, false}, {"PUNICODE_STRING", "ValueName", true, false, false, false}, {"KEY_VALUE_INFORMATION_CLASS", "KeyValueInformationClass", false, false, false, false}, {"PVOID", "KeyValueInformation", false, true, true, false}, {"ULONG", "Length", false, false, false, false}, {"PULONG", "ResultLength", false, false, true, false}}, "NTSTATUS"},

            // Synchronization Objects
            {"NtCreateEvent", {{"PHANDLE", "EventHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"EVENT_TYPE", "EventType", false, false, false, false}, {"BOOLEAN", "InitialState", false, false, false, false}}, "NTSTATUS"},

            {"NtCreateMutant", {{"PHANDLE", "MutantHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"BOOLEAN", "InitialOwner", false, false, false, false}}, "NTSTATUS"},

            {"NtCreateSemaphore", {{"PHANDLE", "SemaphoreHandle", false, false, true, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"LONG", "InitialCount", false, false, false, false}, {"LONG", "MaximumCount", false, false, false, false}}, "NTSTATUS"},

            // Token Operations
            {"NtOpenProcessToken", {{"HANDLE", "ProcessHandle", false, false, false, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"PHANDLE", "TokenHandle", false, false, true, false}}, "NTSTATUS"},

            {"NtOpenThreadToken", {{"HANDLE", "ThreadHandle", false, false, false, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"BOOLEAN", "OpenAsSelf", false, false, false, false}, {"PHANDLE", "TokenHandle", false, false, true, false}}, "NTSTATUS"},

            {"NtDuplicateToken", {{"HANDLE", "ExistingTokenHandle", false, false, false, false}, {"ACCESS_MASK", "DesiredAccess", false, false, false, false}, {"POBJECT_ATTRIBUTES", "ObjectAttributes", true, true, false, false}, {"BOOLEAN", "EffectiveOnly", false, false, false, false}, {"TOKEN_TYPE", "TokenType", false, false, false, false}, {"PHANDLE", "NewTokenHandle", false, false, true, false}}, "NTSTATUS"}};

        // Helper function to find detailed pattern for a syscall
        SyscallSignature GetDetailedPattern(const std::string &function_name)
        {
            SyscallSignature signature;
            signature.function_name = function_name;
            signature.return_type = "NTSTATUS";

            // Try PHNT database first
            {
                std::lock_guard<std::mutex> lock(g_phnt_mutex);
                if (g_phnt_database)
                {
                    auto phnt_func = g_phnt_database->LookupFunction(function_name);
                    if (phnt_func.has_value())
                    {
                        // Found in PHNT database
                        return g_phnt_database->ConvertToSignature(phnt_func.value());
                    }
                }
            }

            // Fall back to our hardcoded patterns
            for (const auto &pattern : DETAILED_SYSCALL_PATTERNS)
            {
                if (pattern.function_name == function_name)
                {
                    for (const auto &param_info : pattern.params)
                    {
                        DetectedParameter param;
                        param.index = signature.parameters.size();
                        param.type_name = param_info.type;
                        param.name = param_info.name;
                        param.is_optional = param_info.is_optional;
                        param.is_output = param_info.is_output;

                        // Map type string to enum
                        if (param_info.type.find("HANDLE") != std::string::npos)
                        {
                            param.type = param_info.type == "PHANDLE" ? ParamType::Pointer : ParamType::Handle;
                        }
                        else if (param_info.type.find("ACCESS_MASK") != std::string::npos)
                        {
                            param.type = ParamType::AccessMask;
                        }
                        else if (param_info.type.find("OBJECT_ATTRIBUTES") != std::string::npos)
                        {
                            param.type = ParamType::ObjectAttributes;
                        }
                        else if (param_info.type.find("UNICODE_STRING") != std::string::npos)
                        {
                            param.type = ParamType::UnicodeString;
                        }
                        else if (param_info.type.find("IO_STATUS_BLOCK") != std::string::npos)
                        {
                            param.type = ParamType::IoStatusBlock;
                        }
                        else if (param_info.type.find("LARGE_INTEGER") != std::string::npos)
                        {
                            param.type = ParamType::LargeInteger;
                        }
                        else if (param_info.type.find("SIZE_T") != std::string::npos)
                        {
                            param.type = ParamType::Size;
                        }
                        else if (param_info.type.find("ULONG") != std::string::npos)
                        {
                            param.type = ParamType::Ulong;
                        }
                        else if (param_info.type.find("BOOLEAN") != std::string::npos)
                        {
                            param.type = ParamType::Boolean;
                        }
                        else if (param_info.type[0] == 'P')
                        {
                            param.type = ParamType::Pointer;
                        }
                        else
                        {
                            param.type = ParamType::Integer;
                        }

                        // Add reserved flag to description if needed
                        if (param_info.is_reserved)
                        {
                            param.description = "Reserved for future use";
                        }

                        signature.parameters.push_back(param);
                    }

                    signature.parameter_count = signature.parameters.size();
                    signature.confidence = 0.95; // Very high confidence for exact matches
                    signature.detection_method = "ExactPattern";
                    signature.return_type = pattern.return_type;
                    signature.is_verified = true;

                    return signature;
                }
            }

            // No exact match found
            signature.confidence = 0.0;
            return signature;
        }

    }
}
