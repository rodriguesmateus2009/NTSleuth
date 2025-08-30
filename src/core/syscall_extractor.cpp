// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "syscall_extractor.h"
#include "os_info.h"
#include "module_manager.h"
#include "disasm/disassembler.h"
#include "disasm/instruction_analyzer.h"
#include "symbols/symbol_parser.h"
#include "symbols/pdb_downloader.h"
#include "output/json_formatter.h"
#include "output/c_header_formatter.h"
#include "utils/logger.h"
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace WinSyscall
{

    SyscallExtractor::SyscallExtractor()
        : os_info_(std::make_unique<OSInfo>()),
          module_manager_(std::make_unique<ModuleManager>()),
          disassembler_(std::make_unique<Disassembler>()),
          pdb_downloader_(std::make_unique<PdbDownloader>())
    {
    }

    SyscallExtractor::~SyscallExtractor() = default;

    void SyscallExtractor::SetConfig(const ExtractionConfig &config)
    {
        config_ = config;
    }

    ExtractionConfig SyscallExtractor::GetConfig() const
    {
        return config_;
    }

    ExtractionResult SyscallExtractor::Extract()
    {
        current_result_ = ExtractionResult{};

        // Initialize components
        if (!InitializeComponents())
        {
            current_result_.errors.push_back("Failed to initialize components");
            return current_result_;
        }

        // Get OS information
        current_result_.os_info = os_info_->GetBuildInfo();
        LogInfo("Extracting syscalls for " + os_info_->GetSystemInfoString());

        // Extract from ntdll.dll
        if (config_.extract_ntdll)
        {
            LogInfo("Extracting from ntdll.dll...");
            std::vector<Syscall> ntdll_syscalls;
            if (ExtractFromModule(ModuleType::NtDll, ntdll_syscalls))
            {
                current_result_.syscalls.insert(current_result_.syscalls.end(),
                                                ntdll_syscalls.begin(),
                                                ntdll_syscalls.end());
                LogInfo("Found " + std::to_string(ntdll_syscalls.size()) + " syscalls in ntdll.dll");
            }
            else
            {
                current_result_.warnings.push_back("Failed to extract from ntdll.dll");
            }
        }

        // Extract from win32u.dll
        if (config_.extract_win32u)
        {
            LogInfo("Extracting from win32u.dll...");
            std::vector<Syscall> win32u_syscalls;
            if (ExtractFromModule(ModuleType::Win32u, win32u_syscalls))
            {
                current_result_.syscalls.insert(current_result_.syscalls.end(),
                                                win32u_syscalls.begin(),
                                                win32u_syscalls.end());
                LogInfo("Found " + std::to_string(win32u_syscalls.size()) + " syscalls in win32u.dll");
            }
            else
            {
                current_result_.warnings.push_back("Failed to extract from win32u.dll");
            }
        }

        // Extract from WOW64 ntdll.dll
        if (config_.extract_wow64 && os_info_->GetArchitecture() == Architecture::x64)
        {
            LogInfo("Extracting from WOW64 ntdll.dll...");
            std::vector<Syscall> wow64_syscalls;
            if (ExtractFromModule(ModuleType::NtDllWow64, wow64_syscalls))
            {
                current_result_.syscalls.insert(current_result_.syscalls.end(),
                                                wow64_syscalls.begin(),
                                                wow64_syscalls.end());
                LogInfo("Found " + std::to_string(wow64_syscalls.size()) + " WOW64 syscalls");
            }
            else
            {
                current_result_.warnings.push_back("Failed to extract from WOW64 ntdll.dll");
            }
        }

        // Resolve aliases
        ResolveAliases(current_result_.syscalls);

        // Sort syscalls by number
        std::sort(current_result_.syscalls.begin(), current_result_.syscalls.end(),
                  [](const Syscall &a, const Syscall &b)
                  {
                      if (a.module_name != b.module_name)
                      {
                          return a.module_name < b.module_name;
                      }
                      return a.syscall_number < b.syscall_number;
                  });

        LogInfo("Extraction completed. Total syscalls: " + std::to_string(current_result_.syscalls.size()));

        return current_result_;
    }

    bool SyscallExtractor::ExtractFromModule(ModuleType module_type, std::vector<Syscall> &syscalls)
    {
        // Try to load from cache first
        if (config_.use_symbol_cache && LoadFromCache(module_type, syscalls))
        {
            LogInfo("Loaded from cache");
            return true;
        }

        // Load module
        if (!module_manager_->LoadModule(module_type))
        {
            LogError("Failed to load module");
            return false;
        }

        ModuleInfo module_info = module_manager_->GetModuleInfo(module_type);
        current_result_.modules.push_back(module_info);

        // Download symbols if needed
        if (config_.download_symbols)
        {
            if (!DownloadSymbols(module_type))
            {
                LogWarning("Failed to download symbols, continuing without prototypes");
            }
        }

        // Extract syscalls
        if (!ExtractSyscalls(module_type, syscalls))
        {
            LogError("Failed to extract syscalls");
            return false;
        }

        // Save to cache
        if (config_.use_symbol_cache)
        {
            SaveToCache(module_type, syscalls);
        }

        return true;
    }

    bool SyscallExtractor::SaveToJson(const ExtractionResult &result, const std::string &path)
    {
        JsonFormatter formatter;
        return formatter.SaveToFile(result, path);
    }

    bool SyscallExtractor::SaveToCHeader(const ExtractionResult &result, const std::string &path)
    {
        CHeaderFormatter formatter;
        return formatter.SaveToFile(result, path);
    }

    std::string SyscallExtractor::GetVersion()
    {
        return "1.0.0";
    }

    bool SyscallExtractor::InitializeComponents()
    {
        // Initialize disassembler for current architecture
        Architecture arch = os_info_->GetArchitecture();
        if (!disassembler_->Initialize(arch))
        {
            LogError("Failed to initialize disassembler");
            return false;
        }

        // Setup PDB downloader
        pdb_downloader_->SetSymbolServer(config_.symbol_server);
        pdb_downloader_->SetCacheDirectory(config_.symbol_cache_path);

        // Create symbol parser
        symbol_parser_ = CreateSymbolParser(true); // Prefer DIA SDK

        // Create cache directory
        std::filesystem::create_directories(config_.symbol_cache_path);
        std::filesystem::create_directories(config_.output_directory);

        return true;
    }

    bool SyscallExtractor::DownloadSymbols(ModuleType module_type)
    {
        std::string pdb_path, pdb_guid;
        uint32_t pdb_age;

        if (!module_manager_->GetPdbInfo(module_type, pdb_path, pdb_guid, pdb_age))
        {
            LogWarning("No PDB information available");
            return false;
        }

        std::string local_pdb_path;
        if (!pdb_downloader_->DownloadPdbByInfo(pdb_path, pdb_guid, pdb_age, local_pdb_path))
        {
            LogWarning("Failed to download PDB: " + pdb_downloader_->GetLastError());
            return false;
        }

        // Initialize symbol parser with the downloaded PDB
        ModuleInfo module_info = module_manager_->GetModuleInfo(module_type);
        if (!symbol_parser_->Initialize(module_info.path, local_pdb_path))
        {
            LogWarning("Failed to initialize symbol parser");
            return false;
        }

        return true;
    }

    bool SyscallExtractor::ExtractSyscalls(ModuleType module_type, std::vector<Syscall> &syscalls)
    {
        // Get exported functions
        std::vector<SymbolInfo> exports;
        if (!module_manager_->GetExportedFunctions(module_type, exports))
        {
            LogError("Failed to get exported functions");
            return false;
        }

        LogInfo("Found " + std::to_string(exports.size()) + " exported functions");

        ModuleInfo module_info = module_manager_->GetModuleInfo(module_type);

        int nt_functions = 0;
        int analyzed_functions = 0;

        // Process each exported function
        for (const auto &symbol : exports)
        {
            if (!ShouldProcessFunction(symbol.name))
            {
                continue;
            }

            nt_functions++;

            Syscall syscall;
            syscall.name = symbol.name;
            syscall.module_name = module_info.name;
            syscall.rva = symbol.address - module_info.base_address;

            // Analyze the stub to extract syscall number
            if (!AnalyzeStub(symbol.name, syscall.rva, module_type, syscall))
            {
                if (config_.extract_non_syscalls)
                {
                    syscall.is_true_syscall = false;
                    syscall.syscall_number = 0;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                analyzed_functions++;
            }

            // Extract prototype if symbols are available
            if (symbol_parser_ && symbol_parser_->HasSymbols())
            {
                ExtractPrototype(symbol.name, syscall);
            }

            syscalls.push_back(syscall);
        }

        LogInfo("Processed " + std::to_string(nt_functions) + " Nt/Zw functions, found " +
                std::to_string(analyzed_functions) + " syscalls");

        return true;
    }

    bool SyscallExtractor::ProcessExportedFunction(const SymbolInfo &symbol,
                                                   ModuleType module_type,
                                                   std::vector<Syscall> &syscalls)
    {
        if (!ShouldProcessFunction(symbol.name))
        {
            return false;
        }

        ModuleInfo module_info = module_manager_->GetModuleInfo(module_type);

        Syscall syscall;
        syscall.name = symbol.name;
        syscall.module_name = module_info.name;
        syscall.rva = symbol.address - module_info.base_address;

        // Analyze stub
        if (!AnalyzeStub(symbol.name, syscall.rva, module_type, syscall))
        {
            if (config_.extract_non_syscalls)
            {
                syscall.is_true_syscall = false;
            }
            else
            {
                return false;
            }
        }

        // Extract prototype
        ExtractPrototype(symbol.name, syscall);

        syscalls.push_back(syscall);
        return true;
    }

    bool SyscallExtractor::AnalyzeStub(const std::string &function_name,
                                       uint64_t function_rva,
                                       ModuleType module_type,
                                       Syscall &syscall)
    {
        const size_t MAX_STUB_SIZE = 64;
        uint8_t stub_buffer[MAX_STUB_SIZE];

        // Read stub bytes
        if (!module_manager_->ReadModuleMemory(module_type, function_rva, stub_buffer, MAX_STUB_SIZE))
        {
            LogWarning("Failed to read stub for " + function_name);
            return false;
        }

        // Store stub bytes
        syscall.stub_bytes.assign(stub_buffer, stub_buffer + 32);

        // Disassemble and analyze
        uint64_t base_address = module_manager_->GetModuleBase(module_type);
        uint32_t syscall_number = 0;
        bool is_syscall = false;

        if (!disassembler_->AnalyzeSyscallStub(stub_buffer, MAX_STUB_SIZE,
                                               base_address + function_rva,
                                               syscall_number, is_syscall))
        {
            return false;
        }

        syscall.syscall_number = syscall_number;
        syscall.is_true_syscall = is_syscall;

        return is_syscall;
    }

    void SyscallExtractor::ResolveAliases(std::vector<Syscall> &syscalls)
    {
        // Build map of Nt functions
        std::unordered_map<std::string, size_t> nt_functions;
        for (size_t i = 0; i < syscalls.size(); ++i)
        {
            if (syscalls[i].name.substr(0, 2) == "Nt")
            {
                nt_functions[syscalls[i].name] = i;
            }
        }

        // Link Zw functions to their Nt counterparts
        for (auto &syscall : syscalls)
        {
            if (IsZwAlias(syscall.name))
            {
                std::string nt_name = GetNtNameFromZw(syscall.name);
                auto it = nt_functions.find(nt_name);
                if (it != nt_functions.end())
                {
                    const Syscall &nt_syscall = syscalls[it->second];
                    syscall.alias_of = nt_name;
                    syscall.syscall_number = nt_syscall.syscall_number;
                    syscall.is_true_syscall = nt_syscall.is_true_syscall;

                    // Copy prototype if not already set
                    if (syscall.parameters.empty() && !nt_syscall.parameters.empty())
                    {
                        syscall.return_type = nt_syscall.return_type;
                        syscall.parameters = nt_syscall.parameters;
                        syscall.calling_convention = nt_syscall.calling_convention;
                    }
                }
            }
        }
    }

    bool SyscallExtractor::IsZwAlias(const std::string &name) const
    {
        return name.substr(0, 2) == "Zw";
    }

    std::string SyscallExtractor::GetNtNameFromZw(const std::string &zw_name) const
    {
        if (zw_name.substr(0, 2) == "Zw")
        {
            return "Nt" + zw_name.substr(2);
        }
        return zw_name;
    }

    bool SyscallExtractor::ExtractPrototype(const std::string &function_name, Syscall &syscall)
    {
        bool success = false;

        // Try to get from PDB symbols
        if (symbol_parser_ && symbol_parser_->HasSymbols())
        {
            success = symbol_parser_->GetFunctionPrototype(
                function_name,
                syscall.return_type,
                syscall.parameters,
                syscall.calling_convention);
        }

        // Default values if we don't have them
        if (syscall.return_type.empty())
        {
            syscall.return_type = "NTSTATUS";
        }
        if (syscall.calling_convention == CallingConvention::Unknown)
        {
            syscall.calling_convention = CallingConvention::Stdcall;
        }

        return success;
    }

    bool SyscallExtractor::ShouldProcessFunction(const std::string &name) const
    {
        // Process Nt* and Zw* functions
        if (name.substr(0, 2) == "Nt" || name.substr(0, 2) == "Zw")
        {
            return true;
        }

        // Process NtUser* and NtGdi* functions (from win32u.dll)
        if (name.substr(0, 6) == "NtUser" || name.substr(0, 5) == "NtGdi")
        {
            return true;
        }

        return false;
    }

    bool SyscallExtractor::IsSystemCall(const std::string &name) const
    {
        return ShouldProcessFunction(name);
    }

    bool SyscallExtractor::LoadFromCache(ModuleType module_type, std::vector<Syscall> & /*syscalls*/)
    {
        std::string cache_key = GetCacheKey(module_type);
        std::string cache_file = config_.symbol_cache_path + "/" + cache_key + ".cache";

        if (!std::filesystem::exists(cache_file))
        {
            return false;
        }

        // Check if cache is still valid
        auto cache_time = std::filesystem::last_write_time(cache_file);
        auto now = std::filesystem::file_time_type::clock::now();
        auto age = std::chrono::duration_cast<std::chrono::hours>(now - cache_time).count();

        if (age > 24 * 7)
        { // Cache expires after 1 week
            return false;
        }

        // Load from cache (implementation would deserialize from JSON)
        // For now, return false to always perform fresh extraction
        return false;
    }

    bool SyscallExtractor::SaveToCache(ModuleType module_type, const std::vector<Syscall> & /*syscalls*/)
    {
        std::string cache_key = GetCacheKey(module_type);
        std::string cache_file = config_.symbol_cache_path + "/" + cache_key + ".cache";

        // Save to cache (implementation would serialize to JSON)
        // For now, just return true
        return true;
    }

    std::string SyscallExtractor::GetCacheKey(ModuleType module_type) const
    {
        std::stringstream ss;

        switch (module_type)
        {
        case ModuleType::NtDll:
            ss << "ntdll";
            break;
        case ModuleType::Win32u:
            ss << "win32u";
            break;
        case ModuleType::NtDllWow64:
            ss << "ntdll_wow64";
            break;
        }

        ss << "_" << current_result_.os_info.build_number;
        ss << "_" << current_result_.os_info.revision;

        switch (current_result_.os_info.architecture)
        {
        case Architecture::x64:
            ss << "_x64";
            break;
        case Architecture::ARM64:
            ss << "_arm64";
            break;
        case Architecture::x86:
            ss << "_x86";
            break;
        default:
            break;
        }

        return ss.str();
    }

    void SyscallExtractor::LogInfo(const std::string &message)
    {
        LOG_INFO(message);
        if (config_.verbose_logging)
        {
            std::cout << "[INFO] " << message << std::endl;
        }
    }

    void SyscallExtractor::LogWarning(const std::string &message)
    {
        LOG_WARNING(message);
        current_result_.warnings.push_back(message);
    }

    void SyscallExtractor::LogError(const std::string &message)
    {
        LOG_ERROR(message);
        current_result_.errors.push_back(message);
    }

}
