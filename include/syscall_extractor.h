// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "types.h"
#include <memory>
#include <vector>
#include <string>

namespace WinSyscall
{

    // Forward declarations
    class OSInfo;
    class ModuleManager;
    class Disassembler;
    class ISymbolParser;
    class PdbDownloader;

    class SyscallExtractor
    {
    public:
        SyscallExtractor();
        ~SyscallExtractor();

        // Configure extraction
        void SetConfig(const ExtractionConfig &config);
        ExtractionConfig GetConfig() const;

        // Main extraction method
        ExtractionResult Extract();

        // Extract from specific module
        bool ExtractFromModule(ModuleType module_type, std::vector<Syscall> &syscalls);

        // Save results
        bool SaveToJson(const ExtractionResult &result, const std::string &path);
        bool SaveToCHeader(const ExtractionResult &result, const std::string &path);

        // Get version
        static std::string GetVersion();

    private:
        ExtractionConfig config_;
        std::unique_ptr<OSInfo> os_info_;
        std::unique_ptr<ModuleManager> module_manager_;
        std::unique_ptr<Disassembler> disassembler_;
        std::unique_ptr<ISymbolParser> symbol_parser_;
        std::unique_ptr<PdbDownloader> pdb_downloader_;

        ExtractionResult current_result_;

        // Core extraction logic
        bool InitializeComponents();
        bool DownloadSymbols(ModuleType module_type);
        bool ExtractSyscalls(ModuleType module_type, std::vector<Syscall> &syscalls);

        // Symbol processing
        bool ProcessExportedFunction(const SymbolInfo &symbol,
                                     ModuleType module_type,
                                     std::vector<Syscall> &syscalls);

        // Stub analysis
        bool AnalyzeStub(const std::string &function_name,
                         uint64_t function_rva,
                         ModuleType module_type,
                         Syscall &syscall);

        // Alias resolution
        void ResolveAliases(std::vector<Syscall> &syscalls);
        bool IsZwAlias(const std::string &name) const;
        std::string GetNtNameFromZw(const std::string &zw_name) const;

        // Prototype extraction
        bool ExtractPrototype(const std::string &function_name,
                              Syscall &syscall);

        // Filtering
        bool ShouldProcessFunction(const std::string &name) const;
        bool IsSystemCall(const std::string &name) const;

        // Caching
        bool LoadFromCache(ModuleType module_type, std::vector<Syscall> &syscalls);
        bool SaveToCache(ModuleType module_type, const std::vector<Syscall> &syscalls);
        std::string GetCacheKey(ModuleType module_type) const;

        // Logging
        void LogInfo(const std::string &message);
        void LogWarning(const std::string &message);
        void LogError(const std::string &message);
    };

}
