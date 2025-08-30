// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "types.h"
#include <Windows.h>
#include <memory>
#include <unordered_map>

namespace WinSyscall
{

    class ModuleManager
    {
    public:
        ModuleManager();
        ~ModuleManager();

        // Load module information
        bool LoadModule(ModuleType type);
        bool LoadModuleByPath(const std::string &path, ModuleType type);

        // Get module information
        ModuleInfo GetModuleInfo(ModuleType type) const;
        std::vector<ModuleInfo> GetLoadedModules() const;

        // Get module handle
        HMODULE GetModuleHandle(ModuleType type) const;

        // Get module base and size
        uint64_t GetModuleBase(ModuleType type) const;
        uint32_t GetModuleSize(ModuleType type) const;

        // Get export directory
        bool GetExportedFunctions(ModuleType type, std::vector<SymbolInfo> &exports) const;

        // Read module memory
        bool ReadModuleMemory(ModuleType type, uint64_t rva, void *buffer, size_t size) const;

        // Get PDB information from module
        bool GetPdbInfo(ModuleType type, std::string &pdb_path, std::string &guid, uint32_t &age) const;

        // Map module into memory (for analysis)
        bool MapModuleIntoMemory(ModuleType type);
        void *GetMappedAddress(ModuleType type) const;

        // Get module path
        static std::string GetSystemModulePath(const std::string &module_name);
        static std::string GetSysWow64ModulePath(const std::string &module_name);

    private:
        struct ModuleData
        {
            ModuleInfo info;
            HMODULE handle = nullptr;
            void *mapped_base = nullptr;
            size_t mapped_size = 0;
            bool is_mapped = false;
        };

        std::unordered_map<ModuleType, std::unique_ptr<ModuleData>> modules_;

        bool LoadModuleInternal(const std::string &path, ModuleType type);
        bool ParsePEHeaders(ModuleData *module_data);
        bool ExtractDebugInfo(ModuleData *module_data);
        std::string GetModuleNameForType(ModuleType type) const;
    };

}
