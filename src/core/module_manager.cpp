// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "module_manager.h"
#include "utils/logger.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <filesystem>
#include <sstream>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

namespace WinSyscall
{

    ModuleManager::ModuleManager()
    {
    }

    ModuleManager::~ModuleManager()
    {
        // Unmap any mapped modules
        for (auto &[type, module] : modules_)
        {
            if (module && module->mapped_base)
            {
                UnmapViewOfFile(module->mapped_base);
            }
            if (module && module->handle)
            {
                FreeLibrary(module->handle);
            }
        }
    }

    bool ModuleManager::LoadModule(ModuleType type)
    {
        std::string module_name = GetModuleNameForType(type);
        std::string module_path;

        switch (type)
        {
        case ModuleType::NtDll:
            module_path = GetSystemModulePath("ntdll.dll");
            break;
        case ModuleType::Win32u:
            module_path = GetSystemModulePath("win32u.dll");
            break;
        case ModuleType::NtDllWow64:
            module_path = GetSysWow64ModulePath("ntdll.dll");
            break;
        default:
            LOG_ERROR("Unknown module type");
            return false;
        }

        return LoadModuleByPath(module_path, type);
    }

    bool ModuleManager::LoadModuleByPath(const std::string &path, ModuleType type)
    {
        if (!std::filesystem::exists(path))
        {
            LOG_ERROR("Module not found: " + path);
            return false;
        }

        auto module_data = std::make_unique<ModuleData>();
        module_data->info.path = path;
        module_data->info.name = std::filesystem::path(path).filename().string();
        module_data->info.type = type;

        // Load module (don't execute DllMain)
        module_data->handle = LoadLibraryExA(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!module_data->handle)
        {
            LOG_ERROR("Failed to load module: " + path);
            return false;
        }

        module_data->info.base_address = reinterpret_cast<uint64_t>(module_data->handle);

        // Parse PE headers
        if (!ParsePEHeaders(module_data.get()))
        {
            FreeLibrary(module_data->handle);
            return false;
        }

        // Extract debug info
        ExtractDebugInfo(module_data.get());

        modules_[type] = std::move(module_data);

        LOG_INFO("Loaded module: " + path);
        return true;
    }

    ModuleInfo ModuleManager::GetModuleInfo(ModuleType type) const
    {
        auto it = modules_.find(type);
        if (it != modules_.end() && it->second)
        {
            return it->second->info;
        }
        return ModuleInfo{};
    }

    std::vector<ModuleInfo> ModuleManager::GetLoadedModules() const
    {
        std::vector<ModuleInfo> result;
        for (const auto &[type, module] : modules_)
        {
            if (module)
            {
                result.push_back(module->info);
            }
        }
        return result;
    }

    HMODULE ModuleManager::GetModuleHandle(ModuleType type) const
    {
        auto it = modules_.find(type);
        if (it != modules_.end() && it->second)
        {
            return it->second->handle;
        }
        return nullptr;
    }

    uint64_t ModuleManager::GetModuleBase(ModuleType type) const
    {
        auto it = modules_.find(type);
        if (it != modules_.end() && it->second)
        {
            return it->second->info.base_address;
        }
        return 0;
    }

    uint32_t ModuleManager::GetModuleSize(ModuleType type) const
    {
        auto it = modules_.find(type);
        if (it != modules_.end() && it->second)
        {
            return it->second->info.size;
        }
        return 0;
    }

    bool ModuleManager::GetExportedFunctions(ModuleType type, std::vector<SymbolInfo> &exports) const
    {
        auto it = modules_.find(type);
        if (it == modules_.end() || !it->second)
        {
            return false;
        }

        const auto &module = it->second;
        PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module->handle);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE *>(module->handle) + dos_header->e_lfanew);

        if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        DWORD export_dir_rva = 0;
        DWORD export_dir_size = 0;

        if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PIMAGE_NT_HEADERS64 nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers);
            export_dir_rva = nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_dir_size = nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_NT_HEADERS32 nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers);
            export_dir_rva = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_dir_size = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        else
        {
            return false;
        }

        if (export_dir_rva == 0 || export_dir_size == 0)
        {
            return false;
        }

        PIMAGE_EXPORT_DIRECTORY export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            reinterpret_cast<BYTE *>(module->handle) + export_dir_rva);

        DWORD *name_rvas = reinterpret_cast<DWORD *>(
            reinterpret_cast<BYTE *>(module->handle) + export_dir->AddressOfNames);
        DWORD *func_rvas = reinterpret_cast<DWORD *>(
            reinterpret_cast<BYTE *>(module->handle) + export_dir->AddressOfFunctions);
        WORD *ordinals = reinterpret_cast<WORD *>(
            reinterpret_cast<BYTE *>(module->handle) + export_dir->AddressOfNameOrdinals);

        exports.clear();
        exports.reserve(export_dir->NumberOfNames);

        for (DWORD i = 0; i < export_dir->NumberOfNames; ++i)
        {
            const char *func_name = reinterpret_cast<const char *>(
                reinterpret_cast<BYTE *>(module->handle) + name_rvas[i]);

            WORD ordinal = ordinals[i];
            DWORD func_rva = func_rvas[ordinal];

            SymbolInfo symbol;
            symbol.name = func_name;
            symbol.address = module->info.base_address + func_rva;
            symbol.is_export = true;

            // Check if it's a forwarder
            if (func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size)
            {
                symbol.is_forward = true;
                symbol.forward_name = reinterpret_cast<const char *>(
                    reinterpret_cast<BYTE *>(module->handle) + func_rva);
            }

            exports.push_back(symbol);
        }

        return true;
    }

    bool ModuleManager::ReadModuleMemory(ModuleType type, uint64_t rva, void *buffer, size_t size) const
    {
        auto it = modules_.find(type);
        if (it == modules_.end() || !it->second)
        {
            return false;
        }

        const auto &module = it->second;
        if (module->mapped_base)
        {
            // Read from mapped memory
            const BYTE *src = reinterpret_cast<const BYTE *>(module->mapped_base) + rva;
            memcpy(buffer, src, size);
            return true;
        }
        else if (module->handle)
        {
            // Read from loaded module
            const BYTE *src = reinterpret_cast<const BYTE *>(module->handle) + rva;
            memcpy(buffer, src, size);
            return true;
        }

        return false;
    }

    bool ModuleManager::GetPdbInfo(ModuleType type, std::string &pdb_path, std::string &guid, uint32_t &age) const
    {
        auto it = modules_.find(type);
        if (it == modules_.end() || !it->second)
        {
            return false;
        }

        const auto &module = it->second;
        pdb_path = module->info.pdb_path;
        guid = module->info.pdb_guid;
        age = module->info.pdb_age;

        return !pdb_path.empty();
    }

    bool ModuleManager::MapModuleIntoMemory(ModuleType type)
    {
        auto it = modules_.find(type);
        if (it == modules_.end() || !it->second)
        {
            return false;
        }

        auto &module = it->second;
        if (module->mapped_base)
        {
            return true; // Already mapped
        }

        // Open file for mapping
        HANDLE file = CreateFileA(module->info.path.c_str(),
                                  GENERIC_READ,
                                  FILE_SHARE_READ,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        // Create file mapping
        HANDLE mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        CloseHandle(file);

        if (!mapping)
        {
            return false;
        }

        // Map view of file
        module->mapped_base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(mapping);

        if (!module->mapped_base)
        {
            return false;
        }

        module->is_mapped = true;
        return true;
    }

    void *ModuleManager::GetMappedAddress(ModuleType type) const
    {
        auto it = modules_.find(type);
        if (it != modules_.end() && it->second)
        {
            return it->second->mapped_base;
        }
        return nullptr;
    }

    std::string ModuleManager::GetSystemModulePath(const std::string &module_name)
    {
        char system_dir[MAX_PATH];
        if (GetSystemDirectoryA(system_dir, MAX_PATH))
        {
            return std::string(system_dir) + "\\" + module_name;
        }
        return module_name;
    }

    std::string ModuleManager::GetSysWow64ModulePath(const std::string &module_name)
    {
        char system_dir[MAX_PATH];
        if (GetSystemWow64DirectoryA(system_dir, MAX_PATH))
        {
            return std::string(system_dir) + "\\" + module_name;
        }
        return module_name;
    }

    bool ModuleManager::ParsePEHeaders(ModuleData *module_data)
    {
        if (!module_data || !module_data->handle)
        {
            return false;
        }

        PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_data->handle);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE *>(module_data->handle) + dos_header->e_lfanew);

        if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        // Get image size
        if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PIMAGE_NT_HEADERS64 nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers);
            module_data->info.size = nt_headers64->OptionalHeader.SizeOfImage;
        }
        else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_NT_HEADERS32 nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers);
            module_data->info.size = nt_headers32->OptionalHeader.SizeOfImage;
        }
        else
        {
            return false;
        }

        return true;
    }

    bool ModuleManager::ExtractDebugInfo(ModuleData *module_data)
    {
        if (!module_data || !module_data->handle)
        {
            return false;
        }

        PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_data->handle);
        PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE *>(module_data->handle) + dos_header->e_lfanew);

        DWORD debug_dir_rva = 0;
        DWORD debug_dir_size = 0;

        if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PIMAGE_NT_HEADERS64 nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers);
            debug_dir_rva = nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debug_dir_size = nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
        else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_NT_HEADERS32 nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers);
            debug_dir_rva = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debug_dir_size = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }

        if (debug_dir_rva == 0 || debug_dir_size == 0)
        {
            return false;
        }

        PIMAGE_DEBUG_DIRECTORY debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
            reinterpret_cast<BYTE *>(module_data->handle) + debug_dir_rva);

        DWORD num_entries = debug_dir_size / sizeof(IMAGE_DEBUG_DIRECTORY);

        for (DWORD i = 0; i < num_entries; ++i)
        {
            if (debug_dir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
            {
                struct CV_INFO_PDB70
                {
                    DWORD Signature;
                    GUID Guid;
                    DWORD Age;
                    char PdbFileName[1];
                };

                CV_INFO_PDB70 *cv_info = reinterpret_cast<CV_INFO_PDB70 *>(
                    reinterpret_cast<BYTE *>(module_data->handle) + debug_dir[i].AddressOfRawData);

                if (cv_info->Signature == 'SDSR')
                { // 'RSDS'
                    // Format GUID
                    std::stringstream ss;
                    ss << std::uppercase << std::hex << std::setfill('0');
                    ss << std::setw(8) << cv_info->Guid.Data1;
                    ss << std::setw(4) << cv_info->Guid.Data2;
                    ss << std::setw(4) << cv_info->Guid.Data3;
                    for (int j = 0; j < 8; ++j)
                    {
                        ss << std::setw(2) << static_cast<int>(cv_info->Guid.Data4[j]);
                    }

                    module_data->info.pdb_guid = ss.str();
                    module_data->info.pdb_age = cv_info->Age;
                    module_data->info.pdb_path = cv_info->PdbFileName;

                    return true;
                }
            }
        }

        return false;
    }

    std::string ModuleManager::GetModuleNameForType(ModuleType type) const
    {
        switch (type)
        {
        case ModuleType::NtDll:
            return "ntdll.dll";
        case ModuleType::Win32u:
            return "win32u.dll";
        case ModuleType::NtDllWow64:
            return "ntdll.dll (WOW64)";
        default:
            return "unknown";
        }
    }

}
