// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "../types.h"
#include <Windows.h>
#include <string>
#include <vector>

namespace WinSyscall
{

    class PEParser
    {
    public:
        PEParser();
        ~PEParser();

        // Load PE file
        bool LoadFile(const std::string &path);
        bool LoadModule(HMODULE module);
        void Unload();

        // Check if loaded
        bool IsLoaded() const { return base_ != nullptr; }

        // Get headers
        PIMAGE_DOS_HEADER GetDosHeader() const;
        PIMAGE_NT_HEADERS GetNtHeaders() const;
        PIMAGE_OPTIONAL_HEADER GetOptionalHeader() const;

        // Get architecture
        Architecture GetArchitecture() const;

        // Get sections
        PIMAGE_SECTION_HEADER GetSectionHeader(const std::string &name) const;
        std::vector<PIMAGE_SECTION_HEADER> GetAllSections() const;

        // Get directories
        bool GetDataDirectory(DWORD index, DWORD &rva, DWORD &size) const;
        PIMAGE_EXPORT_DIRECTORY GetExportDirectory() const;
        PIMAGE_DEBUG_DIRECTORY GetDebugDirectory() const;

        // Get exports
        std::vector<std::string> GetExportedFunctions() const;
        bool GetExportByName(const std::string &name, DWORD &rva) const;
        bool GetExportByOrdinal(WORD ordinal, DWORD &rva) const;

        // Get debug info
        bool GetPdbInfo(std::string &pdb_path, std::string &guid, uint32_t &age) const;

        // RVA/VA conversion
        PVOID RvaToVa(DWORD rva) const;
        DWORD VaToRva(PVOID va) const;

        // File offset conversion
        DWORD RvaToFileOffset(DWORD rva) const;
        DWORD FileOffsetToRva(DWORD offset) const;

    private:
        void *base_ = nullptr;
        HANDLE file_handle_ = INVALID_HANDLE_VALUE;
        HANDLE mapping_handle_ = nullptr;
        bool owns_memory_ = false;

        PIMAGE_DOS_HEADER dos_header_ = nullptr;
        PIMAGE_NT_HEADERS nt_headers_ = nullptr;
    };

}
