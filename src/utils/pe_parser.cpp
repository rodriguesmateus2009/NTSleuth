// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "utils/pe_parser.h"
#include "utils/logger.h"
#include <sstream>
#include <iomanip>

namespace WinSyscall
{

    PEParser::PEParser()
    {
    }

    PEParser::~PEParser()
    {
        Unload();
    }

    bool PEParser::LoadFile(const std::string &path)
    {
        Unload();

        // Open file
        file_handle_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_handle_ == INVALID_HANDLE_VALUE)
        {
            LOG_ERROR("Failed to open file: " + path);
            return false;
        }

        // Create file mapping
        mapping_handle_ = CreateFileMappingA(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_handle_)
        {
            CloseHandle(file_handle_);
            file_handle_ = INVALID_HANDLE_VALUE;
            LOG_ERROR("Failed to create file mapping");
            return false;
        }

        // Map view of file
        base_ = MapViewOfFile(mapping_handle_, FILE_MAP_READ, 0, 0, 0);
        if (!base_)
        {
            CloseHandle(mapping_handle_);
            CloseHandle(file_handle_);
            mapping_handle_ = nullptr;
            file_handle_ = INVALID_HANDLE_VALUE;
            LOG_ERROR("Failed to map view of file");
            return false;
        }

        owns_memory_ = true;

        // Parse headers
        dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(base_);
        if (dos_header_->e_magic != IMAGE_DOS_SIGNATURE)
        {
            Unload();
            LOG_ERROR("Invalid DOS signature");
            return false;
        }

        nt_headers_ = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE *>(base_) + dos_header_->e_lfanew);

        if (nt_headers_->Signature != IMAGE_NT_SIGNATURE)
        {
            Unload();
            LOG_ERROR("Invalid NT signature");
            return false;
        }

        return true;
    }

    bool PEParser::LoadModule(HMODULE module)
    {
        Unload();

        base_ = module;
        owns_memory_ = false;

        // Parse headers
        dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(base_);
        if (dos_header_->e_magic != IMAGE_DOS_SIGNATURE)
        {
            base_ = nullptr;
            return false;
        }

        nt_headers_ = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE *>(base_) + dos_header_->e_lfanew);

        if (nt_headers_->Signature != IMAGE_NT_SIGNATURE)
        {
            base_ = nullptr;
            return false;
        }

        return true;
    }

    void PEParser::Unload()
    {
        if (owns_memory_ && base_)
        {
            UnmapViewOfFile(base_);
        }

        if (mapping_handle_)
        {
            CloseHandle(mapping_handle_);
        }

        if (file_handle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file_handle_);
        }

        base_ = nullptr;
        mapping_handle_ = nullptr;
        file_handle_ = INVALID_HANDLE_VALUE;
        dos_header_ = nullptr;
        nt_headers_ = nullptr;
        owns_memory_ = false;
    }

    PIMAGE_DOS_HEADER PEParser::GetDosHeader() const
    {
        return dos_header_;
    }

    PIMAGE_NT_HEADERS PEParser::GetNtHeaders() const
    {
        return nt_headers_;
    }

    PIMAGE_OPTIONAL_HEADER PEParser::GetOptionalHeader() const
    {
        if (!nt_headers_)
        {
            return nullptr;
        }
        return &nt_headers_->OptionalHeader;
    }

    Architecture PEParser::GetArchitecture() const
    {
        if (!nt_headers_)
        {
            return Architecture::Unknown;
        }

        switch (nt_headers_->FileHeader.Machine)
        {
        case IMAGE_FILE_MACHINE_I386:
            return Architecture::x86;
        case IMAGE_FILE_MACHINE_AMD64:
            return Architecture::x64;
        case IMAGE_FILE_MACHINE_ARM64:
            return Architecture::ARM64;
        default:
            return Architecture::Unknown;
        }
    }

    PIMAGE_SECTION_HEADER PEParser::GetSectionHeader(const std::string &name) const
    {
        if (!nt_headers_)
        {
            return nullptr;
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers_);

        for (WORD i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i)
        {
            if (strncmp(reinterpret_cast<const char *>(section[i].Name), name.c_str(), 8) == 0)
            {
                return &section[i];
            }
        }

        return nullptr;
    }

    std::vector<PIMAGE_SECTION_HEADER> PEParser::GetAllSections() const
    {
        std::vector<PIMAGE_SECTION_HEADER> sections;

        if (!nt_headers_)
        {
            return sections;
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers_);

        for (WORD i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i)
        {
            sections.push_back(&section[i]);
        }

        return sections;
    }

    bool PEParser::GetDataDirectory(DWORD index, DWORD &rva, DWORD &size) const
    {
        if (!nt_headers_ || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        {
            return false;
        }

        const IMAGE_DATA_DIRECTORY *dir = nullptr;

        if (nt_headers_->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PIMAGE_NT_HEADERS64 nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers_);
            dir = &nt64->OptionalHeader.DataDirectory[index];
        }
        else if (nt_headers_->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_NT_HEADERS32 nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers_);
            dir = &nt32->OptionalHeader.DataDirectory[index];
        }
        else
        {
            return false;
        }

        rva = dir->VirtualAddress;
        size = dir->Size;

        return rva != 0 && size != 0;
    }

    PIMAGE_EXPORT_DIRECTORY PEParser::GetExportDirectory() const
    {
        DWORD rva, size;
        if (!GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT, rva, size))
        {
            return nullptr;
        }

        return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RvaToVa(rva));
    }

    PIMAGE_DEBUG_DIRECTORY PEParser::GetDebugDirectory() const
    {
        DWORD rva, size;
        if (!GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG, rva, size))
        {
            return nullptr;
        }

        return reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(RvaToVa(rva));
    }

    std::vector<std::string> PEParser::GetExportedFunctions() const
    {
        std::vector<std::string> exports;

        PIMAGE_EXPORT_DIRECTORY export_dir = GetExportDirectory();
        if (!export_dir)
        {
            return exports;
        }

        DWORD *name_rvas = reinterpret_cast<DWORD *>(RvaToVa(export_dir->AddressOfNames));

        for (DWORD i = 0; i < export_dir->NumberOfNames; ++i)
        {
            const char *name = reinterpret_cast<const char *>(RvaToVa(name_rvas[i]));
            if (name)
            {
                exports.push_back(name);
            }
        }

        return exports;
    }

    bool PEParser::GetExportByName(const std::string &name, DWORD &rva) const
    {
        PIMAGE_EXPORT_DIRECTORY export_dir = GetExportDirectory();
        if (!export_dir)
        {
            return false;
        }

        DWORD *name_rvas = reinterpret_cast<DWORD *>(RvaToVa(export_dir->AddressOfNames));
        WORD *ordinals = reinterpret_cast<WORD *>(RvaToVa(export_dir->AddressOfNameOrdinals));
        DWORD *func_rvas = reinterpret_cast<DWORD *>(RvaToVa(export_dir->AddressOfFunctions));

        for (DWORD i = 0; i < export_dir->NumberOfNames; ++i)
        {
            const char *export_name = reinterpret_cast<const char *>(RvaToVa(name_rvas[i]));
            if (export_name && name == export_name)
            {
                WORD ordinal = ordinals[i];
                rva = func_rvas[ordinal];
                return true;
            }
        }

        return false;
    }

    bool PEParser::GetExportByOrdinal(WORD ordinal, DWORD &rva) const
    {
        PIMAGE_EXPORT_DIRECTORY export_dir = GetExportDirectory();
        if (!export_dir)
        {
            return false;
        }

        if (ordinal < export_dir->Base ||
            ordinal >= export_dir->Base + export_dir->NumberOfFunctions)
        {
            return false;
        }

        DWORD *func_rvas = reinterpret_cast<DWORD *>(RvaToVa(export_dir->AddressOfFunctions));
        rva = func_rvas[ordinal - export_dir->Base];

        return true;
    }

    bool PEParser::GetPdbInfo(std::string &pdb_path, std::string &guid, uint32_t &age) const
    {
        DWORD debug_rva, debug_size;
        if (!GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG, debug_rva, debug_size))
        {
            return false;
        }

        PIMAGE_DEBUG_DIRECTORY debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(RvaToVa(debug_rva));
        if (!debug_dir)
        {
            return false;
        }

        DWORD num_entries = debug_size / sizeof(IMAGE_DEBUG_DIRECTORY);

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

                CV_INFO_PDB70 *cv_info = nullptr;

                if (owns_memory_)
                {
                    // File mapping - use AddressOfRawData
                    DWORD offset = RvaToFileOffset(debug_dir[i].AddressOfRawData);
                    cv_info = reinterpret_cast<CV_INFO_PDB70 *>(
                        reinterpret_cast<BYTE *>(base_) + offset);
                }
                else
                {
                    // Loaded module - use AddressOfRawData as RVA
                    cv_info = reinterpret_cast<CV_INFO_PDB70 *>(
                        RvaToVa(debug_dir[i].AddressOfRawData));
                }

                if (cv_info && cv_info->Signature == 'SDSR')
                { // 'RSDS'
                    pdb_path = cv_info->PdbFileName;
                    age = cv_info->Age;

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
                    guid = ss.str();

                    return true;
                }
            }
        }

        return false;
    }

    PVOID PEParser::RvaToVa(DWORD rva) const
    {
        if (!base_)
        {
            return nullptr;
        }

        return reinterpret_cast<BYTE *>(base_) + rva;
    }

    DWORD PEParser::VaToRva(PVOID va) const
    {
        if (!base_ || va < base_)
        {
            return 0;
        }

        return static_cast<DWORD>(reinterpret_cast<BYTE *>(va) - reinterpret_cast<BYTE *>(base_));
    }

    DWORD PEParser::RvaToFileOffset(DWORD rva) const
    {
        if (!nt_headers_)
        {
            return 0;
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers_);

        for (WORD i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i)
        {
            if (rva >= section[i].VirtualAddress &&
                rva < section[i].VirtualAddress + section[i].SizeOfRawData)
            {
                return section[i].PointerToRawData + (rva - section[i].VirtualAddress);
            }
        }

        // If not in any section, assume it's in the header
        return rva;
    }

    DWORD PEParser::FileOffsetToRva(DWORD offset) const
    {
        if (!nt_headers_)
        {
            return 0;
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers_);

        for (WORD i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i)
        {
            if (offset >= section[i].PointerToRawData &&
                offset < section[i].PointerToRawData + section[i].SizeOfRawData)
            {
                return section[i].VirtualAddress + (offset - section[i].PointerToRawData);
            }
        }

        // If not in any section, assume it's in the header
        return offset;
    }

}
