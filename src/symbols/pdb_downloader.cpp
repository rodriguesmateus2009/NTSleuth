// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "symbols/pdb_downloader.h"
#include "utils/logger.h"
#include <Windows.h>
#include <wininet.h>
#include <urlmon.h>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

namespace WinSyscall
{

    class DownloadCallback : public IBindStatusCallback
    {
    public:
        DownloadCallback(std::function<void(size_t, size_t)> progress_callback)
            : ref_count_(1), progress_callback_(progress_callback) {}

        // IUnknown methods
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override
        {
            if (riid == IID_IUnknown || riid == IID_IBindStatusCallback)
            {
                *ppvObject = this;
                AddRef();
                return S_OK;
            }
            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return InterlockedIncrement(&ref_count_);
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            ULONG count = InterlockedDecrement(&ref_count_);
            if (count == 0)
            {
                delete this;
            }
            return count;
        }

        // IBindStatusCallback methods
        HRESULT STDMETHODCALLTYPE OnStartBinding(DWORD /*dwReserved*/, IBinding * /*pib*/) override
        {
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE GetPriority(LONG * /*pnPriority*/) override
        {
            return E_NOTIMPL;
        }

        HRESULT STDMETHODCALLTYPE OnLowResource(DWORD /*reserved*/) override
        {
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE OnProgress(ULONG ulProgress, ULONG ulProgressMax,
                                             ULONG /*ulStatusCode*/, LPCWSTR /*szStatusText*/) override
        {
            if (progress_callback_)
            {
                progress_callback_(ulProgress, ulProgressMax);
            }
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE OnStopBinding(HRESULT /*hresult*/, LPCWSTR /*szError*/) override
        {
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE GetBindInfo(DWORD * /*grfBINDF*/, BINDINFO * /*pbindinfo*/) override
        {
            return E_NOTIMPL;
        }

        HRESULT STDMETHODCALLTYPE OnDataAvailable(DWORD /*grfBSCF*/, DWORD /*dwSize*/,
                                                  FORMATETC * /*pformatetc*/, STGMEDIUM * /*pstgmed*/) override
        {
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE OnObjectAvailable(REFIID /*riid*/, IUnknown * /*punk*/) override
        {
            return S_OK;
        }

    private:
        LONG ref_count_;
        std::function<void(size_t, size_t)> progress_callback_;
    };

    PdbDownloader::PdbDownloader()
        : symbol_server_("https://msdl.microsoft.com/download/symbols"),
          cache_directory_("cache\\symbols")
    {
        CreateCacheDirectory();
    }

    PdbDownloader::~PdbDownloader() = default;

    void PdbDownloader::SetSymbolServer(const std::string &server_url)
    {
        symbol_server_ = server_url;
    }

    void PdbDownloader::SetCacheDirectory(const std::string &cache_dir)
    {
        cache_directory_ = cache_dir;
        CreateCacheDirectory();
    }

    bool PdbDownloader::DownloadPdb(const std::string &module_path, std::string &out_pdb_path)
    {
        std::string pdb_name, guid;
        uint32_t age;

        if (!ExtractPdbInfo(module_path, pdb_name, guid, age))
        {
            last_error_ = "Failed to extract PDB information from module";
            return false;
        }

        return DownloadPdbByInfo(pdb_name, guid, age, out_pdb_path);
    }

    bool PdbDownloader::DownloadPdbByInfo(const std::string &pdb_name,
                                          const std::string &guid,
                                          uint32_t age,
                                          std::string &out_pdb_path)
    {
        // Check if already cached
        if (IsPdbCached(pdb_name, guid, age))
        {
            out_pdb_path = GetCachePath(pdb_name, guid, age);
            LOG_INFO("PDB found in cache: " + out_pdb_path);
            return true;
        }

        // Format URL
        std::string formatted_guid = FormatGuid(guid);
        std::stringstream url_stream;
        url_stream << symbol_server_ << "/" << pdb_name << "/"
                   << formatted_guid << std::hex << age << "/" << pdb_name;
        std::string url = url_stream.str();

        // Prepare cache path
        out_pdb_path = GetCachePath(pdb_name, guid, age);
        std::filesystem::path cache_path(out_pdb_path);
        std::filesystem::create_directories(cache_path.parent_path());

        LOG_INFO("Downloading PDB from: " + url);

        // Try download without compression first
        if (DownloadFile(url, out_pdb_path))
        {
            LOG_INFO("PDB downloaded successfully");
            return true;
        }

        // Try compressed version (.pd_)
        std::string compressed_url = url;
        size_t last_char = compressed_url.length() - 1;
        if (compressed_url[last_char] == 'b')
        {
            compressed_url[last_char] = '_';
            std::string compressed_path = out_pdb_path + "_";

            if (DownloadFile(compressed_url, compressed_path))
            {
                // Decompress using expand.exe
                std::string cmd = "expand \"" + compressed_path + "\" \"" + out_pdb_path + "\"";
                if (system(cmd.c_str()) == 0)
                {
                    std::filesystem::remove(compressed_path);
                    LOG_INFO("PDB downloaded and decompressed successfully");
                    return true;
                }
            }
        }

        last_error_ = "Failed to download PDB from symbol server";
        return false;
    }

    bool PdbDownloader::IsPdbCached(const std::string &pdb_name,
                                    const std::string &guid,
                                    uint32_t age) const
    {
        std::string cache_path = GetCachePath(pdb_name, guid, age);
        return std::filesystem::exists(cache_path);
    }

    std::string PdbDownloader::GetCachePath(const std::string &pdb_name,
                                            const std::string &guid,
                                            uint32_t age) const
    {
        std::string formatted_guid = FormatGuid(guid);
        std::stringstream path_stream;
        path_stream << cache_directory_ << "\\" << pdb_name << "\\"
                    << formatted_guid << std::hex << age << "\\" << pdb_name;
        return path_stream.str();
    }

    void PdbDownloader::SetProgressCallback(std::function<void(size_t current, size_t total)> callback)
    {
        progress_callback_ = callback;
    }

    bool PdbDownloader::ClearCache()
    {
        try
        {
            if (std::filesystem::exists(cache_directory_))
            {
                std::filesystem::remove_all(cache_directory_);
                CreateCacheDirectory();
                return true;
            }
        }
        catch (const std::exception &e)
        {
            last_error_ = std::string("Failed to clear cache: ") + e.what();
        }
        return false;
    }

    bool PdbDownloader::CreateCacheDirectory()
    {
        try
        {
            std::filesystem::create_directories(cache_directory_);
            return true;
        }
        catch (const std::exception &e)
        {
            last_error_ = std::string("Failed to create cache directory: ") + e.what();
            return false;
        }
    }

    bool PdbDownloader::DownloadFile(const std::string &url, const std::string &dest_path)
    {
        // Use URLDownloadToFile for simplicity
        DownloadCallback *callback = nullptr;
        if (progress_callback_)
        {
            callback = new DownloadCallback(progress_callback_);
        }

        HRESULT hr = URLDownloadToFileA(nullptr, url.c_str(), dest_path.c_str(), 0, callback);

        if (callback)
        {
            callback->Release();
        }

        if (SUCCEEDED(hr))
        {
            // Verify the file was actually downloaded
            if (std::filesystem::exists(dest_path) && std::filesystem::file_size(dest_path) > 0)
            {
                return true;
            }
            // Remove empty file
            std::filesystem::remove(dest_path);
        }

        return false;
    }

    std::string PdbDownloader::FormatGuid(const std::string &guid) const
    {
        // GUID should already be in uppercase hex format without hyphens
        // Just ensure it's uppercase
        std::string formatted = guid;
        std::transform(formatted.begin(), formatted.end(), formatted.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(::toupper(c)); });
        return formatted;
    }

    bool PdbDownloader::ExtractPdbInfo(const std::string &module_path,
                                       std::string &pdb_name,
                                       std::string &guid,
                                       uint32_t &age)
    {
        HANDLE file = CreateFileA(module_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        HANDLE mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        CloseHandle(file);

        if (!mapping)
        {
            return false;
        }

        void *base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(mapping);

        if (!base)
        {
            return false;
        }

        bool result = false;

        // Parse PE headers
        PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
        {
            PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE *>(base) + dos_header->e_lfanew);

            if (nt_headers->Signature == IMAGE_NT_SIGNATURE)
            {
                DWORD debug_dir_rva = 0;
                DWORD debug_dir_size = 0;

                if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    PIMAGE_NT_HEADERS64 nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers);
                    debug_dir_rva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                    debug_dir_size = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                }
                else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    PIMAGE_NT_HEADERS32 nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers);
                    debug_dir_rva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                    debug_dir_size = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                }

                if (debug_dir_rva && debug_dir_size)
                {
                    PIMAGE_DEBUG_DIRECTORY debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
                        reinterpret_cast<BYTE *>(base) + debug_dir_rva);

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
                                reinterpret_cast<BYTE *>(base) + debug_dir[i].AddressOfRawData);

                            if (cv_info->Signature == 'SDSR')
                            { // 'RSDS'
                                // Extract PDB name
                                pdb_name = cv_info->PdbFileName;
                                size_t pos = pdb_name.find_last_of("\\/");
                                if (pos != std::string::npos)
                                {
                                    pdb_name = pdb_name.substr(pos + 1);
                                }

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

                                age = cv_info->Age;
                                result = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        UnmapViewOfFile(base);
        return result;
    }

}