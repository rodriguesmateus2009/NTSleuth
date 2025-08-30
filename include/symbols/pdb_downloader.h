// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "../types.h"
#include <string>
#include <functional>

namespace WinSyscall
{

    class PdbDownloader
    {
    public:
        PdbDownloader();
        ~PdbDownloader();

        // Set symbol server URL
        void SetSymbolServer(const std::string &server_url);

        // Set local cache directory
        void SetCacheDirectory(const std::string &cache_dir);

        // Download PDB for a module
        bool DownloadPdb(const std::string &module_path, std::string &out_pdb_path);

        // Download PDB using explicit info
        bool DownloadPdbByInfo(const std::string &pdb_name,
                               const std::string &guid,
                               uint32_t age,
                               std::string &out_pdb_path);

        // Check if PDB exists in cache
        bool IsPdbCached(const std::string &pdb_name,
                         const std::string &guid,
                         uint32_t age) const;

        // Get cache path for PDB
        std::string GetCachePath(const std::string &pdb_name,
                                 const std::string &guid,
                                 uint32_t age) const;

        // Set progress callback
        void SetProgressCallback(std::function<void(size_t current, size_t total)> callback);

        // Get last error
        std::string GetLastError() const { return last_error_; }

        // Clear cache
        bool ClearCache();

    private:
        std::string symbol_server_;
        std::string cache_directory_;
        std::string last_error_;
        std::function<void(size_t, size_t)> progress_callback_;

        bool CreateCacheDirectory();
        bool DownloadFile(const std::string &url, const std::string &dest_path);
        std::string FormatGuid(const std::string &guid) const;
        bool ExtractPdbInfo(const std::string &module_path,
                            std::string &pdb_name,
                            std::string &guid,
                            uint32_t &age);
    };

}
