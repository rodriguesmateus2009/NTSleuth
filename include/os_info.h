// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "types.h"
#include <Windows.h>

namespace WinSyscall
{

    class OSInfo
    {
    public:
        OSInfo();
        ~OSInfo() = default;

        // Get current OS build information
        OSBuildInfo GetBuildInfo() const;

        // Get architecture
        Architecture GetArchitecture() const;

        // Check if running under WOW64
        bool IsWow64Process() const;

        // Get system information
        std::string GetSystemInfoString() const;

        // Get NT build number directly
        uint32_t GetNtBuildNumber() const;

        // Check if running on specific Windows version
        bool IsWindows10OrGreater() const;
        bool IsWindows11OrGreater() const;
        bool IsWindowsServer() const;

        // Get module version info
        static bool GetModuleVersion(const std::string &module_path,
                                     uint32_t &major, uint32_t &minor,
                                     uint32_t &build, uint32_t &revision);

    private:
        mutable OSBuildInfo cached_info_;
        mutable bool info_cached_ = false;

        void InitializeInfo() const;
        Architecture DetectArchitecture() const;
        bool CheckWow64() const;
    };

}
