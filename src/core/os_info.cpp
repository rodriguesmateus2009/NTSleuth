// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "os_info.h"
#include "utils/logger.h"
#include <Windows.h>
#include <VersionHelpers.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "version.lib")

namespace WinSyscall
{

    OSInfo::OSInfo()
    {
        InitializeInfo();
    }

    OSBuildInfo OSInfo::GetBuildInfo() const
    {
        if (!info_cached_)
        {
            InitializeInfo();
        }
        return cached_info_;
    }

    Architecture OSInfo::GetArchitecture() const
    {
        return DetectArchitecture();
    }

    bool OSInfo::IsWow64Process() const
    {
        return CheckWow64();
    }

    std::string OSInfo::GetSystemInfoString() const
    {
        if (!info_cached_)
        {
            InitializeInfo();
        }

        std::stringstream ss;
        ss << "Windows " << cached_info_.major_version
           << "." << cached_info_.minor_version
           << " Build " << cached_info_.build_number;

        if (cached_info_.revision > 0)
        {
            ss << "." << cached_info_.revision;
        }

        switch (cached_info_.architecture)
        {
        case Architecture::x64:
            ss << " (x64)";
            break;
        case Architecture::ARM64:
            ss << " (ARM64)";
            break;
        case Architecture::x86:
            ss << " (x86)";
            break;
        default:
            ss << " (Unknown)";
            break;
        }

        if (cached_info_.is_wow64)
        {
            ss << " [WOW64]";
        }

        return ss.str();
    }

    uint32_t OSInfo::GetNtBuildNumber() const
    {
        // Get build number directly from PEB
        typedef struct _PEB
        {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PVOID Ldr;
            PVOID ProcessParameters;
            BYTE Reserved4[104];
            PVOID Reserved5[52];
            PVOID PostProcessInitRoutine;
            BYTE Reserved6[128];
            PVOID Reserved7[1];
            ULONG SessionId;
        } PEB, *PPEB;

        // Get PEB using NtCurrentTeb
        typedef struct _TEB
        {
            PVOID Reserved1[12];
            PPEB ProcessEnvironmentBlock;
        } TEB, *PTEB;

        PPEB peb = nullptr;
#ifdef _WIN64
        peb = (PPEB)((PTEB)NtCurrentTeb())->ProcessEnvironmentBlock;
#else
        __asm {
        mov eax, fs:[0x30]
        mov peb, eax
        }
#endif

        // The OS build number is at offset 0x0120 (x64) or 0x00A4 (x86)
        ULONG *pBuildNumber = nullptr;
#ifdef _WIN64
        pBuildNumber = (ULONG *)((BYTE *)peb + 0x0120);
#else
        pBuildNumber = (ULONG *)((BYTE *)peb + 0x00A4);
#endif

        if (pBuildNumber && !IsBadReadPtr(pBuildNumber, sizeof(ULONG)))
        {
            return *pBuildNumber & 0xFFFF; // Lower 16 bits contain build number
        }

        return cached_info_.build_number;
    }

    bool OSInfo::IsWindows10OrGreater() const
    {
        if (!info_cached_)
        {
            InitializeInfo();
        }
        return cached_info_.major_version >= 10;
    }

    bool OSInfo::IsWindows11OrGreater() const
    {
        if (!info_cached_)
        {
            InitializeInfo();
        }
        // Windows 11 is version 10.0.22000+
        return cached_info_.major_version >= 10 && cached_info_.build_number >= 22000;
    }

    bool OSInfo::IsWindowsServer() const
    {
        OSVERSIONINFOEXW osvi = {sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0};
        DWORDLONG const dwlConditionMask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
        osvi.wProductType = VER_NT_SERVER;

        return VerifyVersionInfoW(&osvi, VER_PRODUCT_TYPE, dwlConditionMask) != FALSE;
    }

    bool OSInfo::GetModuleVersion(const std::string &module_path,
                                  uint32_t &major, uint32_t &minor,
                                  uint32_t &build, uint32_t &revision)
    {
        DWORD handle = 0;
        DWORD size = GetFileVersionInfoSizeA(module_path.c_str(), &handle);

        if (size == 0)
        {
            return false;
        }

        std::vector<BYTE> data(size);
        if (!GetFileVersionInfoA(module_path.c_str(), handle, size, data.data()))
        {
            return false;
        }

        VS_FIXEDFILEINFO *file_info = nullptr;
        UINT len = 0;

        if (!VerQueryValueA(data.data(), "\\", (LPVOID *)&file_info, &len))
        {
            return false;
        }

        if (file_info)
        {
            major = HIWORD(file_info->dwFileVersionMS);
            minor = LOWORD(file_info->dwFileVersionMS);
            build = HIWORD(file_info->dwFileVersionLS);
            revision = LOWORD(file_info->dwFileVersionLS);
            return true;
        }

        return false;
    }

    void OSInfo::InitializeInfo() const
    {
        // Use RtlGetVersion for accurate version information
        typedef NTSTATUS(WINAPI * RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
        {
            RtlGetVersionPtr rtl_get_version = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
            if (rtl_get_version)
            {
                RTL_OSVERSIONINFOEXW version_info = {0};
                version_info.dwOSVersionInfoSize = sizeof(version_info);

                if (rtl_get_version((PRTL_OSVERSIONINFOW)&version_info) == 0)
                {
                    cached_info_.major_version = version_info.dwMajorVersion;
                    cached_info_.minor_version = version_info.dwMinorVersion;
                    cached_info_.build_number = version_info.dwBuildNumber;

                    // Get revision from ntdll.dll file version
                    char ntdll_path[MAX_PATH];
                    if (GetModuleFileNameA(ntdll, ntdll_path, MAX_PATH))
                    {
                        uint32_t major, minor, build, revision;
                        if (GetModuleVersion(ntdll_path, major, minor, build, revision))
                        {
                            cached_info_.revision = revision;
                        }
                    }
                }
            }
        }

        // Set architecture
        cached_info_.architecture = DetectArchitecture();

        // Check WOW64
        cached_info_.is_wow64 = CheckWow64();

        // Build version string
        std::stringstream ss;
        ss << cached_info_.major_version << "."
           << cached_info_.minor_version << "."
           << cached_info_.build_number;
        if (cached_info_.revision > 0)
        {
            ss << "." << cached_info_.revision;
        }
        cached_info_.version_string = ss.str();

        info_cached_ = true;

        LOG_INFO("OS Info: " + GetSystemInfoString());
    }

    Architecture OSInfo::DetectArchitecture() const
    {
        SYSTEM_INFO sys_info;
        GetNativeSystemInfo(&sys_info);

        switch (sys_info.wProcessorArchitecture)
        {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return Architecture::x64;
        case PROCESSOR_ARCHITECTURE_ARM64:
            return Architecture::ARM64;
        case PROCESSOR_ARCHITECTURE_INTEL:
            return Architecture::x86;
        default:
            return Architecture::Unknown;
        }
    }

    bool OSInfo::CheckWow64() const
    {
        typedef BOOL(WINAPI * IsWow64Process2Ptr)(HANDLE, USHORT *, USHORT *);
        typedef BOOL(WINAPI * IsWow64ProcessPtr)(HANDLE, PBOOL);

        // Try IsWow64Process2 first (Windows 10 1511+)
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32)
        {
            IsWow64Process2Ptr is_wow64_process2 = (IsWow64Process2Ptr)GetProcAddress(kernel32, "IsWow64Process2");
            if (is_wow64_process2)
            {
                USHORT process_machine = 0;
                USHORT native_machine = 0;
                if (is_wow64_process2(GetCurrentProcess(), &process_machine, &native_machine))
                {
                    return process_machine != native_machine && process_machine != IMAGE_FILE_MACHINE_UNKNOWN;
                }
            }

            // Fall back to IsWow64Process
            IsWow64ProcessPtr is_wow64_process = (IsWow64ProcessPtr)GetProcAddress(kernel32, "IsWow64Process");
            if (is_wow64_process)
            {
                BOOL is_wow64 = FALSE;
                if (is_wow64_process(GetCurrentProcess(), &is_wow64))
                {
                    return is_wow64 != FALSE;
                }
            }
        }

        return false;
    }

}
