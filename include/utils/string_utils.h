// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <string>
#include <vector>
#include <Windows.h>

namespace WinSyscall
{

    class StringUtils
    {
    public:
        // Case conversion
        static std::string ToLower(const std::string &str);
        static std::string ToUpper(const std::string &str);

        // Trimming
        static std::string Trim(const std::string &str);

        // Splitting
        static std::vector<std::string> Split(const std::string &str, char delimiter);

        // String checks
        static bool StartsWith(const std::string &str, const std::string &prefix);
        static bool EndsWith(const std::string &str, const std::string &suffix);

        // String replacement
        static std::string Replace(const std::string &str,
                                   const std::string &from,
                                   const std::string &to);

        // Hex conversion
        static std::string BytesToHexString(const std::vector<uint8_t> &bytes);
        static std::vector<uint8_t> HexStringToBytes(const std::string &hex);

        // Wide/Narrow conversion
        static std::string WideToNarrow(const std::wstring &wide);
        static std::wstring NarrowToWide(const std::string &narrow);
    };

}
