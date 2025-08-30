// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "utils/string_utils.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

namespace WinSyscall
{

    std::string StringUtils::ToLower(const std::string &str)
    {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(::tolower(c)); });
        return result;
    }

    std::string StringUtils::ToUpper(const std::string &str)
    {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(::toupper(c)); });
        return result;
    }

    std::string StringUtils::Trim(const std::string &str)
    {
        const auto strBegin = str.find_first_not_of(" \t\n\r");
        if (strBegin == std::string::npos)
        {
            return "";
        }

        const auto strEnd = str.find_last_not_of(" \t\n\r");
        const auto strRange = strEnd - strBegin + 1;

        return str.substr(strBegin, strRange);
    }

    std::vector<std::string> StringUtils::Split(const std::string &str, char delimiter)
    {
        std::vector<std::string> tokens;
        std::stringstream ss(str);
        std::string token;

        while (std::getline(ss, token, delimiter))
        {
            if (!token.empty())
            {
                tokens.push_back(token);
            }
        }

        return tokens;
    }

    bool StringUtils::StartsWith(const std::string &str, const std::string &prefix)
    {
        return str.size() >= prefix.size() &&
               str.compare(0, prefix.size(), prefix) == 0;
    }

    bool StringUtils::EndsWith(const std::string &str, const std::string &suffix)
    {
        return str.size() >= suffix.size() &&
               str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    std::string StringUtils::Replace(const std::string &str,
                                     const std::string &from,
                                     const std::string &to)
    {
        std::string result = str;
        size_t start_pos = 0;

        while ((start_pos = result.find(from, start_pos)) != std::string::npos)
        {
            result.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }

        return result;
    }

    std::string StringUtils::BytesToHexString(const std::vector<uint8_t> &bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (uint8_t byte : bytes)
        {
            ss << std::setw(2) << static_cast<int>(byte);
        }

        return ss.str();
    }

    std::vector<uint8_t> StringUtils::HexStringToBytes(const std::string &hex)
    {
        std::vector<uint8_t> bytes;

        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    }

    std::string StringUtils::WideToNarrow(const std::wstring &wide)
    {
        if (wide.empty())
        {
            return "";
        }

        int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0)
        {
            return "";
        }

        std::vector<char> buffer(size);
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, buffer.data(), size, nullptr, nullptr);

        return std::string(buffer.data());
    }

    std::wstring StringUtils::NarrowToWide(const std::string &narrow)
    {
        if (narrow.empty())
        {
            return L"";
        }

        int size = MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), -1, nullptr, 0);
        if (size <= 0)
        {
            return L"";
        }

        std::vector<wchar_t> buffer(size);
        MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), -1, buffer.data(), size);

        return std::wstring(buffer.data());
    }

}
