// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "output/json_formatter.h"
#include "utils/logger.h"
#include <fstream>
#include <iomanip>
#include <sstream>

namespace WinSyscall
{

    JsonFormatter::JsonFormatter()
    {
    }

    bool JsonFormatter::Format(const ExtractionResult &result, std::ostream &output)
    {
        try
        {
            nlohmann::json json = ConvertToJson(result);

            if (pretty_print_)
            {
                output << std::setw(indentation_) << json << std::endl;
            }
            else
            {
                output << json << std::endl;
            }

            return true;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Failed to format JSON: " + std::string(e.what()));
            return false;
        }
    }

    bool JsonFormatter::SaveToFile(const ExtractionResult &result, const std::string &path)
    {
        try
        {
            std::ofstream file(path);
            if (!file.is_open())
            {
                LOG_ERROR("Failed to open file: " + path);
                return false;
            }

            bool success = Format(result, file);
            file.close();

            return success;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Failed to save JSON file: " + std::string(e.what()));
            return false;
        }
    }

    nlohmann::json JsonFormatter::ConvertToJson(const ExtractionResult &result)
    {
        nlohmann::json json;

        // OS information
        json["os_info"] = ConvertOSInfo(result.os_info);

        // Module information
        json["modules"] = nlohmann::json::array();
        for (const auto &module : result.modules)
        {
            json["modules"].push_back(ConvertModuleInfo(module));
        }

        // Syscalls
        json["syscalls"] = nlohmann::json::array();
        for (const auto &syscall : result.syscalls)
        {
            json["syscalls"].push_back(ConvertSyscall(syscall));
        }

        // Metadata
        json["metadata"]["extraction_time_ms"] = result.extraction_time_ms;
        json["metadata"]["total_syscalls"] = result.syscalls.size();
        json["metadata"]["errors"] = result.errors;
        json["metadata"]["warnings"] = result.warnings;

        return json;
    }

    nlohmann::json JsonFormatter::ConvertSyscall(const Syscall &syscall)
    {
        nlohmann::json json;

        json["name"] = syscall.name;
        json["syscall_number"] = syscall.syscall_number;
        json["module"] = syscall.module_name;
        json["return_type"] = syscall.return_type;
        json["calling_convention"] = CallingConventionToString(syscall.calling_convention);
        json["is_true_syscall"] = syscall.is_true_syscall;
        json["rva"] = syscall.rva;

        // Parameters
        json["parameters"] = nlohmann::json::array();
        for (const auto &param : syscall.parameters)
        {
            json["parameters"].push_back(ConvertParameter(param));
        }

        // Alias information
        if (!syscall.alias_of.empty())
        {
            json["alias_of"] = syscall.alias_of;
        }

        // Stub bytes (as hex string)
        if (!syscall.stub_bytes.empty())
        {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (uint8_t byte : syscall.stub_bytes)
            {
                ss << std::setw(2) << static_cast<int>(byte);
            }
            json["stub_bytes"] = ss.str();
        }

        return json;
    }

    nlohmann::json JsonFormatter::ConvertParameter(const Parameter &param)
    {
        nlohmann::json json;

        json["name"] = param.name;
        json["type"] = param.type;
        json["is_pointer"] = param.is_pointer;
        json["is_const"] = param.is_const;
        json["is_optional"] = param.is_optional;
        json["is_input"] = param.is_input;
        json["is_output"] = param.is_output;

        // Include SAL annotation if present
        if (!param.sal_annotation.empty())
        {
            json["sal_annotation"] = param.sal_annotation;
        }

        return json;
    }

    nlohmann::json JsonFormatter::ConvertOSInfo(const OSBuildInfo &info)
    {
        nlohmann::json json;

        json["version"] = info.version_string;
        json["major_version"] = info.major_version;
        json["minor_version"] = info.minor_version;
        json["build_number"] = info.build_number;
        json["revision"] = info.revision;
        json["architecture"] = ArchitectureToString(info.architecture);
        json["is_wow64"] = info.is_wow64;

        return json;
    }

    nlohmann::json JsonFormatter::ConvertModuleInfo(const ModuleInfo &info)
    {
        nlohmann::json json;

        json["name"] = info.name;
        json["path"] = info.path;
        json["base_address"] = info.base_address;
        json["size"] = info.size;

        if (!info.pdb_path.empty())
        {
            json["pdb"]["path"] = info.pdb_path;
            json["pdb"]["guid"] = info.pdb_guid;
            json["pdb"]["age"] = info.pdb_age;
        }

        return json;
    }

    std::string JsonFormatter::CallingConventionToString(CallingConvention cc)
    {
        switch (cc)
        {
        case CallingConvention::Stdcall:
            return "stdcall";
        case CallingConvention::Fastcall:
            return "fastcall";
        case CallingConvention::Cdecl:
            return "cdecl";
        case CallingConvention::Thiscall:
            return "thiscall";
        default:
            return "unknown";
        }
    }

    std::string JsonFormatter::ArchitectureToString(Architecture arch)
    {
        switch (arch)
        {
        case Architecture::x64:
            return "x64";
        case Architecture::ARM64:
            return "ARM64";
        case Architecture::x86:
            return "x86";
        default:
            return "unknown";
        }
    }

    std::string IFormatter::SanitizeName(const std::string &name) const
    {
        std::string result = name;
        // Remove or replace invalid characters for identifiers
        for (char &c : result)
        {
            if (!std::isalnum(c) && c != '_')
            {
                c = '_';
            }
        }
        return result;
    }

    std::string IFormatter::EscapeString(const std::string &str) const
    {
        std::string result;
        for (char c : str)
        {
            switch (c)
            {
            case '"':
                result += "\\\"";
                break;
            case '\\':
                result += "\\\\";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                result += c;
                break;
            }
        }
        return result;
    }

}
