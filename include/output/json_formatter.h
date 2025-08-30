// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "formatter.h"
#include <nlohmann/json.hpp>

namespace WinSyscall
{

    class JsonFormatter : public IFormatter
    {
    public:
        JsonFormatter();
        ~JsonFormatter() = default;

        // Format extraction results
        bool Format(const ExtractionResult &result, std::ostream &output) override;

        // Save to file
        bool SaveToFile(const ExtractionResult &result, const std::string &path) override;

        // Get format name
        std::string GetFormatName() const override { return "JSON"; }

        // Get file extension
        std::string GetFileExtension() const override { return ".json"; }

        // Set pretty print
        void SetPrettyPrint(bool pretty) { pretty_print_ = pretty; }

        // Set indentation
        void SetIndentation(int indent) { indentation_ = indent; }

    private:
        bool pretty_print_ = true;
        int indentation_ = 2;

        nlohmann::json ConvertToJson(const ExtractionResult &result);
        nlohmann::json ConvertSyscall(const Syscall &syscall);
        nlohmann::json ConvertParameter(const Parameter &param);
        nlohmann::json ConvertOSInfo(const OSBuildInfo &info);
        nlohmann::json ConvertModuleInfo(const ModuleInfo &info);

        std::string CallingConventionToString(CallingConvention cc);
        std::string ArchitectureToString(Architecture arch);
    };

}
