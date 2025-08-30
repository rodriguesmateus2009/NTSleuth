// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "formatter.h"
#include <set>

namespace WinSyscall
{

    class CHeaderFormatter : public IFormatter
    {
    public:
        CHeaderFormatter();
        ~CHeaderFormatter() = default;

        // Format extraction results
        bool Format(const ExtractionResult &result, std::ostream &output) override;

        // Save to file
        bool SaveToFile(const ExtractionResult &result, const std::string &path) override;

        // Get format name
        std::string GetFormatName() const override { return "C Header"; }

        // Get file extension
        std::string GetFileExtension() const override { return ".h"; }

        // Configuration
        void SetGenerateTypedefs(bool generate) { generate_typedefs_ = generate; }
        void SetGenerateDefines(bool generate) { generate_defines_ = generate; }
        void SetGenerateEnums(bool generate) { generate_enums_ = generate; }
        void SetPrefix(const std::string &prefix) { prefix_ = prefix; }

    private:
        bool generate_typedefs_ = true;
        bool generate_defines_ = true;
        bool generate_enums_ = false;
        std::string prefix_ = "SYSCALL_";

        void WriteHeader(std::ostream &out, const ExtractionResult &result);
        void WriteIncludes(std::ostream &out);
        void WriteTypedefs(std::ostream &out, const std::vector<Syscall> &syscalls);
        void WriteDefines(std::ostream &out, const std::vector<Syscall> &syscalls);
        void WriteEnums(std::ostream &out, const std::vector<Syscall> &syscalls);
        void WriteFooter(std::ostream &out);

        std::string FormatTypedef(const Syscall &syscall);
        std::string FormatParameters(const std::vector<Parameter> &params);
        std::string FormatParameterType(const Parameter &param);
        std::string MakeValidIdentifier(const std::string &name);
        std::string GetCallingConventionMacro(CallingConvention cc);

        // Track unique typedefs to avoid duplicates
        std::set<std::string> generated_typedefs_;
    };

}
