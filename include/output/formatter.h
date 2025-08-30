// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "../types.h"
#include <string>
#include <ostream>

namespace WinSyscall
{

    // Abstract base class for output formatters
    class IFormatter
    {
    public:
        virtual ~IFormatter() = default;

        // Format extraction results
        virtual bool Format(const ExtractionResult &result, std::ostream &output) = 0;

        // Save to file
        virtual bool SaveToFile(const ExtractionResult &result, const std::string &path) = 0;

        // Get format name
        virtual std::string GetFormatName() const = 0;

        // Get file extension
        virtual std::string GetFileExtension() const = 0;

    protected:
        // Helper methods
        std::string SanitizeName(const std::string &name) const;
        std::string EscapeString(const std::string &str) const;
    };

}
