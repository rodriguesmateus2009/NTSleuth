// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "../types.h"
#include <memory>
#include <functional>

namespace WinSyscall
{

    // Abstract base class for symbol parsing
    class ISymbolParser
    {
    public:
        virtual ~ISymbolParser() = default;

        // Initialize the symbol parser with a module
        virtual bool Initialize(const std::string &module_path, const std::string &pdb_path) = 0;

        // Enumerate all symbols
        virtual bool EnumerateSymbols(std::function<bool(const SymbolInfo &)> callback) = 0;

        // Get function prototype
        virtual bool GetFunctionPrototype(const std::string &function_name,
                                          std::string &return_type,
                                          std::vector<Parameter> &parameters,
                                          CallingConvention &calling_convention) = 0;

        // Get symbol by name
        virtual bool GetSymbolByName(const std::string &name, SymbolInfo &info) = 0;

        // Get symbol by address
        virtual bool GetSymbolByAddress(uint64_t address, SymbolInfo &info) = 0;

        // Check if symbol is available
        virtual bool HasSymbols() const = 0;

        // Get last error
        virtual std::string GetLastError() const = 0;

    protected:
        std::string module_path_;
        std::string pdb_path_;
        std::string last_error_;
    };

    // Factory function to create appropriate symbol parser
    std::unique_ptr<ISymbolParser> CreateSymbolParser(bool prefer_dia = true);

}
