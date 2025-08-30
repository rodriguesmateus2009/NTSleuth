// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "symbol_parser.h"

namespace WinSyscall
{

    // DIA SDK-based symbol parser implementation
    // The actual implementation is in dia_symbol_parser.cpp
    // This is created by CreateDiaSymbolParser() when DIA SDK is available

    std::unique_ptr<ISymbolParser> CreateDiaSymbolParser();

}
