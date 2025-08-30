// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "../types.h"
#include <memory>
#include <vector>
#include <cstdint>

namespace WinSyscall
{

    // Forward declarations
    class InstructionAnalyzer;

    // Disassembled instruction
    struct Instruction
    {
        uint64_t address = 0;
        size_t length = 0;
        std::string mnemonic;
        std::string operands;
        std::vector<uint8_t> bytes;

        // For syscall detection
        bool is_syscall = false;
        bool is_svc = false;
        bool is_int2e = false;
        bool is_jump = false;
        bool is_call = false;

        // Immediate value (for syscall number extraction)
        bool has_immediate = false;
        uint64_t immediate_value = 0;
    };

    class Disassembler
    {
    public:
        Disassembler();
        ~Disassembler();

        // Initialize for specific architecture
        bool Initialize(Architecture arch);

        // Disassemble single instruction
        bool DisassembleInstruction(const uint8_t *code, size_t code_size,
                                    uint64_t address, Instruction &instruction);

        // Disassemble range
        bool DisassembleRange(const uint8_t *code, size_t code_size,
                              uint64_t base_address,
                              std::vector<Instruction> &instructions);

        // Analyze syscall stub
        bool AnalyzeSyscallStub(const uint8_t *stub, size_t stub_size,
                                uint64_t address, uint32_t &syscall_number,
                                bool &is_syscall);

        // Find pattern in code
        bool FindPattern(const uint8_t *code, size_t code_size,
                         const std::vector<uint8_t> &pattern,
                         const std::vector<uint8_t> &mask,
                         size_t &offset);

        // Get analyzer for current architecture
        InstructionAnalyzer *GetAnalyzer() const { return analyzer_.get(); }

        // Check if initialized
        bool IsInitialized() const { return initialized_; }

    private:
        Architecture architecture_;
        bool initialized_ = false;
        std::unique_ptr<InstructionAnalyzer> analyzer_;
        void *zydis_decoder_ = nullptr;   // ZydisDecoder handle
        void *zydis_formatter_ = nullptr; // ZydisFormatter handle

        bool InitializeZydis();
        void CleanupZydis();
    };

}
