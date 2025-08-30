// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include "../types.h"
#include "disassembler.h"
#include <vector>
#include <cstdint>

namespace WinSyscall
{

    // Abstract base class for architecture-specific instruction analysis
    class InstructionAnalyzer
    {
    public:
        virtual ~InstructionAnalyzer() = default;

        // Analyze syscall stub and extract syscall number
        virtual bool AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
                                        uint32_t &syscall_number,
                                        bool &is_syscall) = 0;

        // Check if instruction is a system call
        virtual bool IsSyscallInstruction(const Instruction &inst) const = 0;

        // Check if instruction is a jump
        virtual bool IsJumpInstruction(const Instruction &inst) const = 0;

        // Get jump target if applicable
        virtual bool GetJumpTarget(const Instruction &inst, uint64_t &target) const = 0;

        // Extract immediate value from instruction
        virtual bool ExtractImmediate(const Instruction &inst, uint64_t &value) const = 0;

        // Get architecture
        virtual Architecture GetArchitecture() const = 0;

    protected:
        // Helper to skip NOP/padding instructions
        size_t SkipPadding(const std::vector<Instruction> &instructions, size_t start_index);
    };

    // x64 specific analyzer
    class X64Analyzer : public InstructionAnalyzer
    {
    public:
        bool AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
                                uint32_t &syscall_number,
                                bool &is_syscall) override;

        bool IsSyscallInstruction(const Instruction &inst) const override;
        bool IsJumpInstruction(const Instruction &inst) const override;
        bool GetJumpTarget(const Instruction &inst, uint64_t &target) const override;
        bool ExtractImmediate(const Instruction &inst, uint64_t &value) const override;
        Architecture GetArchitecture() const override { return Architecture::x64; }

    private:
        bool FindSyscallPattern(const std::vector<Instruction> &instructions,
                                size_t &mov_index,
                                size_t &syscall_index);
    };

    // ARM64 specific analyzer
    class ARM64Analyzer : public InstructionAnalyzer
    {
    public:
        bool AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
                                uint32_t &syscall_number,
                                bool &is_syscall) override;

        bool IsSyscallInstruction(const Instruction &inst) const override;
        bool IsJumpInstruction(const Instruction &inst) const override;
        bool GetJumpTarget(const Instruction &inst, uint64_t &target) const override;
        bool ExtractImmediate(const Instruction &inst, uint64_t &value) const override;
        Architecture GetArchitecture() const override { return Architecture::ARM64; }

    private:
        bool FindSvcPattern(const std::vector<Instruction> &instructions,
                            size_t &mov_index,
                            size_t &svc_index);

        // Handle multi-instruction immediate loads (MOVZ/MOVK)
        bool ExtractCompositeImmediate(const std::vector<Instruction> &instructions,
                                       size_t start_index,
                                       uint32_t &value);
    };

    // x86 specific analyzer (for WOW64)
    class X86Analyzer : public InstructionAnalyzer
    {
    public:
        bool AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
                                uint32_t &syscall_number,
                                bool &is_syscall) override;

        bool IsSyscallInstruction(const Instruction &inst) const override;
        bool IsJumpInstruction(const Instruction &inst) const override;
        bool GetJumpTarget(const Instruction &inst, uint64_t &target) const override;
        bool ExtractImmediate(const Instruction &inst, uint64_t &value) const override;
        Architecture GetArchitecture() const override { return Architecture::x86; }

    private:
        bool FindInt2EPattern(const std::vector<Instruction> &instructions,
                              size_t &mov_index,
                              size_t &int_index);
    };

    // Factory function
    std::unique_ptr<InstructionAnalyzer> CreateInstructionAnalyzer(Architecture arch);

}
