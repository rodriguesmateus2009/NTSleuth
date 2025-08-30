// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "disasm/instruction_analyzer.h"
#include "utils/logger.h"
#include <algorithm>

namespace WinSyscall
{

    bool X64Analyzer::AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
                                         uint32_t &syscall_number,
                                         bool &is_syscall)
    {
        is_syscall = false;
        syscall_number = 0;

        if (instructions.empty())
        {
            return false;
        }

        size_t mov_index = 0;
        size_t syscall_index = 0;

        // Find the pattern: MOV EAX/R10D, imm32 followed by SYSCALL
        if (!FindSyscallPattern(instructions, mov_index, syscall_index))
        {
            // Check for indirect jumps (Zw -> Nt)
            for (const auto &inst : instructions)
            {
                if (inst.is_jump && inst.has_immediate)
                {
                    // This might be a jump to the actual syscall
                    // We'd need to follow the jump to analyze the target
                    LOG_DEBUG("Found jump instruction, might be an alias");
                    return false;
                }
            }
            return false;
        }

        // Extract syscall number from MOV instruction
        if (instructions[mov_index].has_immediate)
        {
            syscall_number = static_cast<uint32_t>(instructions[mov_index].immediate_value);
            is_syscall = true;
            return true;
        }

        return false;
    }

    bool X64Analyzer::IsSyscallInstruction(const Instruction &inst) const
    {
        return inst.is_syscall;
    }

    bool X64Analyzer::IsJumpInstruction(const Instruction &inst) const
    {
        return inst.is_jump;
    }

    bool X64Analyzer::GetJumpTarget(const Instruction &inst, uint64_t &target) const
    {
        if (!inst.is_jump || !inst.has_immediate)
        {
            return false;
        }

        // For relative jumps, calculate target
        target = inst.address + inst.length + inst.immediate_value;
        return true;
    }

    bool X64Analyzer::ExtractImmediate(const Instruction &inst, uint64_t &value) const
    {
        if (!inst.has_immediate)
        {
            return false;
        }

        value = inst.immediate_value;
        return true;
    }

    bool X64Analyzer::FindSyscallPattern(const std::vector<Instruction> &instructions,
                                         size_t &mov_index,
                                         size_t &syscall_index)
    {
        // Pattern 1: Direct syscall
        // MOV EAX, imm32
        // MOV R10, RCX (optional for Windows 10+)
        // SYSCALL

        for (size_t i = 0; i < instructions.size(); ++i)
        {
            const auto &inst = instructions[i];

            // Look for MOV EAX, imm32
            if (inst.mnemonic == "mov" && inst.has_immediate)
            {
                // Check if this is MOV EAX/RAX, imm
                if (inst.operands.find("eax") != std::string::npos ||
                    inst.operands.find("rax") != std::string::npos)
                {

                    mov_index = i;

                    // Look for SYSCALL within next few instructions
                    for (size_t j = i + 1; j < std::min(i + 5, instructions.size()); ++j)
                    {
                        if (instructions[j].is_syscall)
                        {
                            syscall_index = j;
                            return true;
                        }
                    }
                }
            }
        }

        // Pattern 2: Windows 10 TH2+ with MOV R10D
        for (size_t i = 0; i < instructions.size(); ++i)
        {
            const auto &inst = instructions[i];

            // Look for MOV R10D, imm32
            if (inst.mnemonic == "mov" && inst.has_immediate)
            {
                if (inst.operands.find("r10d") != std::string::npos)
                {
                    mov_index = i;

                    // Look for SYSCALL within next few instructions
                    for (size_t j = i + 1; j < std::min(i + 5, instructions.size()); ++j)
                    {
                        if (instructions[j].is_syscall)
                        {
                            syscall_index = j;
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    size_t InstructionAnalyzer::SkipPadding(const std::vector<Instruction> &instructions,
                                            size_t start_index)
    {
        size_t index = start_index;

        while (index < instructions.size())
        {
            const auto &inst = instructions[index];

            // Skip NOP instructions
            if (inst.mnemonic == "nop" ||
                inst.mnemonic == "int3" ||
                (inst.mnemonic == "lea" && inst.operands.find("rsp") != std::string::npos))
            {
                index++;
            }
            else
            {
                break;
            }
        }

        return index;
    }

    std::unique_ptr<InstructionAnalyzer> CreateInstructionAnalyzer(Architecture arch)
    {
        switch (arch)
        {
        case Architecture::x64:
            return std::make_unique<X64Analyzer>();
        case Architecture::ARM64:
            return std::make_unique<ARM64Analyzer>();
        case Architecture::x86:
            return std::make_unique<X86Analyzer>();
        default:
            return nullptr;
        }
    }

}
