// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "disasm/instruction_analyzer.h"
#include "utils/logger.h"
#include <algorithm>

namespace WinSyscall
{

    bool ARM64Analyzer::AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
                                           uint32_t &syscall_number,
                                           bool &is_syscall)
    {
        is_syscall = false;
        syscall_number = 0;

        if (instructions.empty())
        {
            return false;
        }

        // Windows on ARM64 uses a different pattern:
        // The syscall number is encoded directly in the SVC instruction
        // Pattern: SVC #syscall_number

        for (const auto &inst : instructions)
        {
            // Check for SVC instruction with embedded syscall number
            if (inst.is_svc || inst.mnemonic == "svc")
            {
                if (inst.has_immediate)
                {
                    // Windows ARM64 embeds the syscall number in the SVC instruction
                    syscall_number = static_cast<uint32_t>(inst.immediate_value);
                    is_syscall = true;
                    LOG_DEBUG("Found Windows ARM64 syscall: SVC #" + std::to_string(syscall_number));
                    return true;
                }
            }

            // Check for indirect branches (might be an alias)
            if (inst.mnemonic == "br" || inst.mnemonic == "b")
            {
                LOG_DEBUG("Found branch instruction, might be an alias");
                return false;
            }
        }

        // Also try the Linux pattern (MOV W8, #imm followed by SVC)
        size_t mov_index = 0;
        size_t svc_index = 0;

        if (FindSvcPattern(instructions, mov_index, svc_index))
        {
            // Extract syscall number from MOV instruction
            if (instructions[mov_index].has_immediate)
            {
                syscall_number = static_cast<uint32_t>(instructions[mov_index].immediate_value);
                is_syscall = true;
                return true;
            }

            // Handle composite immediate (MOVZ/MOVK sequence)
            if (ExtractCompositeImmediate(instructions, mov_index, syscall_number))
            {
                is_syscall = true;
                return true;
            }
        }

        return false;
    }

    bool ARM64Analyzer::IsSyscallInstruction(const Instruction &inst) const
    {
        return inst.is_svc;
    }

    bool ARM64Analyzer::IsJumpInstruction(const Instruction &inst) const
    {
        // ARM64 branch instructions
        return inst.mnemonic == "b" ||
               inst.mnemonic == "br" ||
               inst.mnemonic == "blr" ||
               inst.mnemonic.substr(0, 2) == "b."; // Conditional branches
    }

    bool ARM64Analyzer::GetJumpTarget(const Instruction &inst, uint64_t &target) const
    {
        if (!IsJumpInstruction(inst) || !inst.has_immediate)
        {
            return false;
        }

        // For relative branches, calculate target
        target = inst.address + inst.immediate_value;
        return true;
    }

    bool ARM64Analyzer::ExtractImmediate(const Instruction &inst, uint64_t &value) const
    {
        if (!inst.has_immediate)
        {
            return false;
        }

        value = inst.immediate_value;
        return true;
    }

    bool ARM64Analyzer::FindSvcPattern(const std::vector<Instruction> &instructions,
                                       size_t &mov_index,
                                       size_t &svc_index)
    {
        // Pattern for ARM64 syscalls:
        // MOV W8, #imm16     ; Load syscall number
        // (optional additional setup)
        // SVC #0             ; System call

        for (size_t i = 0; i < instructions.size(); ++i)
        {
            const auto &inst = instructions[i];

            // Look for MOV W8, #imm
            if (inst.mnemonic == "mov" && inst.operands.find("w8") != std::string::npos)
            {
                mov_index = i;

                // Look for SVC within next few instructions
                for (size_t j = i + 1; j < std::min(i + 10, instructions.size()); ++j)
                {
                    if (instructions[j].is_svc)
                    {
                        svc_index = j;
                        return true;
                    }
                }
            }

            // Also check for MOVZ W8 (move with zero extend)
            if ((inst.mnemonic == "movz" || inst.mnemonic == "movn") &&
                inst.operands.find("w8") != std::string::npos)
            {
                mov_index = i;

                // Look for SVC
                for (size_t j = i + 1; j < std::min(i + 10, instructions.size()); ++j)
                {
                    if (instructions[j].is_svc)
                    {
                        svc_index = j;
                        return true;
                    }
                }
            }
        }

        return false;
    }

    bool ARM64Analyzer::ExtractCompositeImmediate(const std::vector<Instruction> &instructions,
                                                  size_t start_index,
                                                  uint32_t &value)
    {
        // ARM64 can use multiple instructions to load a 32-bit immediate:
        // MOVZ W8, #lower16
        // MOVK W8, #upper16, LSL #16

        if (start_index >= instructions.size())
        {
            return false;
        }

        const auto &first_inst = instructions[start_index];

        // Check for MOVZ (move with zero)
        if (first_inst.mnemonic != "movz" || !first_inst.has_immediate)
        {
            return false;
        }

        value = static_cast<uint32_t>(first_inst.immediate_value);

        // Check for following MOVK instructions
        for (size_t i = start_index + 1; i < std::min(start_index + 3, instructions.size()); ++i)
        {
            const auto &inst = instructions[i];

            if (inst.mnemonic == "movk" && inst.operands.find("w8") != std::string::npos)
            {
                // Extract shift amount from operands
                size_t lsl_pos = inst.operands.find("lsl");
                if (lsl_pos != std::string::npos)
                {
                    std::string shift_str = inst.operands.substr(lsl_pos + 4);
                    int shift = std::stoi(shift_str);

                    if (inst.has_immediate)
                    {
                        uint32_t imm = static_cast<uint32_t>(inst.immediate_value);
                        value |= (imm << shift);
                    }
                }
            }
            else
            {
                // No more MOVK instructions
                break;
            }
        }

        return true;
    }

}
