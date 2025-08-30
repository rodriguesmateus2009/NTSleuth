// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "disasm/instruction_analyzer.h"
#include "utils/logger.h"
#include <algorithm>

namespace WinSyscall
{

    bool X86Analyzer::AnalyzeSyscallStub(const std::vector<Instruction> &instructions,
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
        size_t int_index = 0;

        // Find the pattern: MOV EAX, imm32 followed by INT 0x2E or SYSENTER
        if (!FindInt2EPattern(instructions, mov_index, int_index))
        {
            // Check for indirect jumps
            for (const auto &inst : instructions)
            {
                if (inst.is_jump && inst.has_immediate)
                {
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

    bool X86Analyzer::IsSyscallInstruction(const Instruction &inst) const
    {
        return inst.is_int2e || inst.mnemonic == "sysenter";
    }

    bool X86Analyzer::IsJumpInstruction(const Instruction &inst) const
    {
        return inst.is_jump;
    }

    bool X86Analyzer::GetJumpTarget(const Instruction &inst, uint64_t &target) const
    {
        if (!inst.is_jump || !inst.has_immediate)
        {
            return false;
        }

        // For relative jumps, calculate target
        target = inst.address + inst.length + inst.immediate_value;
        return true;
    }

    bool X86Analyzer::ExtractImmediate(const Instruction &inst, uint64_t &value) const
    {
        if (!inst.has_immediate)
        {
            return false;
        }

        value = inst.immediate_value;
        return true;
    }

    bool X86Analyzer::FindInt2EPattern(const std::vector<Instruction> &instructions,
                                       size_t &mov_index,
                                       size_t &int_index)
    {
        // Pattern for x86 (WOW64) syscalls:
        // MOV EAX, imm32     ; Syscall number
        // MOV EDX, offset    ; Optional - KiFastSystemCall address
        // CALL EDX           ; or INT 0x2E or SYSENTER

        for (size_t i = 0; i < instructions.size(); ++i)
        {
            const auto &inst = instructions[i];

            // Look for MOV EAX, imm32
            if (inst.mnemonic == "mov" && inst.has_immediate)
            {
                if (inst.operands.find("eax") != std::string::npos)
                {
                    mov_index = i;

                    // Look for INT 0x2E or SYSENTER within next few instructions
                    for (size_t j = i + 1; j < std::min(i + 8, instructions.size()); ++j)
                    {
                        if (instructions[j].is_int2e)
                        {
                            int_index = j;
                            return true;
                        }
                        if (instructions[j].mnemonic == "sysenter")
                        {
                            int_index = j;
                            return true;
                        }
                        // Also check for CALL to KiFastSystemCall
                        if (instructions[j].is_call)
                        {
                            // This could be a call to KiFastSystemCall
                            int_index = j;
                            return true;
                        }
                    }
                }
            }
        }

        // Alternative pattern: Check for direct INT 0x2E with EAX already loaded
        for (size_t i = 0; i < instructions.size(); ++i)
        {
            if (instructions[i].is_int2e || instructions[i].mnemonic == "sysenter")
            {
                // Look backwards for MOV EAX
                for (int j = static_cast<int>(i) - 1; j >= 0 && j >= static_cast<int>(i) - 5; --j)
                {
                    if (instructions[j].mnemonic == "mov" &&
                        instructions[j].operands.find("eax") != std::string::npos &&
                        instructions[j].has_immediate)
                    {
                        mov_index = j;
                        int_index = i;
                        return true;
                    }
                }
            }
        }

        return false;
    }

}
