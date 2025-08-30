// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "disasm/disassembler.h"
#include "disasm/instruction_analyzer.h"
#include "utils/logger.h"
#include <Zydis/Zydis.h>
#include <memory>
#include <cstring>

namespace WinSyscall
{

    struct ZydisContext
    {
        ZydisDecoder decoder;
        ZydisFormatter formatter;
        bool initialized = false;
    };

    Disassembler::Disassembler()
    {
        zydis_decoder_ = new ZydisContext();
        zydis_formatter_ = nullptr;
    }

    Disassembler::~Disassembler()
    {
        CleanupZydis();
        delete static_cast<ZydisContext *>(zydis_decoder_);
    }

    bool Disassembler::Initialize(Architecture arch)
    {
        architecture_ = arch;

        // Initialize Zydis
        if (!InitializeZydis())
        {
            LOG_ERROR("Failed to initialize Zydis disassembler");
            return false;
        }

        // Create architecture-specific analyzer
        analyzer_ = CreateInstructionAnalyzer(arch);
        if (!analyzer_)
        {
            LOG_ERROR("Failed to create instruction analyzer");
            return false;
        }

        initialized_ = true;
        LOG_INFO("Disassembler initialized for " +
                 std::string(arch == Architecture::x64 ? "x64" : arch == Architecture::ARM64 ? "ARM64"
                                                                                             : "x86"));
        return true;
    }

    bool Disassembler::DisassembleInstruction(const uint8_t *code, size_t code_size,
                                              uint64_t address, Instruction &instruction)
    {
        if (!initialized_)
        {
            return false;
        }

        ZydisContext *ctx = static_cast<ZydisContext *>(zydis_decoder_);

        if (architecture_ == Architecture::ARM64)
        {
            // ARM64 disassembly
            if (code_size >= 4)
            {
                uint32_t insn = *reinterpret_cast<const uint32_t *>(code);

                // SVC instruction pattern: 0xD4000001 + (imm16 << 5)
                // The syscall number is encoded in bits 5-20
                if ((insn & 0xFFE0001F) == 0xD4000001)
                {
                    uint32_t syscall_num = (insn >> 5) & 0xFFFF;
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "svc";
                    instruction.operands = "#" + std::to_string(syscall_num);
                    instruction.is_svc = true;
                    instruction.has_immediate = true;
                    instruction.immediate_value = syscall_num;
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // MOVZ W8, #imm16 instruction pattern (52800000 + imm)
                if ((insn & 0xFFE00000) == 0x52800000)
                {
                    uint32_t imm = ((insn >> 5) & 0xFFFF);
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "movz";
                    instruction.operands = "w8, #" + std::to_string(imm);
                    instruction.has_immediate = true;
                    instruction.immediate_value = imm;
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // MOV W8, W register pattern (for indirect syscall number)
                if ((insn & 0xFFE0FFE0) == 0x2A0003E0)
                {
                    uint32_t src_reg = (insn >> 16) & 0x1F;
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "mov";
                    instruction.operands = "w8, w" + std::to_string(src_reg);
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // MOVK W8, #imm16, lsl #16 (for building larger syscall numbers)
                if ((insn & 0xFFE00000) == 0x72A00000)
                {
                    uint32_t imm = ((insn >> 5) & 0xFFFF);
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "movk";
                    instruction.operands = "w8, #" + std::to_string(imm) + ", lsl #16";
                    instruction.has_immediate = true;
                    instruction.immediate_value = imm;
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // B (branch) instruction
                if ((insn & 0xFC000000) == 0x14000000)
                {
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "b";
                    instruction.is_jump = true;
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // RET instruction
                if (insn == 0xD65F03C0)
                {
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "ret";
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // NOP instruction
                if (insn == 0xD503201F)
                {
                    instruction.address = address;
                    instruction.length = 4;
                    instruction.mnemonic = "nop";
                    instruction.bytes.assign(code, code + 4);
                    return true;
                }

                // Generic instruction (unrecognized)
                instruction.address = address;
                instruction.length = 4;
                instruction.mnemonic = "unknown";
                instruction.operands = "";
                instruction.bytes.assign(code, code + 4);
                return true;
            }
            return false;
        }

        // x86/x64 disassembly using Zydis
        ZydisDecodedInstruction zydis_instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        ZyanStatus status = ZydisDecoderDecodeFull(&ctx->decoder, code, code_size,
                                                   &zydis_instruction, operands);

        if (!ZYAN_SUCCESS(status))
        {
            return false;
        }

        instruction.address = address;
        instruction.length = zydis_instruction.length;
        instruction.bytes.assign(code, code + zydis_instruction.length);

        // Format instruction
        char buffer[256];
        ZydisFormatterFormatInstruction(&ctx->formatter, &zydis_instruction, operands,
                                        zydis_instruction.operand_count_visible,
                                        buffer, sizeof(buffer), address, nullptr);

        // Parse formatted string to get mnemonic and operands
        std::string formatted(buffer);
        size_t space_pos = formatted.find(' ');
        if (space_pos != std::string::npos)
        {
            instruction.mnemonic = formatted.substr(0, space_pos);
            instruction.operands = formatted.substr(space_pos + 1);
        }
        else
        {
            instruction.mnemonic = formatted;
        }

        // Check instruction type
        switch (zydis_instruction.mnemonic)
        {
        case ZYDIS_MNEMONIC_SYSCALL:
            instruction.is_syscall = true;
            break;
        case ZYDIS_MNEMONIC_INT:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[0].imm.value.u == 0x2E)
            {
                instruction.is_int2e = true;
            }
            break;
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
            instruction.is_jump = true;
            break;
        case ZYDIS_MNEMONIC_CALL:
            instruction.is_call = true;
            break;
        case ZYDIS_MNEMONIC_MOV:
            // Check for MOV EAX, imm32 pattern (syscall number)
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operands[0].reg.value == ZYDIS_REGISTER_EAX ||
                 operands[0].reg.value == ZYDIS_REGISTER_RAX) &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                instruction.has_immediate = true;
                instruction.immediate_value = operands[1].imm.value.u;
            }
            break;
        }

        return true;
    }

    bool Disassembler::DisassembleRange(const uint8_t *code, size_t code_size,
                                        uint64_t base_address,
                                        std::vector<Instruction> &instructions)
    {
        if (!initialized_)
        {
            return false;
        }

        instructions.clear();
        size_t offset = 0;

        while (offset < code_size)
        {
            Instruction inst;
            if (!DisassembleInstruction(code + offset, code_size - offset,
                                        base_address + offset, inst))
            {
                break;
            }

            instructions.push_back(inst);
            offset += inst.length;

            // Stop at certain instructions
            if (inst.is_syscall || inst.is_svc || inst.is_int2e)
            {
                break;
            }

            // Limit to reasonable number of instructions
            if (instructions.size() > 20)
            {
                break;
            }
        }

        return !instructions.empty();
    }

    bool Disassembler::AnalyzeSyscallStub(const uint8_t *stub, size_t stub_size,
                                          uint64_t address, uint32_t &syscall_number,
                                          bool &is_syscall)
    {
        if (!initialized_ || !analyzer_)
        {
            return false;
        }

        // Disassemble the stub
        std::vector<Instruction> instructions;
        if (!DisassembleRange(stub, stub_size, address, instructions))
        {
            return false;
        }

        // Use architecture-specific analyzer
        return analyzer_->AnalyzeSyscallStub(instructions, syscall_number, is_syscall);
    }

    bool Disassembler::FindPattern(const uint8_t *code, size_t code_size,
                                   const std::vector<uint8_t> &pattern,
                                   const std::vector<uint8_t> &mask,
                                   size_t &offset)
    {
        if (pattern.empty() || pattern.size() != mask.size() || pattern.size() > code_size)
        {
            return false;
        }

        for (size_t i = 0; i <= code_size - pattern.size(); ++i)
        {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j)
            {
                if (mask[j] && code[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                offset = i;
                return true;
            }
        }

        return false;
    }

    bool Disassembler::InitializeZydis()
    {
        ZydisContext *ctx = static_cast<ZydisContext *>(zydis_decoder_);

        ZydisMachineMode machine_mode;
        ZydisStackWidth stack_width;

        switch (architecture_)
        {
        case Architecture::x64:
            machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
            stack_width = ZYDIS_STACK_WIDTH_64;
            break;
        case Architecture::x86:
            machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
            stack_width = ZYDIS_STACK_WIDTH_32;
            break;
        case Architecture::ARM64:
            // Zydis doesn't support ARM64, we'll handle it separately
            ctx->initialized = true;
            return true;
        default:
            return false;
        }

        if (!ZYAN_SUCCESS(ZydisDecoderInit(&ctx->decoder, machine_mode, stack_width)))
        {
            return false;
        }

        if (!ZYAN_SUCCESS(ZydisFormatterInit(&ctx->formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        {
            return false;
        }

        ctx->initialized = true;
        return true;
    }

    void Disassembler::CleanupZydis()
    {
        // Zydis doesn't require explicit cleanup for decoder/formatter
        initialized_ = false;
    }

}
