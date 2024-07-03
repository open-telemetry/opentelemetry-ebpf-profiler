/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//go:build amd64

#include "../../zydis/Zydis.h"
#include "decode_amd64.h"

#include <stdio.h>

// decode_stub_argument() will decode instructions from given code blob until an assignment
// for the given argument register is found. The value loaded is then determined from the
// opcode. A call/jump instruction will terminate the finding as we are finding the argument
// to first function call (or tail call).
// Currently the following addressing schemes for the assignment are supported:
//  1) Loading virtual address with immediate value. This happens for non-PIC globals.
//  2) Loading RIP-relative virtual address. Happens for PIC/PIE globals.
//  3) Loading via pointer + displacement. Happens when the main state is given as argument,
//     and the value is loaded from it. In this case 'memory_base' should be the address of
//     the global state variable.
uint64_t decode_stub_argument(const uint8_t* code, size_t codesz, uint8_t argument_no,
    uint64_t rip_base, uint64_t memory_base) {
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  // Argument number to x86_64 calling convention register mapping.
  ZydisRegister target_register64, target_register32;
  switch (argument_no) {
  case 0:
    target_register64 = ZYDIS_REGISTER_RDI;
    target_register32 = ZYDIS_REGISTER_EDI;
    break;
  case 1:
    target_register64 = ZYDIS_REGISTER_RSI;
    target_register32 = ZYDIS_REGISTER_ESI;
    break;
  case 2:
    target_register64 = ZYDIS_REGISTER_RDX;
    target_register32 = ZYDIS_REGISTER_EDX;
    break;
  default:
    return 0;
  }

  // Iterate instructions
  ZydisDecodedInstruction instr;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZyanUSize instruction_offset = 0;
  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + instruction_offset,
            codesz - instruction_offset, &instr, operands))) {
    instruction_offset += instr.length;
    if (instr.mnemonic == ZYDIS_MNEMONIC_CALL ||
        instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
      // Unexpected call/jmp indicating end of stub code
      return 0;
    }
    if (!(instr.mnemonic == ZYDIS_MNEMONIC_LEA ||
          instr.mnemonic == ZYDIS_MNEMONIC_MOV) ||
        operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        (operands[0].reg.value != target_register64 &&
         operands[0].reg.value != target_register32)) {
      // Only "LEA/MOV target_reg, ..." meaningful
      continue;
    }
    if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      // MOV target_reg, immediate
      return operands[1].imm.value.u;
    }
    if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].mem.disp.has_displacement) {
      if (operands[1].mem.base == ZYDIS_REGISTER_RIP) {
        // MOV/LEA target_reg, [RIP + XXXX]
        return rip_base + instruction_offset + operands[1].mem.disp.value;
      } else if (memory_base) {
        // MOV/LEA target_reg, [REG + XXXX]
        return memory_base + operands[1].mem.disp.value;
      }
      continue;
    }
  }

  return 0;
}
