// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

#include "../../zydis/Zydis.h"
#include "decode_amd64.h"

// #define DECODE_AMD_DEBUG

#if defined(DECODE_AMD_DEBUG)
  #include <stdio.h>
#endif

static int reg_index(ZydisRegister reg)
{
  switch (reg) {
  case ZYDIS_REGISTER_RAX:
  case ZYDIS_REGISTER_EAX: return 1;
  case ZYDIS_REGISTER_RBX:
  case ZYDIS_REGISTER_EBX: return 2;
  case ZYDIS_REGISTER_RCX:
  case ZYDIS_REGISTER_ECX: return 3;
  case ZYDIS_REGISTER_RDX:
  case ZYDIS_REGISTER_EDX: return 4;
  case ZYDIS_REGISTER_RDI:
  case ZYDIS_REGISTER_EDI: return 5;
  case ZYDIS_REGISTER_RSI:
  case ZYDIS_REGISTER_ESI: return 6;
  case ZYDIS_REGISTER_RBP:
  case ZYDIS_REGISTER_EBP: return 7;
  case ZYDIS_REGISTER_RSP:
  case ZYDIS_REGISTER_ESP: return 8;
  case ZYDIS_REGISTER_RIP: return 9;
  default: return 0;
  }
}

struct reg_state {
  ZyanU64 loaded_from;
  ZyanU64 value;
};

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
// todo update comment
// todo rewrite in go
// todo add coredump tests
uint64_t decode_stub_argument(
  const uint8_t *code, size_t code_sz, uint64_t code_address, uint64_t memory_base)
{
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  // Argument number to x86_64 calling convention register mapping.
  ZydisRegister target_register64 = ZYDIS_REGISTER_RDI;

  // Iterate instructions
  ZydisDecodedInstruction instr;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZyanUSize instruction_offset = 0;
  struct reg_state regs[32]    = {};
  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
    &decoder, code + instruction_offset, code_sz - instruction_offset, &instr, operands))) {
#if defined(DECODE_AMD_DEBUG)
    ZydisDisassembledInstruction dbgi = {};
    if (ZYAN_SUCCESS(ZydisDisassembleIntel(
          ZYDIS_MACHINE_MODE_LONG_64,
          code_address + instruction_offset,
          code + instruction_offset,
          code_sz - instruction_offset,
          &dbgi))) {
      printf("%-12p %s\n", (void *)(code_address + instruction_offset), dbgi.text);
      fflush(stdout);
    }
#endif
    instruction_offset += instr.length;
    regs[reg_index(ZYDIS_REGISTER_RIP)].value = code_address + instruction_offset;
    if (instr.mnemonic == ZYDIS_MNEMONIC_CALL || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
      if (regs[reg_index(target_register64)].loaded_from) {
        return regs[reg_index(target_register64)].loaded_from;
      }
      return regs[reg_index(target_register64)].value;
    }
    if (
      (instr.mnemonic == ZYDIS_MNEMONIC_LEA || instr.mnemonic == ZYDIS_MNEMONIC_MOV) &&
      operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

      ZyanU64 v           = 0;
      ZyanU64 loaded_from = 0;
      if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        v = operands[1].imm.value.u;
      }
      if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].mem.disp.has_displacement) {
        ZyanU64 at = regs[reg_index(operands[1].mem.base)].value + operands[1].mem.disp.value;
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
          v           = memory_base;
          loaded_from = at;
        }
        if (instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
          v = at;
        }
      }
      if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        v = regs[reg_index(operands[1].reg.value)].value;
      }
#if defined(DECODE_AMD_DEBUG)
      printf("   | regs[%d] = %lx\n", reg_index(operands[0].reg.value), v);
#endif
      regs[reg_index(operands[0].reg.value)].value       = v;
      regs[reg_index(operands[0].reg.value)].loaded_from = loaded_from;
    }
    if (
      instr.mnemonic == ZYDIS_MNEMONIC_ADD && instr.operand_count == 3 &&
      operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
      operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
      ZyanU64 v = regs[reg_index(operands[0].reg.value)].value + memory_base;
      regs[reg_index(operands[0].reg.value)].value       = v;
      regs[reg_index(operands[0].reg.value)].loaded_from = 0;
#if defined(DECODE_AMD_DEBUG)
      printf("   | regs[%d] = %lx\n", reg_index(operands[0].reg.value), v);
#endif
    }
  }
  return 0;
}