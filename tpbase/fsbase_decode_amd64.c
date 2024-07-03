/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//go:build amd64

#include "../zydis/Zydis.h"
#include "fsbase_decode_amd64.h"


// decode_fsbase_aout_dump_debugregs attempts to compute the offset of `fsbase` in `task_struct` from the x86-64
// assembly code of the `aout_dump_debugregs` function in the kernel, which existed up until kernel 5.9.
// It returns the fsbase offset if successful, or 0 on failure.
// aout_dump_debugregs code: see https://elixir.bootlin.com/linux/v5.9.16/source/arch/x86/kernel/hw_breakpoint.c#L452
//
// This function expects 2 instructions to be present in the code blob:
// 1) A `mov` instruction loading the current task_struct address (recognizable with the GS segment being the base) into
//    a target register.
// 2) A subsequent `mov` instruction loading the address of `task_struct->thread.ptrace_bps[i]`, the base register being
//    the target register of the previous instruction.
//
// From 2) we can extract the offset of ptrace_bps in task_struct.
// The layout of `task_struct.thread` (see arch/x86/include/asm/processor.h) is:
//      [...]
//      unsigned long fsbase;
//      unsigned long gsbase;
//      struct perf_event *ptrace_bps[HBP_NUM];
//      [...]
// => we can then subtract 2*sizeof(unsigned long) to find the fsbase offset.
uint32_t decode_fsbase_aout_dump_debugregs(const uint8_t* code, size_t codesz) {
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  ZydisDecodedInstruction instr;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZydisRegister target_register = ZYDIS_REGISTER_NONE;

  ZyanUSize instruction_offset = 0;

  // 1) Find the first `mov` with a `gs` base. By inspection of the C code, we assume it loads the address of the
  //    current `task_struct`.
  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + instruction_offset,
      codesz - instruction_offset, &instr, operands))) {
    instruction_offset += instr.length;

    if (! (instr.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS)) {
      continue;
    }
    if (instr.mnemonic != ZYDIS_MNEMONIC_MOV) {
      continue;
    }
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
      continue;
    }
    // This instruction loads the address of the current task_struct into `target_register`.
    target_register = operands[0].reg.value;
    break;
  }

  if (target_register == ZYDIS_REGISTER_NONE) {
    return 0;
  }

  int64_t lea_offset = 0;
  int64_t mov_offset = 0;

  // 2) Find the first `mov` instruction that either uses `target_register` as base, or for which the base register is
  //    the result of a LEA that uses `target_register` as base.
  //    We assume that `mov` computes the address of `task_struct.thread.ptrace_bps` based on the `task_struct` address
  //    we expect to have loaded in 1).
  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + instruction_offset,
      codesz - instruction_offset, &instr, operands))) {
    instruction_offset += instr.length;

    // Some compilers will emit LEA+MOV instead of MOV.
    // In this case, we need to add offsets from both.
    if (instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
      if (operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) {
        continue;
      }
      if (operands[1].mem.base != target_register) {
        continue;
      }
      if (lea_offset != 0) {
        // We already found a matching LEA. A second one means we went too far.
        return 0;
      }
      if (! operands[1].mem.disp.has_displacement) {
        return 0;
      }
      if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return 0;
      }
      // Update target register to be this LEA's target
      target_register = operands[0].reg.value;

      lea_offset = operands[1].mem.disp.value;
      continue;
    }

    if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
      if (operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) {
        continue;
      }
      if (operands[1].mem.base != target_register) {
        continue;
      }
      if (! operands[1].mem.disp.has_displacement) {
        return 0;
      }
      // The displacement is the offset of ptrace_bps in task_struct, minus any offset from a previous LEA instruction.
      mov_offset = operands[1].mem.disp.value;
      break;
    }
  }

  if (mov_offset == 0) {
    return 0;
  }

  int64_t result = lea_offset + mov_offset;

  // Compute the `fsbase` offset from the `ptrace_bps` offset, according to the `thread_struct` layout.
  result -= 2*sizeof(long);

  if (result < 0 || result > UINT32_MAX) {
    return 0;
  }

  return (uint32_t)result;
}
