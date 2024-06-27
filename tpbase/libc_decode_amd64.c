/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//go:build amd64

#include "../zydis/Zydis.h"
#include "libc_decode_amd64.h"

//#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif

#define MAX(a, b) ((a)>(b) ? (a) : (b))

enum {
  Unspec = 0,
  TSDBase,
  TSDElementBase,
  TSDIndex,
  TSDValue,
};

typedef struct regInfo {
  uint8_t state;
  uint8_t multiplier;
  uint8_t indirect;
  int16_t offset;
} regInfo;

static int32_t reg2ndx(ZydisRegister reg)
{
  reg = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
  if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15)
    return reg - ZYDIS_REGISTER_RAX + 1;
  return 0;
}

uint32_t decode_pthread_getspecific(const uint8_t* code, size_t codesz) {
  ZydisDecoder decoder;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZydisDecodedInstruction instr;
  regInfo regs[18] = {};
  int32_t destNdx = -1, srcNdx, indexNdx;

  // RDI = first argument = key index
  regs[reg2ndx(ZYDIS_REGISTER_RDI)] = (regInfo) { .state = TSDIndex, .multiplier = 1 };

  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  for (ZyanUSize offs = 0
    ; ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + offs, codesz - offs, &instr, operands))
    ; offs += instr.length) {
#ifdef DEBUG
    if (destNdx >= 0 && destNdx < 32) {
      fprintf(stderr, "r%02d state=%d, offs=%#x, mult=%d\n",
        destNdx, regs[destNdx].state, regs[destNdx].offset, regs[destNdx].multiplier);
    }
#endif
    destNdx = -1;
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
      continue;
    }

    destNdx = reg2ndx(operands[0].reg.value);
    switch (instr.mnemonic) {
    case ZYDIS_MNEMONIC_SHL:
      regs[destNdx].offset <<= operands[1].imm.value.u;
      regs[destNdx].multiplier <<= operands[1].imm.value.u;
      continue;

    case ZYDIS_MNEMONIC_ADD:
      if ((instr.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) &&
          regs[destNdx].state == TSDIndex) {
        regs[destNdx].state = TSDElementBase;
        continue;
      }
      if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        srcNdx = reg2ndx(operands[1].reg.value);
        if ((regs[destNdx].state == TSDBase && regs[srcNdx].state == TSDIndex) ||
            (regs[destNdx].state == TSDIndex && regs[srcNdx].state == TSDBase)) {
          regs[destNdx].offset += regs[srcNdx].offset;
          // The register in TSDBase state has multiplier unset. This selects the
          // multiplier of TSDIndex register.
          regs[destNdx].multiplier = MAX(regs[destNdx].multiplier, regs[srcNdx].multiplier);
          regs[destNdx].state = TSDElementBase;
          continue;
        }
      } else if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        regs[destNdx].offset += operands[1].imm.value.u;
        continue;
      }
      break;

    case ZYDIS_MNEMONIC_LEA:
      srcNdx = reg2ndx(operands[1].mem.base);
      if (regs[srcNdx].state == TSDIndex) {
        if (operands[1].mem.index == ZYDIS_REGISTER_NONE) {
          regs[destNdx] = (regInfo) {
            .state      = TSDIndex,
            .offset     = regs[srcNdx].offset + operands[1].mem.disp.value,
            .multiplier = regs[srcNdx].multiplier,
          };
          continue;
        }
      } else if (regs[srcNdx].state == TSDBase) {
        indexNdx = reg2ndx(operands[1].mem.index);
        if (regs[indexNdx].state == TSDIndex) {
          regs[destNdx] = (regInfo) {
            .state      = TSDElementBase,
            .offset     = regs[srcNdx].offset + regs[indexNdx].offset + operands[1].mem.disp.value,
            .multiplier = regs[indexNdx].multiplier * (operands[1].mem.scale ?: 1),
          };
          continue;
        }
      }
      break;

    case ZYDIS_MNEMONIC_MOV:
      if (instr.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) {
        regs[destNdx] = (regInfo) { .state = TSDBase };
        continue;
      }
      if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        srcNdx = reg2ndx(operands[1].reg.value);
        regs[destNdx] = regs[srcNdx];
        continue;
      }
      if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        srcNdx = reg2ndx(operands[1].mem.base);
        indexNdx = reg2ndx(operands[1].mem.index);
        if (regs[srcNdx].state == TSDBase) {
          if (operands[1].mem.index == ZYDIS_REGISTER_NONE) {
            regs[destNdx] = (regInfo) {
              .state    = TSDBase,
              .offset   = operands[1].mem.disp.value,
              .indirect = 1,
            };
            continue;
          } else if (regs[indexNdx].state == TSDIndex) {
            regs[destNdx] = (regInfo) {
              .state      = TSDValue,
              .offset     = regs[srcNdx].offset,
              .indirect   = regs[srcNdx].indirect,
              .multiplier = operands[1].mem.scale,
            };
            continue;
          }
        } else if (regs[srcNdx].state == TSDElementBase) {
          regs[destNdx] = (regInfo) {
            .state      = TSDValue,
            .offset     = regs[srcNdx].offset + operands[1].mem.disp.value,
            .indirect   = regs[srcNdx].indirect,
            .multiplier = regs[srcNdx].multiplier * (operands[1].mem.scale ?: 1),
          };
          continue;
        }
      }
      break;

    case ZYDIS_MNEMONIC_RET:
      // Return value is in RAX
      srcNdx = reg2ndx(ZYDIS_REGISTER_RAX);
      if (regs[srcNdx].state != TSDValue)
        return 0;

      return (uint16_t)regs[srcNdx].offset |
        ((uint32_t)regs[srcNdx].multiplier << 16) |
        ((uint32_t)regs[srcNdx].indirect << 24);

    case ZYDIS_MNEMONIC_CMP:
    case ZYDIS_MNEMONIC_TEST:
      // Opcodes without effect to destNdx.
      continue;

    default:
      break;
    }

    // Unsupported opcode. Assume it modified the operand 0, and mark it unknown.
    regs[destNdx] = (regInfo) { .state = Unspec };
  }
  return 0;
}
