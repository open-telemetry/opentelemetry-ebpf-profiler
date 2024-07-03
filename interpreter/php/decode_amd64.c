/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//go:build amd64
#include "../../zydis/Zydis.h"
#include "decode_amd64.h"


// retrieveJITBufferPtr will decode instructions from the given code blob until
// an assignment has been made to rdi. This corresponds to loading
// the dasm_buf in preparation for a function call.
int retrieveJITBufferPtr(const uint8_t * const code, const size_t codesize,
                         const uint64_t rip_base, uint64_t * const buffer_ptr,
                         uint64_t * const size_ptr) {
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisDecodedInstruction instr;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZyanUSize instruction_offset = 0;

  // These are to check that we've written to both pointers.
  int written_to_buffer_ptr = 0;
  int written_to_size_ptr = 0;
  
  while(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + instruction_offset,
                                            codesize - instruction_offset, &instr, operands))) {
    instruction_offset += instr.length;    
    if(instr.mnemonic == ZYDIS_MNEMONIC_CALL || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
      // We should have returned by now, so return. 
      return EARLY_RETURN_ERROR;
    }

    
    // We only care about writing into rdi or rsi
    if(instr.mnemonic != ZYDIS_MNEMONIC_MOV
       || operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER
       || !(operands[0].reg.value == ZYDIS_REGISTER_RDI ||
            operands[0].reg.value == ZYDIS_REGISTER_RSI)) {
      continue;
    }

    if(operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
       operands[1].mem.disp.has_displacement &&
       operands[1].mem.base == ZYDIS_REGISTER_RIP &&
       operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
      
      if(operands[0].reg.value == ZYDIS_REGISTER_RDI) {
          *buffer_ptr = rip_base + instruction_offset + operands[1].mem.disp.value;
          written_to_buffer_ptr = 1;
      } else if (operands[0].reg.value == ZYDIS_REGISTER_RSI) {
          *size_ptr = rip_base + instruction_offset + operands[1].mem.disp.value;
          written_to_size_ptr = 1;
      }
    }
    
    if(written_to_size_ptr && written_to_buffer_ptr) {
      return NO_ERROR;
    }
    
  }
  return NOT_FOUND_ERROR;
}

// retrieveExecuteExJumpLabelAddress will decode instructions from the given code blob until
// a jmp instruction is encountered. This corresponds to executing code in PHP's Hybrid VM,
// which allows us to recover accurate PC data for JIT code
int retrieveExecuteExJumpLabelAddress(const uint8_t * const code, const size_t codesize,
                                      const uint64_t rip_base, uint64_t * const out) {
  // The raison d'etre for this function is described in the php8 unwinding doc,
  // in particular in the "disassembling execute_ex" section.
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  // Note: since we're recovering a theoretical return address we need to read "one ahead"
  // so that we can return properly
  ZydisDecodedInstruction instr;
  ZyanUSize instruction_offset = 0;

  while(ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, NULL, code + instruction_offset,
                                                   codesize - instruction_offset, &instr))) {
    instruction_offset += instr.length;
    if(instr.mnemonic == ZYDIS_MNEMONIC_RET) {
      // Unexpected early return indicating end of the function
      // Getting here implies we've had an error.
      return EARLY_RETURN_ERROR;
    }

    // If the instruction is a jmp then we've found the right address.
    if(instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
      // Read the next address.
      if(ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, NULL, code + instruction_offset,
                                                    codesize - instruction_offset, &instr))) {
        *out = instruction_offset + rip_base;
        return NO_ERROR;
      } else {
        // If this fails it implies the buffer isn't big enough, or that
        // the PHP code block is malformed, or our heuristic assumptions are wrong..
        // this is a larger error
        return DECODING_ERROR;
      }
    }   
  }

  // Getting here implies we've had an error
  return NOT_FOUND_ERROR;
}


// retrieveZendVMKind will decode instructions from the given code blob until an
// assignment to (e/r)ax has been made. This corresponds to loading an immediate in
// rax for the return from zend_vm_kind, which contains the VM Mode that we care about.
int retrieveZendVMKind(const uint8_t * const code, const size_t codesize,
                       uint64_t * const out) {
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisDecodedInstruction instr;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZyanUSize instruction_offset = 0;
  while(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + instruction_offset,
                                            codesize - instruction_offset, &instr, operands))) {
    instruction_offset += instr.length;
    if(instr.mnemonic == ZYDIS_MNEMONIC_RET) {
      // Unexpected early return indicating end of the function
      // Getting here implies we've had an error. 
      return EARLY_RETURN_ERROR;
    }

    // This corresponds to an instruction like this:
    // mov eax, 0x...
    // Note that since the immediate is likely small (e.g between 0-4) we check the
    // destination register as both
    // EAX and RAX to account for possible changes in codegen.
    if(instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
       operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
       operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
       ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, operands[0].reg.value) ==
       ZYDIS_REGISTER_RAX) {
      *out = operands[1].imm.value.u;
      return NO_ERROR;
    }
  }

  // We shouldn't get here, so if we do there's been an error. 
  return NOT_FOUND_ERROR;
}
