#ifndef OPTI_STACKDELTATYPES_H
#define OPTI_STACKDELTATYPES_H

#define UNWIND_REG_INVALID 0
#define UNWIND_REG_CFA     1
#define UNWIND_REG_PC      2
#define UNWIND_REG_SP      3
#define UNWIND_REG_FP      4
#define UNWIND_REG_LR      5

#define UNWIND_REG_X86_RAX 6
#define UNWIND_REG_X86_R9  7
#define UNWIND_REG_X86_R11 8
#define UNWIND_REG_X86_R13 9
#define UNWIND_REG_X86_R15 10

// Flag to indicatet that a command (used inside Go stack delta generation only)
#define UNWIND_FLAG_COMMAND   (1 << 0)
// Flag to indicate that a full LR+FR frame is present on aarch64
#define UNWIND_FLAG_FRAME     (1 << 1)
// Flag to indicate that unwinding is valid on leaf frames only (uses untracked register)
#define UNWIND_FLAG_LEAF_ONLY (1 << 2)
// Flag to indicate that the resolve CFA value should be dereferenced
#define UNWIND_FLAG_DEREF_CFA (1 << 3)

// Unsupported or no value for the register
#define UNWIND_COMMAND_INVALID       0
// For CFA: stop unwinding, this function is a stack root function
#define UNWIND_COMMAND_STOP          1
// Unwind a PLT entry
#define UNWIND_COMMAND_PLT           2
// Unwind a signal frame
#define UNWIND_COMMAND_SIGNAL        3
// Unwind using standard frame pointer
#define UNWIND_COMMAND_FRAME_POINTER 4

// If opcode has UNWIND_OPCODEF_DEREF set, the lowest bits of 'param' are used
// as second adder as post-deref operation. This contains the mask for that.
// This assumes that stack and CFA are aligned to register size, so that the
// lowest bits of the offsets are always unset.
#define UNWIND_DEREF_MASK 7

// The argument after dereference is multiplied by this to allow some range.
// This assumes register size offsets are used.
#define UNWIND_DEREF_MULTIPLIER 8

#endif
