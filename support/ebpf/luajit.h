#pragma once

// This is CFRAME_SIZE in src/lj_frame.h
// We could dynamically get this from lj_vm_ffi_callback disassembly and look for:
// lea rax, [rsp+CFRAME_SIZE]
// https://github.com/openresty/luajit2/blob/7952882d/src/vm_x64.dasc#L2725
#define LUAJIT_CFRAME_SPACE_X86_64  80
// This is CFRAME_SIZE in src/lj_frame.h
// We could dynamically get this from lj_vm_ffi_callback disassembly and look for the
// add to sp register instruction but that is not available in stripped binaries.
#define LUAJIT_CFRAME_SPACE_AARCH64 208

#if defined(__x86_64__)
  #define LUAJIT_CFRAME_SPACE LUAJIT_CFRAME_SPACE_X86_64
#elif defined(__aarch64__)
  #define LUAJIT_CFRAME_SPACE LUAJIT_CFRAME_SPACE_AARCH64
#endif
