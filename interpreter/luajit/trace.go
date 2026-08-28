// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

// This offset is the same in arm64/x86_64 for all known versions of luajit.
// (gdb) p &((GCtrace*)0)->startins
// $7 = (uint16_t *) 0x50
const tracePartOffset = 0x50

// Definition:
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_jit.h#L259
type trace struct {
	_       uint32 /* startins Original bytecode of starting instruction. */
	szmcode uint32 /* Size of machine code. */
	mcode   uint64 /* Start of machine code. */
	_       uint32 /* mcloop */
	// For arm is LJ_ABI_PAUTH defined?
	// For docker images at least LJ_ABI_PAUTH is not defined.
	// ASMFunction mcauth;	/* Start of machine code, with ptr auth applied. */
	_        uint16 /* Number of child traces (root trace only). */
	spadjust uint16 /* Stack pointer adjustment (offset in bytes). */
	traceno  uint16 /* Trace number. */
	_        uint16 /* Linked trace (or self for loops). */
	root     uint16 /* Root trace of side trace (or 0 for root traces). */
}
