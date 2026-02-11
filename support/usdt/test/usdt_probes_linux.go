// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package test // import "go.opentelemetry.io/ebpf-profiler/support/usdt/test"

/*
#cgo CFLAGS: -I/usr/include
#include <sys/sdt.h>
#include <stdint.h>
#include <stdio.h>

// Helper functions to create probes with specific argument patterns
// Use __attribute__((noinline)) to prevent inlining
__attribute__((noinline)) void test_simple_probe(int32_t x, int64_t y, uint64_t z) {
    DTRACE_PROBE3(testprov, simple_probe, x, y, z);
    // Add a side effect to prevent optimization
    volatile int dummy = x + y + z;
    (void)dummy;
}

__attribute__((noinline)) void test_memory_probe(int32_t *x, int64_t *y) {
    DTRACE_PROBE2(testprov, memory_probe, x, y);
    volatile int dummy = *x + *y;
    (void)dummy;
}

__attribute__((noinline)) void test_const_probe(void) {
    DTRACE_PROBE1(testprov, const_probe, 100);
}

__attribute__((noinline)) void test_mixed_probe(int32_t x, int64_t *y, int c, double *f) {
    DTRACE_PROBE4(testprov, mixed_probe, x, y, c, f);
    volatile double dummy = x + *y + c + *f;
    (void)dummy;
}

__attribute__((noinline)) void test_probe_int32(int32_t a, int32_t b, int32_t c) {
    DTRACE_PROBE3(testprov, int32_args, a, b, c);
    volatile int dummy = a + b + c;
    (void)dummy;
}

__attribute__((noinline)) void test_probe_int64(int64_t a, int64_t b) {
    DTRACE_PROBE2(testprov, int64_args, a, b);
    volatile long dummy = a + b;
    (void)dummy;
}

__attribute__((noinline)) void test_probe_mixed_refs(int32_t *a, int64_t *b, int32_t c) {
    DTRACE_PROBE3(testprov, mixed_refs, a, b, c);
    volatile long dummy = *a + *b + c;
    (void)dummy;
}

__attribute__((noinline)) void test_probe_uint8(uint8_t a, uint8_t b) {
    DTRACE_PROBE2(testprov, uint8_args, a, b);
    volatile int dummy = a + b;
    (void)dummy;
}
*/
import "C"

// CallTestProbes calls all the USDT test probes to ensure they're included in the binary
func CallTestProbes() {
	var x C.int32_t = 42
	var y C.int64_t = 1234567890
	var z C.uint64_t = 0xDEADBEEF
	var f C.double = 3.14159

	C.test_simple_probe(x, y, z)
	C.test_memory_probe(&x, &y)
	C.test_const_probe()
	C.test_mixed_probe(x, &y, 42, &f)

	var a, b, c C.int32_t = 10, 20, 30
	C.test_probe_int32(a, b, c)

	var p, q C.int64_t = 100, 200
	C.test_probe_int64(p, q)

	C.test_probe_mixed_refs(&a, &p, c)

	var u1, u2 C.uint8_t = 5, 10
	C.test_probe_uint8(u1, u2)
}
