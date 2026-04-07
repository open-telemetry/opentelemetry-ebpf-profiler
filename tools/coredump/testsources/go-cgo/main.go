// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

/*
#include <unistd.h>

// A chain of C functions to create a visible C stack.
void c_leaf(void) {
	sleep(3600);
}

void c_inner(void) {
	c_leaf();
}

void c_outer(void) {
	c_inner();
}
*/
import "C"

//go:noinline
func goCallC() {
	C.c_outer()
}

//go:noinline
func goMiddle() {
	goCallC()
}

//go:noinline
func goOuter() {
	goMiddle()
}

func main() {
	goOuter()
}
