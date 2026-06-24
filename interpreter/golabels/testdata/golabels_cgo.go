//go:build withcgo

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

/*
void golabels_cgo_stub(void) {}
*/
import "C"

func foo() {
	C.golabels_cgo_stub()
}
