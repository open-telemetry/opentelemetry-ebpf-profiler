/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ebpf

// StackDeltaEBPF represents stack deltas preprocessed by the ProcessManager which are
// then loaded to the eBPF map. This is Go equivalent of 'struct StackDelta' in eBPF types.h.
// See the eBPF header file for details.
type StackDeltaEBPF struct {
	AddressLow uint16
	UnwindInfo uint16
}
