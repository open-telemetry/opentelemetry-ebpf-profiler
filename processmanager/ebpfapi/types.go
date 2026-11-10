// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfapi // import "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"

import (
	"go.opentelemetry.io/ebpf-profiler/support"
)

// StackDelta represents stack deltas preprocessed by the ProcessManager which are
// then loaded to the eBPF map. It is a type alias of the Go equivalent of 'struct StackDelta'
// in eBPF types.h. See the eBPF header file for details.
type StackDelta = support.StackDelta

// StackDeltaPageDesc describes the stack delta data of a single 64kB code page in the
// per-executable stack delta map. It is a type alias of the Go equivalent of
// 'struct StackDeltaPageDesc' in eBPF types.h. See the eBPF header file for details.
type StackDeltaPageDesc = support.StackDeltaPageDesc
