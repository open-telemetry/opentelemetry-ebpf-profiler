// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfapi // import "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"

import (
	"go.opentelemetry.io/ebpf-profiler/support"
)

// StackDelta represents stack deltas preprocessed by the ProcessManager which are
// then loaded to the eBPF map. Aliased to the eBPF header version.
type StackDelta = support.StackDelta

// StackDeltaPageDesc describes the stack delta data of a single 64kB code page in the
// per-executable stack delta map. Aliased to the eBPF header version.
type StackDeltaPageDesc = support.StackDeltaPageDesc
