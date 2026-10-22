// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"sync"
)

const (
	size4k  = 4096
	size64k = 65536
)

var pool4k = sync.Pool{
	New: func() any {
		return new([size4k]byte)
	},
}

var pool64k = sync.Pool{
	New: func() any {
		return new([size64k]byte)
	},
}

func GetBuffer(sz int) []byte {
	switch {
	case sz <= size4k:
		return pool4k.Get().(*[size4k]byte)[:sz]
	case sz <= size64k:
		return pool64k.Get().(*[size64k]byte)[:sz]
	default:
		return make([]byte, sz)
	}
}

func PutBuffer(buf []byte) {
	switch cap(buf) {
	case size4k:
		pool4k.Put((*[size4k]byte)(buf[:size4k]))
	case size64k:
		pool64k.Put((*[size64k]byte)(buf[:size64k]))
	}
}
