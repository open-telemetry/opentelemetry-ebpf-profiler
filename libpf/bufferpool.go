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

// GetBuffer returns a byte slice of length sz. Common used buffer sizes
// are served from pools, contents are not zeroed.
func GetBuffer(sz int) []byte {
	switch sz {
	case size4k:
		return pool4k.Get().(*[size4k]byte)[:sz]
	case size64k:
		return pool64k.Get().(*[size64k]byte)[:sz]
	default:
		return make([]byte, sz)
	}
}

// PutBuffer donates a buffer to the pool. The buffer capacity is used
// to determine if the buffer can be pooled. The caller must not use
// the buffer or any slice referring to it after this call.
func PutBuffer(buf []byte) {
	switch cap(buf) {
	case size4k:
		pool4k.Put((*[size4k]byte)(buf[:size4k]))
	case size64k:
		pool64k.Put((*[size64k]byte)(buf[:size64k]))
	}
}
