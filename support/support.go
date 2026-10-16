// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support // import "go.opentelemetry.io/ebpf-profiler/support"

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"

	cebpf "github.com/cilium/ebpf"
)

func decompressedBlob() ([]byte, error) {
	uncompressedSize := binary.LittleEndian.Uint32(tracerData[len(tracerData)-4:])
	buffer := make([]byte, uncompressedSize)

	gzReader, err := gzip.NewReader(bytes.NewReader(tracerData))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	n, err := io.ReadFull(gzReader, buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

// LoadCollectionSpec is a wrapper around ebpf.LoadCollectionSpecFromReader and loads the eBPF
// Spec from the embedded file.
// We expect tracerData to hold all possible eBPF maps and programs.
func LoadCollectionSpec() (*cebpf.CollectionSpec, error) {
	blob, err := decompressedBlob()
	if err != nil {
		return nil, err
	}
	return cebpf.LoadCollectionSpecFromReader(bytes.NewReader(blob))
}
