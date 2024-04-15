/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package support

import (
	"bytes"

	cebpf "github.com/cilium/ebpf"
)

// LoadCollectionSpec is a wrapper around ebpf.LoadCollectionSpecFromReader and loads the eBPF
// Spec from the embedded file.
// We expect tracerData to hold all possible eBPF maps and programs.
func LoadCollectionSpec() (*cebpf.CollectionSpec, error) {
	return cebpf.LoadCollectionSpecFromReader(bytes.NewReader(tracerData))
}
