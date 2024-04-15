//go:build integration && linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ebpf

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/rlimit"
	"github.com/elastic/otel-profiling-agent/lpm"
	"github.com/elastic/otel-profiling-agent/support"
)

func loadTracers(t *testing.T) *ebpfMapsImpl {
	t.Helper()

	coll, err := support.LoadCollectionSpec()
	if err != nil {
		t.Fatalf("Failed to load specification for tracers: %v", err)
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		t.Fatalf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	pidPageToMappingInfo, err := cebpf.NewMap(coll.Maps["pid_page_to_mapping_info"])
	if err != nil {
		t.Fatalf("failed to load 'pid_page_to_mapping_info': %v", err)
	}

	return &ebpfMapsImpl{
		pidPageToMappingInfo: pidPageToMappingInfo,
	}
}

func TestLPM(t *testing.T) {
	tests := map[string]struct {
		pid      libpf.PID
		page     uint64
		pageBits uint32
		rip      uint64
		fileID   uint64
		bias     uint64
	}{
		"direct": {pid: 1000, page: 0xAA55AA, pageBits: 64, rip: 0xAA55AA, fileID: 123, bias: 456},
		"random": {pid: 123, page: 0x500000, pageBits: 44, rip: 0x5a63b5, fileID: 456, bias: 789},
	}

	impl := loadTracers(t)

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			prefix := lpm.Prefix{
				Key:    test.page,
				Length: test.pageBits,
			}
			if err := impl.UpdatePidPageMappingInfo(test.pid, prefix, test.fileID, test.bias); err != nil {
				t.Fatalf("failed to insert value into eBPF map: %v", err)
			}
			if fileID, bias, err := impl.LookupPidPageInformation(uint32(test.pid), test.rip); err != nil {
				t.Errorf("failed to lookup element: %v", err)
			} else {
				if uint64(fileID) != test.fileID {
					t.Fatalf("expected fileID 0x%x but got 0x%x", test.fileID, fileID)
				}
				if bias != test.bias {
					t.Fatalf("expected bias 0x%x but got 0x%x", test.bias, bias)
				}
			}
			if _, err := impl.DeletePidPageMappingInfo(test.pid, []lpm.Prefix{prefix}); err != nil {
				t.Fatalf("failed to delete value from eBPF map: %v", err)
			}
		})
	}
}

func TestBatchOperations(t *testing.T) {
	for _, mapType := range []cebpf.MapType{cebpf.Hash, cebpf.Array, cebpf.LPMTrie} {
		ok := probeBatchOperations(mapType)
		t.Logf("Batch operations are supported for %s: %v", mapType, ok)
	}
}
