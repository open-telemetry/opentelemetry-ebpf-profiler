// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestUnloadIsIdempotent(t *testing.T) {
	probe := New()
	if err := probe.Unload(); err != nil {
		t.Fatalf("first Unload() returned %v", err)
	}
	if !probe.unloaded {
		t.Fatal("Unload() did not mark the probe unloaded")
	}
	if err := probe.Unload(); err != nil {
		t.Fatalf("second Unload() returned %v", err)
	}
	probe.Detach(1)
}

type blockingAttachmentLink struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (l *blockingAttachmentLink) Close() error {
	l.once.Do(func() {
		close(l.started)
		<-l.release
	})
	return nil
}

func TestDetachDoesNotBlockUnloadWhileClosingLink(t *testing.T) {
	probe := New()
	pid := libpf.PID(123)
	key := attachmentKey{name: "alloc", offset: 42}
	lnk := &blockingAttachmentLink{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	probe.attachments[pid] = map[attachmentKey]*attachment{
		key: {
			lnk: lnk,
			specKeys: map[support.USDTSpecKey]libpf.Void{
				{Pid: uint32(pid), Address: 42}: {},
			},
		},
	}

	detachDone := make(chan struct{})
	go func() {
		probe.Detach(pid)
		close(detachDone)
	}()

	select {
	case <-lnk.started:
	case <-time.After(time.Second):
		close(lnk.release)
		<-detachDone
		t.Fatal("Detach did not start closing the link")
	}

	unloadDone := make(chan error, 1)
	go func() { unloadDone <- probe.Unload() }()
	select {
	case err := <-unloadDone:
		if err != nil {
			t.Fatalf("Unload() returned %v", err)
		}
	case <-time.After(time.Second):
		close(lnk.release)
		<-detachDone
		t.Fatal("Unload blocked while Detach was closing a link")
	}

	close(lnk.release)
	select {
	case <-detachDone:
	case <-time.After(time.Second):
		t.Fatal("Detach did not finish after link closure was released")
	}
}

func TestPendingAttachmentCleanup(t *testing.T) {
	tests := map[string]func(*Probe, libpf.PID) error{
		"detach": func(probe *Probe, pid libpf.PID) error {
			probe.Detach(pid)
			return nil
		},
		"unload": func(probe *Probe, _ libpf.PID) error {
			return probe.Unload()
		},
	}

	for name, cleanup := range tests {
		t.Run(name, func(t *testing.T) {
			probe := New()
			pid := libpf.PID(123)
			key := attachmentKey{name: "alloc", offset: 42}
			probe.attachments[pid] = map[attachmentKey]*attachment{
				key: {specKeys: map[support.USDTSpecKey]libpf.Void{
					{Pid: uint32(pid), Address: 42}: {},
					{Pid: uint32(pid), Address: 84}: {},
				}},
			}

			if err := cleanup(probe, pid); err != nil {
				t.Fatalf("cleanup returned %v", err)
			}
			if _, ok := probe.attachments[pid]; ok {
				t.Fatal("pending attachment was not removed")
			}
		})
	}
}

func TestProbeVirtualAddress(t *testing.T) {
	mapping := &process.RawMapping{Vaddr: 0x7000, FileOffset: 0x1000, Length: 0x1000}
	tests := []struct {
		name       string
		fileOffset uint64
		want       uint64
		contained  bool
	}{
		{name: "before mapping", fileOffset: 0xfff},
		{name: "mapping start", fileOffset: 0x1000, want: 0x7000, contained: true},
		{name: "inside mapping", fileOffset: 0x1123, want: 0x7123, contained: true},
		{name: "last mapping byte", fileOffset: 0x1fff, want: 0x7fff, contained: true},
		{name: "mapping end", fileOffset: 0x2000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, contained, err := probeVirtualAddress(mapping, tc.fileOffset)
			if err != nil {
				t.Fatalf("probeVirtualAddress() returned %v", err)
			}
			if got != tc.want || contained != tc.contained {
				t.Fatalf("probeVirtualAddress() = (%#x, %v), want (%#x, %v)",
					got, contained, tc.want, tc.contained)
			}
		})
	}

	overflow := &process.RawMapping{
		Vaddr: math.MaxUint64 - 1, FileOffset: 0x1000, Length: 0x1000,
	}
	if _, _, err := probeVirtualAddress(overflow, 0x1002); err == nil {
		t.Fatal("probeVirtualAddress() accepted an overflowing address")
	}
}

func TestDeriveAllocValues(t *testing.T) {
	meta := &samples.TraceEventMeta{
		ContextValues: []uint64{1000, 0xdeadbeef, 100},
	}
	got := appendAllocValues([]int64{7}, meta)
	want := []int64{7, 1000, 10}
	if !slices.Equal(got, want) {
		t.Fatalf("appendAllocValues() = %v, want %v", got, want)
	}
}

func TestAllocObjectsValue(t *testing.T) {
	tests := map[string]struct {
		weightedBytes int64
		size          uint64
		want          int64
	}{
		"exact multiple":      {weightedBytes: 1000, size: 100, want: 10},
		"single object":       {weightedBytes: 64, size: 64, want: 1},
		"unknown size":        {weightedBytes: 500, size: 0, want: 1},
		"weight below size":   {weightedBytes: 32, size: 64, want: 1},
		"rounds down":         {weightedBytes: 250, size: 100, want: 2},
		"size exceeds maxint": {weightedBytes: 1000, size: math.MaxUint64, want: 1},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := allocObjectsValue(tc.weightedBytes, tc.size); got != tc.want {
				t.Errorf("allocObjectsValue(%d, %d) = %d, want %d",
					tc.weightedBytes, tc.size, got, tc.want)
			}
		})
	}
}
