// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testsupport"
)

// structOffsets returns the member offsets of the named DWARF struct type.
func structOffsets(t *testing.T, d *dwarf.Data, name string) map[string]int64 {
	t.Helper()

	r := d.Reader()
	for {
		e, err := r.Next()
		require.NoError(t, err)
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagStructType {
			continue
		}
		if n, _ := e.Val(dwarf.AttrName).(string); n != name {
			continue
		}

		offsets := make(map[string]int64)
		for {
			c, err := r.Next()
			require.NoError(t, err)
			if c == nil || c.Tag == 0 {
				break
			}
			member, _ := c.Val(dwarf.AttrName).(string)
			off, ok := c.Val(dwarf.AttrDataMemberLoc).(int64)
			if member != "" && ok {
				offsets[member] = off
			}
		}
		return offsets
	}

	t.Fatalf("DWARF struct type %s not found", name)
	return nil
}

// TestSchedOffsets checks the curated Sched_bp_off against a real binary's DWARF,
// covering both a mistyped offset and a version branch that routes to the wrong one.
//
// It also asserts that gobuf.lr is the slot ahead of gobuf.bp, which is what lets
// go_unwind_morestack derive lr from sched_bp_off. tools/gooffsets makes that same
// assertion against newly supported releases; this covers the fixture's version.
func TestSchedOffsets(t *testing.T) {
	const fixture = "integrationtests/pprof_stable"
	testsupport.RequireGeneratedTestFile(t, fixture)

	info, err := buildinfo.ReadFile(fixture)
	require.NoError(t, err)

	f, err := elf.Open(fixture)
	require.NoError(t, err)
	defer f.Close()

	d, err := f.DWARF()
	require.NoError(t, err)

	gobuf := structOffsets(t, d, "runtime.gobuf")
	lr, ok := gobuf["lr"]
	require.True(t, ok, "gobuf has no lr member")
	bp, ok := gobuf["bp"]
	require.True(t, ok, "gobuf has no bp member")
	require.Equal(t, bp, lr+8,
		"gobuf lr and bp are no longer adjacent, so go_unwind_morestack can no "+
			"longer derive lr from sched_bp_off")

	g := structOffsets(t, d, "runtime.g")
	sched, ok := g["sched"]
	require.True(t, ok, "g has no sched member")
	require.Equal(t, int64(getOffsets(info.GoVersion).Sched_bp_off), sched+bp,
		"Sched_bp_off for %s does not match the binary; re-run tools/gooffsets",
		info.GoVersion)
}
