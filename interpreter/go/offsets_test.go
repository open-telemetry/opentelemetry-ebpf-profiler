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
// tools/gooffsets makes that same assertion against newly supported releases;
// this covers the fixture's version.
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
	g := structOffsets(t, d, "runtime.g")
	sched, ok := g["sched"]
	require.True(t, ok, "g has no sched member")

	offsets := getOffsets(info.GoVersion)
	for _, tc := range []struct {
		member string
		got    uint32
		name   string
	}{
		{"sp", offsets.Sched_sp_off, "Sched_sp_off"},
		{"pc", offsets.Sched_pc_off, "Sched_pc_off"},
		{"lr", offsets.Sched_lr_off, "Sched_lr_off"},
		{"bp", offsets.Sched_bp_off, "Sched_bp_off"},
	} {
		off, ok := gobuf[tc.member]
		require.Truef(t, ok, "gobuf has no %s member", tc.member)
		require.Equalf(t, int64(tc.got), sched+off,
			"%s for %s does not match the binary; re-run tools/gooffsets",
			tc.name, info.GoVersion)
	}
}
