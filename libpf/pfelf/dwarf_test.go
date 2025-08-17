// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	//"go.opentelemetry.io/ebpf-profiler/testsupport"
	//"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Probably don't need to redefine this since it is in the same package?
//func getPFELF(path string, t *testing.T) *File {
//	file, err := Open(path)
//	assert.NoError(t, err)
//	return file
//}

// TODO make a basic test suite that asserts struct sizes and offsets from a
// test file with DWARF info in the test data, add to existing makefile

// TODO to start with, just point at the ruby test file and assert on some
// structs from there? 
// Then for the next step, maybe copy the struct definitions from ruby to have
// a bunch of complex and realistic structs


func TestDWARFParseRubyStructs(t *testing.T) {
	elfFile, err := Open("/home/dalehamel.linux/.rubies/ruby-3.4.4/bin/ruby")
	require.NoError(t, err)
	defer elfFile.Close()

	check_structs := []string{
		"rb_execution_context_struct",
		"rb_control_frame_struct",
		"rb_iseq_struct",
		"rb_iseq_constant_body",
		"rb_iseq_location_struct",
		"iseq_insn_info_entry",
		"RString",
		"RArray",
		"succ_index_table",
		"succ_dict_block",
	}

	offset_checks := map[string]map[string]int64{
		"rb_execution_context_struct": map[string]int64{
			"vm_stack": int64(0),
			"cfp": int64(16),
		},
	}

	size_checks := map[string]map[string]int64{
		"rb_execution_context_struct": map[string]int64{
			"vm_stack": int64(8),
		},
	}


	struct_data, err := elfFile.StructData(check_structs)
	require.NoError(t, err)

	structs_by_name := map[string]structData{}

	for _, struct_info := range struct_data {
		structs_by_name[struct_info.name] = struct_info
	}

	assert.Equal(t, len(check_structs), len(struct_data))

	for name, fields := range offset_checks {
		struct_info, ok := structs_by_name[name]
		require.True(t, ok)

		for field, expected_offset := range fields {
			actual_offset, err := struct_info.FieldOffset(field)
			assert.NoError(t, err)

			assert.Equal(t, expected_offset, actual_offset)
		}
	}

	for name, fields := range size_checks {
		struct_info, ok := structs_by_name[name]
		require.True(t, ok)

		for field, expected_size := range fields {
			actual_size, err := struct_info.FieldSize(field)
			assert.NoError(t, err)

			assert.Equal(t, expected_size, actual_size)
		}
	}
}
