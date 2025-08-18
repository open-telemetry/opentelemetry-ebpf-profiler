// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDWARFParseStructs(t *testing.T) {
	tests := []struct {
		desc                 string
		test_file            string
		expectedStructs      []string
		expectedStructSizes  map[string]int64
		expectedFieldOffsets map[string]map[string]int64
		expectedFieldSizes   map[string]map[string]int64
	}{
		{
			desc:           "it should be able to parse arbitrary structs",
			test_file:      "testdata/dwarf_structs",
			expectedStructs : []string {
				"some_struct",
			},
			expectedStructSizes : map[string]int64{
				"some_struct" : 72,
			},
			expectedFieldOffsets : map[string]map[string]int64{
				"some_struct": map[string]int64{
					"some_array": int64(0),
					"some_int":   int64(64),
				},
			},
			expectedFieldSizes : map[string]map[string]int64{
				"some_struct": map[string]int64{
					"some_array": int64(64),
					"some_int": int64(8),
				},
			},
		},
		{
/*
    'execution_context_struct.vm_stack': offset_of('rb_execution_context_struct', 'vm_stack'),
    'execution_context_struct.vm_stack_size': offset_of('rb_execution_context_struct', 'vm_stack_size'),
    'execution_context_struct.cfp': offset_of('rb_execution_context_struct', 'cfp'),

    'control_frame_struct.pc': offset_of('rb_control_frame_struct', 'pc'),
    'control_frame_struct.iseq': offset_of('rb_control_frame_struct', 'iseq'),
    'control_frame_struct.ep': offset_of('rb_control_frame_struct', 'ep'),
    'control_frame_struct.size_of_control_frame_struct': size_of('rb_control_frame_struct'),

    'iseq_struct.body': offset_of('rb_iseq_struct', 'body'),

    'iseq_constant_body.iseq_type': offset_of('rb_iseq_constant_body', 'type'),
    'iseq_constant_body.size': offset_of('rb_iseq_constant_body', 'iseq_size'),
    'iseq_constant_body.encoded': offset_of('rb_iseq_constant_body', 'iseq_encoded'),
    'iseq_constant_body.location': offset_of('rb_iseq_constant_body', 'location'),
    'iseq_constant_body.insn_info_body': offset_of('rb_iseq_constant_body', 'insns_info.body'),
    'iseq_constant_body.insn_info_size': offset_of('rb_iseq_constant_body', 'insns_info.size'),
    'iseq_constant_body.succ_index_table': offset_of('rb_iseq_constant_body', 'insns_info.succ_index_table'),
    'iseq_constant_body.size_of_iseq_constant_body': size_of('rb_iseq_constant_body'),

    'iseq_location_struct.pathobj': offset_of('rb_iseq_location_struct', 'pathobj'),
    'iseq_location_struct.base_label': offset_of('rb_iseq_location_struct', 'base_label'),

    'iseq_insn_info_entry.position': offset_of('iseq_insn_info_entry', 'position'),
    'iseq_insn_info_entry.size_of_position': size_of_field('iseq_insn_info_entry', 'position'),
    'iseq_insn_info_entry.line_no': offset_of('iseq_insn_info_entry', 'line_no'),
    'iseq_insn_info_entry.size_of_line_no': size_of_field('iseq_insn_info_entry', 'line_no'),
    'iseq_insn_info_entry.size_of_iseq_insn_info_entry': size_of('iseq_insn_info_entry'),

    'rstring_struct.as_ary': offset_of('RString', 'as.embed.ary'),
    'rstring_struct.as_heap_ptr': offset_of('RString', 'as.heap.ptr'),

    'rarray_struct.as_ary': offset_of('RArray', 'as.ary'),
    'rarray_struct.as_heap_ptr': offset_of('RArray', 'as.heap.ptr'),

    'size_of_value': size_of('VALUE', ns=''),

    'rb_ractor_struct.running_ec': offset_of('rb_ractor_struct', 'threads.running_ec'),
*/
			desc:           "it should be able to parse complicated ruby structs",
			test_file:      "testdata/ruby_dwarf_structs",
			expectedStructs : []string {
				//"rb_execution_context_struct",
				//"rb_control_frame_struct",
				//"rb_iseq_struct",
				//"rb_iseq_constant_body",
				//"rb_iseq_location_struct",
				//"iseq_insn_info_entry",
				//"RString",
				//"RArray",
				"succ_index_table",
				"succ_dict_block",
			},
			expectedStructSizes : map[string]int64{
				"succ_dict_block" : 80,
			},
			expectedFieldOffsets : map[string]map[string]int64{
				//"rb_execution_context_struct": map[string]int64{
				//	"vm_stack": int64(0),
				//	"cfp": int64(16),
				//},
				"succ_index_table": map[string]int64{
					"succ_part": int64(48),
				},
				"succ_dict_block": map[string]int64{
					"small_block_ranks": int64(8),
					"bits": int64(16),
				},
			},
			expectedFieldSizes : map[string]map[string]int64{
				//"rb_execution_context_struct": map[string]int64{
				//	"vm_stack": int64(8),
				//},
				"succ_index_table": map[string]int64{
					"imm_part": int64(48), // note that in python they multiple this by 9, then divide by 8 https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/078ae4d6ded761b513038440bc8525014fa6c016/tools/coredump/testsources/ruby/gdb-dump-offsets.py#L69 because of https://github.com/Shopify/ruby/blob/70b4b6fea0eeb66647539bcb3b9a50d027d92e51/iseq.c#L4265
					"succ_part": int64(0),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			elfFile, err := Open(tt.test_file)
			require.NoError(err)
			defer elfFile.Close()

			struct_data, err := elfFile.StructData(tt.expectedStructs)
			require.NoError(err)

			assert.Equal(len(tt.expectedStructs), len(struct_data))

			structs_by_name := map[string]structData{}

			for _, struct_info := range struct_data {
				structs_by_name[struct_info.name] = struct_info
			}

			for _, name := range tt.expectedStructs {
				_, ok := structs_by_name[name]
				assert.True(ok)
			}

			for name, expected_size := range tt.expectedStructSizes {
				struct_info, ok := structs_by_name[name]
				require.True(ok)

				assert.Equal(expected_size, struct_info.Size())
			}

			for name, fields := range tt.expectedFieldOffsets {
				struct_info, ok := structs_by_name[name]
				require.True(ok)

				for field, expected_offset := range fields {
					actual_offset, err := struct_info.FieldOffset(field)
					assert.NoError(err)

					assert.Equal(expected_offset, actual_offset)
				}
			}

			for name, fields := range tt.expectedFieldSizes {
				struct_info, ok := structs_by_name[name]
				require.True(ok)

				for field, expected_size := range fields {
					actual_size, err := struct_info.FieldSize(field)
					assert.NoError(err)

					assert.Equal(expected_size, actual_size)
				}
			}
		})
	}
}
