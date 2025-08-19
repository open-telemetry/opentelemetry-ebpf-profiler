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
		expectedTypes        []string
		expectedTypeSizes    map[string]int64
		expectedFieldOffsets map[string]map[string]int64
		expectedFieldSizes   map[string]map[string]int64
	}{
		{
			desc:      "it should be able to parse arbitrary structs",
			test_file: "testdata/dwarf_structs",
			expectedTypes: []string{
				"some_struct",
				"some_typedef",
			},
			expectedTypeSizes: map[string]int64{
				"some_struct":  72,
				"some_typedef": 8,
			},
			expectedFieldOffsets: map[string]map[string]int64{
				"some_struct": map[string]int64{
					"some_array": int64(0),
					"some_int":   int64(64),
				},
			},
			expectedFieldSizes: map[string]map[string]int64{
				"some_struct": map[string]int64{
					"some_array": int64(64),
					"some_int":   int64(8),
				},
			},
		},
		{
			desc:      "it should be able to parse complicated ruby structs",
			test_file: "testdata/ruby_dwarf_structs",
			expectedTypes: []string{
				"rb_execution_context_struct",
				"rb_control_frame_struct",
				"rb_iseq_struct",
				"rb_iseq_constant_body",
				"iseq_insn_info", // sub-struct of rb_iseq_constant_body
				"rb_iseq_location_struct",
				"iseq_insn_info_entry",
				"RString",
				"RArray",
				"succ_index_table",
				"succ_dict_block",
				"rb_ractor_struct",
				"VALUE",
			},
			expectedTypeSizes: map[string]int64{
				"rb_control_frame_struct": 56,
				"rb_iseq_constant_body":   320,
				"iseq_insn_info_entry":    8,
				"succ_dict_block":         80,
				"VALUE":                   8,
			},
			expectedFieldOffsets: map[string]map[string]int64{
				"rb_execution_context_struct": map[string]int64{
					"vm_stack":      int64(0),
					"vm_stack_size": int64(8),
					"cfp":           int64(16),
				},
				"rb_control_frame_struct": map[string]int64{
					"pc":   int64(0),
					"iseq": int64(16),
					"ep":   int64(32),
				},
				"rb_iseq_struct": map[string]int64{
					"body": int64(16),
				},
				"rb_iseq_constant_body": map[string]int64{
					"type":                        int64(0),
					"iseq_size":                   int64(4),
					"iseq_encoded":                int64(8),
					"location":                    int64(64),
					"insns_info":                  int64(112),
					"insns_info.body":             int64(0),
					"insns_info.size":             int64(16),
					"insns_info.succ_index_table": int64(24),
				},
				"iseq_insn_info": map[string]int64{ // substruct of rb_iseq_constant_body, these offsets would be added to the insns_info offset
					"body":             int64(0),
					"size":             int64(16),
					"succ_index_table": int64(24),
				},
				"rb_iseq_location_struct": map[string]int64{
					"pathobj":    int64(0),
					"base_label": int64(8),
				},
				"iseq_insn_info_entry": map[string]int64{
					// position was removed in 3.1
					"line_no": int64(0),
				},
				"RString": map[string]int64{
					"as":           int64(24),
					"as.embed":     int64(0),
					"as.embed.ary": int64(0),
					"as.heap":      int64(0),
					"as.heap.ptr":  int64(0),
				},
				"RArray": map[string]int64{
					"as":          int64(16),
					"as.ary":      int64(0),
					"as.heap":     int64(0),
					"as.heap.ptr": int64(16),
				},
				"succ_index_table": map[string]int64{
					"succ_part": int64(48),
				},
				"succ_dict_block": map[string]int64{
					"small_block_ranks": int64(8),
					"bits":              int64(16),
				},
				"rb_ractor_struct": map[string]int64{
					"threads":            int64(264),
					"threads.running_ec": int64(136),
				},
			},
			expectedFieldSizes: map[string]map[string]int64{
				"rb_execution_context_struct": map[string]int64{
					"vm_stack": int64(8),
				},
				"iseq_insn_info_entry": map[string]int64{
					// position was removed in 3.1
					"line_no": int64(4),
				},
				"succ_index_table": map[string]int64{
					"imm_part":  int64(48), // note that in python they multiple this by 9, then divide by 8 https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/078ae4d6ded761b513038440bc8525014fa6c016/tools/coredump/testsources/ruby/gdb-dump-offsets.py#L69 because of https://github.com/Shopify/ruby/blob/70b4b6fea0eeb66647539bcb3b9a50d027d92e51/iseq.c#L4265
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

			type_data, err := elfFile.TypeData(tt.expectedTypes)
			require.NoError(err)

			assert.Equal(len(tt.expectedTypes), len(type_data))

			types_by_name := map[string]TypeData{}

			for _, struct_info := range type_data {
				types_by_name[struct_info.Name] = struct_info
			}

			for _, name := range tt.expectedTypes {
				_, ok := types_by_name[name]
				assert.True(ok)
			}

			for name, expected_size := range tt.expectedTypeSizes {
				struct_info, ok := types_by_name[name]
				require.True(ok)

				assert.Equal(expected_size, struct_info.Size())
			}

			for name, fields := range tt.expectedFieldOffsets {
				struct_info, ok := types_by_name[name]
				require.True(ok)

				for field, expected_offset := range fields {
					actual_offset, err := struct_info.FieldOffset(field)
					assert.NoError(err)

					assert.Equal(expected_offset, actual_offset)
				}
			}

			for name, fields := range tt.expectedFieldSizes {
				struct_info, ok := types_by_name[name]
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
