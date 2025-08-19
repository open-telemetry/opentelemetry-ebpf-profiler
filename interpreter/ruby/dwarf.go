// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func (r *rubyData) calculateTypesFromDWARF(ef *pfelf.File) error {
	referenced_ruby_types := []string{
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
		"VALUE",
	}

	if r.version >= rubyVersion(3, 0, 0) {
		referenced_ruby_types = append(referenced_ruby_types, "rb_ractor_struct")
	}

	type_info, err := ef.TypeData(referenced_ruby_types)
	if err != nil {
		return err
	}

	if len(referenced_ruby_types) != len(type_info) {
		return fmt.Errorf("unexpected number of returned types, expected %d, got %d",
			len(referenced_ruby_types), len(type_info))
	}

	types_by_name := map[string]pfelf.TypeData{}

	for _, info := range type_info {
		types_by_name[info.Name] = info
	}

	// rb_execution_context_struct fields
	rb_execution_context_struct, ok := types_by_name["rb_execution_context_struct"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "rb_execution_context_struct")
	}

	vm_stack_offset, err := rb_execution_context_struct.FieldOffset("vm_stack")
	if err != nil {
		return err
	}
	r.vmStructs.execution_context_struct.vm_stack = uint8(vm_stack_offset)

	vm_stack_size_offset, err := rb_execution_context_struct.FieldOffset("vm_stack_size")
	if err != nil {
		return err
	}
	r.vmStructs.execution_context_struct.vm_stack_size = uint8(vm_stack_size_offset)

	cfp_offset, err := rb_execution_context_struct.FieldOffset("cfp")
	if err != nil {
		return err
	}
	r.vmStructs.execution_context_struct.cfp = uint8(cfp_offset)

	// rb_control_frame_struct fields
	rb_control_frame_struct, ok := types_by_name["rb_control_frame_struct"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "rb_control_frame_struct")
	}
	pc_offset, err := rb_control_frame_struct.FieldOffset("pc")
	if err != nil {
		return err
	}
	r.vmStructs.control_frame_struct.pc = uint8(pc_offset)

	iseq_offset, err := rb_control_frame_struct.FieldOffset("iseq")
	if err != nil {
		return err
	}
	r.vmStructs.control_frame_struct.iseq = uint8(iseq_offset)

	ep_offset, err := rb_control_frame_struct.FieldOffset("ep")
	if err != nil {
		return err
	}
	r.vmStructs.control_frame_struct.ep = uint8(ep_offset)
	r.vmStructs.control_frame_struct.
		size_of_control_frame_struct = uint8(rb_control_frame_struct.Size())

	// rb_iseq_struct fields
	rb_iseq_struct, ok := types_by_name["rb_iseq_struct"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "rb_iseq_struct")
	}
	iseq_body_offset, err := rb_iseq_struct.FieldOffset("body")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_struct.body = uint8(iseq_body_offset)

	// rb_iseq_constant_body fields
	rb_iseq_constant_body, ok := types_by_name["rb_iseq_constant_body"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "rb_iseq_constant_body")
	}
	iseq_body_type, err := rb_iseq_constant_body.FieldOffset("type")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.iseq_type = uint8(iseq_body_type)

	iseq_body_size, err := rb_iseq_constant_body.FieldOffset("iseq_size")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.size = uint8(iseq_body_size)

	iseq_body_encoded, err := rb_iseq_constant_body.FieldOffset("iseq_encoded")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.encoded = uint8(iseq_body_encoded)

	iseq_body_location, err := rb_iseq_constant_body.FieldOffset("location")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.location = uint8(iseq_body_location)

	// insns_info is a sub_struct, calculate its offset as the base for it submembers
	iseq_body_insns_info, err := rb_iseq_constant_body.FieldOffset("insns_info")
	if err != nil {
		return err
	}

	iseq_body_insns_info_body, err := rb_iseq_constant_body.FieldOffset("insns_info.body")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.insn_info_body = uint8(iseq_body_insns_info) +
		uint8(iseq_body_insns_info_body)

	iseq_body_insns_info_size, err := rb_iseq_constant_body.FieldOffset("insns_info.size")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.insn_info_size = uint8(iseq_body_insns_info) +
		uint8(iseq_body_insns_info_size)

	iseq_body_insns_info_succ_index_table, err := rb_iseq_constant_body.
		FieldOffset("insns_info.succ_index_table")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_constant_body.succ_index_table = uint8(iseq_body_insns_info) +
		uint8(iseq_body_insns_info_succ_index_table)

	r.vmStructs.iseq_constant_body.size_of_iseq_constant_body = uint16(rb_iseq_constant_body.Size())

	// rb_iseq_location_struct fields
	rb_iseq_location_struct, ok := types_by_name["rb_iseq_location_struct"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "rb_iseq_location_struct")
	}
	pathobj_offset, err := rb_iseq_location_struct.FieldOffset("pathobj")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_location_struct.pathobj = uint8(pathobj_offset)

	base_label_offset, err := rb_iseq_location_struct.FieldOffset("base_label")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_location_struct.base_label = uint8(base_label_offset)

	// iseq_insn_info_entry fields
	iseq_insn_info_entry, ok := types_by_name["iseq_insn_info_entry"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "iseq_insn_info_entry")
	}
	position_offset, err := iseq_insn_info_entry.FieldOffset("position")
	if err != nil {
		// removed in 2.6+
		if r.version < rubyVersion(2, 6, 0) {
			return err
		}
	} else {
		r.vmStructs.iseq_insn_info_entry.position = uint8(position_offset)
	}

	position_size, err := iseq_insn_info_entry.FieldSize("position")
	if err != nil {
		if r.version < rubyVersion(2, 6, 0) {
			return err
		}
	} else {
		r.vmStructs.iseq_insn_info_entry.size_of_position = uint8(position_size)
	}

	lineno_offset, err := iseq_insn_info_entry.FieldOffset("line_no")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_insn_info_entry.line_no = uint8(lineno_offset)

	lineno_size, err := iseq_insn_info_entry.FieldSize("line_no")
	if err != nil {
		return err
	}
	r.vmStructs.iseq_insn_info_entry.size_of_line_no = uint8(lineno_size)

	r.vmStructs.iseq_insn_info_entry.
		size_of_iseq_insn_info_entry = uint8(iseq_insn_info_entry.Size())

	// RString fields
	rstring, ok := types_by_name["RString"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "RString")
	}
	rstring_as_offset, err := rstring.FieldOffset("as")
	if err != nil {
		return err
	}

	rstring_as_embed_offset, err := rstring.FieldOffset("as.embed")
	if err != nil {
		return err
	}

	rstring_as_embed_ary_offset, err := rstring.FieldOffset("as.embed.ary")
	if err != nil {
		return err
	}
	r.vmStructs.rstring_struct.as_ary = uint8(rstring_as_offset) +
		uint8(rstring_as_embed_offset) + uint8(rstring_as_embed_ary_offset)

	rstring_as_heap_offset, err := rstring.FieldOffset("as.heap")
	if err != nil {
		return err
	}

	rstring_as_heap_ptr_offset, err := rstring.FieldOffset("as.heap.ptr")
	if err != nil {
		return err
	}
	r.vmStructs.rstring_struct.as_heap_ptr = uint8(rstring_as_offset) +
		uint8(rstring_as_heap_offset) + uint8(rstring_as_heap_ptr_offset)

	// RArray fields
	rarray, ok := types_by_name["RArray"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "RArray")
	}

	rarray_as_offset, err := rarray.FieldOffset("as")
	if err != nil {
		return err
	}

	rarray_as_ary_offset, err := rarray.FieldOffset("as.ary")
	if err != nil {
		return err
	}
	r.vmStructs.rarray_struct.as_ary = uint8(rarray_as_offset) + uint8(rarray_as_ary_offset)

	rarray_as_heap_offset, err := rarray.FieldOffset("as.heap")
	if err != nil {
		return err
	}

	rarray_as_heap_ptr_offset, err := rarray.FieldOffset("as.heap.ptr")
	if err != nil {
		return err
	}
	r.vmStructs.rarray_struct.as_heap_ptr = uint8(rarray_as_offset) +
		uint8(rarray_as_heap_offset) + uint8(rarray_as_heap_ptr_offset)

	// succ_dict_block fields
	succ_dict_block, ok := types_by_name["succ_dict_block"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "succ_dict_block")
	}

	small_block_ranks_offset, err := succ_dict_block.FieldOffset("small_block_ranks")
	if err != nil {
		return err
	}
	r.vmStructs.succ_index_table_struct.small_block_ranks = uint8(small_block_ranks_offset)

	succ_bits_offset, err := succ_dict_block.FieldOffset("bits")
	if err != nil {
		return err
	}
	r.vmStructs.succ_index_table_struct.block_bits = uint8(succ_bits_offset)
	r.vmStructs.succ_index_table_struct.size_of_succ_dict_block = uint8(succ_dict_block.Size())

	// succ_index_table fields
	succ_index_table, ok := types_by_name["succ_index_table"]
	if !ok {
		return fmt.Errorf("unable to locate struct %s", "succ_index_table")
	}

	succ_part_offset, err := succ_index_table.FieldOffset("succ_part")
	if err != nil {
		return err
	}
	r.vmStructs.succ_index_table_struct.succ_part = uint8(succ_part_offset)

	imm_part_size, err := succ_index_table.FieldOffset("imm_part")
	if err != nil {
		return err
	}

	// equivalent of "floor division" by 8 after multiplying by 9
	r.vmStructs.size_of_immediate_table = uint8((imm_part_size * 9) / 8)

	// rb_ractor_struct not added until ruby 3.0.0+
	if r.version >= rubyVersion(3, 0, 0) {
		var rb_ractor_struct pfelf.TypeData
		// rb_ractor_struct fields
		rb_ractor_struct, ok = types_by_name["rb_ractor_struct"]
		if !ok {
			return fmt.Errorf("unable to locate struct %s", "rb_ractor_struct")
		}

		running_ec_offset, err := rb_ractor_struct.FieldOffset("running_ec")
		if err != nil {
			return err
		}
		r.vmStructs.rb_ractor_struct.running_ec = uint16(running_ec_offset)
	}

	// VALUE
	rb_value, ok := types_by_name["VALUE"]
	if !ok {
		return fmt.Errorf("unable to locate type %s", "VALUE")
	}

	r.vmStructs.size_of_value = uint8(rb_value.Size())

	return nil
}
