// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file implements an interface to read struct sizes and field offsets
// from DWARF if it is present.

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"debug/dwarf"
	"fmt"
	"os"
	"slices"
	"strings"
)

type typeData struct {
	name           string
	size           int64
	structTypeInfo *dwarf.StructType
}

func (data typeData) String() string {
	var str string = ""

	if data.structTypeInfo != nil {
		str += fmt.Sprintf("\nstruct %s {\n", data.name)

		// Print field information
		for _, field := range data.structTypeInfo.Field {
			fieldType := field.Type.String()
			// Clean up the type string a bit
			fieldType = strings.TrimPrefix(fieldType, "struct ")

			str += fmt.Sprintf("  %s %s; // offset: %d, size: %d",
				fieldType, field.Name, field.ByteOffset, field.Type.Size())
			str += "\n"
		}

		str += fmt.Sprintf("} // total size: %d bytes", (&data).Size())
		str += "\n"
	} else {
		str += fmt.Sprintf("\n%s ", data.name)
		str += fmt.Sprintf(" // total size: %d bytes", data.size)
	}

	return str
}

func (data *typeData) FieldOffset(name string) (int64, error) {
	field, err := data.field(name)
	if err != nil {
		return -1, err
	}
	return field.ByteOffset, nil
}

func (data *typeData) FieldSize(name string) (int64, error) {
	field, err := data.field(name)
	if err != nil {
		return -1, err
	}
	return field.Type.Size(), nil
}

func (data *typeData) field(name string) (*dwarf.StructField, error) {
	var found *dwarf.StructField = nil

	parts := strings.Split(name, ".")

	if len(parts) > 1 {
		var parent *dwarf.StructType = data.structTypeInfo
		for i, part := range parts {
			for _, field := range parent.Field {
				if field.Name == part {
					if i == len(parts)-1 {
						found = field
						break
					}
					struct_type, ok := field.Type.(*dwarf.StructType)
					if ok {
						parent = struct_type
					}
					break
				}
			}
		}

	} else {
		for _, field := range data.structTypeInfo.Field {
			if field.Name == name {
				found = field
				break
			}
		}
	}

	if found == nil {
		return nil, fmt.Errorf("unable to locate struct field %s", name)
	}

	return found, nil
}

func (data *typeData) Size() int64 {
	if data.structTypeInfo == nil {
		return data.size
	}
	// Calculate size based on fields
	calculatedSize := int64(0)

	// Print field information
	for _, field := range data.structTypeInfo.Field {
		// Update calculated size
		fieldEnd := field.ByteOffset + field.Type.Size()
		if fieldEnd > calculatedSize {
			calculatedSize = fieldEnd
		}
	}
	// Get the struct size from DWARF
	dwarfSize := data.structTypeInfo.ByteSize

	// Use calculated size if DWARF size is 0 or negative
	reportedSize := dwarfSize
	if dwarfSize <= 0 { //|| (hasFlexibleArray && dwarfSize < flexArrayOffset) { // TODO verify if flex array offset logic actually needed
		reportedSize = calculatedSize
	}

	return reportedSize
}

// This accepts a list of names to look up, as we want to try and get "everything in one go",
// since DWARF is inherently O(n) to look up these symbols
func loadStructData(debugInfo, debugAbbrev, debugStr, debugLineStr *Section, names []string) ([]typeData, error) {
	results := []typeData{}

	// To reduce memory usage, we will use the Section's Data() accessor to
	// get a memory mapped "subslice" and avoid allocations
	// This prevents a substantial amount of memory bloat that elf.File's DWARF() accessor
	// otherwise incurs
	abbrevData, err := debugAbbrev.Data(maxBytesLargeSection)
	if err != nil {
		return nil, err
	}

	debugData, err := debugInfo.Data(maxBytesLargeSection)
	if err != nil {
		return nil, err
	}

	strData, err := debugStr.Data(maxBytesLargeSection)
	if err != nil {
		return nil, err
	}

	lineStrData, err := debugLineStr.Data(maxBytesLargeSection)
	if err != nil {
		return nil, err
	}

	// Directly construct the DWARF file from the memory mapped slices above
	dwarfData, err := dwarf.New(abbrevData, nil, nil, debugData, nil, nil, nil, strData)
	if err != nil {
		return nil, err
	}

	// This section is required to be able to decode
	if err := dwarfData.AddSection(".debug_line_str", lineStrData); err != nil {
		return nil, err
	}

	processedTypes := make(map[string]struct{})

	reader := dwarfData.Reader()
	for {
		// return early if we have all of the structs that were asked for
		if len(processedTypes) == len(names) {
			return results, nil
		}

		entry, err := reader.Next()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading DWARF entry: %v\n", err)
			break
		}
		if entry == nil {
			break
		}
		// Look for struct type entries
		if entry.Tag == dwarf.TagStructType {
			nameVal, ok := entry.Val(dwarf.AttrName).(string)
			if !ok {
				continue // Skip unnamed structs
			}
			name := nameVal

			if _, ok := processedTypes[name]; ok {
				continue
			}

			// Ignore structs that weren't asked for
			if !slices.Contains(names, name) {
				continue
			}

			// Get the type information
			structType, err := dwarfData.Type(entry.Offset)
			if err != nil {
				fmt.Printf("Warning: Error getting type info for %s: %v\n", name, err)
				continue
			}

			// Type assertion to get the struct type
			structTypeInfo, ok := structType.(*dwarf.StructType)
			if !ok {
				continue
			}

			// Skip incomplete structs, try another compilation unit
			if structTypeInfo.Incomplete {
				continue
			}

			results = append(results, typeData{
				name:           name,
				structTypeInfo: structTypeInfo,
			})

			processedTypes[name] = struct{}{}
		} else if entry_name, ok := entry.Val(dwarf.AttrName).(string); ok && slices.Contains(names, entry_name) {

			if _, ok := processedTypes[entry_name]; ok {
				continue
			}

			// look for anything with the name
			t, err := dwarfData.Type(entry.Offset)
			if err != nil {
				return nil, err
			}
			if t.Size() > 0 {
				results = append(results, typeData{
					name: entry_name,
					size: t.Size(),
				})
				processedTypes[entry_name] = struct{}{}
			}
		}
	}

	return results, nil
}
