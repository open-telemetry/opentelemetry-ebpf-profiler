// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file implements an interface to read struct sizes and field offsets
// from DWARF if it is present.

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"debug/dwarf"
	//"debug/elf"
	"fmt"
	"os"
	//"io"
	"strings"
	"slices"
)

type structData struct {
	name string
	structTypeInfo *dwarf.StructType
}

func (data structData) String() string {
	var str string = ""
	
	str += fmt.Sprintf("\nstruct %s {\n", data.name)
	
	// Calculate size based on fields
	calculatedSize := int64(0)
	hasFlexibleArray := false
	var flexArrayOffset int64 = 0
	
	// Print field information
	for i, field := range data.structTypeInfo.Field {
		fieldType := field.Type.String()
		// Clean up the type string a bit
		fieldType = strings.TrimPrefix(fieldType, "struct ")
		
		str += fmt.Sprintf("  %s %s; // offset: %d, size: %d", 
			fieldType, field.Name, field.ByteOffset, field.Type.Size())
		
		// Check if this might be a flexible array member
		isLastField := i == len(data.structTypeInfo.Field)-1
		isArrayType := strings.HasSuffix(fieldType, "[]") || 
					  strings.Contains(fieldType, "[0]") ||
					  strings.Contains(fieldType, "FLEX_ARY")
		hasArrayName := strings.HasSuffix(field.Name, "_array") ||
					   strings.HasSuffix(field.Name, "_part")
		
		if isLastField && (isArrayType || hasArrayName) {
			str += fmt.Sprintf(" (flexible array member)")
			hasFlexibleArray = true
			flexArrayOffset = field.ByteOffset
		}
		str += "\n"
		
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
	if dwarfSize <= 0 || (hasFlexibleArray && dwarfSize < flexArrayOffset) {
		reportedSize = calculatedSize
	}
	
	str += fmt.Sprintf("} // total size: %d bytes", reportedSize)
	if hasFlexibleArray {
		str += fmt.Sprintf(" (base size without flexible array)")
	}
	if dwarfSize != reportedSize {
		str += fmt.Sprintf(" (DWARF: %d, calculated: %d)", dwarfSize, calculatedSize)
	}
	str += "\n"

	return str
}

func loadStructData(debugInfo, debugAbbrev, debugStr, debugLineStr *Section, names []string) ([]structData, error) {
	results := []structData{}

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
	
	processedStructs := make(map[string]struct{})

	reader := dwarfData.Reader()
	for {
		// return early if we have all of the structs that were asked for
		if len(processedStructs) == len(names) {
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

			if _, ok := processedStructs[name]; ok {
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
		
			results = append(results, structData{
				name: name,
				structTypeInfo: structTypeInfo,
			})

			processedStructs[name] = struct{}{}
		}
	}
	
	return results, nil
}
