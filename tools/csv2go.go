package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

//nolint:lll
const templateStr = `// Code generated from complete_offsets.csv; DO NOT EDIT.

package nodev8

// nodeOffsets holds the Node.js environment offset data for specific versions
type nodeOffsets struct {
	contextHandle      uint32
	nativeContext      uint32
	embedderData       uint32
	environmentPointer uint32
	executionAsyncId   uint32
}

// nodeOffsetTable maps Node.js versions to their corresponding offsets
// Data embedded from complete_offsets.csv
var nodeOffsetTable = map[string]nodeOffsets{
{{- range .}}
	"{{.Version}}": { {{.ContextHandle}}, {{.NativeContext}}, {{.EmbedderData}}, {{.EnvironmentPointer}}, {{.ExecutionAsyncId}} },
{{- end}}
}
`

type OffsetData struct {
	Version            string
	ContextHandle      uint32
	NativeContext      uint32
	EmbedderData       uint32
	EnvironmentPointer uint32
	ExecutionAsyncId   uint32
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input.csv> <output.go>\n", os.Args[0])
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	// Read CSV file
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
		os.Exit(1)
	}

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CSV: %v\n", err)
		os.Exit(1)
	}

	if len(records) < 2 {
		fmt.Fprintf(os.Stderr, "CSV file must have at least header and one data row\n")
		os.Exit(1)
	}

	// Skip header row
	var data []OffsetData
	for i := 1; i < len(records); i++ {
		record := records[i]
		if len(record) != 6 {
			fmt.Fprintf(os.Stderr,
				"Invalid record at line %d: expected 6 columns, got %d\n",
				i+1, len(record))
			continue
		}

		var contextHandle, nativeContext, embedderData, environmentPointer, executionAsyncId uint64
		contextHandle, err = strconv.ParseUint(strings.TrimSpace(record[1]), 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing contextHandle at line %d: %v\n", i+1, err)
			continue
		}

		nativeContext, err = strconv.ParseUint(strings.TrimSpace(record[2]), 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"Error parsing nativeContext at line %d: %v\n",
				i+1, err)
			continue
		}

		embedderData, err = strconv.ParseUint(strings.TrimSpace(record[3]), 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing embedderData at line %d: %v\n", i+1, err)
			continue
		}

		environmentPointer, err = strconv.ParseUint(strings.TrimSpace(record[4]), 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing environmentPointer at line %d: %v\n", i+1, err)
			continue
		}

		executionAsyncId, err = strconv.ParseUint(strings.TrimSpace(record[5]), 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing executionAsyncId at line %d: %v\n", i+1, err)
			continue
		}

		data = append(data, OffsetData{
			Version:            strings.TrimSpace(record[0]),
			ContextHandle:      uint32(contextHandle),
			NativeContext:      uint32(nativeContext),
			EmbedderData:       uint32(embedderData),
			EnvironmentPointer: uint32(environmentPointer),
			ExecutionAsyncId:   uint32(executionAsyncId),
		})
	}

	// Create output directory if needed
	if err = os.MkdirAll(filepath.Dir(outputFile), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Generate Go file
	var tmpl *template.Template
	tmpl, err = template.New("offsets").Parse(templateStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing template: %v\n", err)
		os.Exit(1)
	}

	var outFile *os.File
	outFile, err = os.Create(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}

	if err = tmpl.Execute(outFile, data); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing template: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s from %s with %d entries\n", outputFile, inputFile, len(data))
}
