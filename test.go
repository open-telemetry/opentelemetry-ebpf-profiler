package main


import (
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"os"
	"fmt"
)


func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <elf-file> [struct-name]\n", os.Args[0])
		os.Exit(1)
	}

	elfFile := os.Args[1]
	specificStructs := []string{}
	if len(os.Args) > 2 {
		specificStructs = os.Args[2:]
	}

	pf, err := pfelf.Open(elfFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ELF file for %s: %v\n", specificStructs, err)
		os.Exit(1)
	}
	defer pf.Close()

	data, err := pf.StructData(specificStructs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ELF file: %v\n", err)
		os.Exit(1)
	}

	for _, s := range data {
		fmt.Printf("%s\n", s)
	}
}
