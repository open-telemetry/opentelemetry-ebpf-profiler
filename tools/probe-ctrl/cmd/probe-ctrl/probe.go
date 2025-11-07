package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// iteratePrograms iterates through all eBPF programs and calls the visitor function for each.
// The visitor receives the program ID and info, and should return true to continue iteration.
func iteratePrograms(visitor func(id ebpf.ProgramID, info *ebpf.ProgramInfo) bool) {
	var lastID ebpf.ProgramID

	for {
		nextID, err := ebpf.ProgramGetNextID(lastID)
		if err != nil {
			return
		}
		lastID = nextID

		prog, err := ebpf.NewProgramFromID(nextID)
		if err != nil {
			continue
		}

		info, err := prog.Info()
		prog.Close()
		if err != nil {
			continue
		}

		if !visitor(nextID, info) {
			return
		}
	}
}

func getProbe(name string) (*ebpf.Program, error) {
	var found *ebpf.Program

	iteratePrograms(func(id ebpf.ProgramID, info *ebpf.ProgramInfo) bool {
		if info.Name == name {
			prog, err := ebpf.NewProgramFromID(id)
			if err == nil {
				found = prog
			}
			return false
		}
		return true
	})

	if found != nil {
		return found, nil
	}
	return nil, fmt.Errorf("probe %q not found", name)
}

func listAllPrograms() int {
	fmt.Println("Loaded eBPF programs:")
	fmt.Println("=====================")

	count := 0
	iteratePrograms(func(id ebpf.ProgramID, info *ebpf.ProgramInfo) bool {
		count++
		fmt.Printf("  [%d] ID=%d Name=%s Type=%s\n", count, id, info.Name, info.Type)
		return true
	})

	fmt.Printf("\nTotal: %d programs\n", count)
	return 0
}
