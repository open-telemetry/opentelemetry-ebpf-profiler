package main

import (
	"github.com/cilium/ebpf"
)

func getProbe() (*ebpf.Program, error) {
	var lastID ebpf.ProgramID

	for {
		nextID, err := ebpf.ProgramGetNextID(lastID)
		if err != nil {
			return nil, err
		}
		lastID = nextID

		prog, err := ebpf.NewProgramFromID(nextID)
		if err != nil {
			return nil, err
		}
		defer prog.Close()

		info, err := prog.Info()
		if err != nil {
			return nil, err
		}

		if info.Name == "uprobe__generic" {
			return prog.Clone()
		}
	}
}
