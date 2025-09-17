package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
)

var (
	argExec   string
	argSymbol string
	argClear  bool
)

var (
	pinPath = "/sys/fs/bpf/probe-ctrl/"
)

func init() {
	flag.StringVar(&argExec, "exec", "", "Executable to which the probe should be attached.")
	flag.StringVar(&argSymbol, "symb", "", "Symbol in the executable to which the probe will be attached.")
	flag.BoolVar(&argClear, "clear", false, "Remove probe from all links.")
}

func main() {
	os.Exit(run())
}

func run() int {
	flag.Parse()

	if argClear {
		// bpf_link_detach does not exist for uprobes. So just remove
		// the pinned path to deactivate uprobes as a work around.
		if err := os.RemoveAll(pinPath); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return -1
		}
		return 0
	}

	if argExec == "" || argSymbol == "" {
		fmt.Fprintf(os.Stderr, "Both -exec <exec_value> and -symb <symb_value> need to be set\n")
		return -1
	}

	exec, err := link.OpenExecutable(argExec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return -1
	}

	probe, err := getProbe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return -1
	}

	probeLink, err := exec.Uprobe(argSymbol, probe, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed attaching probe to '%s' in '%s': %v\n", argSymbol, argExec, err)
		return -1
	}

	if err := os.MkdirAll(pinPath, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return -1
	}

	if err := probeLink.Pin(fmt.Sprintf("%s/%d", pinPath, time.Now().Unix())); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to pin link: %v\n", err)
		return -1
	}

	return 0
}
