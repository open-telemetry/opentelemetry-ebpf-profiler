package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

var (
	argProbeLink string
	argClear     bool
	argListProgs bool
	argBPFFS     string
)

var (
	defaultBPFFSPath = "/sys/fs/bpf"
)

func init() {
	flag.StringVar(&argProbeLink, "probe-link", "", "kprobe|kretprobe|uprobe|uretprobe:<target>[:<symbol>]")
	flag.BoolVar(&argClear, "clear", false, "Remove probe from all links.")
	flag.StringVar(&argBPFFS, "bpffs", defaultBPFFSPath, "Path to BPF filesystem mount point.")
}

func main() {
	os.Exit(run())
}

func run() int {
	flag.Parse()

	pinPath := fmt.Sprintf("%s/probe-ctrl/", argBPFFS)

	if argClear {
		if err := os.RemoveAll(pinPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove pin path: %v\n", err)
			return -1
		}
		return 0
	}

	probeSpec, err := tracer.ParseProbe(argProbeLink)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse probe: %v\n", err)
		return -1
	}

	tracerProg, err := getProbe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get probe %q: %v\n", probeSpec.ProgName, err)
		return -1
	}

	probeLink, err := tracer.AttachProbe(tracerProg, probeSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach probe: %v\n", err)
		return -1
	}

	if err := os.MkdirAll(pinPath, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create pin path: %v\n", err)
		return -1
	}

	pinFile := filepath.Join(pinPath, fmt.Sprintf("%d", time.Now().Unix()))
	if err := probeLink.Pin(pinFile); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to pin link: %v\n", err)
		return -1
	}

	fmt.Printf("Attached probe %s to %s:%s\n", probeSpec.ProgName, probeSpec.Target, probeSpec.Symbol)
	fmt.Printf("Pinned to: %s\n", pinFile)

	return 0
}
