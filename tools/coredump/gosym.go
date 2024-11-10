package main

import (
	"context"
	"debug/elf"
	"debug/gosym"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/peterbourgon/ff/v3/ffcli"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

type gosymCmd struct {
	store    *modulestore.Store
	casePath string
}

func newGosymCmd(store *modulestore.Store) *ffcli.Command {
	args := &gosymCmd{store: store}

	set := flag.NewFlagSet("gosym", flag.ExitOnError)
	set.StringVar(&args.casePath, "case", "", "Path of the test case to debug")

	return &ffcli.Command{
		Name:       "gosym",
		Exec:       args.exec,
		ShortUsage: "gosym",
		ShortHelp:  "Symbolize go test case",
		FlagSet:    set,
	}
}

func (cmd *gosymCmd) exec(context.Context, []string) (err error) {
	// Validate arguments.
	if cmd.casePath == "" {
		return errors.New("please specify `-case`")
	}

	var test *CoredumpTestCase
	test, err = readTestCase(cmd.casePath)
	if err != nil {
		return fmt.Errorf("failed to read test case: %w", err)
	}

	module, addrs, err := goModuleAddrs(test)
	if err != nil {
		return fmt.Errorf("failed to find go module addresses: %w", err)
	}

	goBinary, err := cmd.store.OpenReadAt(module.Ref)
	if err != nil {
		return fmt.Errorf("failed to open module: %w", err)
	}
	defer goBinary.Close()

	locs, err := goSymbolize(goBinary, addrs)
	if err != nil {
		return fmt.Errorf("failed to symbolize: %w", err)
	}

	for addr, frame := range locs {
		for _, originFrame := range addrs[addr] {
			*originFrame = formatSymbolizedFrame(frame, false) + " (" + *originFrame + ")"
		}
	}

	return writeTestCaseJSON(os.Stdout, test)
}

// goModuleAddrs returns the go module and the addresses to symbolize for it
// mapped to pointers to the frames in c that reference them.
func goModuleAddrs(c *CoredumpTestCase) (*ModuleInfo, map[libpf.AddressOrLineno][]*string, error) {
	type moduleAddrs struct {
		module *ModuleInfo
		addrs  map[libpf.AddressOrLineno][]*string
	}

	moduleNames := map[string]*moduleAddrs{}
	for i, module := range c.Modules {
		moduleName := filepath.Base(module.LocalPath)
		if _, ok := moduleNames[moduleName]; ok {
			return nil, nil, fmt.Errorf("ambiguous module name: %q", moduleName)
		}
		moduleNames[moduleName] = &moduleAddrs{
			module: &c.Modules[i],
			addrs:  map[libpf.AddressOrLineno][]*string{},
		}
	}

	// maxAddrs is the module with the most addresses to symbolize. We use this
	// as a heuristic to determine which module is the Go module we're
	// interested in.
	// TODO(fg) alternatively we could extract all modules and run some check on
	// them to see if they are go binaries. But this is more complex, so the
	// current heuristic should be good enough for now.
	var maxAddrs *moduleAddrs
	for _, thread := range c.Threads {
		for i, frame := range thread.Frames {
			moduleName, addr, err := parseUnsymbolizedFrame(frame)
			if err != nil {
				continue
			}

			moduleAddrs, ok := moduleNames[moduleName]
			if !ok {
				return nil, nil, fmt.Errorf("module not found: %q", moduleName)
			}

			moduleAddrs.addrs[addr] = append(moduleAddrs.addrs[addr], &thread.Frames[i])
			if maxAddrs == nil || len(moduleAddrs.addrs[addr]) > len(maxAddrs.addrs[addr]) {
				maxAddrs = moduleAddrs
			}
		}
	}
	return maxAddrs.module, maxAddrs.addrs, nil
}

type addrSet[T any] map[libpf.AddressOrLineno]T

func goSymbolize[T any](goBinary io.ReaderAt, addrs addrSet[T]) (map[libpf.AddressOrLineno]*reporter.FrameMetadataArgs, error) {
	exe, err := elf.NewFile(goBinary)
	if err != nil {
		return nil, err
	}

	lineTableData, err := exe.Section(".gopclntab").Data()
	if err != nil {
		return nil, err
	}
	lineTable := gosym.NewLineTable(lineTableData, exe.Section(".text").Addr)
	if err != nil {
		return nil, err
	}

	symTableData, err := exe.Section(".gosymtab").Data()
	if err != nil {
		return nil, err
	}

	symTable, err := gosym.NewTable(symTableData, lineTable)
	if err != nil {
		return nil, err
	}

	frames := map[libpf.AddressOrLineno]*reporter.FrameMetadataArgs{}
	for addr, _ := range addrs {
		file, line, fn := symTable.PCToLine(uint64(addr))
		frames[addr] = &reporter.FrameMetadataArgs{
			FunctionName: fn.Name,
			SourceFile:   file,
			SourceLine:   libpf.SourceLineno(line),
		}
	}
	return frames, nil
}
