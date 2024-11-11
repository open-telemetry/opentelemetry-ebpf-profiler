package main

import (
	"context"
	"debug/elf"
	"debug/gosym"
	"errors"
	"flag"
	"fmt"
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

	symTable, addrs, err := goModuleAddrs(cmd.store, test)
	if err != nil {
		return fmt.Errorf("failed to find go module addresses: %w", err)
	}

	for addr, originFrames := range addrs {
		file, line, fn := symTable.PCToLine(uint64(addr))
		for _, originFrame := range originFrames {
			frame := reporter.FrameMetadataArgs{
				FunctionName: fn.Name,
				SourceFile:   file,
				SourceLine:   libpf.SourceLineno(line),
			}
			*originFrame = formatSymbolizedFrame(&frame, false) + " (" + *originFrame + ")"
		}
	}

	return writeTestCaseJSON(os.Stdout, test)
}

// goModuleAddrs returns the symtable for the go module of test case and the
// addresses to symbolize for it mapped to pointers to the frames in the test
// case that reference them.
func goModuleAddrs(store *modulestore.Store, c *CoredumpTestCase) (
	*gosym.Table, map[libpf.AddressOrLineno][]*string, error,
) {
	var symTable *gosym.Table
	var module *ModuleInfo
	var errs []error
	for i := range c.Modules {
		table, err := gosymTable(store, &c.Modules[i])
		if err != nil {
			errs = append(errs, err)
			continue
		} else if symTable != nil {
			return nil, nil, errors.New("multiple go modules found")
		}
		symTable = table
		module = &c.Modules[i]
	}

	if module == nil {
		return nil, nil, fmt.Errorf("no go module found: %w", errors.Join(errs...))
	}

	addrs := map[libpf.AddressOrLineno][]*string{}
	moduleName := filepath.Base(module.LocalPath)
	for _, thread := range c.Threads {
		for i, frame := range thread.Frames {
			frameModuleName, addr, err := parseUnsymbolizedFrame(frame)
			if err != nil {
				continue
			}

			if frameModuleName != moduleName {
				continue
			}

			addrs[addr] = append(addrs[addr], &thread.Frames[i])
		}
	}
	return symTable, addrs, nil
}

func gosymTable(store *modulestore.Store, module *ModuleInfo) (*gosym.Table, error) {
	reader, err := store.OpenReadAt(module.Ref)
	if err != nil {
		return nil, fmt.Errorf("failed to open module: %w", err)
	}
	defer reader.Close()

	exe, err := elf.NewFile(reader)
	if err != nil {
		return nil, err
	}

	// Look up the address of the .text section.
	var textAddr uint64
	if sect := exe.Section(".text"); sect != nil {
		textAddr = sect.Addr
	}

	// But prefer the runtime.text symbol if it exists. This is modeled after go
	// tool addr2line, see src/cmd/internal/objfile/objfile.go in the Go tree.
	symbols, err := exe.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name == "runtime.text" {
				textAddr = sym.Value
			}
		}
	}

	if textAddr == 0 {
		return nil, errors.New("missing .text section and runtime.text symbol")
	}

	// TODO(fg): The section headers might be stripped, in which case we could
	// try to locate gopclntab using alternative heuristics. See
	// nativeunwind/elfunwindinfo/elfgopclntab.go for code that does this.
	pclntab := exe.Section(".gopclntab")
	if pclntab == nil {
		return nil, errors.New("missing .gopclntab section")
	}

	lineTableData, err := pclntab.Data()
	if err != nil {
		return nil, err
	}
	lineTable := gosym.NewLineTable(lineTableData, textAddr)
	return gosym.NewTable(nil, lineTable)
}
