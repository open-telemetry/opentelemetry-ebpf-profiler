/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/peterbourgon/ff/v3/ffcli"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/process"
	"github.com/elastic/otel-profiling-agent/tools/coredump/modulestore"
)

// gcorePathPrefix specifies the path prefix we ask gcore to use when creating coredumps.
const gcorePathPrefix = "/tmp/coredump"

type newCmd struct {
	store *modulestore.Store

	// User-specified command line arguments.
	coredumpPath     string
	pid              uint64
	name             string
	importThreadInfo string
	debugEbpf        bool
	noModuleBundling bool
}

type trackedCoredump struct {
	*process.CoredumpProcess

	prefix string
	seen   libpf.Set[string]
}

func newTrackedCoredump(corePath, filePrefix string) (*trackedCoredump, error) {
	core, err := process.OpenCoredump(corePath)
	if err != nil {
		return nil, err
	}

	return &trackedCoredump{
		CoredumpProcess: core,
		prefix:          filePrefix,
		seen:            libpf.Set[string]{},
	}, nil
}

func (tc *trackedCoredump) GetMappingFileLastModified(_ *process.Mapping) int64 {
	return 0
}

func (tc *trackedCoredump) CalculateMappingFileID(m *process.Mapping) (libpf.FileID, error) {
	fid, err := libpf.FileIDFromExecutableFile(tc.prefix + m.Path)
	if err == nil {
		tc.seen[m.Path] = libpf.Void{}
	}
	return fid, err
}

func (tc *trackedCoredump) OpenMappingFile(m *process.Mapping) (process.ReadAtCloser, error) {
	rac, err := os.Open(tc.prefix + m.Path)
	if err == nil {
		tc.seen[m.Path] = libpf.Void{}
	}
	return rac, err
}

func (tc *trackedCoredump) OpenELF(fileName string) (*pfelf.File, error) {
	f, err := pfelf.Open(tc.prefix + fileName)
	if err == nil {
		tc.seen[fileName] = libpf.Void{}
	}
	return f, err
}

func newNewCmd(store *modulestore.Store) *ffcli.Command {
	args := &newCmd{store: store}

	set := flag.NewFlagSet("new", flag.ExitOnError)
	set.StringVar(&args.coredumpPath, "core", "", "Path of the coredump to import")
	set.Uint64Var(&args.pid, "pid", 0, "PID to create a fresh coredump for")
	set.StringVar(&args.name, "name", "", "Name for the test case [required]")
	set.StringVar(&args.importThreadInfo, "import-thread-info", "", "If this flag is specified, "+
		"the expected thread state is imported from another test case at the given path. If "+
		"omitted, the thread state is extracted by unwinding the coredump.")
	set.BoolVar(&args.debugEbpf, "debug-ebpf", false, "Enable eBPF debug printing")
	set.BoolVar(&args.noModuleBundling, "no-module-bundling", false,
		"Don't bundle binaries from local disk with the testcase. Should be avoided in general, "+
			"but can be useful when importing coredumps from other systems.")

	return &ffcli.Command{
		Name:       "new",
		Exec:       args.exec,
		ShortUsage: "new [flags]",
		ShortHelp:  "Create or import a new test case",
		FlagSet:    set,
	}
}

func (cmd *newCmd) exec(context.Context, []string) (err error) {
	// Validate arguments.
	if (cmd.coredumpPath == "") != (cmd.pid != 0) {
		return errors.New("please specify either `-core` or `-pid` (but not both)")
	}
	if cmd.name == "" {
		return errors.New("missing required argument `-name`")
	}

	var corePath string
	prefix := ""
	if cmd.coredumpPath != "" {
		corePath = cmd.coredumpPath
	} else {
		// No path provided: create a new dump.
		corePath, err = dumpCore(cmd.pid)
		if err != nil {
			return fmt.Errorf("failed to create coredump: %w", err)
		}
		defer os.Remove(corePath)
		prefix = fmt.Sprintf("/proc/%d/root/", cmd.pid)
	}

	core, err := newTrackedCoredump(corePath, prefix)
	if err != nil {
		return fmt.Errorf("failed to open coredump: %w", err)
	}
	defer core.Close()

	testCase := &CoredumpTestCase{}

	testCase.Threads, err = ExtractTraces(context.Background(), core, cmd.debugEbpf, nil)
	if err != nil {
		return fmt.Errorf("failed to extract traces: %w", err)
	}

	if cmd.importThreadInfo != "" {
		var importTestCase *CoredumpTestCase
		importTestCase, err = readTestCase(cmd.importThreadInfo)
		if err != nil {
			return fmt.Errorf("failed to read testcase to import thread info from: %w", err)
		}
		testCase.Threads = importTestCase.Threads
	}

	testCase.CoredumpRef, _, err = cmd.store.InsertModuleLocally(corePath)
	if err != nil {
		return fmt.Errorf("failed to place coredump into local module storage: %w", err)
	}

	if !cmd.noModuleBundling {
		for fileName := range core.seen {
			putModule(cmd.store, fileName, prefix, &testCase.Modules)
		}
	}

	path := makeTestCasePath(cmd.name)
	if err = writeTestCase(path, testCase, false); err != nil {
		return fmt.Errorf("failed to write test case: %w", err)
	}

	log.Info("Test case successfully written!")

	return nil
}

func dumpCore(pid uint64) (string, error) {
	// Backup current coredump filter mask.
	// https://man7.org/linux/man-pages/man5/core.5.html
	coredumpFilterPath := fmt.Sprintf("/proc/%d/coredump_filter", pid)
	prevMask, err := os.ReadFile(coredumpFilterPath)
	if err != nil {
		return "", fmt.Errorf("failed to read coredump filter: %w", err)
	}
	// Adjust coredump filter mask.
	//nolint:gosec
	err = os.WriteFile(coredumpFilterPath, []byte("0x3f"), 0o644)
	if err != nil {
		return "", fmt.Errorf("failed to write coredump filter: %w", err)
	}
	// Restore coredump filter mask upon leaving the function.
	defer func() {
		//nolint:gosec
		err2 := os.WriteFile(coredumpFilterPath, prevMask, 0o644)
		if err2 != nil {
			log.Warnf("Failed to restore previous coredump filter: %v", err2)
		}
	}()

	// `gcore` only accepts a path-prefix, not an exact path.
	//nolint:gosec
	err = exec.Command("gcore", "-o", gcorePathPrefix, strconv.FormatUint(pid, 10)).Run()
	if err != nil {
		return "", fmt.Errorf("gcore failed: %w", err)
	}

	return fmt.Sprintf("%s.%d", gcorePathPrefix, pid), nil
}

func putModule(store *modulestore.Store, fileName, prefix string, modules *[]ModuleInfo) {
	// Put the module into the module storage.
	id, isNew, err := store.InsertModuleLocally(prefix + fileName)
	if err != nil {
		log.Errorf("Failed to place file into local module storage: %v", err)
		return
	}

	if isNew {
		log.Infof("Module `%s` was newly added to local storage", fileName)
	} else {
		log.Infof("Module `%s` is already present in local storage", fileName)
	}

	*modules = append(*modules, ModuleInfo{
		Ref:       id,
		LocalPath: fileName,
	})
}
