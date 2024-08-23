/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package proc provides functionality for retrieving kallsyms, modules and
// executable mappings via /proc.
package proc

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/stringutil"
)

const defaultMountPoint = "/proc"

// GetKallsyms returns SymbolMap for kernel symbols from /proc/kallsyms.
func GetKallsyms(kallsymsPath string) (*libpf.SymbolMap, error) {
	var address uint64
	var symbol string

	symmap := libpf.SymbolMap{}
	noSymbols := true

	file, err := os.Open(kallsymsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s: %v", kallsymsPath, err)
	}
	defer file.Close()

	var scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		// Avoid heap allocation by not using scanner.Text().
		// NOTE: The underlying bytes will change with the next call to scanner.Scan(),
		// so make sure to not keep any references after the end of the loop iteration.
		line := stringutil.ByteSlice2String(scanner.Bytes())

		// Avoid heap allocations here - do not use strings.FieldsN()
		var fields [4]string
		nFields := stringutil.FieldsN(line, fields[:])

		if nFields < 3 {
			return nil, fmt.Errorf("unexpected line in kallsyms: '%s'", line)
		}

		if address, err = strconv.ParseUint(fields[0], 16, 64); err != nil {
			return nil, fmt.Errorf("failed to parse address value: '%s'", fields[0])
		}

		if address != 0 {
			noSymbols = false
		}

		symbol = strings.Clone(fields[2])

		symmap.Add(libpf.Symbol{
			Name:    libpf.SymbolName(symbol),
			Address: libpf.SymbolValue(address),
		})
	}
	symmap.Finalize()

	if noSymbols {
		return nil, errors.New(
			"all addresses from kallsyms are zero - check process permissions")
	}

	return &symmap, nil
}

// GetKernelModules returns SymbolMap for kernel modules from /proc/modules.
func GetKernelModules(modulesPath string,
	kernelSymbols *libpf.SymbolMap) (*libpf.SymbolMap, error) {
	symmap := libpf.SymbolMap{}

	file, err := os.Open(modulesPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s: %v", modulesPath, err)
	}
	defer file.Close()

	stext, err := kernelSymbols.LookupSymbol("_stext")
	if err != nil {
		return nil, fmt.Errorf("unable to find kernel text section start: %v", err)
	}
	etext, err := kernelSymbols.LookupSymbol("_etext")
	if err != nil {
		return nil, fmt.Errorf("unable to find kernel text section end: %v", err)
	}
	log.Debugf("Found KERNEL TEXT at %x-%x", stext.Address, etext.Address)
	symmap.Add(libpf.Symbol{
		Name:    "vmlinux",
		Address: stext.Address,
		Size:    int(etext.Address - stext.Address),
	})

	var scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		var size, refcount, address uint64
		var name, dependencies, state string

		line := scanner.Text()

		nFields, _ := fmt.Sscanf(line, "%s %d %d %s %s 0x%x",
			&name, &size, &refcount, &dependencies, &state, &address)
		if nFields < 6 {
			return nil, fmt.Errorf("unexpected line in modules: '%s'", line)
		}
		if address == 0 {
			return nil, fmt.Errorf(
				"addresses from modules is zero - "+
					"check process permissions: '%s'", line)
		}

		symmap.Add(libpf.Symbol{
			Name:    libpf.SymbolName(name),
			Address: libpf.SymbolValue(address),
			Size:    int(size),
		})
	}
	symmap.Finalize()

	return &symmap, nil
}

// ListPIDs from the proc filesystem mount point and return a list of util.PID to be processed
func ListPIDs() ([]libpf.PID, error) {
	pids := make([]libpf.PID, 0)
	files, err := os.ReadDir(defaultMountPoint)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		// Make sure this is a PID file entry
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(f.Name(), 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, libpf.PID(pid))
	}
	return pids, nil
}

// IsPIDLive checks if a PID belongs to a live process. It will never produce a false negative but
// may produce a false positive (e.g. due to permissions) in which case an error will also be
// returned.
func IsPIDLive(pid libpf.PID) (bool, error) {
	// A kill syscall with a 0 signal is documented to still do the check
	// whether the process exists: https://linux.die.net/man/2/kill
	err := unix.Kill(int(pid), 0)
	if err == nil {
		return true, nil
	}

	var errno unix.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.ESRCH:
			return false, nil
		case unix.EPERM:
			// continue with procfs fallback
		default:
			return true, err
		}
	}

	path := fmt.Sprintf("%s/%d/maps", defaultMountPoint, pid)
	_, err = os.Stat(path)

	if err != nil && os.IsNotExist(err) {
		return false, nil
	}

	return true, err
}
