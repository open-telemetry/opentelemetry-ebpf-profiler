// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package proc provides functionality for retrieving kallsyms, modules and
// executable mappings via /proc.
package proc // import "go.opentelemetry.io/ebpf-profiler/proc"

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

const defaultMountPoint = "/proc"

// GetKallsyms returns SymbolMap for kernel symbols from /proc/kallsyms.
func GetKallsyms(kallsymsPath string) (*libpf.SymbolMap, error) {
	var address uint64
	var symbol string

	// As an example, the Debian 6.10.11 kernel has ~180k text symbols.
	symmap := libpf.NewSymbolMap(200 * 1024)
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

		// Skip non-text symbols, see 'man nm'.
		// Special case for 'etext', which can be of type `D` (data) in some kernels.
		if strings.IndexByte("TtVvWwA", fields[1][0]) == -1 && fields[2] != "_etext" {
			continue
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

	return symmap, nil
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
		Size:    uint64(etext.Address - stext.Address),
	})

	modules, err := parseKernelModules(bufio.NewScanner(file))
	if err != nil {
		return nil, fmt.Errorf("failed to parse kernel modules: %v", err)
	}

	for _, kmod := range modules {
		symmap.Add(libpf.Symbol{
			Name:    libpf.SymbolName(kmod.name),
			Address: libpf.SymbolValue(kmod.address),
			Size:    kmod.size,
		})
	}

	symmap.Finalize()

	return &symmap, nil
}

func parseKernelModules(scanner *bufio.Scanner) ([]kernelModule, error) {
	var (
		modules                []kernelModule
		atLeastOneValidAddress = false
		count                  = 0
	)

	for scanner.Scan() {
		line := scanner.Text()

		count++

		kmod, err := parseKernelModuleLine(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse kernel module line '%s': %v", line, err)
		}
		if kmod.address == 0 {
			continue
		}
		atLeastOneValidAddress = true

		modules = append(modules, kmod)
	}

	if count > 0 && !atLeastOneValidAddress {
		return nil, errors.New("addresses from all modules is zero - check process permissions")
	}

	return modules, nil
}

type kernelModule struct {
	name    string
	size    uint64
	address uint64
}

func parseKernelModuleLine(line string) (kernelModule, error) {
	// The format is: "name size refcount dependencies state address"
	// The string is split into 7 parts as after address there can be an optional string.
	parts := strings.SplitN(line, " ", 7)
	if len(parts) < 6 {
		return kernelModule{}, fmt.Errorf("unexpected line in modules: '%s'", line)
	}

	size, err := parseSize(parts[1])
	if err != nil {
		return kernelModule{}, err
	}

	address, err := parseAddress(parts[5])
	if err != nil {
		return kernelModule{}, err
	}

	return kernelModule{
		name:    parts[0],
		size:    size,
		address: address,
	}, nil
}

func parseAddress(addressStr string) (uint64, error) {
	address, err := strconv.ParseUint(strings.TrimPrefix(addressStr, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse address '%s' as hex value: %v",
			addressStr, err)
	}

	return address, nil
}

func parseSize(sizeStr string) (uint64, error) {
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size int value: %q: %v", sizeStr, err)
	}

	return size, nil
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
