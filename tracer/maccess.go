// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"errors"
	"fmt"
	"runtime"

	cebpf "github.com/cilium/ebpf"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/maccess"
)

// checkForMmaccessPatch validates if a Linux kernel function is patched by
// extracting the kernel code of the function and analyzing it.
func checkForMaccessPatch(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kernelSymbols *libpf.SymbolMap) error {
	faultyFunc, err := kernelSymbols.LookupSymbol(
		libpf.SymbolName("copy_from_user_nofault"))
	if err != nil {
		return fmt.Errorf("failed to look up Linux kernel symbol "+
			"'copy_from_user_nofault': %v", err)
	}

	code, err := loadKernelCode(coll, maps, faultyFunc.Address)
	if err != nil {
		return fmt.Errorf("failed to load kernel code for %s: %v", faultyFunc.Name, err)
	}

	newCheckFunc, err := kernelSymbols.LookupSymbol(
		libpf.SymbolName("nmi_uaccess_okay"))
	if err != nil {
		//nolint:goconst
		if runtime.GOARCH == "arm64" {
			// On arm64 this symbol might not be available and we do not use
			// the symbol address in the arm64 case to check for the patch.
			// As there was an error getting the symbol, newCheckFunc is nil.
			// To still be able to access newCheckFunc safely, create a dummy element.
			newCheckFunc = &libpf.Symbol{
				Address: 0,
			}
		} else {
			// Without the symbol information, we can not continue with checking the
			// function and determine whether it got patched.
			return fmt.Errorf("failed to look up Linux kernel symbol 'nmi_uaccess_okay': %v", err)
		}
	}

	patched, err := maccess.CopyFromUserNoFaultIsPatched(code, uint64(faultyFunc.Address),
		uint64(newCheckFunc.Address))
	if err != nil {
		return fmt.Errorf("failed to check if %s is patched: %v", faultyFunc.Name, err)
	}
	if !patched {
		return errors.New("kernel is not patched")
	}
	return nil
}
