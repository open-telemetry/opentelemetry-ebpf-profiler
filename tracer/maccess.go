/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

import (
	"runtime"

	cebpf "github.com/cilium/ebpf"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/maccess"
	log "github.com/sirupsen/logrus"
)

// checkForMmaccessPatch validates if a Linux kernel function is patched by
// extracting the kernel code of the function and analyzing it.
func checkForMaccessPatch(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kernelSymbols *libpf.SymbolMap) bool {
	faultyFunc, err := kernelSymbols.LookupSymbol(
		libpf.SymbolName("copy_from_user_nofault"))
	if err != nil {
		log.Warnf("Failed to look up Linux kernel symbol "+
			"'copy_from_user_nofault': %v", err)
		return false
	}

	code, err := loadKernelCode(coll, maps, faultyFunc.Address)
	if err != nil {
		log.Warnf("Failed to load code for %s: %v", faultyFunc.Name, err)
		return false
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
			log.Warnf("Failed to look up Linux kernel symbol 'nmi_uaccess_okay': %v",
				err)

			// Without the symbol information, we can not continue with checking the
			// function and determine whether it got patched.
			return false
		}
	}

	patched, err := maccess.CopyFromUserNoFaultIsPatched(code, uint64(faultyFunc.Address),
		uint64(newCheckFunc.Address))
	if err != nil {
		log.Warnf("Failed to check if %s is patched: %v", faultyFunc.Name, err)
		return false
	}
	return patched
}
