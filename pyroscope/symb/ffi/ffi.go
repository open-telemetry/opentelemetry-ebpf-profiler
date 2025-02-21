package ffi

/*
#cgo CFLAGS: -g -Wall
#include "symblib.h"
#include <stdlib.h>
// inc-4

// Declare wrapper functions for linking.
SymblibStatus rangeVisitorWrapper(void* user_data, SymblibRange* range);
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

func symlibError(c C.SymblibStatus) error {
	switch c {
	case C.SymblibStatus(0):
		return errors.New("OK: not actually an error")
	case C.SymblibStatus(1):
		return errors.New("IO error")
	case C.SymblibStatus(2):
		return errors.New("IO error: file not found")
	case C.SymblibStatus(3):
		return errors.New("object file reading error")
	case C.SymblibStatus(4):
		return errors.New("DWARF reading error")
	case C.SymblibStatus(5):
		return errors.New("symbol conversion error")
	case C.SymblibStatus(6):
		return errors.New("return pad extraction error")
	case C.SymblibStatus(7):
		return errors.New("invalid UTF-8")
	case C.SymblibStatus(8):
		return errors.New("the channel was already closed in a previous call")
	default:
		return fmt.Errorf("unknown error code: %v", c)
	}
}

type rangeExtractor struct {
	v Visitor
}

//export rangeVisitorWrapper
func rangeVisitorWrapper(userData unsafe.Pointer, rangePtr *C.SymblibRange) C.SymblibStatus {
	e := (*rangeExtractor)(userData)
	elfVA := uint64(rangePtr.elf_va)
	length := uint32(rangePtr.length)
	function := C.GoString(rangePtr._func)
	e.v.VisitRange(elfVA, length, uint32(rangePtr.depth), function)

	return 0
}

type Visitor interface {
	VisitRange(va uint64, length uint32, depth uint32, function string)
}

func RangeExtractor(f *os.File, v Visitor) error {
	ctx := new(rangeExtractor)
	ctx.v = v
	var p runtime.Pinner
	p.Pin(ctx.v)
	defer p.Unpin()
	status := C.symblib_rangeextr(
		C.int(f.Fd()),
		C.int(-1),
		C.SymblibRangeVisitor(C.rangeVisitorWrapper),
		unsafe.Pointer(ctx),
	)
	if status != 0 {
		return symlibError(C.SymblibStatus(status))
	}
	return nil
}
