package ffi

/*
#cgo CFLAGS: -g -Wall
#include "symblib.h"
#include <stdlib.h>
// inc-5

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

	// link to symblib
	_ "go.opentelemetry.io/ebpf-profiler/interpreter/go/link" // link to symblib
)

func symlibError(c C.SymblibStatus) error {
	switch c {
	case C.SymblibStatus(C.Ok):
		return errors.New("OK: not actually an error")
	case C.SymblibStatus(C.IoMisc):
		return errors.New("IO error")
	case C.SymblibStatus(C.IoFileNotFound):
		return errors.New("IO error: file not found")
	case C.SymblibStatus(C.Objfile):
		return errors.New("object file reading error")
	case C.SymblibStatus(C.Dwarf):
		return errors.New("DWARF reading error")
	case C.SymblibStatus(C.Symbconv):
		return errors.New("symbol conversion error")
	case C.SymblibStatus(C.Retpad):
		return errors.New("return pad extraction error")
	case C.SymblibStatus(C.BadUtf8):
		return errors.New("invalid UTF-8")
	case C.SymblibStatus(C.AlreadyClosed):
		return errors.New("the channel was already closed in a previous call")
	default:
		return fmt.Errorf("unknown error code: %v", c)
	}
}

type rangeExtractor struct {
	v Visitor
}

type LineTableEntry struct {
	Offset     uint32
	LineNumber uint32
}
type LineTable []LineTableEntry

type GoRange struct {
	VA        uint64
	Length    uint32
	Function  string
	File      string
	CallFile  string
	CallLine  uint32
	Depth     uint32
	LineTable LineTable
}

//export rangeVisitorWrapper
func rangeVisitorWrapper(userData unsafe.Pointer, rangePtr *C.SymblibRange) C.SymblibStatus {
	e := (*rangeExtractor)(userData)
	elfVA := uint64(rangePtr.elf_va)
	length := uint32(rangePtr.length)
	file := C.GoString(rangePtr.file)
	callFile := C.GoString(rangePtr.call_file)
	callLine := uint32(rangePtr.call_line)
	function := C.GoString(rangePtr._func)
	depth := uint32(rangePtr.depth)
	var lines LineTable
	if rangePtr.line_table.data != nil {
		lines = unsafe.Slice(
			(*LineTableEntry)(unsafe.Pointer(rangePtr.line_table.data)),
			int(rangePtr.line_table.len),
		)
	}
	rr := GoRange{
		VA:        elfVA,
		Length:    length,
		Function:  function,
		File:      file,
		CallFile:  callFile,
		CallLine:  callLine,
		Depth:     depth,
		LineTable: lines,
	}
	e.v.VisitRange(&rr)

	return 0
}

type Visitor interface {
	VisitRange(r *GoRange)
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
