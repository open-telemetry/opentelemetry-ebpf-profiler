/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hotspot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/freelru"
	"github.com/elastic/otel-profiling-agent/libpf/remotememory"
	"github.com/elastic/otel-profiling-agent/lpm"
)

func TestJavaDemangling(t *testing.T) {
	cases := []struct {
		klass, method, signature, demangled string
	}{
		{"java/lang/Object", "<init>", "()V",
			"void java.lang.Object.<init>()"},
		{"java/lang/StringLatin1", "equals", "([B[B)Z",
			"boolean java.lang.StringLatin1.equals(byte[], byte[])"},
		{"java/util/zip/ZipUtils", "CENSIZ", "([BI)J",
			"long java.util.zip.ZipUtils.CENSIZ(byte[], int)"},
		{"java/util/regex/Pattern$BmpCharProperty", "match",
			"(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z",
			"boolean java.util.regex.Pattern$BmpCharProperty.match" +
				"(java.util.regex.Matcher, int, java.lang.CharSequence)"},
		{"java/lang/AbstractStringBuilder", "appendChars", "(Ljava/lang/String;II)V",
			"void java.lang.AbstractStringBuilder.appendChars" +
				"(java.lang.String, int, int)"},
		{"foo/test", "bar", "([)J", "long foo.test.bar()"},
	}

	for _, c := range cases {
		demangled := demangleJavaMethod(c.klass, c.method, c.signature)
		if demangled != c.demangled {
			t.Errorf("signature '%s' != '%s'", demangled, c.demangled)
		}
	}
}

// TestJavaLineNumbers tests that the Hotspot delta encoded line table decoding works.
// The set here is an actually table extracting from JVM. It is fairly easy to encode
// these numbers if needed, but we don't need to generate them currently for anything.
func TestJavaLineNumbers(t *testing.T) {
	bciLine := []struct {
		bci, line uint32
	}{
		{0, 478},
		{5, 479},
		{9, 480},
		{19, 481},
		{26, 482},
		{33, 483},
		{47, 490},
		{50, 485},
		{52, 486},
		{58, 490},
		{61, 488},
		{63, 489},
		{68, 491},
	}

	decoder := unsigned5Decoder{
		r: bytes.NewReader([]byte{
			255, 0, 252, 11, 41, 33, 81, 57, 57, 119,
			255, 6, 9, 17, 52, 255, 6, 3, 17, 42, 0}),
	}

	var bci, line uint32
	for i := 0; i < len(bciLine); i++ {
		if err := decoder.decodeLineTableEntry(&bci, &line); err != nil {
			t.Fatalf("line table decoding failed: %v", err)
		}
		if bciLine[i].bci != bci || bciLine[i].line != line {
			t.Fatalf("{%v,%v} != {%v,%v}\n", bci, line, bciLine[i].bci, bciLine[i].line)
		}
	}
	if err := decoder.decodeLineTableEntry(&bci, &line); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("compressed data has more entries than expected")
		}
		t.Fatalf("line table not empty at end: %v", err)
	}
}

func TestJavaSymbolExtraction(t *testing.T) {
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(os.Getpid()))
	id := hotspotData{}
	vmd, _ := id.GetOrInit(func() (hotspotVMData, error) {
		vmd := hotspotVMData{}
		vmd.vmStructs.Symbol.Length = 2
		vmd.vmStructs.Symbol.Body = 4
		return vmd, nil
	})

	addrToSymbol, err := freelru.New[libpf.Address, string](2, libpf.Address.Hash32)
	if err != nil {
		t.Fatalf("symbol cache lru: %v", err)
	}
	ii := hotspotInstance{
		d:            &id,
		rm:           rm,
		addrToSymbol: addrToSymbol,
		prefixes:     libpf.Set[lpm.Prefix]{},
		stubs:        map[libpf.Address]StubRoutine{},
	}
	maxLength := 1024
	sym := make([]byte, vmd.vmStructs.Symbol.Body+uint(maxLength))
	str := strings.Repeat("a", maxLength)
	copy(sym[vmd.vmStructs.Symbol.Body:], str)
	for i := 0; i <= maxLength; i++ {
		binary.LittleEndian.PutUint16(sym[vmd.vmStructs.Symbol.Length:], uint16(i))
		address := libpf.Address(uintptr(unsafe.Pointer(&sym[0])))
		got := ii.getSymbol(address)
		if str[:i] != got {
			t.Errorf("sym '%s' != '%s'", str[:i], got)
		}
		ii.addrToSymbol.Purge()
	}
}
