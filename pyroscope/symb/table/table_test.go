package table

import (
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/ffi"
)

type testRange struct {
	va       uint64
	len      uint64
	depth    uint64
	funcName string
	fileName string

	lines ffi.LineTable
}
type lookupChecks struct {
	addr     uint64
	expected []LookupResult
}

type test struct {
	name        string
	testRanges  []testRange
	checks      []lookupChecks
	extraChecks func(t *testing.T, st *Table)
}

func testDataRanges() []testRange {
	return []testRange{
		{va: 0x1000, len: 0x200, depth: 0, funcName: "outer", fileName: "file1"},
		{va: 0x1050, len: 0x100, depth: 1, funcName: "middle", fileName: "file2"},
		{va: 0x1075, len: 0x50, depth: 2, funcName: "inner", fileName: "file3"},
		{va: 0x2000, len: 0x100, depth: 0, funcName: "func1", fileName: "file4"},
		{va: 0x3000, len: 0x200, depth: 0, funcName: "func2", fileName: "file5"},
		{va: 0x3400, len: 0x100, depth: 0, funcName: "func_with_lines",
			fileName: "file_with_lines", lines: []ffi.LineTableEntry{
				{LineNumber: 4}, {Offset: 3, LineNumber: 9},
			}},
	}
}

func testDataChecks() []lookupChecks {
	return []lookupChecks{
		{addr: 0x0999, expected: nil},
		{addr: 0x1000, expected: []LookupResult{{"outer", "file1", 0}}},
		{addr: 0x1025, expected: []LookupResult{{"outer", "file1", 0}}},
		{addr: 0x1050, expected: []LookupResult{{"middle", "file2", 0},
			{"outer", "file1", 0}}},
		{addr: 0x1074, expected: []LookupResult{{"middle", "file2", 0},
			{"outer", "file1", 0}}},
		{addr: 0x1075, expected: []LookupResult{{"inner", "file3", 0},
			{"middle", "file2", 0}, {"outer", "file1", 0}}},
		{addr: 0x1080, expected: []LookupResult{{"inner", "file3", 0},
			{"middle", "file2", 0}, {"outer", "file1", 0}}},
		{addr: 0x10c4, expected: []LookupResult{{"inner", "file3", 0},
			{"middle", "file2", 0}, {"outer", "file1", 0}}},
		{addr: 0x10c5, expected: []LookupResult{{"middle", "file2", 0},
			{"outer", "file1", 0}}},
		{addr: 0x1149, expected: []LookupResult{{"middle", "file2", 0},
			{"outer", "file1", 0}}},
		{addr: 0x1150, expected: []LookupResult{{"outer", "file1", 0}}},
		{addr: 0x1199, expected: []LookupResult{{"outer", "file1", 0}}},
		{addr: 0x1200, expected: nil},
		{addr: 0x2000, expected: []LookupResult{{"func1", "file4", 0}}},
		{addr: 0x2050, expected: []LookupResult{{"func1", "file4", 0}}},
		{addr: 0x3100, expected: []LookupResult{{"func2", "file5", 0}}},
		{addr: 0x3200, expected: nil},
		{addr: 0x3400, expected: []LookupResult{{"func_with_lines", "file_with_lines", 4}}},
		{addr: 0x3401, expected: []LookupResult{{"func_with_lines", "file_with_lines", 4}}},
		{addr: 0x3402, expected: []LookupResult{{"func_with_lines", "file_with_lines", 4}}},
		{addr: 0x3403, expected: []LookupResult{{"func_with_lines", "file_with_lines", 9}}},
		{addr: 0x34ff, expected: []LookupResult{{"func_with_lines", "file_with_lines", 9}}},
		{addr: 0x3500, expected: nil},
		{addr: 0x4000, expected: nil},
	}
}

var testDataRanges1 = testDataRanges()
var testDataRanges2 = append(testDataRanges(), testRange{
	va: uint64(^uint32(0)) + 1, len: 0x200, depth: 0,
	funcName: "largefunc1", fileName: "largefile1",
	lines: []ffi.LineTableEntry{
		{LineNumber: 4}, {Offset: 3, LineNumber: uint32(^uint16(0)) + 1}},
})

var testDataRanges3 = append(testDataRanges(), testRange{
	va: 0x5000, len: uint64(^uint32(0)) + 1, depth: 0,
	funcName: "largefunc2", fileName: "largefile2",
})

func createTestFile(t testing.TB, ranges []testRange, option ...Option) string {
	path := t.TempDir() + "/test.symb"
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	sb := newStringBuilder()
	rb := newRangesBuilder()
	lb := newLineTableBuilder()

	for _, r := range ranges {
		funcOffset := sb.add(r.funcName)
		fileOffset := sb.add(r.fileName)
		lt := lb.add(r.lines)
		e := rangeEntry{
			length:     r.len,
			depth:      r.depth,
			funcOffset: funcOffset,
			fileOffset: fileOffset,
			lineTable:  lt,
		}
		rb.add(r.va, e)
	}
	o := options{}
	for _, opt := range option {
		opt(&o)
	}
	rc := &rangeCollector{sb: sb, rb: rb, lb: lb, opt: o}
	err = rc.write(file)
	require.NoError(t, err)
	return path
}

func TestSymbTable(t *testing.T) {
	tests := []test{
		{"normal u32", testDataRanges1, testDataChecks(), func(t *testing.T, st *Table) {
			assert.Equal(t, 4, int(st.hdr.vaTableHeader.entrySize))
			assert.Equal(t, 4, int(st.hdr.rangeTableHeader.fieldSize))
			assert.Equal(t, 2, int(st.hdr.lineTablesHeader.fieldSize))
		}},
		{"u64 va", testDataRanges2, append(testDataChecks(), lookupChecks{
			addr: uint64(^uint32(0)) + 1 + 3,
			expected: []LookupResult{
				{"largefunc1", "largefile1", int(uint32(^uint16(0)) + 1)},
			},
		}), func(t *testing.T, st *Table) {
			assert.Equal(t, 8, int(st.hdr.vaTableHeader.entrySize))
			assert.Equal(t, 4, int(st.hdr.rangeTableHeader.fieldSize))
			assert.Equal(t, 4, int(st.hdr.lineTablesHeader.fieldSize))
		}},
		{"u64 fields", testDataRanges3, testDataChecks(), func(t *testing.T, st *Table) {
			assert.Equal(t, 4, int(st.hdr.vaTableHeader.entrySize))
			assert.Equal(t, 8, int(st.hdr.rangeTableHeader.fieldSize))
			assert.Equal(t, 2, int(st.hdr.lineTablesHeader.fieldSize))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := createTestFile(t, tc.testRanges, WithFiles(), WithCRC(), WithLines())
			symtab, err := OpenPath(path, WithFiles(), WithCRC(), WithLines())
			require.NoError(t, err)
			t.Cleanup(func() {
				symtab.Close()
			})

			for _, check := range tc.checks {
				check := check
				t.Run(fmt.Sprintf("fn_%x", check.addr), func(t *testing.T) {
					got, _ := symtab.Lookup(check.addr)
					assert.Equal(t, check.expected, got)
				})
			}
			tc.extraChecks(t, symtab)
		})
	}
}

func TestSymbTabErrors(t *testing.T) {
	_, err := OpenPath("nonexistent")
	require.Error(t, err)

	_, err = OpenPath("")
	require.Error(t, err)
}

func TestSymbTabClose(t *testing.T) {
	path := createTestFile(t, testDataRanges1)

	symtab, err := OpenPath(path)
	require.NoError(t, err)

	symtab.Close()
	symtab.Close()
}

func BenchmarkFindFunc(b *testing.B) {
	path := createTestFile(b, testDataRanges1)

	symtab, err := OpenPath(path)
	require.NoError(b, err)
	defer symtab.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = symtab.Lookup(0x1075) // Test with an inlined function case
		require.NoError(b, err)
	}
}

func TestLibc(t *testing.T) {
	var err error
	libc, err := os.Open("../testdata/64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug")
	require.NoError(t, err)
	t.Cleanup(func() {
		libc.Close()
	})

	tableFile, err := os.Create(t.TempDir() + "/out")
	require.NoError(t, err)
	t.Cleanup(func() {
		tableFile.Close()
	})
	err = FDToTable(libc, tableFile, WithCRC(), WithFiles(), WithLines())
	require.NoError(t, err)

	_, err = tableFile.Seek(0, io.SeekStart)
	require.NoError(t, err)
	table, err := OpenFile(tableFile, WithCRC(), WithFiles(), WithLines())
	require.NoError(t, err)

	testdata := []struct {
		addr     []uint64
		expected []LookupResult
	}{
		{[]uint64{0x9cbb0}, []LookupResult{
			{"__pthread_create_2_1", "./nptl/pthread_create.c", 626},
		}},
		{[]uint64{0x9cbf3}, []LookupResult{
			{"__pthread_create_2_1", "./nptl/pthread_create.c", 632},
		}},
		{[]uint64{0x9d1e0, 0x9d1e7}, []LookupResult{
			{"late_init", "./nptl/pthread_create.c", 83},
			{"__pthread_create_2_1", "./nptl/pthread_create.c", 634},
		}},
		{[]uint64{0x9d1e9}, []LookupResult{
			{"late_init", "./nptl/pthread_create.c", 81},
			{"__pthread_create_2_1", "./nptl/pthread_create.c", 634},
		}},
		{[]uint64{0x9d1f5}, []LookupResult{
			{"__sigemptyset", "../sysdeps/unix/sysv/linux/sigsetops.h", 54},
			{"late_init", "./nptl/pthread_create.c", 75},
			{"__pthread_create_2_1", "./nptl/pthread_create.c", 634},
		}},
		{[]uint64{0x9ca94}, []LookupResult{
			{"start_thread", "./nptl/pthread_create.c", 447}}},
		{[]uint64{0x11ba61}, []LookupResult{
			{"__GI___libc_read", "../sysdeps/unix/sysv/linux/read.c", 26}}},
		{[]uint64{0x18833e}, []LookupResult{
			{"__memcmp_avx2_movbe", "../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S", 136}}},

		{[]uint64{0x129c3c}, []LookupResult{
			{"__clone3", "../sysdeps/unix/sysv/linux/x86_64/clone3.S", 80}}},
		{[]uint64{0x98d61}, []LookupResult{
			{"__futex_abstimed_wait_common64", "./nptl/futex-internal.c", 57},
			{"__futex_abstimed_wait_common", "./nptl/futex-internal.c", 87},
			{"__GI___futex_abstimed_wait_cancelable64", "./nptl/futex-internal.c", 139}}},
		{[]uint64{0x9bc7e}, []LookupResult{
			{"__pthread_cond_wait_common", "./nptl/pthread_cond_wait.c", 506},
			{"___pthread_cond_timedwait64", "./nptl/pthread_cond_wait.c", 652},
		}},
	}

	for _, td := range testdata {
		addr := td.addr
		expected := td.expected
		name := fmt.Sprintf("%s %s %d",
			expected[0].Name, expected[0].File, expected[0].Line)
		t.Run(name, func(t *testing.T) {
			for _, a := range addr {
				t.Run(strconv.FormatUint(a, 16), func(t *testing.T) {
					syms, err := table.Lookup(a)
					require.NoError(t, err)
					assert.NotEmpty(t, syms)
					assert.Equal(t, expected, syms)
				})
			}
		})
	}
}

func BenchmarkLibc(b *testing.B) {
	var err error
	libc, err := os.Open("../testdata/64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug")
	require.NoError(b, err)
	defer libc.Close()

	tableFile, err := os.Create(b.TempDir() + "/out")
	require.NoError(b, err)
	defer tableFile.Close()
	err = FDToTable(libc, tableFile)
	require.NoError(b, err)

	_, err = tableFile.Seek(0, io.SeekStart)
	require.NoError(b, err)
	table, err := OpenFile(tableFile)
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = table.Lookup(0x11ba61)
		_, _ = table.Lookup(0x18833e)
		_, _ = table.Lookup(0x9ca94)
		_, _ = table.Lookup(0x129c3c)
		_, _ = table.Lookup(0x98d61)
		_, _ = table.Lookup(0x9bc7e)
	}
}

func TestSelfAddrLookup(t *testing.T) {
	tests := []struct {
		addr uint64
		name string
	}{
		{
			addr: uint64(reflect.ValueOf(TestSelfAddrLookup).Pointer()),
			name: "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/table.TestSelfAddrLookup",
		},
	}

	exef, err := os.Open("/proc/self/exe")
	require.NoError(t, err)

	dst := t.TempDir() + "/out"
	dstf, err := os.Create(dst)
	require.NoError(t, err)

	err = FDToTable(exef, dstf, WithFiles(), WithLines())
	require.NoError(t, err)
	require.NoError(t, err)

	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)
	defer table.Close()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotEqual(t, uint32(0), test.addr)
			res, _ := table.Lookup(test.addr)
			res[0].File = "" // Don't check file
			expected := []LookupResult{{test.name, "", 0}}
			assert.Equal(t, expected, res)
		})
	}
}

func TestLibcAddrLookup(t *testing.T) {
	dst := "../testdata/libc.gtbl"
	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)

	readelfData, err := os.ReadFile("../testdata/libc_readelf_funcs.txt")
	require.NoError(t, err)
	expectedFuncLines := strings.Split(string(readelfData), "\n")

	checkedAddresses := map[uint64][]string{}
	for _, line := range expectedFuncLines {
		fields := strings.Fields(line)
		if len(fields) != 8 {
			continue
		}
		addr := fields[1]
		name := fields[7]
		iaddr, err := strconv.ParseUint(addr, 16, 64)
		require.NoError(t, err)
		checkedAddresses[iaddr] = append(checkedAddresses[iaddr], name)
		assert.LessOrEqual(t, iaddr, uint64(math.MaxUint32))
	}
	skips := map[uint64]bool{
		0x45320: true,
		0:       true,
	}
	for addr, expectedNames := range checkedAddresses {
		if skips[addr] {
			continue
		}
		t.Run(fmt.Sprintf("%x %+v", addr, expectedNames), func(t *testing.T) {
			res, _ := table.Lookup(addr)
			require.NotEmpty(t, res)
			name := res[len(res)-1].Name
			found := false
			for _, expectedName := range expectedNames {
				if name == expectedName || strings.HasPrefix(expectedName, name) {
					found = true
					break
				}
			}
			assert.True(t, found)
		})
	}
}

func TestHeaderSize(t *testing.T) {
	sz := unsafe.Sizeof(header{})
	assert.Equal(t, int(headerSize), int(sz))
}
