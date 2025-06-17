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

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

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
	expected []samples.SourceInfoFrame
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
		{addr: 0x1000, expected: []samples.SourceInfoFrame{
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1025, expected: []samples.SourceInfoFrame{
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1050, expected: []samples.SourceInfoFrame{
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1074, expected: []samples.SourceInfoFrame{
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1075, expected: []samples.SourceInfoFrame{
			{FunctionName: "inner", FilePath: "file3"},
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1080, expected: []samples.SourceInfoFrame{
			{FunctionName: "inner", FilePath: "file3"},
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x10c4, expected: []samples.SourceInfoFrame{
			{FunctionName: "inner", FilePath: "file3"},
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x10c5, expected: []samples.SourceInfoFrame{
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1149, expected: []samples.SourceInfoFrame{
			{FunctionName: "middle", FilePath: "file2"},
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1150, expected: []samples.SourceInfoFrame{
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1199, expected: []samples.SourceInfoFrame{
			{FunctionName: "outer", FilePath: "file1"}}},
		{addr: 0x1200, expected: nil},
		{addr: 0x2000, expected: []samples.SourceInfoFrame{
			{FunctionName: "func1", FilePath: "file4"}}},
		{addr: 0x2050, expected: []samples.SourceInfoFrame{
			{FunctionName: "func1", FilePath: "file4"}}},
		{addr: 0x3100, expected: []samples.SourceInfoFrame{
			{FunctionName: "func2", FilePath: "file5"}}},
		{addr: 0x3200, expected: nil},
		{addr: 0x3400, expected: []samples.SourceInfoFrame{
			{LineNumber: 4,
				FunctionName: "func_with_lines",
				FilePath:     "file_with_lines"}}},
		{addr: 0x3401, expected: []samples.SourceInfoFrame{
			{LineNumber: 4,
				FunctionName: "func_with_lines",
				FilePath:     "file_with_lines"}}},
		{addr: 0x3402, expected: []samples.SourceInfoFrame{
			{LineNumber: 4,
				FunctionName: "func_with_lines",
				FilePath:     "file_with_lines"}}},
		{addr: 0x3403, expected: []samples.SourceInfoFrame{
			{LineNumber: 9,
				FunctionName: "func_with_lines",
				FilePath:     "file_with_lines"}}},
		{addr: 0x34ff, expected: []samples.SourceInfoFrame{
			{LineNumber: 9,
				FunctionName: "func_with_lines",
				FilePath:     "file_with_lines"}}},
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
		{name: "u64 va", testRanges: testDataRanges2, checks: append(testDataChecks(), lookupChecks{
			addr: uint64(^uint32(0)) + 1 + 3,
			expected: []samples.SourceInfoFrame{
				{LineNumber: libpf.SourceLineno(int64(uint32(^uint16(0)) + 1)),
					FunctionName: "largefunc1", FilePath: "largefile1"},
			},
		}), extraChecks: func(t *testing.T, st *Table) {
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
		_ = libc.Close()
	})

	tableFile, err := os.Create(t.TempDir() + "/out")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = tableFile.Close()
	})
	err = FDToTable(libc, tableFile, WithCRC(), WithFiles(), WithLines())
	require.NoError(t, err)

	_, err = tableFile.Seek(0, io.SeekStart)
	require.NoError(t, err)
	table, err := OpenFile(tableFile, WithCRC(), WithFiles(), WithLines())
	require.NoError(t, err)

	testdata := []struct {
		addr     []uint64
		expected []samples.SourceInfoFrame
	}{
		{addr: []uint64{0x9cbb0}, expected: []samples.SourceInfoFrame{
			{LineNumber: 626,
				FunctionName: "__pthread_create_2_1",
				FilePath:     "./nptl/pthread_create.c"},
		}},
		{addr: []uint64{0x9cbf3}, expected: []samples.SourceInfoFrame{
			{LineNumber: 632,
				FunctionName: "__pthread_create_2_1",
				FilePath:     "./nptl/pthread_create.c"},
		}},
		{addr: []uint64{0x9d1e0, 0x9d1e7}, expected: []samples.SourceInfoFrame{
			{LineNumber: 83,
				FunctionName: "late_init",
				FilePath:     "./nptl/pthread_create.c"},
			{LineNumber: 634,
				FunctionName: "__pthread_create_2_1",
				FilePath:     "./nptl/pthread_create.c"},
		}},
		{addr: []uint64{0x9d1e9}, expected: []samples.SourceInfoFrame{
			{LineNumber: 81,
				FunctionName: "late_init",
				FilePath:     "./nptl/pthread_create.c"},
			{LineNumber: 634,
				FunctionName: "__pthread_create_2_1",
				FilePath:     "./nptl/pthread_create.c"},
		}},
		{addr: []uint64{0x9d1f5}, expected: []samples.SourceInfoFrame{
			{LineNumber: 54,
				FunctionName: "__sigemptyset",
				FilePath:     "../sysdeps/unix/sysv/linux/sigsetops.h"},
			{LineNumber: 75,
				FunctionName: "late_init",
				FilePath:     "./nptl/pthread_create.c"},
			{LineNumber: 634,
				FunctionName: "__pthread_create_2_1",
				FilePath:     "./nptl/pthread_create.c"},
		}},
		{addr: []uint64{0x9ca94}, expected: []samples.SourceInfoFrame{
			{LineNumber: 447,
				FunctionName: "start_thread",
				FilePath:     "./nptl/pthread_create.c"}}},
		{addr: []uint64{0x11ba61}, expected: []samples.SourceInfoFrame{
			{LineNumber: 26,
				FunctionName: "__GI___libc_read",
				FilePath:     "../sysdeps/unix/sysv/linux/read.c"}}},
		{addr: []uint64{0x18833e}, expected: []samples.SourceInfoFrame{
			{LineNumber: 136,
				FunctionName: "__memcmp_avx2_movbe",
				FilePath:     "../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S"}}},

		{addr: []uint64{0x129c3c}, expected: []samples.SourceInfoFrame{
			{LineNumber: 80,
				FunctionName: "__clone3",
				FilePath:     "../sysdeps/unix/sysv/linux/x86_64/clone3.S"}}},
		{addr: []uint64{0x98d61}, expected: []samples.SourceInfoFrame{
			{LineNumber: 57,
				FunctionName: "__futex_abstimed_wait_common64",
				FilePath:     "./nptl/futex-internal.c"},
			{LineNumber: 87,
				FunctionName: "__futex_abstimed_wait_common",
				FilePath:     "./nptl/futex-internal.c"},
			{LineNumber: 139,
				FunctionName: "__GI___futex_abstimed_wait_cancelable64",
				FilePath:     "./nptl/futex-internal.c"}}},
		{addr: []uint64{0x9bc7e}, expected: []samples.SourceInfoFrame{
			{LineNumber: 506,
				FunctionName: "__pthread_cond_wait_common",
				FilePath:     "./nptl/pthread_cond_wait.c"},
			{LineNumber: 652,
				FunctionName: "___pthread_cond_timedwait64",
				FilePath:     "./nptl/pthread_cond_wait.c"},
		}},
	}

	for _, td := range testdata {
		addr := td.addr
		expected := td.expected
		name := fmt.Sprintf("%s %s %d",
			expected[0].FunctionName, expected[0].FilePath, expected[0].LineNumber)
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
			res[0].FilePath = "" // Don't check file
			expected := []samples.SourceInfoFrame{{
				FunctionName: test.name}}
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
			name := res[len(res)-1].FunctionName
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
