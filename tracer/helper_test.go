package tracer

import (
	"strings"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/support"
	"golang.org/x/sys/unix"
)

func TestReadCPURange(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []int
	}{
		"mixed": {
			input:    "0,3-6,8-11",
			expected: []int{0, 3, 4, 5, 6, 8, 9, 10, 11},
		},
		"all": {
			input:    "0-7",
			expected: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
		"empty": {
			input:    "",
			expected: []int{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ReadCPURange(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestIntersectCPURanges(t *testing.T) {
	tests := map[string]struct {
		online   []int
		enabled  []int
		expected []int
		wantErr  bool
	}{
		"all": {
			online:   []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			enabled:  []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			expected: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			wantErr:  false,
		},
		"partial intersection": {
			online:   []int{0, 2, 4, 6, 8},
			enabled:  []int{0, 1, 2, 3, 4},
			expected: []int{0, 2, 4},
			wantErr:  false,
		},
		"empty intersection": {
			online:   []int{0, 2, 4, 6, 8},
			enabled:  []int{1, 3, 5, 7, 9},
			expected: nil,
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := intersectCPURanges(tc.online, tc.enabled)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, got)
			}
		})
	}
}

func TestDisableVMAHelperCalls(t *testing.T) {
	findVMA := asm.FnFindVma.Call().WithSymbol("find_vma")
	getTask := asm.FnGetCurrentTaskBtf.Call()
	findVMACallback := asm.Instruction{
		OpCode:   asm.LoadImmOp(asm.DWord),
		Dst:      asm.R3,
		Src:      asm.PseudoFunc,
		Constant: -1,
	}.WithReference("find_vma_callback.linked")
	keep := btf.WithFuncMetadata(asm.FnMapLookupElem.Call().WithSource(asm.Comment("keep")),
		&btf.Func{Name: "prog"})
	otherKeep := btf.WithFuncMetadata(asm.FnMapLookupElem.Call().WithSource(asm.Comment("other")),
		&btf.Func{Name: "other"})
	findVMACallbackBody := btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).
		WithSymbol("find_vma_callback.linked"), &btf.Func{Name: "find_vma_callback.linked"})

	coll := &cebpf.CollectionSpec{
		Programs: map[string]*cebpf.ProgramSpec{
			"prog": {
				Instructions: asm.Instructions{
					keep,
					findVMACallback,
					findVMA,
					getTask,
					findVMACallbackBody,
					asm.Return(),
				},
			},
			"other": {
				Instructions: asm.Instructions{
					otherKeep,
				},
			},
		},
	}

	require.Equal(t, 3, disableVMAHelperCalls(coll))
	require.Equal(t, asm.FnMapLookupElem.Call(), coll.Programs["prog"].Instructions[0])
	require.Nil(t, btf.FuncMetadata(&coll.Programs["prog"].Instructions[0]))
	require.Nil(t, coll.Programs["prog"].Instructions[0].Source())
	require.Equal(t, asm.LoadImm(asm.R3, 0, asm.DWord), coll.Programs["prog"].Instructions[1])
	require.Equal(t, asm.Mov.Imm(asm.R0, -int32(unix.ENOTSUP)).WithMetadata(findVMA.Metadata),
		coll.Programs["prog"].Instructions[2])
	require.Equal(t, asm.Mov.Imm(asm.R0, 0), coll.Programs["prog"].Instructions[3])
	require.Len(t, coll.Programs["prog"].Instructions, 4)
	require.Equal(t, otherKeep, coll.Programs["other"].Instructions[0])
}

func TestDisableVMAHelperCallsOnEmbeddedCollection(t *testing.T) {
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	require.NotZero(t, disableVMAHelperCalls(coll))
	for progName, progSpec := range coll.Programs {
		for i := range progSpec.Instructions {
			ins := &progSpec.Instructions[i]
			require.Falsef(t, ins.IsLoadOfFunctionPointer() &&
				strings.HasPrefix(ins.Reference(), "find_vma_callback"),
				"%s still references find_vma_callback at instruction %d", progName, i)
			require.Falsef(t, strings.HasPrefix(ins.Symbol(), "find_vma_callback"),
				"%s still contains find_vma_callback subprogram at instruction %d", progName, i)
			if !ins.IsBuiltinCall() {
				continue
			}
			require.NotEqualf(t, asm.FnGetCurrentTaskBtf, asm.BuiltinFunc(ins.Constant),
				"%s still calls bpf_get_current_task_btf at instruction %d", progName, i)
			require.NotEqualf(t, asm.FnFindVma, asm.BuiltinFunc(ins.Constant),
				"%s still calls bpf_find_vma at instruction %d", progName, i)
		}
	}
}
