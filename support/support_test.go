package support

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestSizeOfCGoStruct(t *testing.T) {
	tests := []struct {
		// Name of Go wrapper struct
		name  string
		input uintptr
		want  uintptr
	}{
		{name: "ApmIntProcInfo", input: unsafe.Sizeof(ApmIntProcInfo{}),
			want: sizeof_ApmIntProcInfo},
		{name: "DotnetProcInfo", input: unsafe.Sizeof(DotnetProcInfo{}),
			want: sizeof_DotnetProcInfo},
		{name: "PHPProcInfo", input: unsafe.Sizeof(PHPProcInfo{}),
			want: sizeof_PHPProcInfo},
		{name: "RubyProcInfo", input: unsafe.Sizeof(RubyProcInfo{}),
			want: sizeof_RubyProcInfo},
		{name: "ThreadContextProcInfo", input: unsafe.Sizeof(ThreadContextProcInfo{}),
			want: sizeof_ThreadContextProcInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equalf(t, tt.want, tt.input,
				"unsafe.Sizeof(%v{}) = %v, want %v", tt.name, tt.input, tt.want)
		})
	}
}

// TestCustomLabelsUnionLayout guards the unsafe.Pointer reinterpret of
// Trace.Custom_labels_data as CustomLabelsArray (tracer/tracer.go). The C side
// asserts the same size equality, but only when types.h is compiled, so keep a
// Go-side check that runs in make test.
func TestCustomLabelsUnionLayout(t *testing.T) {
	require.Zero(t,
		unsafe.Offsetof(Trace{}.Custom_labels_data)%unsafe.Alignof(CustomLabelsArray{}),
		"Trace.Custom_labels_data is not aligned for CustomLabelsArray")
	// The cast reads a whole CustomLabelsArray out of the field, so it must not
	// be the smaller of the two.
	require.Equal(t,
		unsafe.Sizeof(CustomLabelsData{}), unsafe.Sizeof(CustomLabelsArray{}),
		"CustomLabelsData and CustomLabelsArray must be the same size")
}
