package mmap_test

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"
)

func TestMmap_Subslice(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), t.Name()+".testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// Write some testData into the file.
	testData := "data-for-the-test"
	fmt.Fprintf(f, "%s", testData)

	mf, err := mmap.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()

	t.Run("invalid subslice", func(t *testing.T) {
		// Try to access data out of scope from the data
		// in the backing file.
		_, err := mf.Subslice(1024, 1024)
		if !errors.Is(err, mmap.ErrInvalRequest) {
			t.Fatalf("expected %v but got %v", mmap.ErrInvalRequest, err)
		}
	})

	t.Run("valid subslice", func(t *testing.T) {
		// Try to access data out within the scope of
		// len(testData).
		res, err := mf.Subslice(9, 8)
		if err != nil {
			t.Fatalf("expected no error but got %v", err)
		}
		if string(res) != testData[9:] {
			t.Fatalf("expected '%s' but got '%s'", testData[9:], string(res))
		}
	})
}
