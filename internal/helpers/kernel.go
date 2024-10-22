package helpers // import "go.opentelemetry.io/ebpf-profiler/internal/helpers"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// GetKernelVersion returns the current version of the kernel
func GetKernelVersion() (string, error) {
	major, minor, patch, err := tracer.GetCurrentKernelVersion()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
}
