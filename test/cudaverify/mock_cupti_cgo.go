//go:build linux

package cudaverify // import "go.opentelemetry.io/ebpf-profiler/test/cudaverify"

/*
#cgo LDFLAGS: -Wl,--export-dynamic -ldl

#include <stdlib.h>
#include <stdint.h>

int  init_parcagpu(const char *so_path);
void simulate_kernel_launch(uint32_t correlation_id);
void simulate_buffer_completion(uint32_t correlation_id, uint32_t device_id,
                                uint32_t stream_id, const char *kernel_name);
void cleanup_parcagpu(void);
*/
import "C"

import "unsafe"

func cInitParcaGPU(soPath string) int {
	cPath := C.CString(soPath)
	defer C.free(unsafe.Pointer(cPath))
	return int(C.init_parcagpu(cPath))
}

func cSimulateKernelLaunch(correlationID uint32) {
	C.simulate_kernel_launch(C.uint32_t(correlationID))
}

func cSimulateBufferCompletion(correlationID, deviceID, streamID uint32, kernelName string) {
	cName := C.CString(kernelName)
	defer C.free(unsafe.Pointer(cName))
	C.simulate_buffer_completion(C.uint32_t(correlationID), C.uint32_t(deviceID),
		C.uint32_t(streamID), cName)
}

func cCleanupParcaGPU() {
	C.cleanup_parcagpu()
}
