package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"fmt"
	"time"

	"github.com/tklauser/numcpus"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// TraceCacheSize defines the maximum number of elements for the caches in tracehandler.
// The caches in tracehandler have a size-"processing overhead" trade-off: Every cache miss will
// trigger additional processing for that trace in userspace (Go). For most maps, we use
// maxElementsPerInterval as a base sizing factor. For the tracehandler caches, we also multiply
// with traceCacheIntervals. For typical/small values of maxElementsPerInterval, this can lead to
// non-optimal map sizing (reduced cache_hit:cache_miss ratio and increased processing overhead).
// Simply increasing traceCacheIntervals is problematic when maxElementsPerInterval is large
// (e.g. too many CPU cores present) as we end up using too much memory. A minimum size is
// therefore used here.
func TraceCacheSize(monitorInterval time.Duration, samplesPerSecond int) (uint32, error) {
	const (
		traceCacheIntervals = 6
		traceCacheMinSize   = 65536
	)

	presentCores, err := numcpus.GetPresent()
	if err != nil {
		return 0, fmt.Errorf("failed to read CPU file: %w", err)
	}

	maxElements := maxElementsPerInterval(monitorInterval, samplesPerSecond, uint16(presentCores))

	size := maxElements * uint32(traceCacheIntervals)
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return util.NextPowerOfTwo(size), nil
}
