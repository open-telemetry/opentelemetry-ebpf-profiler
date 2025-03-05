package controller

import (
	"flag"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
)

func RegisterPyroscopeFlags(fs *flag.FlagSet, args *controller.Config) {
	fs.BoolVar(&args.SymbolizeNativeFrames, "pyroscope-symbolize-native-frames", true, "")
	fs.IntVar(
		&args.SymbCacheSizeBytes,
		"pyroscope-symb-cache-size-bytes",
		2*1024*1024*1024,
		"",
	)
	fs.StringVar(&args.SymbCachePath, "pyroscope-symb-cache-path", "/tmp/symb-cache", "")
}
