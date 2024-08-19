package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

func main() {
	err := mainWithError()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func mainWithError() error {
	args, err := parseArgs()
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %v", err)
	}

	if err = args.SanityCheck(); err != nil {
		return err
	}

	summary, err := benchmark(args.inputDir)
	if err != nil {
		return fmt.Errorf("benchmark failed: %v", err)
	}

	switch filepath.Ext(args.outputFile) {
	case ".csv":
		if err = summary.toCSV(args.outputFile); err != nil {
			return fmt.Errorf("failed to generate bar chart: %v", err)
		}
	case ".png":
		if err = summary.toBarChart(args.outputFile); err != nil {
			return fmt.Errorf("failed to generate bar chart: %v", err)
		}
	default:
		summary.printCSV()
	}

	return nil
}

func benchmark(inputDir string) (*benchSummary, error) {
	// scan directory for files
	files, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %v", inputDir, err)
	}

	summary := &benchSummary{
		totalFiles: len(files),
		results:    make([]benchResult, 0, len(compressors)+1),
	}

	totalUncompressed, maxSize := sumFileSizes(files)
	summary.totalUncompressed = totalUncompressed

	// pre-allocate buffer for compressed data to avoid reallocations
	var buf = bytes.NewBuffer(make([]byte, 0, maxSize))

	// Warm-up
	_, _ = compressFiles(noneCompressor{name: "none"}, files, inputDir, buf)

	baseUsage := int64(0)
	for _, c := range compressors {
		var compressed int64

		cpuUsage := getCPUUsage(func() {
			compressed, err = compressFiles(c, files, inputDir, buf)
		})

		if err != nil {
			return nil, fmt.Errorf("compression failed: %v", err)
		}

		summary.results = append(summary.results, benchResult{
			name:            c.id(),
			totalCompressed: compressed,
			cpuUsage:        cpuUsage - baseUsage,
		})

		if baseUsage == 0 {
			// The CPU usage of the noneCompressor is used as the base usage for all compressors.
			baseUsage = cpuUsage
		}
	}

	return summary, nil
}

func getCPUUsage(f func()) int64 {
	start := getCPUTime()
	f()
	return getCPUTime() - start
}

func getCPUTime() int64 {
	usage := new(syscall.Rusage)
	err := syscall.Getrusage(syscall.RUSAGE_SELF, usage)
	if err != nil {
		panic(fmt.Errorf("failed to get CPU usage: %v", err))
	}
	return usage.Utime.Nano() + usage.Stime.Nano()
}

func sumFileSizes(files []os.DirEntry) (total, maxSize int64) {
	for _, f := range files {
		if fi, err := f.Info(); err == nil {
			total += fi.Size()
			maxSize = max(maxSize, fi.Size())
		}
	}
	return
}

func compressFiles(c compressor, files []os.DirEntry, benchProtoDir string,
	buf *bytes.Buffer) (int64, error) {
	var totalCompressed int64
	for _, f := range files {
		pathName := filepath.Join(benchProtoDir, f.Name())

		// read file contents
		content, err := os.ReadFile(pathName)
		if err != nil {
			return 0, fmt.Errorf("failed to read file %s: %v", pathName, err)
		}

		buf.Reset()

		// compress content with compressor to memory
		compressed, err := c.compress(content, buf)
		if err != nil {
			return 0, fmt.Errorf("failed to compress file %s with %s: %v",
				pathName, c.id(), err)
		}

		totalCompressed += compressed
	}
	return totalCompressed, nil
}

var compressors = []compressor{
	noneCompressor{name: "none"},
	gzipCompressor{name: "gzip.BestSpeed", level: gzip.BestSpeed},
	gzipCompressor{name: "gzip.BestCompression", level: gzip.BestCompression},
	zstdCompressor{name: "zstd.SpeedFastest", level: zstd.SpeedFastest},
	zstdCompressor{name: "zstd.SpeedDefault", level: zstd.SpeedDefault},
	zstdCompressor{name: "zstd.SpeedBetterCompression", level: zstd.SpeedBetterCompression},
	brotliCompressor{name: "brotli.BestSpeed", level: brotli.BestSpeed},
	brotliCompressor{name: "brotli.DefaultCompression", level: brotli.DefaultCompression},
	// Removed due to extremely high CPU usage.
	//	brotliCompressor{name: "brotli.BestCompression", level: brotli.BestCompression},
	s2Compressor{name: "s2.WriterBetterCompression", level: s2.WriterBetterCompression()},
	s2Compressor{name: "s2.WriterBestCompression", level: s2.WriterBestCompression()},
	lz4Compressor{name: "lz4.Level1", level: lz4.Level1},
	lz4Compressor{name: "lz4.Level6", level: lz4.Level6},
	lz4Compressor{name: "lz4.Level9", level: lz4.Level9},
}
