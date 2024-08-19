package benchreporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
)

type fileInfo struct {
	name      string
	timestamp int64
	id        uint64
	funcName  string
}

// Replay replays the stored data from benchDataDir.
// The argument r is the reporter that will receive the replayed data.
func Replay(ctx context.Context, benchDataDir string, rep reporter.Reporter) error {
	files, err := os.ReadDir(benchDataDir)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %v", benchDataDir, err)
	}

	fileInfos := make([]fileInfo, 0, len(files))

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}

		name := f.Name()
		// scan name for timestamp, counter and function name
		var timestamp int64
		var id uint64
		var funcName string
		if _, err = fmt.Sscanf(name, "%d_%x_%s", &timestamp, &id, &funcName); err != nil {
			log.Errorf("Failed to parse file name %s: %v", name, err)
			continue
		}
		funcName = strings.TrimSuffix(funcName, ".json")

		fileInfos = append(fileInfos, fileInfo{
			name:      name,
			timestamp: timestamp,
			id:        id,
			funcName:  funcName,
		})
	}

	if len(fileInfos) == 0 {
		return nil
	}

	// Sort fileInfos ascending by ID.
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].id < fileInfos[j].id
	})

	if fileInfos[0].funcName != "Start" {
		return fmt.Errorf("first function name must be \"Start\", instead it is \"%s\"",
			fileInfos[0].funcName)
	}

	curTS := fileInfos[0].timestamp

	// Replay the stored data
	for _, fi := range fileInfos[1:] {
		time.Sleep(time.Duration(fi.timestamp-curTS) * time.Nanosecond)
		curTS = fi.timestamp

		switch fi.funcName {
		case "TraceEvent":
			var v traceEvent
			if err = dataFromFileInfo(benchDataDir, fi, &v); err == nil {
				rep.ReportTraceEvent(v.Trace, v.Meta)
			}
		case "CountForTrace":
			var v countForTrace
			if err = dataFromFileInfo(benchDataDir, fi, &v); err == nil {
				rep.ReportCountForTrace(v.TraceHash, v.Count, v.Meta)
			}
		case "FramesForTrace":
			var v libpf.Trace
			if err = dataFromFileInfo[libpf.Trace](benchDataDir, fi, &v); err == nil {
				rep.ReportFramesForTrace(&v)
			}
		case "FallbackSymbol":
			var v fallbackSymbol
			if err = dataFromFileInfo(benchDataDir, fi, &v); err == nil {
				rep.ReportFallbackSymbol(v.FrameID, v.Symbol)
			}
		case "ExectableMetadata":
			var v executableMetadata
			if err = dataFromFileInfo(benchDataDir, fi, &v); err == nil {
				rep.ExecutableMetadata(context.Background(), v.FileID, v.FileName, v.BuildID,
					v.Interp, nil)
			}
		case "FrameMetadata":
			var v frameMetadata
			if err = dataFromFileInfo(benchDataDir, fi, &v); err == nil {
				rep.FrameMetadata(v.FileID, v.AddressOrLine, v.LineNumber, v.FunctionOffset,
					v.FunctionName, v.FilePath)
			}
		case "HostMetadata":
			var v hostMetadata
			if err = dataFromFileInfo(benchDataDir, fi, &v); err == nil {
				rep.ReportHostMetadata(v.Metadata)
			}
		case "Metrics":
			var v metrics
			if err = dataFromFileInfo[metrics](benchDataDir, fi, &v); err == nil {
				rep.ReportMetrics(v.Timestamp, v.IDs, v.Values)
			}
		default:
			err = fmt.Errorf("unsupported function name in file %s: %s", fi.name, fi.funcName)
		}

		if err != nil {
			log.Errorf("Failed to replay data from file %s: %v", fi.name, err)
		}

		if err = ctx.Err(); err != nil {
			return err
		}
	}

	return nil
}

func dataFromFileInfo[T any](dir string, fi fileInfo, data *T) error {
	pathName := filepath.Join(dir, fi.name)
	f, err := os.Open(pathName)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", pathName, err)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(data); err != nil {
		return fmt.Errorf("failed to decode JSON from file %s: %v", pathName, err)
	}

	return nil
}
