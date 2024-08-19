package benchreporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
)

// Replay replays the stored data from replayInputsFrom.
// The argument r is the reporter that will receive the replayed data.
func Replay(ctx context.Context, replayInputsFrom string, rep reporter.Reporter) error {
	stream, err := os.Open(replayInputsFrom)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", replayInputsFrom, err)
	}
	decoder := json.NewDecoder(stream)

	var m metaInfo
	var curTS int64

	for {
		if err = decoder.Decode(&m); err != nil {
			// EOF is returned at the end of the stream.
			if err != io.EOF {
				return err
			}
			break
		}

		if curTS != 0 {
			time.Sleep(time.Duration(m.TS-curTS) * time.Nanosecond)
		}
		curTS = m.TS

		switch m.Name {
		case "TraceEvent":
			var v traceEvent
			if err = decodeTo(decoder, &v); err == nil {
				rep.ReportTraceEvent(v.Trace, v.Meta)
			}
		case "CountForTrace":
			var v countForTrace
			if err = decodeTo(decoder, &v); err == nil {
				rep.ReportCountForTrace(v.TraceHash, v.Count, v.Meta)
			}
		case "FramesForTrace":
			var v libpf.Trace
			if err = decodeTo[libpf.Trace](decoder, &v); err == nil {
				rep.ReportFramesForTrace(&v)
			}
		case "FallbackSymbol":
			var v fallbackSymbol
			if err = decodeTo(decoder, &v); err == nil {
				rep.ReportFallbackSymbol(libpf.NewFrameID(v.FileID, v.AddressOrLine), v.Symbol)
			}
		case "ExecutableMetadata":
			var v executableMetadata
			if err = decodeTo(decoder, &v); err == nil {
				rep.ExecutableMetadata(context.Background(), v.FileID, v.FileName, v.BuildID,
					v.Interp, nil)
			}
		case "FrameMetadata":
			var v frameMetadata
			if err = decodeTo(decoder, &v); err == nil {
				rep.FrameMetadata(v.FileID, v.AddressOrLine, v.LineNumber, v.FunctionOffset,
					v.FunctionName, v.FilePath)
			}
		case "HostMetadata":
			var v hostMetadata
			if err = decodeTo(decoder, &v); err == nil {
				rep.ReportHostMetadata(v.Metadata)
			}
		case "Metrics":
			var v metrics
			if err = decodeTo[metrics](decoder, &v); err == nil {
				rep.ReportMetrics(v.Timestamp, v.IDs, v.Values)
			}
		default:
			err = fmt.Errorf("unsupported function name in file %s: %s", replayInputsFrom, m.Name)
		}

		if err != nil {
			log.Errorf("Failed to replay data from file %s: %v", m.Name, err)
		}

		if err = ctx.Err(); err != nil {
			return err
		}
	}

	return nil
}

func decodeTo[T any](decoder *json.Decoder, data *T) error {
	if err := decoder.Decode(data); err != nil {
		return fmt.Errorf("failed to decode JSON: %v", err)
	}

	return nil
}
