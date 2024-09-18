package benchreporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"
)

// compile time check for interface implementation
var _ reporter.Reporter = (*BenchmarkReporter)(nil)

type BenchmarkReporter struct {
	saveInputsTo string
	f            *os.File
	rep          reporter.Reporter
	uid          int
	gid          int
}

func (r *BenchmarkReporter) ReportFramesForTrace(trace *libpf.Trace) {
	r.store("FramesForTrace", trace)
	r.rep.ReportFramesForTrace(trace)
}

type countForTrace struct {
	TraceHash libpf.TraceHash
	Meta      *reporter.TraceEventMeta
	Count     uint16
}

func (r *BenchmarkReporter) ReportCountForTrace(traceHash libpf.TraceHash,
	count uint16, meta *reporter.TraceEventMeta) {
	r.store("CountForTrace", &countForTrace{
		TraceHash: traceHash,
		Meta:      meta,
		Count:     count,
	})
	r.rep.ReportCountForTrace(traceHash, count, meta)
}

type traceEvent struct {
	Trace *libpf.Trace
	Meta  *reporter.TraceEventMeta
}

func (r *BenchmarkReporter) ReportTraceEvent(trace *libpf.Trace, meta *reporter.TraceEventMeta) {
	r.store("TraceEvent", &traceEvent{
		Trace: trace,
		Meta:  meta,
	})
	r.rep.ReportTraceEvent(trace, meta)
}

func (r *BenchmarkReporter) SupportsReportTraceEvent() bool {
	return r.rep.SupportsReportTraceEvent()
}

type fallbackSymbol struct {
	FileID        libpf.FileID
	AddressOrLine libpf.AddressOrLineno
	Symbol        string
}

func (r *BenchmarkReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	r.store("FallbackSymbol", &fallbackSymbol{
		FileID:        frameID.FileID(),
		AddressOrLine: frameID.AddressOrLine(),
		Symbol:        symbol,
	})
	r.rep.ReportFallbackSymbol(frameID, symbol)
}

type executableMetadata struct {
	FileID   libpf.FileID
	FileName string
	BuildID  string
	Interp   libpf.InterpreterType
}

func (r *BenchmarkReporter) ExecutableMetadata(fileID libpf.FileID,
	fileName, buildID string, interp libpf.InterpreterType, open reporter.ExecutableOpener) {
	r.store("ExecutableMetadata", &executableMetadata{
		FileID:   fileID,
		FileName: fileName,
		BuildID:  buildID,
		Interp:   interp,
	})
	r.rep.ExecutableMetadata(fileID, fileName, buildID, interp, open)
}

type frameMetadata struct {
	FileID         libpf.FileID
	AddressOrLine  libpf.AddressOrLineno
	LineNumber     util.SourceLineno
	FunctionOffset uint32
	FunctionName   string
	FilePath       string
}

func (r *BenchmarkReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
	lineNumber util.SourceLineno, functionOffset uint32, functionName, filePath string) {
	r.store("FrameMetadata", &frameMetadata{
		FileID:         fileID,
		AddressOrLine:  addressOrLine,
		LineNumber:     lineNumber,
		FunctionOffset: functionOffset,
		FunctionName:   functionName,
		FilePath:       filePath,
	})
	r.rep.FrameMetadata(fileID, addressOrLine, lineNumber, functionOffset, functionName, filePath)
}

type hostMetadata struct {
	Metadata map[string]string
}

func (r *BenchmarkReporter) ReportHostMetadata(metadata map[string]string) {
	r.store("HostMetadata", &hostMetadata{
		Metadata: metadata,
	})
	r.rep.ReportHostMetadata(metadata)
}

func (r *BenchmarkReporter) ReportHostMetadataBlocking(ctx context.Context,
	metadataMap map[string]string, maxRetries int, waitRetry time.Duration) error {
	return r.rep.ReportHostMetadataBlocking(ctx, metadataMap, maxRetries, waitRetry)
}

type metrics struct {
	Timestamp uint32
	IDs       []uint32
	Values    []int64
}

func (r *BenchmarkReporter) ReportMetrics(timestamp uint32, ids []uint32, values []int64) {
	r.store("Metrics", &metrics{
		Timestamp: timestamp,
		IDs:       ids,
		Values:    values,
	})
	r.rep.ReportMetrics(timestamp, ids, values)
}

func (r *BenchmarkReporter) Stop() {
	r.rep.Stop()
	_ = r.f.Close()
}

func (r *BenchmarkReporter) GetMetrics() reporter.Metrics {
	return r.rep.GetMetrics()
}

func NewBenchmarkReporter(saveInputsTo string, rep reporter.Reporter) (*BenchmarkReporter, error) {
	r := &BenchmarkReporter{
		saveInputsTo: saveInputsTo,
		rep:          rep,
	}
	r.uid, r.gid = originUser()

	var err error
	if r.f, err = os.OpenFile(saveInputsTo,
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", saveInputsTo, err)
	}

	if err = r.f.Chown(r.uid, r.gid); err != nil {
		return nil, fmt.Errorf("failed to change ownership of %s to %d:%d: %v",
			saveInputsTo, r.uid, r.gid, err)
	}

	return r, nil
}

func originUser() (uid, gid int) {
	if uidStr := os.Getenv("SUDO_UID"); uidStr != "" {
		uid, _ = strconv.Atoi(uidStr)
	}
	if gidStr := os.Getenv("SUDO_GID"); gidStr != "" {
		gid, _ = strconv.Atoi(gidStr)
	}
	return
}

type metaInfo struct {
	TS   int64  `json:"ts"`
	Name string `json:"name"`
}

// store appends data as NDJSON to the output file.
func (r *BenchmarkReporter) store(name string, data any) {
	meta := metaInfo{
		TS:   time.Now().UnixNano(),
		Name: name,
	}

	// encode meta data to JSON
	bytes, err := json.Marshal(meta)
	if err != nil {
		panic(err)
	}
	if err = appendToFile(r.f, bytes); err != nil {
		panic(err)
	}

	// encode reporter input to JSON
	bytes, err = json.Marshal(data)
	if err != nil {
		panic(err)
	}
	if err = appendToFile(r.f, bytes); err != nil {
		panic(err)
	}
}

func appendToFile(f *os.File, bytes []byte) error {
	_, err := f.Write(append(bytes, '\n'))
	return err
}

func changeOwner(pathName string, uid, gid int) {
	if err := os.Chown(pathName, uid, gid); err != nil {
		log.Errorf("Failed to change ownership of %s to %d:%d: %v",
			pathName, uid, gid, err)
	}
}

func changeDirOwner(dirName string, uid, gid int) {
	dirs := strings.Split(dirName, "/")
	for i := 1; i <= len(dirs); i++ {
		dir := filepath.Join(dirs[:i]...)
		changeOwner(dir, uid, gid)
	}
}

func GRPCInterceptor(saveDir string) grpc.UnaryClientInterceptor {
	if saveDir != "" {
		if err := os.MkdirAll(saveDir, 0o755); err != nil {
			log.Errorf("Failed to create directory for storing protobuf messages: %v", err)
			return nil
		}

		uid, gid := originUser()

		if uid != 0 || gid != 0 {
			changeDirOwner(saveDir, uid, gid)
		}

		// return interceptor to write the uncompressed protobuf messages to disk.
		return func(ctx context.Context, method string, req, reply any,
			cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			storeProtobuf(saveDir, req, uid, gid)
			return invoker(ctx, method, req, reply, cc, opts...)
		}
	}

	return nil
}

var protoMsgID atomic.Uint64

func storeProtobuf(msgDir string, msg any, uid, gid int) {
	protoMsgID.Add(1)

	// Get the wire format of the request message.
	msgBytes, err := proto.Marshal(msg.(proto.Message))
	if err != nil {
		log.Errorf("failed to marshal request: %v", err)
		return
	}

	filePath := fmt.Sprintf("%s/%05X.proto", msgDir, protoMsgID.Load())
	if err = os.WriteFile(filePath, msgBytes, 0o600); err != nil {
		log.Errorf("failed to write request: %v", err)
		return
	}

	changeOwner(filePath, uid, gid)
}
