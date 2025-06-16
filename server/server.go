// Package main implements a stub gRPC server.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strings"

	pb "github.com/elastic/otel-profiling-agent/proto/experiments/opentelemetry/proto/collector/profiles/v1"
	"github.com/elastic/otel-profiling-agent/proto/experiments/opentelemetry/proto/profiles/v1/alternatives/pprofextended"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

type exitCode int

const (
	RPCMaxMsgSize int = 33554432 // 32 MiB

	exitSuccess exitCode = 0
	exitFailure exitCode = 1

	rpcPrefix = "/opentelemetry.proto.collector.profiles.v1.ProfilesService/"
)

var (
	port = flag.Int("port", 8260, "The gRPC server port")

	// Number of ExportXYZ RPCs, set in mainWithExitCode
	rpcCount int
)

type profilesServer struct {
	pb.UnimplementedProfilesServiceServer
	batches chan batch
}

type Line struct { // Line
	LineNo int64
	Column int64

	// Function
	Name       string
	Filename   string
	SystemName string
	StartLine  int64
}

type Frame struct { // Location
	Address   uint64
	FrameType string
	Lines     []Line

	// Mapping
	MemoryStart uint64
	MemoryLimit uint64
	FileOffset  uint64
	Filename    string
	BuildID     string
}

type stackTrace struct { // Sample
	Frames []Frame
}

func (st stackTrace) String() string {
	out := ""
	for _, fr := range st.Frames {
		out += fmt.Sprintf("%v\n", fr)
	}
	return out
}

type batch struct {
	id      uint32
	rpcName string
	traces  []stackTrace
}

func extractFrame(profile *pprofextended.Profile, locIdx int64) Frame {
	stringTable := profile.StringTable
	pLoc := profile.Location[locIdx]
	pMap := profile.Mapping[pLoc.MappingIndex]
	frm := Frame{
		Address:     pLoc.Address,
		FrameType:   stringTable[pLoc.TypeIndex],
		MemoryStart: pMap.MemoryStart,
		MemoryLimit: pMap.MemoryLimit,
		FileOffset:  pMap.FileOffset,
		Filename:    stringTable[pMap.Filename],
		BuildID:     stringTable[pMap.BuildId],
	}

	for _, pLine := range pLoc.Line {
		pFunc := profile.Function[pLine.FunctionIndex]
		lin := Line{
			LineNo:     pLine.Line,
			Column:     pLine.Column,
			Name:       stringTable[pFunc.Name],
			Filename:   stringTable[pFunc.Filename],
			SystemName: stringTable[pFunc.SystemName],
			StartLine:  pFunc.StartLine,
		}

		frm.Lines = append(frm.Lines, lin)
	}
	return frm
}

func extractSimple(prof *pprofextended.Profile, sample *pprofextended.Sample) stackTrace {
	var st stackTrace
	locStart := sample.LocationsStartIndex
	locEnd := locStart + sample.LocationsLength
	for locIdx := locStart; locIdx < locEnd; locIdx++ {
		st.Frames = append(st.Frames,
			extractFrame(prof, prof.LocationIndices[locIdx]))
	}
	return st
}

func extractStacks(prof *pprofextended.Profile, sample *pprofextended.Sample) stackTrace {
	var st stackTrace
	stack := prof.StackTable[sample.StackIndex]
	for _, locIdx := range stack.LocationIndices {
		st.Frames = append(st.Frames,
			extractFrame(prof, int64(locIdx)))
	}
	return st
}

func extractArrays(prof *pprofextended.Profile, sample *pprofextended.Sample) stackTrace {
	var st stackTrace
	for stackIdx := sample.StackIndex; stackIdx != 0; {
		locIdx := prof.StackLocationIndex[stackIdx]
		st.Frames = append(st.Frames,
			extractFrame(prof, int64(locIdx)))
		stackIdx = prof.StackParentArray[stackIdx]
	}
	return st
}

// Extract and return all stack traces from a pprofextended.Profile
func extractStackTraces(profile *pprofextended.Profile) []stackTrace {
	traces := make([]stackTrace, 0, len(profile.Sample))
	for _, sample := range profile.Sample {
		var st stackTrace
		if len(profile.StackTable) == 0 {
			if len(profile.StackParentArray) > 0 {
				st = extractArrays(profile, sample)
			} else {
				st = extractSimple(profile, sample)
			}
		} else {
			st = extractStacks(profile, sample)
		}
		traces = append(traces, st)
	}
	return traces
}

func verify(ctx context.Context, in <-chan batch) {
	batches := make(map[uint32][]batch)

	for {
		select {
		case <-ctx.Done():
			return
		case b := <-in:
			batches[b.id] = append(batches[b.id], b)

			if len(batches[b.id]) == rpcCount {
				for i := 0; i < rpcCount-1; i++ {
					b1 := batches[b.id][i]
					b2 := batches[b.id][i+1]

					if !reflect.DeepEqual(b1.traces, b2.traces) {
						log.Printf("len(B1): %v len(B2): %v", len(b1.traces), len(b2.traces))
						for idx, st := range b1.traces {
							if !reflect.DeepEqual(st, b2.traces[idx]) {
								log.Printf("IDX: %v B1: %v\nB2: %v\n\n", idx, st, b2.traces[idx])
							}
						}
						log.Fatalf("ERROR: %v != %v", b1.rpcName, b2.rpcName)
					} else {
						log.Printf("%v = %v", b1.rpcName, b2.rpcName)
					}
				}
				delete(batches, b.id)
			}
		}
	}
}

// RPC handler method for every ExportXYZ RPC
func (p *profilesServer) exportHandler(_ context.Context, rpcMethod string,
	req *pb.ExportProfilesServiceRequest) (*pb.ExportProfilesServiceResponse, error) {
	container := req.ResourceProfiles[0].ScopeProfiles[0].Profiles[0]
	id := binary.BigEndian.Uint32(container.ProfileId)

	p.batches <- batch{
		id:      id,
		rpcName: rpcMethod,
		traces:  extractStackTraces(container.Profile),
	}

	log.Printf("%v[%d]", rpcMethod, id)
	return &pb.ExportProfilesServiceResponse{}, nil
}

func newServer() *profilesServer {
	p := &profilesServer{batches: make(chan batch)}
	return p
}

func mainWithExitCode() exitCode {
	flag.Parse()

	listenAddress := fmt.Sprintf("localhost:%d", *port)
	lis, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Printf("Error: failed to listen at %v: %v", listenAddress, err)
		return exitFailure
	}

	pbServer := newServer()

	var unaryAuth grpc.UnaryServerInterceptor = func(ctx context.Context,
		req any, si *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		if v, ok := req.(*pb.ExportProfilesServiceRequest); ok {
			return pbServer.exportHandler(ctx,
				strings.TrimPrefix(si.FullMethod, rpcPrefix), v)
		}
		return handler(ctx, req)
	}

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(RPCMaxMsgSize),
		grpc.MaxSendMsgSize(RPCMaxMsgSize),
		grpc.UnaryInterceptor(unaryAuth),
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterProfilesServiceServer(grpcServer, pbServer)

	info := grpcServer.GetServiceInfo()

	// Iterate over the services and extract RPC "ExportXYZ" count.
	// This is later used by the batch verification logic.
	for sname, si := range info {
		if strings.HasSuffix(sname, ".ProfilesService") {
			for _, methodInfo := range si.Methods {
				if strings.HasPrefix(methodInfo.Name, "Export") {
					rpcCount += 1
				}
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer stop()

	go verify(ctx, pbServer.batches)

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
		log.Printf("Stopping gRPC server")
	}()

	log.Printf("Serving gRPC at: %v", listenAddress)
	if err := grpcServer.Serve(lis); err != nil {
		log.Printf("Error: serving gRPC: %v", err)
		return exitFailure
	}
	return exitSuccess
}

func main() {
	os.Exit(int(mainWithExitCode()))
}
