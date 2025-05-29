// Package main implements a stub gRPC server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	pb "github.com/elastic/otel-profiling-agent/proto/experiments/opentelemetry/proto/collector/profiles/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

type exitCode int

const (
	RPCMaxMsgSize int = 33554432 // 32 MiB

	exitSuccess exitCode = 0
	exitFailure exitCode = 1
)

var (
	port = flag.Int("port", 8260, "The gRPC server port")
)

type profilesServer struct {
	pb.UnimplementedProfilesServiceServer
}

func (p *profilesServer) Export(context.Context, *pb.ExportProfilesServiceRequest) (
	*pb.ExportProfilesServiceResponse, error) {
	log.Printf("Export!")
	return &pb.ExportProfilesServiceResponse{}, nil
}

func newServer() *profilesServer {
	p := &profilesServer{}
	return p
}

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	flag.Parse()

	listenAddress := fmt.Sprintf("localhost:%d", *port)
	lis, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Printf("Error: failed to listen at %v: %v", listenAddress, err)
		return exitFailure
	}

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(RPCMaxMsgSize),
		grpc.MaxSendMsgSize(RPCMaxMsgSize),
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterProfilesServiceServer(grpcServer, newServer())

	ctx, stop := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer stop()

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
