/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"context"
	"crypto/tls"
	"os"
	"time"

	"github.com/elastic/otel-profiling-agent/libpf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// setupGrpcConnection sets up a gRPC connection instrumented with our auth interceptor
func setupGrpcConnection(parent context.Context, c *Config,
	statsHandler *statsHandlerImpl) (*grpc.ClientConn, error) {
	// authGrpcInterceptor intercepts gRPC operations, adds metadata to each operation and
	// checks for authentication errors. If an authentication error is encountered, a
	// process exit is triggered.
	authGrpcInterceptor := func(ctx context.Context, method string, req, reply any,
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code := st.Code()
				if code == codes.Unauthenticated ||
					code == codes.FailedPrecondition {
					log.Errorf("Setup gRPC: %v", err)
					//nolint:errcheck
					libpf.SleepWithJitterAndContext(parent,
						c.Times.GRPCAuthErrorDelay(), 0.3)
					os.Exit(1)
				}
			}
		}
		return err
	}

	opts := []grpc.DialOption{grpc.WithBlock(),
		grpc.WithStatsHandler(statsHandler),
		grpc.WithUnaryInterceptor(authGrpcInterceptor),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(c.MaxRPCMsgSize),
			grpc.MaxCallSendMsgSize(c.MaxRPCMsgSize)),
		grpc.WithReturnConnectionError(),
	}

	if c.DisableTLS {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				// Support only TLS1.3+ with valid CA certificates
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
			})))
	}

	ctx, cancel := context.WithTimeout(parent, c.Times.GRPCConnectionTimeout())
	defer cancel()
	return grpc.DialContext(ctx, c.CollAgentAddr, opts...)
}

// When we are not able to connect immediately to the backend,
// we will wait forever until a connection happens and we receive a response,
// or the operation is canceled.
func waitGrpcEndpoint(ctx context.Context, c *Config,
	statsHandler *statsHandlerImpl) (*grpc.ClientConn, error) {
	// Sleep with a fixed backoff time added of +/- 20% jitter
	tick := time.NewTicker(libpf.AddJitter(c.Times.GRPCStartupBackoffTime(), 0.2))
	defer tick.Stop()

	var retries uint32
	for {
		if collAgentConn, err := setupGrpcConnection(ctx, c, statsHandler); err != nil {
			if retries >= c.MaxGRPCRetries {
				return nil, err
			}
			retries++

			log.Warnf(
				"Failed to setup gRPC connection (try %d of %d): %v",
				retries,
				c.MaxGRPCRetries,
				err,
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-tick.C:
				continue
			}
		} else {
			return collAgentConn, nil
		}
	}
}
