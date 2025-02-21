// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// coredump provides a tool for extracting stack traces from coredumps.
// It also includes a test suite to unit test profiling agent components against
// a set of coredumps to validate stack extraction code.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/peterbourgon/ff/v3/ffcli"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

// moduleStoreRegion defines the S3 bucket OCI region.
const moduleStoreRegion = "us-sanjose-1"

// moduleStoreObjectNamespace defines the S3 bucket OCI object name space.
const moduleStoreObjectNamespace = "axtwf1hkrwcy"

// modulePublicReadUrl defines the S3 bucket OCI public read only base path.
//
//nolint:lll
const modulePublicReadURL = "sm-wftyyzHJkBghWeexmK1o5ArimNwZC-5eBej5Lx4e46sLVHtO_y7Zf7FZgoIu_/n/axtwf1hkrwcy"

// moduleStoreS3Bucket defines the S3 bucket used for the module store.
const moduleStoreS3Bucket = "ebpf-profiling-coredumps"

func main() {
	log.SetReportCaller(false)
	log.SetFormatter(&log.TextFormatter{})

	store, err := initModuleStore()
	if err != nil {
		log.Fatalf("%v", err)
	}

	root := ffcli.Command{
		Name:       "coredump",
		ShortUsage: "coredump <subcommand> [flags]",
		ShortHelp:  "Tool for creating and managing coredump test cases",
		Subcommands: []*ffcli.Command{
			newAnalyzeCmd(store),
			newCleanCmd(store),
			newExportModuleCmd(store),
			newNewCmd(store),
			newRebaseCmd(store),
			newUploadCmd(store),
			newGdbCmd(store),
			newGosymCmd(store),
		},
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
	}

	if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			log.Fatalf("%v", err)
		}
	}
}

func initModuleStore() (*modulestore.Store, error) {
	publicReadURL := fmt.Sprintf("https://%s.objectstorage.%s.oci.customer-oci.com/p/%s/b/%s/o/",
		moduleStoreObjectNamespace, moduleStoreRegion, modulePublicReadURL, moduleStoreS3Bucket)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		baseEndpoint := fmt.Sprintf("https://%s.compat.objectstorage.%s.oraclecloud.com/",
			moduleStoreObjectNamespace, moduleStoreRegion)
		o.Region = moduleStoreRegion
		o.BaseEndpoint = aws.String(baseEndpoint)
		o.UsePathStyle = true
	})
	return modulestore.New(s3Client, publicReadURL, moduleStoreS3Bucket, "modulecache")
}
