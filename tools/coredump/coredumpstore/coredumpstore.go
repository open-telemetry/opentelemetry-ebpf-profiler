// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package coredumpstore // import "go.opentelemetry.io/ebpf-profiler/tools/coredump/coredumpstore"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

const localCachePath = "tools/coredump/modulecache"

// New creates a new modulestore.Store pointing to the public s3 used for coredump tests
func New() (*modulestore.Store, error) {
	gitRoot, err := findGitRoot()
	if err != nil {
		return nil, err
	}

	localCachePath := filepath.Join(gitRoot, localCachePath)
	publicReadURL := fmt.Sprintf("https://%s.objectstorage.%s.oci.customer-oci.com/p/%s/b/%s/o/",
		moduleStoreObjectNamespace, moduleStoreRegion, modulePublicReadURL, moduleStoreS3Bucket)

	cfg, err := config.LoadDefaultConfig(context.Background())
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
	return modulestore.New(s3Client, publicReadURL, moduleStoreS3Bucket, localCachePath)
}

func findGitRoot() (string, error) {
	it, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for len(it) > 1 {
		_, err = os.Stat(filepath.Join(it, ".git"))
		if err == nil {
			return it, nil
		}
		it = filepath.Dir(it)
	}
	return "", errors.New("git not found")
}
