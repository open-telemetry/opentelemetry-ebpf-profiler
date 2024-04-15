/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hostmetadata

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/hostmetadata/agent"
	"github.com/elastic/otel-profiling-agent/hostmetadata/azure"
	"github.com/elastic/otel-profiling-agent/hostmetadata/ec2"
	"github.com/elastic/otel-profiling-agent/hostmetadata/gce"
	"github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/reporter"
)

// Collector implements host metadata collection and reporting
type Collector struct {
	// caEndpoint is the collection agent endpoint, which is necessary to determine the source IP
	// address from which traffic will be routed. This IP address is reported as host metadata.
	caEndpoint string
	// collectionInterval specifies the duration between host metadata collections.
	collectionInterval time.Duration
}

// NewCollector returns a new Collector for the specified collection agent endpoint.
func NewCollector(caEndpoint string) *Collector {
	return &Collector{
		caEndpoint: caEndpoint,

		// Changing this significantly must be done in coordination with pf-web-service, as
		// it bounds the minimum time for which host metadata must be retrieved.
		// 23021 is 6h23m41s - picked randomly so we don't do the collection at the same
		// time every day.
		collectionInterval: 23021 * time.Second,
	}
}

// GetHostMetadata returns a map that contains all host metadata key/value pairs.
func (c *Collector) GetHostMetadata() map[string]string {
	result := make(map[string]string)

	agent.AddMetadata(result)

	if err := host.AddMetadata(c.caEndpoint, result); err != nil {
		log.Errorf("Unable to get host metadata: %v", err)
	}

	// Here we can gather more metadata, which may be dependent on the cloud provider, container
	// technology, container orchestration stack, etc.
	switch {
	case config.RunsOnGCP():
		gce.AddMetadata(result)
	case config.RunsOnAWS():
		ec2.AddMetadata(result)
	case config.RunsOnAzure():
		azure.AddMetadata(result)
	default:
	}

	return result
}

// StartMetadataCollection starts a goroutine that reports host metadata every collectionInterval.
func (c *Collector) StartMetadataCollection(ctx context.Context,
	rep reporter.HostMetadataReporter) {
	collectionTicker := time.NewTicker(c.collectionInterval)
	go func() {
		defer collectionTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-collectionTicker.C:
				metadataMap := c.GetHostMetadata()
				// metadataMap will always contain revision and build timestamp
				rep.ReportHostMetadata(metadataMap)
			}
		}
	}()
}
