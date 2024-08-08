/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hostmetadata

import (
	"context"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
)

// Collector implements host metadata collection and reporting
type Collector struct {
	// caEndpoint is the collection agent endpoint, which is necessary to determine the source IP
	// address from which traffic will be routed. This IP address is reported as host metadata.
	caEndpoint string
	// collectionInterval specifies the duration between host metadata collections.
	collectionInterval time.Duration

	// customData is a map of custom key/value pairs that can be added to the host metadata.
	customData map[string]string
}

// NewCollector returns a new Collector for the specified collection agent endpoint.
func NewCollector(caEndpoint string) *Collector {
	return &Collector{
		caEndpoint: caEndpoint,
		customData: make(map[string]string),

		// Changing this significantly must be done in coordination with readers of the host
		// metadata, as it bounds the minimum time for which host metadata must be retrieved.
		// 23021 is 6h23m41s - picked randomly, so we don't do the collection at the same
		// time every day.
		collectionInterval: 23021 * time.Second,
	}
}

// AddCustomData adds a custom key/value pair to the host metadata.
func (c *Collector) AddCustomData(key, value string) {
	c.customData[key] = value
}

// GetHostMetadata returns a map that contains all host metadata key/value pairs.
func (c *Collector) GetHostMetadata() map[string]string {
	result := make(map[string]string)

	for k, v := range c.customData {
		result[k] = v
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
