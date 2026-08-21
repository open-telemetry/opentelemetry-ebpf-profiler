// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// The base resource a process declares through its environment. Enricher
// contributions merge on top of it, so what a process publishes at runtime wins over
// what it was started with.

package procmeta // import "go.opentelemetry.io/ebpf-profiler/procmeta"

import (
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	// resourceAttrKey is the environment variable OpenTelemetry resource
	// attributes are read from.
	resourceAttrKey = "OTEL_RESOURCE_ATTRIBUTES"

	// svcNameKey is the environment variable the service name is read from.
	svcNameKey = "OTEL_SERVICE_NAME"
)

// The keys above, interned once rather than on every lookup.
var (
	internedResourceAttrKey = libpf.Intern(resourceAttrKey)
	internedSvcNameKey      = libpf.Intern(svcNameKey)
)

// EnvVarNames returns the environment variables the base resource is derived from.
// The process manager captures these whether or not the user asked to report them.
func EnvVarNames() []string {
	return []string{svcNameKey, resourceAttrKey}
}

// ResourceFromEnvVars builds the base resource a process's environment declares,
// from the variables EnvVarNames names, or nil if neither yields an attribute.
// Contributions merge on top, so what a process publishes at runtime wins.
func ResourceFromEnvVars(envVars map[libpf.String]libpf.String) *pcommon.Resource {
	if len(envVars) == 0 {
		return nil
	}
	r := pcommon.NewResource()
	if v, ok := envVars[internedResourceAttrKey]; ok {
		pairs, err := parseResourceAttributes(v.String())
		if err != nil {
			log.Debugf("OTEL_RESOURCE_ATTRIBUTES=%q: discarding invalid value: %v", v.String(), err)
		} else {
			for _, p := range pairs {
				r.Attributes().PutStr(p.key, p.value)
			}
		}
	}
	if v, ok := envVars[internedSvcNameKey]; ok {
		r.Attributes().PutStr(string(semconv.ServiceNameKey), v.String())
	}
	if r.Attributes().Len() == 0 {
		return nil
	}
	return &r
}

// resourceAttribute is one parsed entry from OTEL_RESOURCE_ATTRIBUTES.
type resourceAttribute struct {
	key, value string
}

// parseResourceAttributes parses OTEL_RESOURCE_ATTRIBUTES as comma-separated
// percent-encoded key=value pairs, returned in source order for the caller to dedup
// last-writer-wins. Per OTel spec any decoding error discards the whole value.
func parseResourceAttributes(raw string) ([]resourceAttribute, error) {
	if raw == "" {
		return nil, nil
	}
	var pairs []resourceAttribute
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("missing '=' in %q", pair)
		}
		key, err := url.PathUnescape(strings.TrimSpace(k))
		if err != nil {
			return nil, fmt.Errorf("invalid key %q: %w", k, err)
		}
		value, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("invalid value for key %q: %w", key, err)
		}
		pairs = append(pairs, resourceAttribute{key, value})
	}
	return pairs, nil
}
