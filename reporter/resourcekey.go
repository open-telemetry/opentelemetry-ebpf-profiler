// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/pcommon"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// resourceToContextKey returns a stable key derived from the
// (service.namespace, service.name, service.instance.id) triplet which the
// OTel semantic conventions describe as globally unique for a service
// instance.
// See: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/service.md
//
// Returns libpf.NullString only when resource is nil or none of the three
// attributes is present. When at least one is present, the result joins all
// three with ':' (missing components render as empty strings); callers
// should treat the null sentinel as "unidentifiable" and may choose to
// group such samples by other fields.
func resourceToContextKey(resource *pcommon.Resource) libpf.String {
	if resource == nil {
		return libpf.NullString
	}
	serviceNamespace, namespaceOK := resource.Attributes().Get(string(semconv.ServiceNamespaceKey))
	serviceName, nameOK := resource.Attributes().Get(string(semconv.ServiceNameKey))
	serviceInstanceID, instanceIDOK := resource.Attributes().Get(string(semconv.ServiceInstanceIDKey))
	if !namespaceOK && !nameOK && !instanceIDOK {
		return libpf.NullString
	}
	return libpf.Intern(fmt.Sprintf("%s:%s:%s",
		serviceNamespace.Str(), serviceName.Str(), serviceInstanceID.Str()))
}
