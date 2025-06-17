package samples // import "go.opentelemetry.io/ebpf-profiler/pyroscope/samples"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/discovery"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type AttributesProvider struct {
	Discovery discovery.TargetProducer
}

func (p *AttributesProvider) CollectExtraSampleMeta(_ *libpf.Trace,
	meta *samples.TraceEventMeta) any {
	return p.Discovery.FindTarget(uint32(meta.PID))
}

func (p *AttributesProvider) ExtraSampleAttrs(attrMgr *samples.AttrTableManager, meta any) []int32 {
	target, ok := meta.(*discovery.Target)
	if target == nil || !ok {
		return nil
	}
	attrs := pcommon.NewInt32Slice() // id dont like this
	_, ls := target.Labels()
	for _, lbl := range ls {
		attrMgr.AppendOptionalString(attrs, attribute.Key(lbl.Name), lbl.Value)
	}
	if target.ServiceName() != "" {
		attrMgr.AppendOptionalString(attrs, semconv.ServiceNameKey, target.ServiceName())
	}
	return attrs.AsRaw()
}

func NewAttributesProviderFromDiscovery(sd discovery.TargetProducer) *AttributesProvider {
	return &AttributesProvider{
		Discovery: sd,
	}
}
