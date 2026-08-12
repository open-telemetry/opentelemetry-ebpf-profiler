module github.com/open-telemetry/opentelemetry-ebpf-profiler/tools/strobelight-ctrl

go 1.25.0

tool (
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

replace go.opentelemetry.io/ebpf-profiler => ../../

require (
	github.com/cilium/ebpf v0.22.0
	go.opentelemetry.io/ebpf-profiler v0.0.202633
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/elastic/go-freelru v0.16.0 // indirect
	github.com/elastic/go-perf v0.0.0-20260224073651-af0ee0c731b7 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/mdlayher/kobject v0.0.0-20200520190114-19ca17470d7d // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.opentelemetry.io/collector/consumer v1.64.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.158.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.64.0 // indirect
	go.opentelemetry.io/collector/pdata v1.64.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.158.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.opentelemetry.io/proto/otlp/processcontext/v1development v0.4.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/arch v0.30.0 // indirect
	golang.org/x/exp v0.0.0-20260811152304-ee035b5b010f // indirect
	golang.org/x/exp/typeparams v0.0.0-20260209203927-2842357ff358 // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/telemetry v0.0.0-20260708182218-49f421fb7959 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.org/x/vuln v1.6.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260720211330-0afa2a65878a // indirect
	google.golang.org/grpc v1.83.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	honnef.co/go/tools v0.7.0 // indirect
)
