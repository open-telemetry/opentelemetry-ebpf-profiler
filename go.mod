module go.opentelemetry.io/ebpf-profiler

// NOTE:
// This go.mod is NOT used to build any official binary.
// To see the builder manifests used for official binaries,
// check https://github.com/open-telemetry/opentelemetry-collector-releases
//
// For the OpenTelemetry eBPF Profiler distribution specifically, see
// https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-ebpf-profiler

go 1.26.0

require (
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.3
	github.com/cilium/ebpf v0.22.0
	github.com/elastic/go-freelru v0.16.0
	github.com/elastic/go-perf v0.0.0-20260224073651-af0ee0c731b7
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.20.3
	github.com/mdlayher/kobject v0.0.0-20200520190114-19ca17470d7d
	github.com/minio/sha256-simd v1.0.1
	github.com/open-telemetry/sig-profiling/profcheck v0.0.0-20261020082046-1ae91cf2c9a7
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/stretchr/testify v1.12.1
	github.com/zeebo/xxh3 v1.1.0
	go.opentelemetry.io/collector/component v1.69.0
	go.opentelemetry.io/collector/component/componenttest v0.163.0
	go.opentelemetry.io/collector/confmap v1.69.0
	go.opentelemetry.io/collector/consumer/consumertest v0.163.0
	go.opentelemetry.io/collector/consumer/xconsumer v0.163.0
	go.opentelemetry.io/collector/extension v1.69.0
	go.opentelemetry.io/collector/pdata v1.69.0
	go.opentelemetry.io/collector/pdata/pprofile v0.163.0
	go.opentelemetry.io/collector/receiver v1.69.0
	go.opentelemetry.io/collector/receiver/receivertest v0.163.0
	go.opentelemetry.io/collector/receiver/xreceiver v0.163.0
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/metric v1.47.0
	go.opentelemetry.io/proto/otlp v1.11.1
	go.opentelemetry.io/proto/otlp/processcontext/v1development v0.4.1
	go.opentelemetry.io/proto/otlp/profiles/v1development v0.4.1
	go.uber.org/zap/exp v0.3.0
	golang.org/x/arch v0.32.0
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e
	golang.org/x/mod v0.42.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.22 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jsimonetti/rtnetlink/v2 v2.0.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/knadh/koanf/maps v0.1.3 // indirect
	github.com/knadh/koanf/providers/confmap v1.0.1 // indirect
	github.com/knadh/koanf/v2 v2.3.8 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/collector/consumer v1.69.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.163.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.69.0 // indirect
	go.opentelemetry.io/collector/internal/componentalias v0.163.0 // indirect
	go.opentelemetry.io/collector/pipeline v1.69.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
)
