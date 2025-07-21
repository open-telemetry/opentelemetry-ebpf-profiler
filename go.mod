module go.opentelemetry.io/ebpf-profiler

go 1.23.6

require (
	github.com/aws/aws-sdk-go-v2 v1.36.4
	github.com/aws/aws-sdk-go-v2/config v1.29.16
	github.com/aws/aws-sdk-go-v2/service/s3 v1.80.2
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cilium/ebpf v0.18.0
	github.com/elastic/go-freelru v0.16.0
	github.com/elastic/go-perf v0.0.0-20241029065020-30bec95324b8
	github.com/google/uuid v1.6.0
	github.com/grafana/pyroscope/lidia v0.0.0-20250716102313-506840f4afcd
	github.com/jsimonetti/rtnetlink/v2 v2.0.3
	github.com/klauspost/compress v1.18.0
	github.com/mdlayher/kobject v0.0.0-20200520190114-19ca17470d7d
	github.com/minio/sha256-simd v1.0.1
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/prometheus/common v0.55.0
	github.com/prometheus/prometheus v0.51.2
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	github.com/tklauser/numcpus v0.10.0
	github.com/zeebo/xxh3 v1.0.2
	go.opentelemetry.io/collector/component v1.34.0
	go.opentelemetry.io/collector/consumer/consumertest v0.128.0
	go.opentelemetry.io/collector/consumer/xconsumer v0.128.0
	go.opentelemetry.io/collector/pdata v1.34.0
	go.opentelemetry.io/collector/pdata/pprofile v0.128.0
	go.opentelemetry.io/collector/receiver v1.34.0
	go.opentelemetry.io/collector/receiver/receivertest v0.128.0
	go.opentelemetry.io/collector/receiver/xreceiver v0.128.0
	go.opentelemetry.io/otel v1.36.0
	go.opentelemetry.io/otel/metric v1.36.0
	golang.org/x/arch v0.18.0
	golang.org/x/exp v0.0.0-20250606033433-dcc06ee1d476
	golang.org/x/sync v0.15.0
	golang.org/x/sys v0.33.0
	google.golang.org/grpc v1.73.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.69 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.7.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.21 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/grafana/regexp v0.0.0-20221122212121-6b5c0a4cb7fd // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/component/componenttest v0.128.0 // indirect
	go.opentelemetry.io/collector/consumer v1.34.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.128.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.34.0 // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.128.0 // indirect
	go.opentelemetry.io/collector/pipeline v0.128.0 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.11.0 // indirect
	go.opentelemetry.io/otel/log v0.12.2 // indirect
	go.opentelemetry.io/otel/sdk v1.36.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
