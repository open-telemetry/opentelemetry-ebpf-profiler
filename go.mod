module go.opentelemetry.io/ebpf-profiler

go 1.24.6

require (
	github.com/aws/aws-sdk-go-v2 v1.39.0
	github.com/aws/aws-sdk-go-v2/config v1.31.8
	github.com/aws/aws-sdk-go-v2/service/s3 v1.88.1
	github.com/cilium/ebpf v0.19.0
	github.com/elastic/go-freelru v0.16.0
	github.com/elastic/go-perf v0.0.0-20241029065020-30bec95324b8
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.18.0
	github.com/mdlayher/kobject v0.0.0-20200520190114-19ca17470d7d
	github.com/minio/sha256-simd v1.0.1
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	github.com/tklauser/numcpus v0.10.0
	github.com/zeebo/xxh3 v1.0.2
	go.opentelemetry.io/collector/component v1.41.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/consumer/consumertest v0.135.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/consumer/xconsumer v0.135.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/pdata v1.41.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/pdata/pprofile v0.135.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/receiver v1.41.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/receiver/receivertest v0.135.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/collector/receiver/xreceiver v0.135.1-0.20250918163459-ba0b327d5fe9
	go.opentelemetry.io/otel v1.38.0
	go.opentelemetry.io/otel/metric v1.38.0
	golang.org/x/arch v0.21.0
	golang.org/x/exp v0.0.0-20250911091902-df9299821621
	golang.org/x/mod v0.28.0
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.36.0
	google.golang.org/grpc v1.75.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.8.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.4 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jsimonetti/rtnetlink/v2 v2.0.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/component/componenttest v0.135.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/collector/consumer v1.41.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.135.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/collector/featuregate v1.41.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.135.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/collector/pdata/testdata v0.135.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/collector/pipeline v1.41.1-0.20250915160638-4b4e557b86cb // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.12.0 // indirect
	go.opentelemetry.io/otel/log v0.14.0 // indirect
	go.opentelemetry.io/otel/sdk v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
