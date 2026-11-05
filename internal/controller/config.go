package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"go.opentelemetry.io/ebpf-profiler/process"

	"go.opentelemetry.io/collector/consumer/xconsumer"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type Config struct {
	config.Config

	ExecutableReporter reporter.ExecutableReporter
	// ProcessMetaEnrichers are optional hooks for enriching process metadata at
	// process discovery and executable change time. Multiple enrichers are called in order.
	ProcessMetaEnrichers []process.MetaEnricher
	OnShutdown           func() error

	// If ReporterFactory is set, it will be used to create a Reporter and set it as the Reporter field.
	// Either ReporterFactory or Reporter must be set. If both are set, ReporterFactory will be used.
	ReporterFactory func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)
	Reporter        reporter.Reporter
}

// Validate runs validations on the provided configuration, and returns errors
// if invalid values were provided.
func (cfg *Config) Validate() error {
	return cfg.Config.Validate()
}
