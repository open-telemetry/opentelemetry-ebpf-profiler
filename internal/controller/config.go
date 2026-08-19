package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"flag"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/process"

	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type Config struct {
	config.Config
	CollAgentAddr string
	Copyright     bool
	DisableTLS    bool
	PprofAddr     string
	Version       bool

	ExecutableReporter reporter.ExecutableReporter
	// ProcessMetaEnrichers are optional hooks for enriching process metadata at
	// process discovery and executable change time. Multiple enrichers are called in order.
	ProcessMetaEnrichers []process.MetaEnricher
	OnShutdown           func() error

	// If ReporterFactory is set, it will be used to create a Reporter and set it as the Reporter
	// field. Either ReporterFactory or Reporter must be set. If both are set, ReporterFactory
	// will be used.
	ReporterFactory func(
		cfg *reporter.Config, nextConsumer xconsumer.Profiles,
	) (reporter.Reporter, error)
	Reporter reporter.Reporter

	Fs *flag.FlagSet
}

// Dump visits all flag sets, and dumps them all to debug
// Used for verbose mode logging.
func (cfg *Config) Dump() {
	log.Debug("Config:")
	cfg.Fs.VisitAll(func(f *flag.Flag) {
		log.Debug(fmt.Sprintf("%s: %v", f.Name, f.Value))
	})
}

// Validate runs validations on the provided configuration, and returns errors
// if invalid values were provided.
func (cfg *Config) Validate() error {
	return cfg.Config.Validate()
}
