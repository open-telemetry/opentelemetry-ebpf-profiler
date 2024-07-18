package profilingreceiver

import (
	"errors"
	"fmt"
	"time"

	tracertypes "github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer/types"
	log "github.com/sirupsen/logrus"
	"github.com/tklauser/numcpus"
	"go.opentelemetry.io/collector/component"
)

// Config represents the receiver config settings within the collector's config.yaml
type Config struct {
	ProjectID              string        `mapstructure:"project-id"`
	HostID                 uint64        `mapstructure:"host-id"`
	SecretToken            string        `mapstructure:"secret-token"`
	CollectionAgent        string        `mapstructure:"collection-agent"`
	Tracers                string        `mapstructure:"tracers"`
	Tags                   string        `mapstructure:"tags"`
	BpfVerifierLogSize     int           `mapstructure:"bpf-log-size"`
	BpfVerifierLogLevel    uint          `mapstructure:"bpf-log-level"`
	MapScaleFactor         uint8         `mapstructure:"map-scale-factor"`
	Verbose                bool          `mapstructure:"verbose"`
	DisableTLS             bool          `mapstructure:"disable-tls"`
	NoKernelVersionCheck   bool          `mapstructure:"no-kernel-version-check"`
	ProbabilisticThreshold uint          `mapstructure:"probabilistic-threshold"`
	ProbabilisticInterval  time.Duration `mapstructure:"probabilistic-interval"`
	EnvironmentType        string        `mapstructure:"environment-type"`
	ReporterInterval       time.Duration `mapstructure:"reporter-interval"`
	MonitorInterval        time.Duration `mapstructure:"monitor-interval"`
	SamplesPerSecond       int           `mapstructure:"samples-per-second"`
	SendErrorFrames        bool          `mapstructure:"send-error-frames"`

	// Written in createDefaultConfig()
	PresentCPUCores int
}

// Validate checks if the receiver configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.ReporterInterval.Seconds() < 1 {
		return errors.New("the interval has to be set to at least 1 second (1s)")
	}

	if cfg.ProjectID == "" {
		return errors.New("projectid must be set")
	}

	if cfg.PresentCPUCores <= 0 {
		return errors.New("failed to determine number of CPUs")
	}

	if cfg.SamplesPerSecond <= 0 {
		return errors.New("samples per second must be > 0")
	}

	if _, err := tracertypes.Parse(cfg.Tracers); err != nil {
		return fmt.Errorf("failed to parse tracers '%s': %v", cfg.Tracers, err)
	}

	// todo: Add more validation

	return nil
}

func createDefaultConfig() component.Config {
	presentCores, err := numcpus.GetPresent()
	if err != nil {
		log.Errorf("Failed to read CPU file: %v", err)
	}

	// todo: export default values (currently in main.go)
	return &Config{
		ProjectID:              defaultProjectID,
		HostID:                 defaultHostID,
		ReporterInterval:       5 * time.Second,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		CollectionAgent:        "127.0.0.1:11000", // devfiler
		Tracers:                "all",
		PresentCPUCores:        presentCores,
	}
}
