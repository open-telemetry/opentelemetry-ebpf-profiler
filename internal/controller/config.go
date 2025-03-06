package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import (
	"errors"
	"flag"
	"fmt"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type Config struct {
	BpfVerifierLogLevel    uint
	CollAgentAddr          string
	Copyright              bool
	DisableTLS             bool
	MapScaleFactor         uint
	MonitorInterval        time.Duration
	ClockSyncInterval      time.Duration
	NoKernelVersionCheck   bool
	PprofAddr              string
	ProbabilisticInterval  time.Duration
	ProbabilisticThreshold uint
	ReporterInterval       time.Duration
	SamplesPerSecond       int
	SendErrorFrames        bool
	Tracers                string
	VerboseMode            bool
	Version                bool
	// HostName is the name of the host.
	HostName string
	// IPAddress is the IP address of the host that sends data to CollAgentAddr.
	IPAddress       string
	OffCPUThreshold uint

	Reporter reporter.Reporter

	Fs *flag.FlagSet
}

const (
	// 1TB of executable address space
	MaxArgMapScaleFactor = 8
)

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
	if cfg.SamplesPerSecond < 1 {
		return fmt.Errorf("invalid sampling frequency: %d", cfg.SamplesPerSecond)
	}

	if cfg.MapScaleFactor > 8 {
		return fmt.Errorf(
			"eBPF map scaling factor %d exceeds limit (max: %d)",
			cfg.MapScaleFactor, MaxArgMapScaleFactor,
		)
	}

	if cfg.BpfVerifierLogLevel > 2 {
		return fmt.Errorf("invalid eBPF verifier log level: %d", cfg.BpfVerifierLogLevel)
	}

	if cfg.ProbabilisticInterval < 1*time.Minute || cfg.ProbabilisticInterval > 5*time.Minute {
		return errors.New(
			"invalid argument for probabilistic-interval: use " +
				"a duration between 1 and 5 minutes",
		)
	}

	if cfg.ProbabilisticThreshold < 1 ||
		cfg.ProbabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return fmt.Errorf(
			"invalid argument for probabilistic-threshold. Value "+
				"should be between 1 and %d",
			tracer.ProbabilisticThresholdMax,
		)
	}

	if cfg.OffCPUThreshold > support.OffCPUThresholdMax {
		return fmt.Errorf(
			"invalid argument for off-cpu-threshold. Value "+
				"should be between 1 and %d, or 0 to disable off-cpu profiling",
			support.OffCPUThresholdMax,
		)
	}

	if !cfg.NoKernelVersionCheck {
		major, minor, patch, err := tracer.GetCurrentKernelVersion()
		if err != nil {
			return fmt.Errorf("failed to get kernel version: %v", err)
		}

		var minMajor, minMinor uint32
		switch runtime.GOARCH {
		case "amd64":
			if cfg.VerboseMode {
				minMajor, minMinor = 5, 2
			} else {
				minMajor, minMinor = 4, 19
			}
		case "arm64":
			// Older ARM64 kernel versions have broken bpf_probe_read.
			// https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47
			minMajor, minMinor = 5, 5
		default:
			return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
		}

		if major < minMajor || (major == minMajor && minor < minMinor) {
			return fmt.Errorf("host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
		}
	}

	return nil
}
