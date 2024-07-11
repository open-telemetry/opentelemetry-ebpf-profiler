/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	log "github.com/sirupsen/logrus"
)

// Config is the structure to pass the configuration into host-agent.
type Config struct {
	HostID              uint64
	BpfVerifierLogSize  int
	BpfVerifierLogLevel uint
	ProjectID           uint32

	// Bits of hostmetadata that we save in config so that they can be
	// conveniently accessed globally in the agent.
	IPAddress     string
	Hostname      string
	KernelVersion string
}

// Profiling specific variables which are set once at startup of the agent.
// To avoid passing them as argument to every function, they are declared
// on package scope.
var (
	// hostID represents project wide unique id to identify the host.
	hostID uint64
	// projectID is read from the provided configuration file and sent to the collection agent
	// along with traces to identify the project that they belong to.
	projectID uint32

	// bpfVerifierLogLevel holds the defined log level of the eBPF verifier.
	// Currently there are three different log levels applied by the kernel verifier:
	// 0 - no logging
	// BPF_LOG_LEVEL1 (1) - enable logging
	// BPF_LOG_LEVEL2 (2) - more logging
	//
	// Some older kernels do not handle BPF_LOG_LEVEL2.
	bpfVerifierLogLevel uint32
	// bpfVerifierLogSize defines the number of bytes that are pre-allocated to hold the output
	// of the eBPF verifier log.
	bpfVerifierLogSize int

	// ipAddress holds the IP address of the interface through which the agent traffic is routed
	ipAddress string

	// hostname hosts the hostname of the machine that is running the agent
	hostname string

	// kernelVersion holds the kernel release (uname -r) of the machine that is running the agent
	kernelVersion string
)

// configurationSet signals that SetConfiguration() has been successfully called and
// the variables it sets can be read.
var configurationSet = false

func SetConfiguration(conf *Config) error {
	projectID = conf.ProjectID
	hostID = conf.HostID

	bpfVerifierLogLevel = uint32(conf.BpfVerifierLogLevel)
	bpfVerifierLogSize = conf.BpfVerifierLogSize

	ipAddress = conf.IPAddress
	hostname = conf.Hostname
	kernelVersion = conf.KernelVersion

	configurationSet = true
	return nil
}

// BpfVerifierLogSetting returns the eBPF verifier log settings.
func BpfVerifierLogSetting() (level uint32, size int) {
	return bpfVerifierLogLevel, bpfVerifierLogSize
}

// HostID returns the hostID of the running agent. The host ID is calculated by calling
// GenerateNewHostIDIfNecessary().
func HostID() uint64 {
	if hostID == 0 {
		log.Fatalf("HostID is not set")
	}
	return hostID
}

// ProjectID returns the projectID
func ProjectID() uint32 {
	if !configurationSet {
		log.Fatal("Cannot access ProjectID. Configuration has not been read")
	}
	return projectID
}

// IP address of the interface through which the agent traffic is routed
func IPAddress() string {
	return ipAddress
}

// Hostname of the machine that is running the agent
func Hostname() string {
	return hostname
}

// Kernel release (uname -r) of the machine that is running the agent
func KernelVersion() string {
	return kernelVersion
}
