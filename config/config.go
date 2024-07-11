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
	HostID uint64

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

	// ipAddress holds the IP address of the interface through which the agent traffic is routed
	ipAddress string

	// hostname hosts the hostname of the machine that is running the agent
	hostname string

	// kernelVersion holds the kernel release (uname -r) of the machine that is running the agent
	kernelVersion string
)

func SetConfiguration(conf *Config) error {
	hostID = conf.HostID

	ipAddress = conf.IPAddress
	hostname = conf.Hostname
	kernelVersion = conf.KernelVersion

	return nil
}

// HostID returns the hostID of the running agent. The host ID is calculated by calling
// GenerateNewHostIDIfNecessary().
func HostID() uint64 {
	if hostID == 0 {
		log.Fatalf("HostID is not set")
	}
	return hostID
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
