/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

// Config is the structure to pass the configuration into host-agent.
type Config struct {
	// Bits of hostmetadata that we save in config so that they can be
	// conveniently accessed globally in the agent.
	IPAddress string
	Hostname  string
}

// Profiling specific variables which are set once at startup of the agent.
// To avoid passing them as argument to every function, they are declared
// on package scope.
var (
	// ipAddress holds the IP address of the interface through which the agent traffic is routed
	ipAddress string

	// hostname hosts the hostname of the machine that is running the agent
	hostname string
)

func SetConfiguration(conf *Config) error {
	ipAddress = conf.IPAddress
	hostname = conf.Hostname

	return nil
}

// IP address of the interface through which the agent traffic is routed
func IPAddress() string {
	return ipAddress
}

// Hostname of the machine that is running the agent
func Hostname() string {
	return hostname
}
