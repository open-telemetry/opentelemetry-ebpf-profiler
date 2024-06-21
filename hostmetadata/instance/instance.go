/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package instance provides functionality common to cloud providers,
// including synthetic cloud "instance" metadata.
package instance

import "strings"

const (
	// Prefix for synthetic instance metadata (used by azure, gce and ec2)
	instancePrefix = "instance:"

	KeyPublicIPV4s  = "public-ipv4s"
	KeyPrivateIPV4s = "private-ipv4s"

	// Only Azure supports IPV6

	KeyPublicIPV6s  = "public-ipv6s"
	KeyPrivateIPV6s = "private-ipv6s"

	KeyCloudProvider = "cloud:provider"
	KeyCloudRegion   = "cloud:region"
	KeyHostType      = "host:type"
)

func AddToResult(metadata map[string][]string, result map[string]string) {
	for k, v := range metadata {
		if len(v) > 0 {
			result[instancePrefix+k] = strings.Join(v, ",")
		}
	}
}
