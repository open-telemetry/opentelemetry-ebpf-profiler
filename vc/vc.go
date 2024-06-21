/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package vc provides buildtime information.
package vc

var (
	// The following variables are going to be set at link time using ldflags
	// and can be referenced later in the program.

	// revision of the service
	revision = ""
	// buildTimestamp, timestamp of the build
	buildTimestamp = ""
	// version in vX.Y.Z{-N-abbrev} format (via git-describe --tags)
	version = ""
)

// Revision of the service.
func Revision() string {
	return revision
}

// BuildTimestamp returns the timestamp of the build.
func BuildTimestamp() string {
	return buildTimestamp
}

// Version in vX.Y.Z{-N-abbrev} format.
func Version() string {
	return version
}
