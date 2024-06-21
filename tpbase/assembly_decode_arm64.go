//go:build arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tpbase

func GetAnalyzers() []Analyzer {
	return arm64GetAnalyzers()
}
