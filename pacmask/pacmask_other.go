//go:build !arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package pacmask

// GetPACMask always returns 0 on this platform.
func GetPACMask() uint64 {
	return 0
}
