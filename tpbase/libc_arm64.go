//go:build arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tpbase

func ExtractTSDInfoX64_64(_ []byte) (TSDInfo, error) {
	return TSDInfo{}, errArchNotImplemented
}

func ExtractTSDInfoNative(code []byte) (TSDInfo, error) {
	return ExtractTSDInfoARM64(code)
}
