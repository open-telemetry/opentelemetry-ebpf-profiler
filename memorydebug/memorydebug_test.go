//go:build debug
// +build debug

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package memorydebug

import "testing"

func TestReadOwnRSS(t *testing.T) {
	rssAnon, rssFile, rssShmem := readOwnRSS()
	if rssAnon == 0 && rssFile == 0 && rssShmem == 0 {
		t.Fatalf("At least one of the RSS values should be non-zero.")
	}
}
