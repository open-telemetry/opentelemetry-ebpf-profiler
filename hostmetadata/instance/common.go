/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package instance

import (
	"bufio"
	"bytes"
	"strings"
)

// Enumerate converts a string response from a metadata service into a list of elements
func Enumerate(payload string) []string {
	result := make([]string, 0)
	s := bufio.NewScanner(bytes.NewBufferString(payload))
	for s.Scan() {
		line := strings.TrimSuffix(strings.TrimSpace(s.Text()), "/")
		// In case the response has empty lines we discard them
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
