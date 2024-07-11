/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	agentmeta "github.com/elastic/otel-profiling-agent/hostmetadata/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/libpf"
)

const (
	tags      = "foo;bar;this-tag-should-be-dropped-!;baz;1.2.3.4;key:value;a_b_c"
	validTags = "foo;bar;baz;1.2.3.4;key:value;a_b_c"
)

func TestSetTags(t *testing.T) {
	tests := map[string]string{
		tags: validTags,
		"":   "",
	}

	for testTags, testValidatedTags := range tests {
		SetTags(testTags)
		if validatedTags != testValidatedTags {
			t.Errorf("validated tags %s != %s", validatedTags, testValidatedTags)
		}
	}
}

func TestAddMetadata(t *testing.T) {
	err := config.SetConfiguration(&config.Config{})
	require.NoError(t, err)

	agentmeta.SetAgentData(&agentmeta.Config{
		CollectionAgentAddr: "localhost:12345",
	})

	// This tests checks that common metadata keys are populated
	metadataMap := make(map[string]string)
	SetTags(validTags)

	// Ignore errors because collection may fail in unit tests. However, we check the contents of
	// the returned map, which ensures test coverage.
	_ = AddMetadata(metadataMap)
	expectedHostname, err := os.Hostname()
	require.NoError(t, err)

	if actualHostname, found := metadataMap[KeyHostname]; assert.True(t, found) {
		assert.Equal(t, expectedHostname, actualHostname)
	}
	if tags, found := metadataMap[keyTags]; assert.True(t, found) {
		assert.Equal(t, validatedTags, tags)
	}
	if ip, found := metadataMap[KeyIPAddress]; assert.True(t, found) {
		parsedIP := net.ParseIP(ip)
		assert.NotNil(t, parsedIP)
	}
	if procVersion, found := metadataMap[KeyKernelProcVersion]; assert.True(t, found) {
		expectedProcVersion, err := os.ReadFile("/proc/version")
		if assert.NoError(t, err) {
			assert.Equal(t, sanitizeString(expectedProcVersion), procVersion)
		}
	}
	_, found := metadataMap[KeyKernelVersion]
	assert.True(t, found)

	// The below test for bpf_jit_enable may not be reproducible in all environments, as we may not
	// be able to read the value depending on the capabilities/privileges/network namespace of the
	// test process.
	jitEnabled, found := metadataMap["host:sysctl/net.core.bpf_jit_enable"]
	if found {
		switch jitEnabled {
		case "0", "1", "2":
		default:
			assert.Fail(t, "unexpected value for sysctl: %v", jitEnabled)
		}
	}

	cacheKey := key(keyCPUCacheL1d)
	cache, ok := metadataMap[cacheKey]
	assert.True(t, ok)
	assert.NotEmpty(t, cache)

	cacheSockets, ok := metadataMap[keySocketID(cacheKey)]
	assert.True(t, ok)
	assert.NotEmpty(t, cacheSockets)
	assert.Equal(t, "0", cacheSockets[0:1],
		"expected '0' at start of '%v'", cacheSockets)
	sids := strings.Split(cacheSockets, ",")
	socketIDs := libpf.MapSlice(sids, func(a string) int {
		n, _ := strconv.Atoi(a)
		return n
	})
	assert.True(t, sort.IntsAreSorted(socketIDs),
		"expected '%v' to be numerically sorted", sids)
}
