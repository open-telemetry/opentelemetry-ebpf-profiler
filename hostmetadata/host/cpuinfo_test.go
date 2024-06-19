/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadCPUInfo(t *testing.T) {
	info, err := readCPUInfo()
	require.NoError(t, err)

	assertions := map[string]func(t *testing.T){
		"NotEmptyOnAnyCPU": func(t *testing.T) { assert.NotEmpty(t, info) },
		"FlagsAreSorted": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUFlags)], 0)
			assert.True(t,
				sort.StringsAreSorted(strings.Split(info[key(keyCPUFlags)][0], ",")))
		},
		"ThreadsPerCore": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUThreadsPerCore)], 0)
			assert.NotEmpty(t, info[key(keyCPUThreadsPerCore)][0])
		},
		"Caches": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUCacheL1i)], 0)
			assert.Contains(t, info[key(keyCPUCacheL1d)], 0)
			assert.Contains(t, info[key(keyCPUCacheL2)], 0)
			assert.Contains(t, info[key(keyCPUCacheL3)], 0)
			assert.NotEmpty(t, info[key(keyCPUCacheL1i)][0])
			assert.NotEmpty(t, info[key(keyCPUCacheL1d)][0])
			assert.NotEmpty(t, info[key(keyCPUCacheL2)][0])
			assert.NotEmpty(t, info[key(keyCPUCacheL3)][0])
		},
		"CachesIsANumber": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUCacheL1i)], 0)
			_, err := strconv.Atoi(info[key(keyCPUCacheL1i)][0])
			require.NoError(t, err)
			assert.Contains(t, info[key(keyCPUCacheL3)], 0)
			_, err = strconv.Atoi(info[key(keyCPUCacheL3)][0])
			require.NoError(t, err)
		},
		"NumCPUs": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUNumCPUs)], 0)
			assert.NotEmpty(t, info[key(keyCPUNumCPUs)][0])
		},
		"CoresPerSocket": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUCoresPerSocket)], 0)
			cps := info[key(keyCPUCoresPerSocket)][0]
			assert.NotEmpty(t, cps)
			i, err := strconv.Atoi(cps)
			require.NoErrorf(t, err, "%v must be parseable as a number", cps)
			assert.Greater(t, i, 0)
		},
		"OnlineCPUs": func(t *testing.T) {
			assert.Contains(t, info[key(keyCPUOnline)], 0)
			onlines := info[key(keyCPUOnline)][0]
			assert.NotEmpty(t, onlines)
			ints, err := readCPURange(onlines)
			require.NoError(t, err)
			assert.NotEmpty(t, t, ints)
		},
	}
	for assertion, run := range assertions {
		t.Run(assertion, run)
	}
}

func TestOnlineCPUsFor(t *testing.T) {
	const siblings = `0-7`

	type args struct {
		coreIDs  []int
		expected string
	}
	tests := map[string]args{
		"One_CPU_Only":                 {[]int{3}, `3`},
		"A_Comma":                      {[]int{3, 5}, `3,5`},
		"A_Range":                      {[]int{0, 1, 2, 3}, `0-3`},
		"A_Range_And_Single":           {[]int{0, 1, 2, 5}, `0-2,5`},
		"Two_Ranges":                   {[]int{0, 1, 2, 5, 6, 7}, `0-2,5-7`},
		"Ranges_And_Commas":            {[]int{1, 2, 4, 6, 7}, `1-2,4,6-7`},
		"Multiple_Comma":               {[]int{1, 2, 4, 7}, `1-2,4,7`},
		"Multiple_Mixes_MultipleTimes": {[]int{0, 1, 3, 4, 6, 7}, `0-1,3-4,6-7`},
	}

	for name, test := range tests {
		c := test
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, c.expected, onlineCPUsFor(siblings, c.coreIDs))
		})
	}
}
