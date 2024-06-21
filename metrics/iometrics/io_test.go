/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package iometrics

import (
	"context"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	// Other tests can set procDiskstatsFile to something else. But for this test,
	// we explicitly want to use its original value.
	procDiskstatsFile = "/proc/diskstats"

	defer Start(context.TODO(), 0)()

	_, _, err := getIOData(time.Now())
	require.NoError(t, err)

	// wait to get a 1s value
	time.Sleep(1 * time.Second)

	throughput, duration, err := getIOData(time.Now())
	require.NoError(t, err)

	t.Logf("I/O: throughput %d%% duration %d\n", throughput, duration)
}

func TestParse(t *testing.T) {
	tests := map[string]struct {
		inputFile string
		err       bool
	}{
		"successful file parsing of /proc/diskstats": {
			inputFile: "/proc/diskstats",
			err:       false},
		"successful file parsing of procstat.ok": {
			inputFile: "testdata/diskstats.ok",
			err:       false},
		"unparsable file content": {
			inputFile: "testdata/diskstats.garbage",
			err:       true},
		"empty file content": {
			inputFile: "testdata/diskstats.empty",
			err:       true},
		"not existing file": {
			inputFile: "testdata/__does-not-exist__",
			err:       true},
	}
	var err error

	for name, testcase := range tests {
		testcase := testcase

		t.Run(name, func(t *testing.T) {
			procDiskstatsFile = testcase.inputFile
			file, err = os.Open(procDiskstatsFile)
			if err != nil {
				require.Truef(t, testcase.err, "failed to open %s: %v",
					procDiskstatsFile, err)
				return
			}
			defer file.Close()

			// Start calls parse() internally and reports any error
			_, _, err := getIOData(time.Now())
			if testcase.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// createProcDiskstats creates an ad-hoc /proc/stat like file
func createProcDiskstats(t *testing.T, throughput, duration uint64) string {
	f, err := os.CreateTemp("", "*_diskstats")
	require.NoError(t, err)
	defer f.Close()

	_, err = fmt.Fprintf(f, "1 0 hda 0 0 %d 0 0 0 %d 0 0 0 %d\n",
		throughput/2, throughput-(throughput/2), duration)
	require.NoError(t, err)

	return f.Name()
}

func TestGet(t *testing.T) {
	tests := map[string]struct {
		// prevThroughput simulates the value from the previous call of getIOData()
		prevThroughput uint64
		// throughput is put into the dynamically created input file
		throughput uint64

		// prevDuration simulates the value from the previous call of getIOData()
		prevDuration uint64
		// duration is put into the dynamically created input file
		duration uint64

		// expThroughput represents the expected return from getIOData()
		expThroughput uint64
		// expDuration represents the expected return from getIOData()
		expDuration uint64
	}{
		"0 Throughput, 0 wait": {
			prevThroughput: 0,
			prevDuration:   0,
			throughput:     0,
			duration:       0,
			expThroughput:  0,
			expDuration:    0,
		},
		"Test #2": {
			prevThroughput: 500,
			throughput:     550,
			prevDuration:   150,
			duration:       750,
			expThroughput:  25600,
			expDuration:    600,
		},
		"Kilo throughput": {
			prevThroughput: 0,
			throughput:     2000,
			duration:       135,
			expThroughput:  1024000,
			expDuration:    135,
		},
		"Mega throughput": {
			prevThroughput: 0,
			throughput:     2000000,
			duration:       135,
			expThroughput:  1024000000,
			expDuration:    135,
		},
		"Giga throughput": {
			prevThroughput: 0,
			throughput:     2000000000,
			duration:       135,
			expThroughput:  1024000000000,
			expDuration:    135,
		},
		"Throughput wrap-around": {
			prevThroughput: math.MaxUint64 - 25,
			throughput:     24,
			duration:       0,
			expThroughput:  25600,
			expDuration:    0,
		},
	}
	var err error

	for name, testcase := range tests {
		name := name
		tc := testcase
		t.Run(name, func(t *testing.T) {
			testProcDiskstatsFile := createProcDiskstats(t, tc.throughput, tc.duration)
			defer os.Remove(testProcDiskstatsFile)

			file, err = os.Open(testProcDiskstatsFile)
			require.NoError(t, err)
			defer file.Close()

			now := time.Now()
			procDiskstatsFile = testProcDiskstatsFile
			prevIODuration = tc.prevDuration
			prevThroughput = tc.prevThroughput
			prevTime = now.Add(-1 * time.Second)

			throughput, duration, err := getIOData(now)
			require.NoError(t, err)
			assert.Equal(t, tc.expThroughput, throughput)
			assert.Equal(t, tc.expDuration, duration)
		})
	}
}
