/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package cpumetrics

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	// Other tests can set procStatFile to something else. But for this test,
	// we explicitly want to use its original value.
	procStatFile = "/proc/stat"

	defer Start(context.TODO(), 0)()

	// check internal values
	require.NotEqual(t, 0, userHZ, "userHZ not set")
	require.NotEqual(t, 0, nCPUs, "nCPUs not set")

	_, err := getCPUUsage()
	require.NoError(t, err)

	// wait to get a 1s value
	time.Sleep(1 * time.Second)

	avg, err := getCPUUsage()
	require.NoError(t, err)

	t.Logf("CPU Usage: %d%%\n", avg)
	require.LessOrEqual(t, avg, uint16(100))
}

func TestParse(t *testing.T) {
	tests := map[string]struct {
		inputFile string
		err       bool
	}{
		"successful file parsing of /proc/stat": {
			inputFile: "/proc/stat",
			err:       false},
		"successful file parsing of procstat.ok": {
			inputFile: "testdata/procstat.ok",
			err:       false},
		"unparsable file content": {
			inputFile: "testdata/procstat.garbage",
			err:       true},
		"empty file content": {
			inputFile: "testdata/procstat.empty",
			err:       true},
		"not existing file": {
			inputFile: "testdata/__does-not-exist__",
			err:       true},
	}
	var err error

	for name, testcase := range tests {
		testcase := testcase

		t.Run(name, func(t *testing.T) {
			procStatFile = testcase.inputFile
			file, err = os.Open(procStatFile)
			if err != nil {
				require.Truef(t, testcase.err, "open failed: %v", err)
				return
			}
			defer file.Close()

			// Start calls parse() internally and reports any error
			_, err := getCPUUsage()
			if testcase.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// createProcStat creates an ad-hoc /proc/stat like file.
func createProcStat(t *testing.T, user, system uint64,
	addLongLineBeforeCPU, addLongLineAfterCPU bool) string {
	f, err := os.CreateTemp("", "*_procstat")
	require.NoError(t, err)
	defer f.Close()

	addLongLine := func() {
		_, err2 := fmt.Fprintf(f, "intr%s\n", strings.Repeat(" 0", 2048))
		require.NoError(t, err2)
	}

	if addLongLineBeforeCPU {
		addLongLine()
	}

	_, err = fmt.Fprintf(f, "cpu %d 0 %d\n", user, system)
	require.NoError(t, err)

	if addLongLineAfterCPU {
		addLongLine()
	}

	return f.Name()
}

func TestGet(t *testing.T) {
	tests := map[string]struct {
		// userHz and nCPUs represent the host specific values that are set in Start()
		userHZ uint32
		nCPUs  uint32
		// prevUser and prevSystem simulate the values from the previous call of getCPUUsage()
		prevUser   uint64
		prevSystem uint64
		// user and system are put into the dynamically created procStatFile
		user   uint64
		system uint64
		// expAvgCPU represents the expected return from getCPUUsage()
		expAvgCPU uint16
		// addLongLineBeforeCPU indicates whether we add a very long line before 'cpu ...'
		addLongLineBeforeCPU bool
		// addLongLineAfterCPU indicates whether we add a very long line after 'cpu ...'
		addLongLineAfterCPU bool
	}{
		"0% CPU": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   0,
			prevSystem: 0,
			user:       0,
			system:     0,
			expAvgCPU:  0,
		},
		"50% CPU": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   500,
			prevSystem: 700,
			user:       550,
			system:     750,
			expAvgCPU:  50,
		},
		"100% CPU": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   0,
			prevSystem: 0,
			user:       75,
			system:     125,
			expAvgCPU:  100,
		},
		"100% CPU (timing glitch)": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   0,
			prevSystem: 0,
			user:       75,
			system:     135, // basically at 105%, still expect report of 100%
			expAvgCPU:  100,
		},
		"User wrap-around": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   math.MaxUint64 - 25,
			prevSystem: 0,
			user:       24,
			system:     0,
			expAvgCPU:  25,
		},
		"System wrap-around": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   0,
			prevSystem: math.MaxUint64 - 25,
			user:       0,
			system:     24,
			expAvgCPU:  25,
		},
		"Double wrap-around": {
			userHZ:     100,
			nCPUs:      2,
			prevUser:   math.MaxUint64 - 25,
			prevSystem: math.MaxUint64 - 25,
			user:       24,
			system:     24,
			expAvgCPU:  50,
		},
		"Many cores, high userHZ": {
			userHZ:     1000,
			nCPUs:      1024,
			prevUser:   0,
			prevSystem: 0,
			user:       (1000 * 1024 / 100) * 15, // 15% user load
			system:     (1000 * 1024 / 100) * 20, // 20% system load
			expAvgCPU:  35,                       // 35% total load
		},
		"50% CPU LongLineBefore": {
			userHZ:               100,
			nCPUs:                2,
			prevUser:             500,
			prevSystem:           700,
			user:                 550,
			system:               750,
			expAvgCPU:            50,
			addLongLineBeforeCPU: true,
		},
		"50% CPU LongLineAfter": {
			userHZ:              100,
			nCPUs:               2,
			prevUser:            500,
			prevSystem:          700,
			user:                550,
			system:              750,
			expAvgCPU:           50,
			addLongLineAfterCPU: true,
		},
	}
	var err error

	for name, testcase := range tests {
		name := name
		tc := testcase
		t.Run(name, func(t *testing.T) {
			testProcStatFile := createProcStat(t, tc.user, tc.system,
				tc.addLongLineBeforeCPU, tc.addLongLineAfterCPU)
			defer os.Remove(testProcStatFile)

			file, err = os.Open(testProcStatFile)
			require.NoError(t, err)
			defer file.Close()

			procStatFile = testProcStatFile
			userHZ = tc.userHZ
			nCPUs = tc.nCPUs
			prevUser = tc.prevUser
			prevSystem = tc.prevSystem
			prevTime = time.Now().Add(-1 * time.Second)

			avgCPU, err := getCPUUsage()
			require.NoError(t, err)
			require.Equal(t, tc.expAvgCPU, avgCPU)
		})
	}
}
