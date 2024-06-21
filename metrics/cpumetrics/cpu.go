/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

/*
Package cpumetrics is responsible for measuring CPU metrics.

The package is assumed and designed to run only once in host agent (singleton).
The "downside" is that we can not Start() this package twice - that would even
be considered a bug as we would store the same metrics twice in the database.

The directory structure is

	  cpumetrics/
	  ├── cpu.go
	  ├── cpu_test.go
	  └── testdata
	      ├── procstat.empty
	      ├── procstat.garbage
		  └── procstat.ok

The CPU usage reporting is started after the metrics package has been started
by calling the Start() function with a context and an interval argument.

The context variable allows for explicit cancellation of the background goroutine
in case defer doesn't work, e.g. when the application is stopped by os.Exit().

The interval specifies in which intervals the CPU usage is collected. We agreed upon
1x per second. This interval is independent of the reporting interval, which is how often
buffered metrics data is sent to the backend (collection agent / storage).

Start returns a Stop() function that should be called to release package resources.

Example code from main.go to start CPU metric reporting with a 1s interval:

	defer cpumetrics.Start(mainCtx, 1*time.Second)()

The description of '/proc/stat' can be found at

	https://man7.org/linux/man-pages/man5/proc.5.html.
*/
package cpumetrics

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/otel-profiling-agent/periodiccaller"
	"github.com/elastic/otel-profiling-agent/stringutil"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/metrics"

	sysconf "github.com/tklauser/go-sysconf"
)

var (
	// scannerBuffer is a static buffer used by the scanner in parse()
	// The reason we can use a static buffer because the code is guaranteed concurrency free.
	scannerBuffer [8192]byte

	// procStatFile is the file name to read the CPU usage values from.
	procStatFile = "/proc/stat"

	// file is the open file to parse user and system CPU load from
	file *os.File

	// nCPUs is the number of configured CPUs (not the number of online CPUs)
	nCPUs uint32

	// userHZ is the ticks per second, the unit for the values in /proc/stat
	userHZ uint32

	// prevUser is the previously measured user time in ticks (userHZ units)
	prevUser uint64

	// prevSystem is the previously measured system time in ticks (userHZ units)
	prevSystem uint64

	// prevTime is the timestamp of the previous measurement
	prevTime time.Time

	// onceStart helps to make this package a thread-safe singleton
	onceStart sync.Once

	// onceStop helps to make this package a thread-safe singleton
	onceStop sync.Once
)

// initialize contains the one-time initialization - called from Report().
func initialize() error {
	var err error

	file, err = os.Open(procStatFile)
	if err != nil {
		return fmt.Errorf("failed to initialize: %v", err)
	}

	// From 'man 5 proc':
	// The amount of time, measured in units of USER_HZ
	// (1/100ths of a second on most architectures), use
	// sysconf(_SC_CLK_TCK) to obtain the right value).
	tmpUserHZ, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		log.Warnf("Failed to get value of UserHZ / SC_CLK_TCK (using 100 as default)")
		tmpUserHZ = 100 // default on most Linux systems
	}
	userHZ = uint32(tmpUserHZ)

	tmpNCPUs := int64(runtime.NumCPU())
	if tmpNCPUs < 0 {
		log.Warnf("Failed to get number of available CPUs (using 1 as default)")
		tmpNCPUs = 1
	}
	nCPUs = uint32(tmpNCPUs)

	log.Debugf("userHZ %d nCPUs %d", userHZ, nCPUs)

	// Initialize prevUser and prevSystem for further delta calculations.
	// If we don't do this we'll see a single 100% spike in the metrics.
	if prevUser, prevSystem, err = parse(); err != nil {
		return fmt.Errorf("failed to init CPU delta values: %v", err)
	}

	return nil
}

// parse parses and returns the system and user CPU usage values.
// The format of /proc/stat is described in
// https://man7.org/linux/man-pages/man5/proc.5.html.
func parse() (user, system uint64, err error) {
	// rewind procStatFile instead of open/close at every interval
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}

	scanner := bufio.NewScanner(file)
	// We only want to read the first line which fits very likely into buf.
	// The fallback is to support up to 8192 bytes per line.
	scanner.Buffer(scannerBuffer[:], cap(scannerBuffer))

	for scanner.Scan() {
		// Avoid heap allocation by not using scanner.Text().
		// NOTE: The underlying bytes will change with the next call to scanner.Scan(),
		// so make sure to not keep any references after the end of the loop iteration.
		line := stringutil.ByteSlice2String(scanner.Bytes())

		if !strings.HasPrefix(line, "cpu ") {
			continue
		}

		// Avoid heap allocations here - do not use strings.FieldsN()
		var fields [5]string
		n := stringutil.FieldsN(line, fields[:])
		if n < 4 {
			return 0, 0, fmt.Errorf("failed to find at least 4 fields in '%s'", line)
		}

		if user, err = strconv.ParseUint(fields[1], 10, 64); err != nil {
			return 0, 0, errors.New("failed to parse CPU user value")
		}

		if system, err = strconv.ParseUint(fields[3], 10, 64); err != nil {
			return 0, 0, errors.New("failed to parse CPU system value")
		}

		return user, system, nil
	}

	if err = scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("failed to parse %s: %v", procStatFile, err)
	}

	return 0, 0, fmt.Errorf("failed to find 'cpu' keyword in %s", procStatFile)
}

// getCPUUsage measures and calculates the average CPU usage as percentage value measured between
// the previous (successful) call and now.
func getCPUUsage() (pAvgCPU uint16, err error) {
	user, system, err := parse()
	if err != nil {
		return 0, err
	}

	now := time.Now()
	duration := now.Sub(prevTime)
	prevTime = now

	var load uint64

	// handle wrap-around of user value
	if user < prevUser {
		log.Debugf("User wrap-around detected %d -> %d", prevUser, user)
		load = (math.MaxUint64 - prevUser) + user + 1
	} else {
		load = user - prevUser
	}

	// handle wrap-around of system value
	if system < prevSystem {
		log.Debugf("System wrap-around detected %d -> %d", prevSystem, system)
		load += (math.MaxUint64 - prevSystem) + system + 1
	} else {
		load += system - prevSystem
	}

	prevUser = user
	prevSystem = system

	// Calculate the maximum possible value for the elapsed time (duration).
	// nCPUs*userHZ: The max. number of ticks per second.
	// duration / time.Second: Time elapsed in seconds.
	max := float64(nCPUs*userHZ) * (float64(duration) / float64(time.Second))

	// Calculate the % value of the CPU usage with rounding.
	if max > 0 {
		pAvgCPU = uint16(float64(load*100)/max + 0.5)
		if pAvgCPU > 100 {
			pAvgCPU = 100
		}
	}

	return pAvgCPU, nil
}

// report get the actual measurement and reports it to the metrics package.
func report() {
	if value, err := getCPUUsage(); err != nil {
		log.Errorf("Failed to measure CPU metrics: %v", err)
	} else {
		metrics.Add(metrics.IDCPUUsage, metrics.MetricValue(value))
	}
}

// Start starts the CPU metric retrieval and reporting.
func Start(ctx context.Context, interval time.Duration) func() {
	var stopPeriodic func()

	onceStart.Do(func() { // <-- atomic, does not allow repeating
		err := initialize()
		if err != nil {
			log.Errorf("Failed to initialize CPU metrics: %v", err)
			return
		}

		if interval != 0 {
			// Start CPU metric reporting, report every second.
			log.Infof("Start CPU metrics")
			stopPeriodic = periodiccaller.Start(ctx, interval, report)
		}
	})

	// return a one-time close function to avoid leaks
	return func() {
		onceStop.Do(func() { // <-- atomic, does not allow repeating
			if stopPeriodic != nil {
				stopPeriodic()
				file.Close()
			}
		})
	}
}
