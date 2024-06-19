/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

/*
Package iometrics is responsible for measuring I/O metrics.

The package is assumed and designed to run only once in host agent (singleton).
The "downside" is that we can not Start() this package twice - that would even
be considered a bug as we would store the same metrics twice in the database.

The directory structure is

	iometrics/
	├── io.go
	├── io_test.go
	└── testdata
	    ├── diskstats.empty
	    ├── diskstats.garbage
		└── diskstats.ok

The I/O metrics reporting is started after the metrics package has been started
by calling the Start() function with a context and an interval argument.

The context variable allows for explicit cancellation of the background goroutine
in case defer doesn't work, e.g. when the application is stopped by os.Exit().

The interval specifies in which intervals the I/O metrics are collected. We agreed upon
1x per second. This interval is independent of the reporting interval, which is how often
buffered metrics data is sent to the backend (collection agent / storage).

Start returns a Stop() function that should be called to release package resources.

Example code from main.go to start I/O metrics reporting with a 1s interval:

	defer iometrics.Start(mainCtx, 1*time.Second)()

The description of '/proc/diskstats' can be found at

	https://www.kernel.org/doc/Documentation/iostats.txt.
*/
package iometrics

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/elastic/otel-profiling-agent/periodiccaller"
	"github.com/elastic/otel-profiling-agent/stringutil"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/metrics"
)

var (
	// scannerBuffer is a static buffer used by the scanner in parse().
	// The reason we can use a static buffer because the code is guaranteed concurrency free.
	scannerBuffer [1024]byte

	// procDiskstatsFile is the file name to read the IO metrics values from.
	procDiskstatsFile = "/proc/diskstats"

	// file is the open file to parse I/O metrics from
	file *os.File

	// prevThroughput is the previously measured I/O throughput (blocks read+write)
	prevThroughput uint64

	// prevIODuration is the previously measured I/O duration in "weighted # of milliseconds"
	prevIODuration uint64

	// prevTime is the timestamp of the previous measurement
	prevTime time.Time

	// onceStart helps to make this package a thread-safe singleton
	onceStart sync.Once

	// onceStop helps to make this package a thread-safe singleton
	onceStop sync.Once
)

const bytesPerBlock = 512

// initialize contains the one-time initialization - called from report().
func initialize() error {
	var err error

	file, err = os.Open(procDiskstatsFile)
	if err != nil {
		return fmt.Errorf("failed to initialize: %v", err)
	}

	// Initialize prevUser and prevSystem for further delta calculations.
	// If we don't do this we'll see a single 100% spike in the metrics.
	if prevThroughput, prevIODuration, err = parse(); err != nil {
		return fmt.Errorf("failed to init I/O delta values: %v", err)
	}

	prevTime = time.Now()

	return nil
}

// parse returns the I/O throughput and duration values parsed from /proc/diskstats.
// I/O throughput is measured in blocks read and written.
// duration is measured in millisends spent for read and write.
// The format of /proc/diskstats is described in
// https://www.kernel.org/doc/Documentation/iostats.txt
func parse() (totalThroughput, totalDuration uint64, err error) {
	// rewind procDiskstatsFile instead of open/close at every interval
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}

	scanner := bufio.NewScanner(file)
	// We have to parse the whole file. Since these are normally not too big and the lines are
	// not long, a good default value may be 1024 (length of buf).
	// 4096 is the scanner's internal default value for the buffer size.
	scanner.Buffer(scannerBuffer[:], 4096)
	ok := false

	for scanner.Scan() {
		// Avoid heap allocation by not using scanner.Text().
		// NOTE: The underlying bytes will change with the next call to scanner.Scan(),
		// so make sure to not keep any references after the end of the loop iteration.
		line := stringutil.ByteSlice2String(scanner.Bytes())

		// Avoid heap allocations here - do not use strings.FieldsN()
		var fields [15]string
		n := stringutil.FieldsN(line, fields[:])
		if n < 14 {
			continue
		}

		// we are only interested in devices (minor ID 0)
		if fields[1] != "0" {
			continue
		}

		ioRead, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return 0, 0, errors.New("failed to parse read blocks")
		}

		ioWrite, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return 0, 0, errors.New("failed to parse written blocks")
		}

		ioDuration, err := strconv.ParseUint(fields[13], 10, 64)
		if err != nil {
			return 0, 0, errors.New("failed to parse I/O duration")
		}

		totalThroughput += ioRead + ioWrite
		totalDuration += ioDuration
		ok = true
	}
	if !ok {
		return 0, 0, errors.New("no data found")
	}
	return totalThroughput, totalDuration, nil
}

// Get returns the I/O throughput and I/O duration measured between
// the previous (successful) call and now.
func getIOData(now time.Time) (avgThroughput, avgDuration uint64, err error) {
	var deltaThroughput, deltaDuration uint64

	ioThroughput, ioDuration, err := parse()
	if err != nil {
		return 0, 0, err
	}

	duration := now.Sub(prevTime)
	prevTime = now

	// handle wrap-around
	if ioThroughput < prevThroughput {
		log.Debugf("I/O throughput wrap-around detected %d -> %d", prevThroughput, ioThroughput)
		deltaThroughput = (math.MaxUint64 - prevThroughput) + ioThroughput + 1
	} else {
		deltaThroughput = ioThroughput - prevThroughput
	}

	// handle wrap-around
	if ioDuration < prevIODuration {
		log.Debugf("I/O duration wrap-around detected %d -> %d", prevIODuration, ioDuration)
		deltaDuration = (math.MaxUint64 - prevIODuration) + ioDuration + 1
	} else {
		deltaDuration = ioDuration - prevIODuration
	}

	prevThroughput = ioThroughput
	prevIODuration = ioDuration

	// scaling regarding the interval duration
	scale := float64(time.Second) / float64(duration)

	// average throughput delta as bytes
	avgThroughput = uint64(scale * float64(deltaThroughput*bytesPerBlock))

	// average I/O duration delta as milliseconds
	avgDuration = uint64(scale * float64(deltaDuration))

	return avgThroughput, avgDuration, nil
}

// report get the actual measurement and reports it to the metrics package.
func report() {
	if avgThroughput, avgDuration, err := getIOData(time.Now()); err != nil {
		log.Errorf("Failed to measure I/O metrics: %v", err)
	} else {
		metrics.AddSlice([]metrics.Metric{
			{
				ID:    metrics.IDIOThroughput,
				Value: metrics.MetricValue(avgThroughput),
			},
			{
				ID:    metrics.IDIODuration,
				Value: metrics.MetricValue(avgDuration),
			},
		})
	}
}

// Start starts the I/O metric retrieval and reporting.
func Start(ctx context.Context, interval time.Duration) func() {
	var stopPeriodic func()

	onceStart.Do(func() { // <-- atomic, does not allow repeating
		if err := initialize(); err != nil {
			log.Errorf("Failed to initialize I/O metrics: %v", err)
			return
		}

		if interval != 0 {
			// Start I/O metric reporting, report every second.
			log.Infof("Start I/O metrics")
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
