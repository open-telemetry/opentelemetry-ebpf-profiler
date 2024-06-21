//go:build debug
// +build debug

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package memorydebug

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// If memory usage during a call to DebugLogMemoryUsage() exceeds the threshold in this
// variable, the code will write a full heapdump with timestamp to /tmp
var heapDumpLimit uint64

// If memory usage during a call to DebugLogMemoryUsage() exceeds the threshold in this
// variable, the code will write a memory profile to /tmp
var profileDumpLimit uint64

// Init sets up the limits for memory debugging: At what amount of heap usage should heap dumps
// or heap profiles be written. It also starts a web server on port 6060 so that live memory
// profiles can be pulled.
func Init(maxHeapBeforeDump, maxHeapBeforeProfile uint64) {
	log.Debug("Initializing memory usag debugging.")
	heapDumpLimit = maxHeapBeforeDump
	profileDumpLimit = maxHeapBeforeProfile
	// Start a local webserver to serve pprof profiles.
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}

// readOwnRSS reads /proc/self/status to parse the usage of the resident set for the
// current process. We could parse /proc/self/statm instead (cheaper), but given that
// we won't do this often and only in debug, "expensive" parsing of /proc/self/status
// is fine.
func readOwnRSS() (rssAnon uint64, rssFile uint64, rssShmem uint64) {
	contents, err := os.ReadFile("/proc/self/status")
	if err != nil {
		log.Fatalf("Reading our own RSS should never fail")
		return 0, 0, 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		// Ignoring errors in the following lines is fine -- RssAnon and RssFile can never be
		// zero for a live process, so problems are immediately evident.
		if strings.HasPrefix(line, "RssAnon:") {
			rssAnon, _ = strconv.ParseUint(strings.TrimSpace(line[10:len(line)-3]), 10, 64)
		} else if strings.HasPrefix(line, "RssFile:") {
			rssFile, _ = strconv.ParseUint(strings.TrimSpace(line[10:len(line)-3]), 10, 64)
		} else if strings.HasPrefix(line, "RssShmem:") {
			rssShmem, _ = strconv.ParseUint(strings.TrimSpace(line[10:len(line)-3]), 10, 64)
		}
	}
	return rssAnon * 1024, rssFile * 1024, rssShmem * 1024
}

// DebugLogMemoryUsage is a no-op in release mode. In debug mode, it asks the runtime
// about actual memory use, logs information about the usage, and if the configured
// thresholds are exceeded dumps full memory logs to /tmp
func DebugLogMemoryUsage() {
	// Read sizes of resident sets.
	rssAnon, rssFile, rssShmem := readOwnRSS()
	// Read the memory statistics from the Go runtime.
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	// Output the results.
	log.Debugf("Alloc: %d Sys: %d Mallocs: %d Frees: %d HeapAlloc: %d HeapSys: %d RssAnon: %d RssFile: %d RssShmem: %d",
		stats.Alloc, stats.Sys, stats.Mallocs, stats.Frees, stats.HeapAlloc, stats.HeapSys, rssAnon,
		rssFile, rssShmem)

	// If the number of allocated bytes ever exceeds heapDumpLimit, make a heap dump.
	if stats.Alloc > heapDumpLimit {
		filename := fmt.Sprintf("/tmp/heap_dump_%d_%d", os.Getpid(), int32(time.Now().Unix()))
		f, err := os.Create(filename)
		defer f.Close()
		if err != nil {
			panic(err)
		}
		log.Debugf("Writing heap dump...")
		debug.WriteHeapDump(f.Fd())
	}
	if stats.Alloc > profileDumpLimit {
		filename := fmt.Sprintf("/tmp/pprof_dump_%d_%d", os.Getpid(), int32(time.Now().Unix()))
		f, err := os.Create(filename)
		defer f.Close()
		if err != nil {
			panic(err)
		}
		log.Debugf("Writing heap profile...")
		w := bufio.NewWriter(f)
		pprof.Lookup("heap").WriteTo(w, 0)
		w.Flush()
	}
}
