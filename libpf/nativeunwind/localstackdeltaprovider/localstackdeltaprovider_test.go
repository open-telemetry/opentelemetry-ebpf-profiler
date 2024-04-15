/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package localstackdeltaprovider

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind/localintervalcache"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

// /usr/lib/vlc/plugins/video_filter/libinvert_plugin.so gzip'ed and base64'ed.
// nolint:lll
var usrLibVlcPluginsVideoFilterLibinvertPluginSo = `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
Jyh+9nPa/x+sJOndADgAAA==`

// nolint:lll
var usrLibVlcPluginsVideoFilterLibEdgedetectionPluginSo = `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`

var usrBinGs = `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
AA==`

func unzipBase64Buffer(buffer string) ([]byte, error) {
	gzipped, err := base64.StdEncoding.DecodeString(buffer)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to base64-decode buffer: %w", err)
	}
	unzipper, err := gzip.NewReader(bytes.NewBuffer(gzipped))
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer unzipper.Close()
	finaldata, err := io.ReadAll(unzipper)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to unzip the decoded buffer: %w", err)
	}
	return finaldata, nil
}

func doConfigure(t testing.TB) string {
	// Set up a CacheDirectory as it is needed by the interval cache
	cacheDirectory, err := os.MkdirTemp("", "*_TestGetIntervalStructures")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}

	err = config.SetConfiguration(&config.Config{
		ProjectID:      42,
		CacheDirectory: cacheDirectory,
		SecretToken:    "secret"})
	if err != nil {
		t.Fatalf("Failed to set temporary config: %s", err)
	}

	return cacheDirectory
}

func doWriteExes(t testing.TB) []string {
	testFiles := []string{usrLibVlcPluginsVideoFilterLibEdgedetectionPluginSo,
		usrLibVlcPluginsVideoFilterLibinvertPluginSo, usrBinGs}
	filenames := make([]string, len(testFiles))
	for idx, inData := range testFiles {
		exeData, err := unzipBase64Buffer(inData)
		if err != nil {
			t.Fatalf("failed to unzip buffer: %v", err)
		}
		filename, err1 := libpf.WriteTempFile(exeData, "", "elf_")
		if err1 != nil {
			t.Errorf("Failure to write tempfile for executable 1 %v", err1)
		}
		filenames[idx] = filename
	}

	return filenames
}

// dummyCache satisfies the nativeunwind.IntervalCache interface but does not cache
// data. It is used to simulate a broken cache.
type dummyCache struct{ hasIntervals bool }

// HasIntervals satisfies IntervalCache.HasHasIntervals.
func (d *dummyCache) HasIntervals(host.FileID) bool { return d.hasIntervals }

// GetIntervalData satisfies IntervalCache.GetIntervalData.
func (*dummyCache) GetIntervalData(host.FileID, *sdtypes.IntervalData) error {
	return fmt.Errorf("getIntervalData is not implemented for dummyCache")
}

// SaveIntervalData satisfies IntervalCache.SaSaveIntervalData.
func (*dummyCache) SaveIntervalData(host.FileID, *sdtypes.IntervalData) error {
	// To fake an successful write to the cache we need to return nil here.
	return nil
}

// GetCurrentCacheSize satisfies IntervalCache.GetCurrentCacheSize.
func (*dummyCache) GetCurrentCacheSize() (uint64, error) {
	return 0, nil
}

// GetAndResetHitMissCounters satisfies IntervalCache.GetAndResetHitMissCounters
func (*dummyCache) GetAndResetHitMissCounters() (hit, miss uint64) {
	return 0, 0
}

// Make sure on compile time of the test that dummyCache satisfies nativeunwind.IntervalCache.
var _ nativeunwind.IntervalCache = &dummyCache{}

func TestGetIntervalStructuresForFile(t *testing.T) {
	cacheDirectory := doConfigure(t)
	defer os.RemoveAll(cacheDirectory)
	filenames := doWriteExes(t)
	defer func() {
		for _, filename := range filenames {
			os.Remove(filename)
		}
	}()

	localCache, err := localintervalcache.New(2000)
	if err != nil {
		t.Fatalf("Failed to get local interval cache: %v", err)
	}

	tests := map[string]struct {
		cache nativeunwind.IntervalCache
	}{
		// Cache without intervals simulates a test case where the cache of the
		// local stack delta provider does not cache at all.
		"Cache without intervals": {cache: &dummyCache{}},
		// Cache with intervals simulates a test case where the cache of the
		// local stack delta provider has cached something, but the files are actually
		// not there so we expect an error to be logged and the rest of execution to be continued.
		"Cache with intervals": {cache: &dummyCache{true}},
		// Local cache simulates a test case where a regular local interval cache is used
		// to cache interval data.
		"Local cache": {cache: localCache},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			sdp := New(testcase.cache)
			for _, filename := range filenames {
				fileID, err := host.CalculateID(filename)
				if err != nil {
					t.Fatalf("Failed to get FileID for %s: %v", filename, err)
				}
				elfRef := pfelf.NewReference(filename, pfelf.SystemOpener)

				var intervalData, intervalData2 sdtypes.IntervalData
				err = sdp.GetIntervalStructuresForFile(fileID, elfRef, &intervalData)
				if err != nil {
					t.Errorf("Failed to get interval structures: %s", err)
				}
				if len(intervalData.Deltas) == 0 {
					t.Fatalf("Failed to get delta arrays for %s", filename)
				}
				err = sdp.GetIntervalStructuresForFile(fileID, elfRef, &intervalData2)
				if err != nil {
					t.Errorf("Failed to get interval structures: %s", err)
				}
				if len(intervalData2.Deltas) == 0 {
					t.Fatalf("Failed to get delta arrays for %s", filename)
				}
				if diff := cmp.Diff(intervalData, intervalData2); diff != "" {
					t.Errorf("Different interval data for same file:\n%s", diff)
				}
				elfRef.Close()
			}
		})
	}
}

func BenchmarkLocalStackDeltaProvider_GetIntervalStructuresForFile(b *testing.B) {
	b.StopTimer()
	cacheDirectory := doConfigure(b)
	defer os.RemoveAll(cacheDirectory)
	// Try to extract the Go binary running this test
	// this is not going to be comparable between different hosts/go runtimes but
	// it can serve as a real-world case for reading real ELF files
	underTest := ownGoBinary(b)
	// We use dummycache to skip the HasInterval check and focus on the Extract elf method
	sdp := New(&dummyCache{})
	for i := 0; i < b.N; i++ {
		var intervalData sdtypes.IntervalData
		fileID, err := host.CalculateID(underTest)
		if err != nil {
			b.Fatalf("failed to calculate fileID: %v", err)
		}
		b.StartTimer()
		elfRef := pfelf.NewReference(underTest, pfelf.SystemOpener)
		err = sdp.GetIntervalStructuresForFile(fileID, elfRef, &intervalData)
		elfRef.Close()
		b.StopTimer()
		if err != nil {
			b.Fatalf("failed to get interval structures: %v", err)
		}
	}
}

func ownGoBinary(tb testing.TB) string {
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil {
		tb.Fatalf("can't read own process executable symlink")
	}
	return executable
}
