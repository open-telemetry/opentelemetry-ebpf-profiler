/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package localintervalcache

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/host"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
)

// preTestSetup defines a type for a setup function that can be run prior to a particular test
// executing. It is used below to allow table-drive tests to modify CacheDirectory to point to
// different cache directories, as required.
type preTestSetup func(t *testing.T)

func TestNewIntervalCache(t *testing.T) {
	// nolint:gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	// A top level directory to hold other directories created during this test
	testTopLevel, err := os.MkdirTemp("", "*_TestNewIntervalCache")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(testTopLevel)

	tests := map[string]struct {
		// setupFunc is a function that will be called prior to running a test that will
		// set up a cache directory in a new CacheDirectory, in whatever manner the test
		// requires. It will then modify the configuration to set the config.cacheDirectory
		// equal to the new CacheDirectory.
		setupFunc preTestSetup
		// hasError should be true if a test expects an error from New, or false
		// otherwise.
		hasError bool
		// expectedSize holds the expected size of the cache in bytes.
		expectedSize uint64
	}{
		// Successful creation when there is no pre-existing cache directory
		"CorrectCacheDirectoryNoCache": {
			setupFunc: func(t *testing.T) {
				// A directory to use as CacheDirectory that does not have a cache already
				cacheDirectoryNoCache := path.Join(testTopLevel,
					fmt.Sprintf("%x", seededRand.Uint32()))
				if err := os.Mkdir(cacheDirectoryNoCache, os.ModePerm); err != nil {
					t.Fatalf("Failed to create directory (%s): %s", cacheDirectoryNoCache, err)
				}

				err := config.SetConfiguration(&config.Config{
					ProjectID:      42,
					CacheDirectory: cacheDirectoryNoCache,
					SecretToken:    "secret"})
				if err != nil {
					t.Fatalf("failed to set temporary config: %s", err)
				}
			},
			hasError: false,
		},
		// Successful creation when there is a pre-existing cache
		"CorrectCacheDirectoryWithCache": {
			setupFunc: func(t *testing.T) {
				// A directory to use as CacheDirectory that has an accessible cache
				cacheDirectoryWithCache := path.Join(testTopLevel,
					fmt.Sprintf("%x", seededRand.Uint32()))
				cacheDir := path.Join(cacheDirectoryWithCache, cacheDirPathSuffix())
				if err := os.MkdirAll(cacheDir, os.ModePerm); err != nil {
					t.Fatalf("Failed to create directory (%s): %s", cacheDir, err)
				}

				err := config.SetConfiguration(&config.Config{
					ProjectID:      42,
					CacheDirectory: cacheDirectoryWithCache,
					SecretToken:    "secret"})
				if err != nil {
					t.Fatalf("failed to set temporary config: %s", err)
				}
			},
			hasError: false,
		},
		// Successful creation of a cache with pre-existing elements
		"Use pre-exiting elements": {
			setupFunc: func(t *testing.T) {
				// A directory to use as CacheDirectory that has an accessible cache
				cacheDirectoryWithCache := path.Join(testTopLevel,
					fmt.Sprintf("%x", seededRand.Uint32()))
				cacheDir := path.Join(cacheDirectoryWithCache, cacheDirPathSuffix())
				if err := os.MkdirAll(cacheDir, os.ModePerm); err != nil {
					t.Fatalf("Failed to create directory (%s): %s", cacheDir, err)
				}

				err := config.SetConfiguration(&config.Config{
					ProjectID:      42,
					CacheDirectory: cacheDirectoryWithCache,
					SecretToken:    "secret"})
				if err != nil {
					t.Fatalf("failed to set temporary config: %s", err)
				}
				populateCache(t, cacheDir, 100)
			},
			expectedSize: 100 * 10,
			hasError:     false,
		},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			tc.setupFunc(t)
			expectedCacheDir := path.Join(config.CacheDirectory(), cacheDirPathSuffix())
			cacheDirExistsBeforeTest := true
			if _, err := os.Stat(expectedCacheDir); os.IsNotExist(err) {
				cacheDirExistsBeforeTest = false
			}

			intervalCache, err := New(100)
			if tc.hasError {
				if err == nil {
					t.Errorf("Expected an error but didn't get one")
				}

				if intervalCache != nil {
					t.Errorf("Expected nil IntervalCache")
				}

				if _, err = os.Stat(expectedCacheDir); err == nil && !cacheDirExistsBeforeTest {
					t.Errorf("Cache directory (%s) should not be created on failure",
						expectedCacheDir)
				}
				return
			}

			if err != nil {
				t.Errorf("%s", err)
			}

			if intervalCache == nil {
				t.Fatalf("Expected an IntervalCache but got nil")
				return
			}

			if intervalCache.cacheDir != expectedCacheDir {
				t.Errorf("Expected cache dir '%s' but got '%s'",
					expectedCacheDir, intervalCache.cacheDir)
			}

			if _, err = os.Stat(intervalCache.cacheDir); err != nil {
				t.Errorf("Tried to stat cache dir (%s) and got error: %s",
					intervalCache.cacheDir, err)
			}

			size, err := intervalCache.GetCurrentCacheSize()
			if err != nil {
				t.Fatalf("Failed to get size of cache: %v", err)
			}
			if size != tc.expectedSize {
				t.Fatalf("Expected a size of %d but got %d", tc.expectedSize, size)
			}
		})
	}
}

func TestDeleteObsoletedABICaches(t *testing.T) {
	// A top level directory to hold other directories created during this test
	testTopLevel := setupDirAndConf(t, "*_TestEviction")
	defer os.RemoveAll(testTopLevel)
	cacheDir := path.Join(testTopLevel, cacheDirPathSuffix())
	if err := os.MkdirAll(cacheDir, os.ModePerm); err != nil {
		t.Fatalf("Failed to create directory (%s): %s", cacheDir, err)
	}

	// Prepopulate the cache with 100 elements where each element
	// has a size of 10 bytes.
	populateCache(t, cacheDir, 100)

	// Create an obsolete cache and populate it.
	cacheDirBase := filepath.Dir(cacheDir)
	obsoleteCacheDir := path.Join(cacheDirBase, fmt.Sprintf("%d", sdtypes.ABI-1))
	if err := os.MkdirAll(obsoleteCacheDir, os.ModePerm); err != nil {
		t.Fatalf("Failed to create directory (%s): %s", obsoleteCacheDir, err)
	}
	// Prepopulate the cache with 100 elements where each element
	// has a size of 10 bytes.
	populateCache(t, obsoleteCacheDir, 100)

	cache, err := New(100 * 10)
	if err != nil {
		t.Fatalf("failed to create cache for test: %v", err)
	}

	_, err = cache.GetCurrentCacheSize()
	if err != nil {
		t.Fatalf("Failed to get current size: %v", err)
	}

	if _, err = os.Stat(obsoleteCacheDir); os.IsNotExist(err) {
		// The obsolete cache directory no longer exists. We
		// received the expected error and can return here.
		return
	}
	t.Fatalf("Expected obsolete cache directory to no longer exist but got %v", err)
}

// TestEvictionFullCache tests with a cache that exceeds the maximum size that a newly
// added element is added to the tail of the LRU and after this element got accessed it
// is moved to the front of the LRU.
func TestEvictionFullCache(t *testing.T) {
	// A top level directory to hold other directories created during this test
	testTopLevel := setupDirAndConf(t, "*_TestEviction")
	defer os.RemoveAll(testTopLevel)
	cacheDir := path.Join(testTopLevel, cacheDirPathSuffix())
	if err := os.MkdirAll(cacheDir, os.ModePerm); err != nil {
		t.Fatalf("Failed to create directory (%s): %s", cacheDir, err)
	}

	// Prepopulate the cache with 202 elements where each element
	// has a size of 10 bytes.
	populateCache(t, cacheDir, 202)

	maxCacheSize := uint64(200 * 10)

	cache, err := New(maxCacheSize)
	if err != nil {
		t.Fatalf("failed to create cache for test: %v", err)
	}

	currentCacheSize, err := cache.GetCurrentCacheSize()
	if err != nil {
		t.Fatalf("Failed to get current size: %v", err)
	}
	t.Logf("current cache size before adding new elements: %d", currentCacheSize)

	// Create a new element that will be added to the cache.
	// nolint:gosec
	id := rand.Uint64()
	idString := cache.getPathForCacheFile(host.FileID(id))
	exeID1, intervalData1 := testArtifacts(id)

	// Add the new element to the full cache.
	if err = cache.SaveIntervalData(exeID1, intervalData1); err != nil {
		t.Fatalf("Failed to add new element to cache: %v", err)
	}
	currentCacheSize, err = cache.GetCurrentCacheSize()
	if err != nil {
		t.Fatalf("Failed to get current size: %v", err)
	}
	if currentCacheSize > maxCacheSize {
		t.Fatalf("current cache size (%d) is larger than max cache size (%d)",
			currentCacheSize, maxCacheSize)
	}

	// Make sure the newly added element was added to the front of the LRU.
	currentFirstElement := (cache.lru.Front().Value).(string)
	if !strings.Contains(idString, currentFirstElement) {
		t.Fatalf("Newly inserted element is not first element of lru")
	}

	// Create a new element that will be added to the cache.
	// nolint:gosec
	id2 := rand.Uint64()
	id2String := cache.getPathForCacheFile(host.FileID(id2))
	exeID2, intervalData2 := testArtifacts(id2)

	// Add the new element to the cache.
	if err = cache.SaveIntervalData(exeID2, intervalData2); err != nil {
		t.Fatalf("Failed to add new element to cache: %v", err)
	}

	// Make sure the newly added element was added to the front of the LRU.
	currentFirstElement = (cache.lru.Front().Value).(string)
	if !strings.Contains(id2String, currentFirstElement) {
		t.Fatalf("Newly inserted element is not first element of lru")
	}

	result := new(sdtypes.IntervalData)
	if err := cache.GetIntervalData(exeID1, result); err != nil {
		t.Fatalf("Failed to get interval data: %v", err)
	}

	// Make sure that the last accessed element is the first element of the LRU.
	currentFirstElement = (cache.lru.Front().Value).(string)
	if !strings.Contains(idString, currentFirstElement) {
		t.Fatalf("Newly inserted element is not newest recently used element of lru " +
			"after call to GetIntervalData()")
	}
}

// populateCache creates m fake elements within dir. Each element will have a size of 10 bytes.
func populateCache(t *testing.T, dir string, m int) {
	t.Helper()
	// nolint:gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	dummyContent := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for i := 0; i < m; i++ {
		fileName := dir + fmt.Sprintf("/%x.gz", seededRand.Uint32())
		f, err := os.Create(fileName)
		if err != nil {
			t.Fatalf("Failed to create '%s': %v", fileName, err)
		}
		n, err := f.Write(dummyContent)
		if err != nil || n != 10 {
			t.Fatalf("Failed to write to '%s': %v", fileName, err)
		}
		f.Close()
	}
}

func TestCacheHasIntervals(t *testing.T) {
	// nolint:gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A top level directory to hold other directories created during this test
	testTopLevel, err := os.MkdirTemp("", "TestCacheHasIntervals_*")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(testTopLevel)

	exeID1 := host.FileID(1)
	exeID2 := host.FileID(2)

	tests := map[string]struct {
		// setupFunc is a function that will be called prior to running a test that will
		// set up a cache directory in a new CacheDirectory, in whatever manner the test
		// requires. It will then modify the configuration to set the config.cacheDirectory
		// equal to the new CacheDirectory.
		setupFunc preTestSetup
		// exeID specifies the ID of the executable that we wish to check the cache for
		exeID host.FileID
		// hasIntervals indicates the result we expect from calling intervalCache.HasIntervals
		hasIntervals bool
	}{
		// Check the case where we have interval data
		"hasIntervals": {
			exeID:        exeID1,
			hasIntervals: true,
			setupFunc: func(t *testing.T) {
				// A directory to use as CacheDirectory that has an accessible cache
				validCacheDirectory := path.Join(testTopLevel,
					fmt.Sprintf("%x", seededRand.Uint32()))
				if err := os.Mkdir(validCacheDirectory, os.ModePerm); err != nil {
					t.Fatalf("Failed to create directory (%s): %s", validCacheDirectory, err)
				}

				err := config.SetConfiguration(&config.Config{
					ProjectID:      42,
					CacheDirectory: validCacheDirectory,
					SecretToken:    "secret"})
				if err != nil {
					t.Fatalf("failed to set temporary config: %s", err)
				}

				validIC, err := New(100)
				if err != nil {
					t.Fatalf("failed to create new interval cache")
				}

				// Create a valid cache entry for exeID1
				cacheFile := validIC.getPathForCacheFile(exeID1)
				emptyFile, err := os.Create(cacheFile)
				if err != nil {
					t.Fatalf("Failed to create cache file (%s): %s", cacheFile, err)
				}
				emptyFile.Close()
			}},
		// Check the case where we don't have interval data
		"doesNotHaveIntervals": {
			exeID:        exeID2,
			hasIntervals: false,
			setupFunc: func(t *testing.T) {
				// A directory to use as CacheDirectory that has an accessible cache
				validCacheDirectory := path.Join(testTopLevel,
					fmt.Sprintf("%x", seededRand.Uint32()))
				if err := os.Mkdir(validCacheDirectory, os.ModePerm); err != nil {
					t.Fatalf("Failed to create directory (%s): %s", validCacheDirectory, err)
				}

				err := config.SetConfiguration(&config.Config{
					ProjectID:      42,
					CacheDirectory: validCacheDirectory,
					SecretToken:    "secret"})
				if err != nil {
					t.Fatalf("failed to set temporary config: %s", err)
				}
			}},
		// Check the case where the cache directory is not accessible
		"brokenCacheDir": {
			exeID:        exeID1,
			hasIntervals: false,
			setupFunc: func(t *testing.T) {
				// A directory in which the cache dir is unreadable
				cacheDirectoryWithBrokenCacheDir := path.Join(testTopLevel, fmt.Sprintf("%x",
					seededRand.Uint32()))
				if err := os.Mkdir(cacheDirectoryWithBrokenCacheDir, os.ModePerm); err != nil {
					t.Fatalf("Failed to create directory (%s): %s",
						cacheDirectoryWithBrokenCacheDir, err)
				}

				err := config.SetConfiguration(&config.Config{
					ProjectID:      42,
					CacheDirectory: cacheDirectoryWithBrokenCacheDir,
					SecretToken:    "secret"})
				if err != nil {
					t.Fatalf("failed to set temporary config: %s", err)
				}

				icWithBrokenCache, err := New(100)
				if err != nil {
					t.Fatalf("failed to create interval cache: %s", err)
				}
				if err = os.Remove(icWithBrokenCache.cacheDir); err != nil {
					t.Fatalf("Failed to remove %s: %s", icWithBrokenCache.cacheDir, err)
				}
			}}}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			tc.setupFunc(t)
			ic, err := New(100)
			if err != nil {
				t.Fatalf("failed to create interval cache: %s", err)
			}
			hasIntervals := ic.HasIntervals(tc.exeID)

			if tc.hasIntervals != hasIntervals {
				t.Errorf("Expected %v but got %v", tc.hasIntervals, hasIntervals)
			}
		})
	}
}

func TestSaveAndGetIntervalData(t *testing.T) {
	tmpDir := setupDirAndConf(t, "TestSaveAndGetIntervaldata_*")
	defer os.RemoveAll(tmpDir)

	tests := map[string]struct {
		// maxCacheSize defines the maximum size of the test cache.
		maxCacheSize uint64
		// saveErr defines an expected error if any for a call to SaveIntervalData.
		saveErr error
	}{
		"too small cache": {maxCacheSize: 100, saveErr: errElementTooLarge},
		"regular cache":   {maxCacheSize: 1000},
	}

	exeID, intervalData := testArtifacts(1)

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			icWithData, err := New(test.maxCacheSize)
			if err != nil {
				t.Fatalf("Failed to create IntervalCache: %s", err)
			}

			if err := icWithData.SaveIntervalData(exeID, intervalData); err != nil {
				if test.saveErr != nil && errors.Is(err, test.saveErr) {
					// We received the expected error and can return here.
					return
				}
				t.Fatalf("Failed to save interval data: %v", err)
			}
			if test.saveErr != nil {
				t.Fatalf("Expected '%s' but got none", test.saveErr)
			}

			result := new(sdtypes.IntervalData)

			if err := icWithData.GetIntervalData(exeID, result); err != nil {
				t.Fatalf("Failed to get interval data: %v", err)
			}

			if diff := cmp.Diff(intervalData, result); diff != "" {
				t.Errorf("GetIntervaldata() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkCache_SaveIntervalData(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	tmpDir := setupDirAndConf(b, "BenchmarkSaveIntervalData_*")
	defer os.RemoveAll(tmpDir)
	intervalCache, err := New(1000)
	if err != nil {
		b.Fatalf("Failed to create IntervalCache: %s", err)
	}

	exe, data := testArtifacts(1)

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		err := intervalCache.SaveIntervalData(exe, data)
		b.StopTimer()
		if err != nil {
			b.Fatalf("SaveIntervalData error: %v", err)
		}
		assert.Nil(b, os.Remove(intervalCache.getPathForCacheFile(exe)))
	}
}

func BenchmarkCache_GetIntervalData(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	tmpDir := setupDirAndConf(b, "BenchmarkGetIntervalData_*")
	defer os.RemoveAll(tmpDir)
	intervalCache, err := New(1000)
	if err != nil {
		b.Fatalf("Failed to create IntervalCache: %s", err)
	}

	exe, data := testArtifacts(1)
	if err := intervalCache.SaveIntervalData(exe, data); err != nil {
		b.Fatalf("error storing cache: %v", err)
	}

	for i := 0; i < b.N; i++ {
		var result sdtypes.IntervalData
		b.StartTimer()
		err := intervalCache.GetIntervalData(exe, &result)
		b.StopTimer()
		if err != nil {
			b.Fatalf("GetIntervalData error: %v", err)
		}
		assert.Equal(b, data, &result)
	}
}

func deltaSP(sp int32) sdtypes.UnwindInfo {
	return sdtypes.UnwindInfo{Opcode: sdtypes.UnwindOpcodeBaseSP, Param: sp}
}

func testArtifacts(id uint64) (host.FileID, *sdtypes.IntervalData) {
	exeID := host.FileID(id)

	intervalData := &sdtypes.IntervalData{
		Deltas: []sdtypes.StackDelta{
			{Address: 0 + id, Info: deltaSP(16)},
			{Address: 100 + id, Info: deltaSP(3)},
			{Address: 110 + id, Info: deltaSP(64)},
			{Address: 190 + id, Info: deltaSP(48)},
			{Address: 200 + id, Info: deltaSP(16)},
		},
	}
	return exeID, intervalData
}

// setupDirAndConf creates a temporary directory and sets the host-agent
// configuration with the test directory to avoid collisions during tests.
// Returns the path of the directory to be used for testing:
// the caller is responsible to delete this directory.
func setupDirAndConf(tb testing.TB, pattern string) string {
	// A top level directory to hold test artifacts
	testTopLevel, err := os.MkdirTemp("", pattern)
	if err != nil {
		tb.Fatalf("Failed to create temporary directory: %v", err)
	}

	if err = config.SetConfiguration(&config.Config{
		ProjectID:      42,
		CacheDirectory: testTopLevel,
		SecretToken:    "secret"}); err != nil {
		tb.Fatalf("failed to set temporary config: %s", err)
	}
	return testTopLevel
}
