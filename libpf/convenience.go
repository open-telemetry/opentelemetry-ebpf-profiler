/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	log "github.com/sirupsen/logrus"

	sha256 "github.com/minio/sha256-simd"
)

// HashString turns a string into a 64-bit hash.
func HashString(s string) uint64 {
	h := fnv.New64a()
	if _, err := h.Write([]byte(s)); err != nil {
		log.Fatalf("Failed to write '%v' to hash: %v", s, err)
	}

	return h.Sum64()
}

// HashStrings turns a list of strings into a 128-bit hash.
func HashStrings(strs ...string) []byte {
	h := fnv.New128a()
	for _, s := range strs {
		if _, err := h.Write([]byte(s)); err != nil {
			log.Fatalf("Failed to write '%v' to hash: %v", s, err)
		}
	}
	return h.Sum(nil)
}

// HexToUint64 is a convenience function to extract a hex string to a uint64 and
// not worry about errors. Essentially a "mustConvertHexToUint64".
func HexToUint64(str string) uint64 {
	v, err := strconv.ParseUint(str, 16, 64)
	if err != nil {
		log.Fatalf("Failure to hex-convert %s to uint64: %v", str, err)
	}
	return v
}

// DecToUint64 is a convenience function to extract a decimal string to a uint64
// and not worry about errors. Essentially a "mustConvertDecToUint64".
func DecToUint64(str string) uint64 {
	v, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		log.Fatalf("Failure to dec-convert %s to uint64: %v", str, err)
	}
	return v
}

// WriteTempFile writes a data buffer to a temporary file on the filesystem. It
// is the callers responsibility to clean up that file again. The function returns
// the filename if successful.
func WriteTempFile(data []byte, directory, prefix string) (string, error) {
	file, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("failed to write data to temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("failed to synchronize file data: %w", err)
	}
	return file.Name(), nil
}

// SleepWithJitter sleeps for baseDuration +/- jitter (jitter is [0..1])
func SleepWithJitter(baseDuration time.Duration, jitter float64) {
	time.Sleep(AddJitter(baseDuration, jitter))
}

// SleepWithJitterAndContext blocks for duration +/- jitter (jitter is [0..1]) or until ctx
// is canceled.
func SleepWithJitterAndContext(ctx context.Context, duration time.Duration, jitter float64) error {
	tick := time.NewTicker(AddJitter(duration, jitter))
	defer tick.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tick.C:
		return nil
	}
}

// AddJitter adds +/- jitter (jitter is [0..1]) to baseDuration
func AddJitter(baseDuration time.Duration, jitter float64) time.Duration {
	if jitter < 0.0 || jitter > 1.0 {
		log.Errorf("Jitter (%f) out of range [0..1].", jitter)
		return baseDuration
	}
	// nolint:gosec
	return time.Duration((1 + jitter - 2*jitter*rand.Float64()) * float64(baseDuration))
}

func ComputeFileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// IsValidString checks if string is UTF-8-encoded and only contains expected characters.
func IsValidString(s string) bool {
	if s == "" {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// GetURLWithoutQueryParams returns an URL with all query parameters removed
// For example, http://hello.com/abc?a=1&b=2 becomes http://hello.com/abc
func GetURLWithoutQueryParams(url string) string {
	return strings.Split(url, "?")[0]
}

// NextPowerOfTwo returns the next highest power of 2 for a given value v or v,
// if v is a power of 2.
func NextPowerOfTwo(v uint32) uint32 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

// AtomicUpdateMaxUint32 updates the value in store using atomic memory primitives. newValue will
// only be placed in store if newValue is larger than the current value in store.
// To avoid inconsistency parallel updates to store should be avoided.
func AtomicUpdateMaxUint32(store *atomic.Uint32, newValue uint32) {
	for {
		// Load the current value
		oldValue := store.Load()
		if newValue <= oldValue {
			// No update needed.
			break
		}
		if store.CompareAndSwap(oldValue, newValue) {
			// The value was atomically updated.
			break
		}
		// The value changed between load and update attempt.
		// Retry with the new value.
	}
}

// VersionUint returns a single integer composed of major, minor, patch.
func VersionUint(major, minor, patch uint32) uint32 {
	return (major << 16) + (minor << 8) + patch
}

// SliceFrom converts a Go struct pointer or slice to []byte to read data into
func SliceFrom(data any) []byte {
	var s []byte
	val := reflect.ValueOf(data)
	switch val.Kind() {
	case reflect.Slice:
		if val.Len() != 0 {
			e := val.Index(0)
			addr := e.Addr().UnsafePointer()
			l := val.Len() * int(e.Type().Size())
			s = unsafe.Slice((*byte)(addr), l)
		}
	case reflect.Ptr:
		e := val.Elem()
		addr := e.Addr().UnsafePointer()
		l := int(e.Type().Size())
		s = unsafe.Slice((*byte)(addr), l)
	default:
		panic("invalid type")
	}
	return s
}

// CheckError tries to match err with an error in the passed slice and returns
// true if a match is found.
func CheckError(err error, errList ...error) bool {
	for _, e := range errList {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// CheckCanceled tries to match the first error with context canceled/deadline exceeded
// and returns it. If no match is found, the second error is returned.
func CheckCanceled(err1, err2 error) error {
	if CheckError(err1,
		context.Canceled,
		context.DeadlineExceeded) {
		return err1
	}
	return err2
}
