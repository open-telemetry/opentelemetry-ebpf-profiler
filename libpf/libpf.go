/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// UnixTime32 is another type to represent seconds since epoch.
// In most cases 32bit time values are good enough until year 2106.
// Our time series database backend uses this type for TimeStamps as well,
// so there is no need to use a different type than uint32.
// Also, Go's semantics on map[time.Time] are particularly nasty footguns,
// and since the code is mostly dealing with UNIX timestamps, we may
// as well use uint32s instead.
// To restore some semblance of type safety, we declare a type alias here.
type UnixTime32 uint32

func (t UnixTime32) MarshalJSON() ([]byte, error) {
	return time.Unix(int64(t), 0).UTC().MarshalJSON()
}

// Compile-time interface checks
var _ json.Marshaler = (*UnixTime32)(nil)

// NowAsUInt32 is a convenience function to avoid code repetition
func NowAsUInt32() uint32 {
	return uint32(time.Now().Unix())
}

// UnixTime64 represents nanoseconds or (reduced precision) seconds since epoch.
type UnixTime64 uint64

func (t *UnixTime64) MarshalJSON() ([]byte, error) {
	if *t > math.MaxUint32 {
		// Nanoseconds, ES does not support 'epoch_nanoseconds' so
		// we have to pass it a value formatted as 'strict_date_optional_time_nanos'.
		out := []byte(fmt.Sprintf("%q",
			time.Unix(0, int64(*t)).UTC().Format(time.RFC3339Nano)))
		return out, nil
	}

	// Reduced precision seconds-since-the-epoch, ES 'epoch_second' formatter will match these.
	out := []byte(fmt.Sprintf("%d", *t))
	return out, nil
}

func (t *UnixTime64) UnmarshalJSON(data []byte) error {
	var ts time.Time
	if err := ts.UnmarshalJSON(data); err != nil {
		return err
	}

	*t = UnixTime64(ts.UnixNano())
	return nil
}

// Unix returns the value as seconds since epoch.
func (t *UnixTime64) Unix() int64 {
	if *t > math.MaxUint32 {
		// Nanoseconds, convert to seconds-since-the-epoch
		return time.Unix(0, int64(*t)).Unix()
	}

	return int64(*t)
}

// Compile-time interface checks
var _ json.Marshaler = (*UnixTime64)(nil)

// AddressOrLineno represents a line number in an interpreted file or an offset into
// a native file.
type AddressOrLineno uint64

type TraceAndCounts struct {
	Hash           TraceHash
	Timestamp      UnixTime64
	Count          uint16
	Comm           string
	PodName        string
	ContainerName  string
	APMServiceName string
}

type FrameMetadata struct {
	FileID         FileID
	AddressOrLine  AddressOrLineno
	LineNumber     SourceLineno
	FunctionOffset uint32
	FunctionName   string
	Filename       string
}

// Void allows to use maps as sets without memory allocation for the values.
// From the "Go Programming Language":
//
//	The struct type with no fields is called the empty struct, written struct{}. It has size zero
//	and carries no information but may be useful nonetheless. Some Go programmers
//	use it instead of bool as the value type of a map that represents a set, to emphasize
//	that only the keys are significant, but the space saving is marginal and the syntax more
//	cumbersome, so we generally avoid it.
type Void struct{}

// SourceLineno represents a line number within a source file. It is intended to be used for the
// source line numbers associated with offsets in native code, or for source line numbers in
// interpreted code.
type SourceLineno uint64
