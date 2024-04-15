/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

// TracerType values identify tracers, such as the native code tracer, or PHP tracer
type TracerType int

const (
	PerlTracer TracerType = iota
	PHPTracer
	PythonTracer
	HotspotTracer
	RubyTracer
	V8Tracer

	// MaxTracers indicates the max. number of different tracers
	MaxTracers
)

var tracerTypeToString = map[TracerType]string{
	PerlTracer:    "perl",
	PHPTracer:     "php",
	PythonTracer:  "python",
	HotspotTracer: "hotspot",
	RubyTracer:    "ruby",
	V8Tracer:      "v8",
}

// allTracers is returned by a call to AllTracers(). To avoid allocating memory every time the
// function is called we keep the returned array outside of the function.
var allTracers []TracerType

// AllTracers returns a slice containing all supported tracers.
func AllTracers() []TracerType {
	// As allTracers is not immutable we first check if it still holds all
	// expected values before returning it.
	if len(allTracers) != int(MaxTracers) {
		allTracers = make([]TracerType, MaxTracers)
	}

	for i := 0; i < int(MaxTracers); i++ {
		if allTracers[i] != TracerType(i) {
			allTracers[i] = TracerType(i)
		}
	}
	return allTracers
}

// GetString converts the tracer type t to its related string value.
func (t TracerType) GetString() string {
	if result, ok := tracerTypeToString[t]; ok {
		return result
	}

	return "<unknown>"
}
