/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import "github.com/elastic/otel-profiling-agent/support"

// InterpreterType variables can hold one of the interpreter type values defined below.
type InterpreterType int

const (
	// UnknownInterp signifies that the interpreter is unknown.
	UnknownInterp InterpreterType = support.FrameMarkerUnknown
	// PHP identifies the PHP interpreter.
	PHP InterpreterType = support.FrameMarkerPHP
	// PHPJIT identifies PHP JIT processes.
	PHPJIT InterpreterType = support.FrameMarkerPHPJIT
	// Python identifies the Python interpreter.
	Python InterpreterType = support.FrameMarkerPython
	// Native identifies native code.
	Native InterpreterType = support.FrameMarkerNative
	// Kernel identifies kernel code.
	Kernel InterpreterType = support.FrameMarkerKernel
	// HotSpot identifies the Java HotSpot VM.
	HotSpot InterpreterType = support.FrameMarkerHotSpot
	// Ruby identifies the Ruby interpreter.
	Ruby InterpreterType = support.FrameMarkerRuby
	// Perl identifies the Perl interpreter.
	Perl InterpreterType = support.FrameMarkerPerl
	// V8 identifies the V8 interpreter.
	V8 InterpreterType = support.FrameMarkerV8
	// Dotnet identifies the Dotnet interpreter.
	Dotnet InterpreterType = support.FrameMarkerDotnet
)

// Pseudo-interpreters without a corresponding frame type.
const (
	// pseudoInterpreterStart marks the start of the pseudo interpreter ID space.
	pseudoInterpreterStart InterpreterType = 0x100

	// APMInt identifies the pseudo-interpreter for the APM integration.
	APMInt InterpreterType = 0x100
)

// Frame converts the interpreter type into the corresponding frame type.
func (i InterpreterType) Frame() FrameType {
	if i >= pseudoInterpreterStart {
		return unknownFrame
	}

	return FrameType(i)
}

var interpreterTypeToString = map[InterpreterType]string{
	UnknownInterp: "unknown",
	PHP:           "php",
	PHPJIT:        "phpjit",
	Python:        "python",
	Native:        "native",
	Kernel:        "kernel",
	HotSpot:       "jvm",
	Ruby:          "ruby",
	Perl:          "perl",
	V8:            "v8",
	Dotnet:        "dotnet",
	APMInt:        "apm-integration",
}

var stringToInterpreterType = make(map[string]InterpreterType, len(interpreterTypeToString))

func init() {
	for k, v := range interpreterTypeToString {
		stringToInterpreterType[v] = k
	}
}

func InterpreterTypeFromString(name string) InterpreterType {
	if result, ok := stringToInterpreterType[name]; ok {
		return result
	}
	return UnknownInterp
}

// String converts the frame type int to the related string value to be displayed in the UI.
func (i InterpreterType) String() string {
	if result, ok := interpreterTypeToString[i]; ok {
		return result
	}
	//nolint:goconst
	return "<invalid>"
}
