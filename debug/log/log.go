/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package log

import (
	"github.com/sirupsen/logrus"
)

const (
	PanicLevel = logrus.PanicLevel
	FatalLevel = logrus.FatalLevel
	ErrorLevel = logrus.ErrorLevel
	WarnLevel  = logrus.WarnLevel
	InfoLevel  = logrus.InfoLevel
	DebugLevel = logrus.DebugLevel

	// time.RFC3339Nano removes trailing zeros from the seconds field.
	// The following format doesn't (fixed-width output).
	timeStampFormat = "2006-01-02T15:04:05.000000000Z07:00"
)

type JSONFormatter struct {
	formatter   logrus.JSONFormatter
	serviceName string
}

func (l JSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if l.serviceName != "" {
		entry.Data["service.name"] = l.serviceName
	}
	return l.formatter.Format(entry)
}

// The default logger sets properties to work with the rest of the platform:
// log collection happens from StdOut, with precise timestamps and full level names.
// This variable is a pointer to the logger singleton offered by the underlying library
// and should be shared across the whole application that wants to consume it, rather than copied.
var logger = StandardLogger()

// StandardLogger provides a global instance of the logger used in this package:
// it should be the only logger used inside an application.
// This function mirrors the library API currently used in our codebase, applying
// default settings to the logger that conforms to the structured logging practices
// we want to adopt: always-quoted fields (for easier parsing), microsecond-resolution
// timestamps.
func StandardLogger() Logger {
	l := logrus.StandardLogger()
	// TextFormatter is the key/value pair format that allows for logs labeling;
	// here we define the format that will have to be parsed by other components,
	// updating these properties will require reviewing the rest of the log processing pipeline.
	l.SetFormatter(&logrus.TextFormatter{
		DisableColors:          true,
		FullTimestamp:          true,
		ForceQuote:             false,
		TimestampFormat:        timeStampFormat,
		DisableSorting:         true,
		DisableLevelTruncation: true,
		QuoteEmptyFields:       true,
	})
	// Default Level
	l.SetLevel(InfoLevel)
	// Allow concurrent writes to log destination (os.Stdout).
	l.SetNoLock()
	// Explicitly disable method/package fields to every message line,
	// because there will be no use of them
	l.SetReportCaller(false)
	return l
}

// Logger is the type to encapsulate structured logging, embeds the logging library interface.
type Logger interface {
	logrus.FieldLogger
}

// Labels to add key/value pairs to messages, to be used later in the pipeline for filtering.
type Labels map[string]any

// With augments the structured log message using the provided key/value map,
// every entry will be written as a separate label, and we should avoid
// inserting values with unbound number of unique occurrences.
// Using high-cardinality values (in the order of tens of unique values)
// does not pose a performance problem when writing the logs, but when reading them.
// We risk hogging the parsing/querying part of the log pipeline, requiring high
// resource consumption when filtering based on many unique label values.
func With(labels Labels) Logger {
	return logger.WithFields(logrus.Fields(labels))
}

// Printf mirrors the library function, using the global logger.
func Printf(format string, args ...any) {
	logger.Printf(format, args...)
}

// Fatalf mirrors the library function, using the global logger.
func Fatalf(format string, args ...any) {
	logger.Fatalf(format, args...)
}

// Errorf mirrors the library function, using the global logger.
func Errorf(format string, args ...any) {
	logger.Errorf(format, args...)
}

// Warnf mirrors the library function, using the global logger.
func Warnf(format string, args ...any) {
	logger.Warnf(format, args...)
}

// Infof mirrors the library function, using the global logger.
func Infof(format string, args ...any) {
	logger.Infof(format, args...)
}

// Debugf mirrors the library function, using the global logger.
func Debugf(format string, args ...any) {
	logger.Debugf(format, args...)
}

// Print mirrors the library function, using the global logger.
func Print(args ...any) {
	logger.Print(args...)
}

// Fatal mirrors the library function, using the global logger.
func Fatal(args ...any) {
	logger.Fatal(args...)
}

// Error mirrors the library function, using the global logger.
func Error(args ...any) {
	logger.Error(args...)
}

// Warn mirrors the library function, using the global logger.
func Warn(args ...any) {
	logger.Warn(args...)
}

// Info mirrors the library function, using the global logger.
func Info(args ...any) {
	logger.Info(args...)
}

// Debug mirrors the library function, using the global logger.
func Debug(args ...any) {
	logger.Debug(args...)
}

// SetLevel of the global logger.
func SetLevel(level logrus.Level) {
	logger.(*logrus.Logger).SetLevel(level)
}

// SetJSONFormatter replaces the default Formatter settings with the given ones.
func SetJSONFormatter(formatter logrus.JSONFormatter, serviceName string) {
	logger.(*logrus.Logger).SetFormatter(JSONFormatter{
		formatter:   formatter,
		serviceName: serviceName,
	})
}
