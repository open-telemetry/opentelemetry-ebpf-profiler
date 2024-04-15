/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package log_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/otel-profiling-agent/debug/log"
)

// SetLevel can be used to instruct the logger which type of levels should direct
// the log message to the log output.
func ExampleSetLevel() {
	// Set the logger to DEBUG, store every message
	log.SetLevel(log.DebugLevel)
	log.Infof("This will be logged")

	log.SetLevel(log.ErrorLevel)
	log.Infof("Now this will not be logged")
}

// With can be used to add arbitrary key/value pairs (fields) to log messages,
// enabling fine-grained filtering based on fields' values.
func ExampleWith() {
	aFile, err := os.CreateTemp("", "content_to_be_read")
	if err != nil {
		panic(err)
	}
	defer os.Remove(aFile.Name())
	contentOf := func(reader io.Reader) []byte {
		b, err := io.ReadAll(reader)
		if err != nil {
			// We record in a log the read error,
			// adding a label with the file name we failed to read.
			log.With(log.Labels{"file_name": aFile.Name()}).Errorf("failed: %v", err)
			return nil
		}
		return b
	}
	fmt.Fprint(os.Stdout, contentOf(aFile))
}

func TestLogging_sharedLoggerHasDefaults(t *testing.T) {
	logger := log.StandardLogger()
	assert.NotNil(t, logger)
	assert.Equal(t, logger.(*logrus.Logger).Level, logrus.InfoLevel)
	log.SetLevel(log.WarnLevel)
	assert.Equal(t, logger.(*logrus.Logger).Level, logrus.WarnLevel)
}

func TestLogging_logsHasRFC3339NanoTimestamp(t *testing.T) {
	output := setupLogger(log.StandardLogger(), t)
	log.Infof("Something: %s", "test")
	assert.Regexp(t, `time="[0-9\-]+T[0-9:]+\.[0-9]{9}(\+|\-|Z)([0-9:]+)?"`, output.String())
}

func TestLogging_logLinesCanBeRecordedWithMultipleArgs(t *testing.T) {
	output := setupLogger(log.StandardLogger(), t)
	log.Infof("Something: %s - %d - %f", "test1", 2, 3.4)
	assert.Contains(t, output.String(),
		fmt.Sprintf(`msg="Something: %s - %d - %f"`, "test1", 2, 3.4))
}

// We want to test all levels but Fatalf requires a separate test
func TestLogging_leveledLoggerOnAllLevelsButFatal(t *testing.T) {
	output := setupLogger(log.StandardLogger(), t)
	tests := map[string]func(string, ...any){
		"fatal":   log.Fatalf,
		"error":   log.Errorf,
		"warning": log.Warnf,
		"info":    log.Infof,
		"debug":   log.Debugf,
	}
	for name, run := range tests {
		level := name
		run := run
		t.Run(name, func(t *testing.T) {
			run("%s-test", level)
			assert.Contains(t, output.String(), fmt.Sprintf(`level=%s`, level))
			assert.Contains(t, output.String(),
				fmt.Sprintf(`msg=%s-test`, level))
		})
	}
}

func TestLogging_logWithLabels(t *testing.T) {
	output := setupLogger(log.StandardLogger(), t)
	log.With(log.Labels{
		"key": "val",
	}).Infof("test")
	assert.Contains(t, output.String(), fmt.Sprintf(`%s=%s`, "key", "val"))
}

func TestLogging_logWithNumericLabelValues(t *testing.T) {
	output := setupLogger(log.StandardLogger(), t)
	log.With(log.Labels{
		"key": 123,
	}).Infof("test")
	assert.Contains(t, output.String(), fmt.Sprintf(`%s=%d`, "key", 123))
}

func TestLogging_logStateWithLabels(t *testing.T) {
	output := setupLogger(log.StandardLogger(), t)
	const emptyKey = "empty"
	log.With(log.Labels{
		"key":    "val",
		emptyKey: "",
	}).Infof("test")
	assert.Contains(t, output.String(), fmt.Sprintf(`%s=%s`, "key", "val"))
	// Ensure empty fields are in quotes for later parsing
	assert.Contains(t, output.String(), fmt.Sprintf(`%s=""`, emptyKey))
}

func TestLogging_logJSONFormatter(t *testing.T) {
	const (
		fieldKeyLevel = "log.level"
		fieldKeyMsg   = "message"
		serviceName   = "testService"
		testMsg       = "testMsg"
	)

	output := setupLogger(log.StandardLogger(), t)

	log.SetJSONFormatter(
		logrus.JSONFormatter{
			DisableTimestamp: true,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyLevel: fieldKeyLevel,
				logrus.FieldKeyMsg:   fieldKeyMsg,
			},
		},
		serviceName)

	log.Info(testMsg)

	type JSONFormatterResult struct {
		Level string `json:"log.level"`
		Msg   string `json:"message"`
		Name  string `json:"service.name"`
	}

	var r JSONFormatterResult
	err := json.NewDecoder(output).Decode(&r)
	assert.Nil(t, err)

	assert.Equal(t, "info", r.Level)
	assert.Equal(t, testMsg, r.Msg)
	assert.Equal(t, serviceName, r.Name)
}

func setupLogger(logger log.Logger, tb testing.TB) *bytes.Buffer {
	b := bytes.NewBufferString("")
	logger.(*logrus.Logger).Out = b
	logger.(*logrus.Logger).SetLevel(logrus.DebugLevel)
	logger.(*logrus.Logger).ExitFunc = func(int) {
		if tb.Failed() {
			tb.Fatalf("error running test %s", tb.Name())
		}
	}
	return b
}
