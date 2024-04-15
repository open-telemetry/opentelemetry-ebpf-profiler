/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package log_test

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/otel-profiling-agent/debug/log"
)

func BenchmarkBaselineLogrus(b *testing.B) {
	cases := []struct {
		name string
		run  func(string)
	}{
		{"Infof", func(s string) { logrus.Infof(s) }},
		{"With_Dot_Infof", func(s string) {
			logrus.WithFields(logrus.Fields{"a": "b"}).Infof(s)
		}},
	}
	for i := range cases {
		bench := cases[i]
		b.Run(bench.name, func(b *testing.B) {
			loggingCall(b, bench.run, logrus.StandardLogger())
		})
	}
}

func BenchmarkLogger(b *testing.B) {
	cases := []struct {
		name string
		run  func(string)
	}{
		{"Infof",
			func(s string) { log.Infof(s) },
		},
		{"With_Dot_Infof",
			func(s string) {
				log.With(log.Labels{"a": "b"}).Infof(s)
			},
		},
	}
	for i := range cases {
		bench := cases[i]
		b.Run(bench.name, func(b *testing.B) {
			loggingCall(b, bench.run, log.StandardLogger())
		})
	}
}

func loggingCall(b *testing.B, underTest func(string), logger log.Logger) {
	b.StopTimer()
	output := setupLogger(logger, b)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		underTest("AAA")
		b.StopTimer()
		if !assert.Contains(b, output.String(), "AAA") {
			b.Fatalf("mismatch in output text")
		}
	}
	output.Reset()
}
