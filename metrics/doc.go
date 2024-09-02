// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
Package metrics contains the code for receiving and reporting host metrics.

The design document can be found at

	https://docs.google.com/document/d/1nGxf-J0gVNqxgGDqJNdJvcw_VBrUa8PVSZYmHj2BH1s

This is the implementation of Proposal C from the design doc.

Example code to initialize metrics reporting:

	defer metrics.Start(mainCtx)()

# Aim

The UI should allow to quickly detect unusual issues. These could be spikes in metrics,
one or more processes eating 100% CPU over a long time, slowness issues over time,
unusual increase in error counters, etc.

We should add user stories here.

# Directory Structure

The current directory structure looks like

	metrics
	├── [sub packages]
	├── doc.go          // this file
	├── metrics.go      // implement Start(), Add() and AddSlice()
	├── metrics_test.go // tests the metrics package
	└── types.go        // definitions of metric ids and Metric, MetricID, MetricValue

# CPU Usage

The CPU usage (sum of user + system read from /proc/stat) is a first 'sub package'
of the metrics package.

The directory structure is

	metrics
	└──cpumetrics/
	   ├── cpu.go
	   ├── cpu_test.go
	   └── testdata
	       ├── procstat.empty
	       ├── procstat.garbage
	       └── procstat.ok

# Comments

Clickhouse stores data "columnar" (which means data for a column will be stored sequentially),
and you can chose different encodings for it.
For example: If you have data that very rarely changes, you can tell clickhouse to encode
only the deltas and put ZSTD compression on that. Essentially all you need to do is append
CODEC(Delta, ZSTD) to your column declaration in the schema.

Clickhouse Overwiev

	https://www.altinity.com/blog/2019/7/new-encodings-to-improve-clickhouse

Clickhouse Docs

	https://clickhouse.tech/docs/en/sql-reference/statements/create/#create-query-specialized-codecs
*/
package metrics
