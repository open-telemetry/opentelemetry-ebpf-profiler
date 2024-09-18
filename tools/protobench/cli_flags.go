/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"

	"github.com/peterbourgon/ff/v3"
)

const (
	defaultArgInputDir   = ""
	defaultArgOutputFile = ""
)

// Help strings for command line arguments
var (
	inputDirHelp   = "Directory to read and compress files from."
	outputFileHelp = "Output file to store the benchmark results (*.csv or *.png)."
)

type arguments struct {
	inputDir   string
	outputFile string

	fs *flag.FlagSet
}

func (args *arguments) SanityCheck() error {
	if args.inputDir == "" {
		return errors.New("no protobuf message directory specified")
	}

	if args.outputFile != "" {
		switch filepath.Ext(args.outputFile) {
		case ".csv", ".png":
		default:
			return errors.New("output file must be either a .csv or .png file")
		}
	}

	return nil
}

// Package-scope variable, so that conditionally compiled other components can refer
// to the same flagset.

func parseArgs() (*arguments, error) {
	var args arguments

	fs := flag.NewFlagSet("protobench", flag.ExitOnError)

	fs.StringVar(&args.inputDir, "input-dir", defaultArgInputDir, inputDirHelp)
	fs.StringVar(&args.outputFile, "output-file", defaultArgOutputFile, outputFileHelp)

	fs.Usage = func() {
		fs.PrintDefaults()
	}

	args.fs = fs

	return &args, ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("OTEL_PROTOBENCH"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ff.PlainParser),
		ff.WithAllowMissingConfigFile(true),
	)
}
