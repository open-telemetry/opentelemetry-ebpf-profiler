/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/elastic/otel-profiling-agent/tools/coredump/modulestore"
)

type exportModuleCmd struct {
	store *modulestore.Store

	// User-specified command line arguments.
	id  string
	out string
}

func newExportModuleCmd(store *modulestore.Store) *ffcli.Command {
	cmd := exportModuleCmd{store: store}
	set := flag.NewFlagSet("export-module", flag.ExitOnError)
	set.StringVar(&cmd.id, "id", "", "ID of the module to extract [required]")
	set.StringVar(&cmd.out, "out", "", "Output path to write module to [required]")

	return &ffcli.Command{
		Name:       "export-module",
		ShortUsage: "export-module [flags]",
		ShortHelp:  "Export a module from the module store to a local path",
		FlagSet:    set,
		Exec:       cmd.exec,
	}
}

func (cmd *exportModuleCmd) exec(context.Context, []string) error {
	if cmd.id == "" {
		return errors.New("missing required argument `-id`")
	}
	if cmd.out == "" {
		return errors.New("missing required argument `-out`")
	}

	id, err := modulestore.IDFromString(cmd.id)
	if err != nil {
		return fmt.Errorf("unable to parse module ID: %w", err)
	}

	return cmd.store.UnpackModuleToPath(id, cmd.out)
}
