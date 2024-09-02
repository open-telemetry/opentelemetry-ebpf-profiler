//go:build amd64 && debugtracer

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package support

import (
	_ "embed"
)

//go:embed ebpf/tracer.debug.ebpf.amd64
var debugTracerData []byte
