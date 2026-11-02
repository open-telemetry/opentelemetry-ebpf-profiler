// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpfdefs.h"
#include "types.h"
#include "usdt_defs.h"

// usdt_specs maps each process and USDT site to its decoded argument
// locations. USDT-consuming probes create and manage one probe-owned map.
struct usdt_specs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, USDTSpecKey);
  __type(value, USDTSpec);
  // One entry is used per live (PID, runtime probe address). Consumers may
  // scale this base capacity before creating their private map. The heap probe
  // uses a default scale factor of 2, giving it 4096 entries.
  __uint(max_entries, 1024);
} usdt_specs SEC(".maps");
