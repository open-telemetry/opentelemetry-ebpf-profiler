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
  // One entry is used per live (PID, runtime probe address). This default
  // supports 4096 single-site processes at about 1 MiB of locked memory.
  // Consumers may override MaxEntries before creating their private map.
  __uint(max_entries, 4096);
} usdt_specs SEC(".maps");
