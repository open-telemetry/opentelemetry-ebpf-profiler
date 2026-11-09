// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpfdefs.h"
#include "types.h"
#include "usdt_defs.h"

// usdt_specs maps each process and USDT site to its decoded argument
// locations. USDT-consuming probes create and manage one probe-owned map.
//
// Keying by (PID, runtime address) keeps the eBPF lookup to a single map
// access. An alternative is to key by (FileID, file offset), sharing one
// entry per file and site across processes. That would use less memory but
// needs FileID refcounting in userspace and an extra pid_page_to_mapping_info
// lookup in eBPF. It may be worth revisiting if USDT probes are ever attached
// system-wide rather than per PID.
struct usdt_specs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, USDTSpecKey);
  __type(value, USDTSpec);
  // One entry is used per live (PID, runtime probe address). Consumers may
  // scale this base capacity before creating their private map. The heap probe
  // uses a default scale factor of 2, giving it 4096 entries.
  __uint(max_entries, 1024);
} usdt_specs SEC(".maps");
