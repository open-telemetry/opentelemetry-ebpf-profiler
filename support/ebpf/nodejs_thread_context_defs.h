// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The V8 layout is fixed by the nodejs_v1 schema, which admits only 64-bit
// builds without pointer compression and the V8 sandbox.

// NODE_TC_TAGGED_SIZE defines the width of a V8 tagged word.
#define NODE_TC_TAGGED_SIZE        8
// NODE_TC_JSMAP_TABLE_OFFSET defines the offset of the OrderedHashMap pointer
// within a JSMap.
#define NODE_TC_JSMAP_TABLE_OFFSET 24
// NODE_TC_FIXED_ARRAY_HEADER defines the FixedArray header size preceding the
// OrderedHashMap counts.
#define NODE_TC_FIXED_ARRAY_HEADER 16
// NODE_TC_HASH_COUNTS defines the number of count words ahead of the buckets.
#define NODE_TC_HASH_COUNTS        3
// NODE_TC_HASH_ENTRY_SIZE defines the words per entry: key, value and chain.
#define NODE_TC_HASH_ENTRY_SIZE    3
// NODE_TC_HASH_LOAD_FACTOR defines the entries per bucket V8 allocates.
#define NODE_TC_HASH_LOAD_FACTOR   2
// NODE_TC_MAX_CHAIN defines the bucket chain length walked before giving up.
#define NODE_TC_MAX_CHAIN          16

// NODE_TC_TEST_* define what raw_tracepoint_integration__node_tc_record found.
#define NODE_TC_TEST_NONE     0
#define NODE_TC_TEST_EXPECTED 1
#define NODE_TC_TEST_OTHER    2
