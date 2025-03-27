package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/golang"

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"

// defaultVersion is used if the go binary has an unrecognized major+minor version.
// Consider bumping this whenever a new version of Go is released.
var latestVersion = "go1.24"

// Offsets come from DWARF debug information:
// https://github.com/parca-dev/parca-agent/blob/2815ded21704934c/pkg/runtime/golang/golang.go#L85
// However since DWARF information can be stripped we record them here.
// TODO: Should we look for DWARF information to support new versions
// automatically when available?
var allOffsets = map[string]C.GoCustomLabelsOffsets{
	"go1.13": {
		m_offset:               48,
		curg:                   192,
		labels:                 344,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.14": {
		m_offset:               48,
		curg:                   192,
		labels:                 344,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.15": {
		m_offset:               48,
		curg:                   192,
		labels:                 344,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.16": {
		m_offset:               48,
		curg:                   192,
		labels:                 344,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.17": {
		m_offset:               48,
		curg:                   192,
		labels:                 360,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.18": {
		m_offset:               48,
		curg:                   192,
		labels:                 360,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.19": {
		m_offset:               48,
		curg:                   192,
		labels:                 360,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.20": {
		m_offset:               48,
		curg:                   192,
		labels:                 360,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.21": {
		m_offset:               48,
		curg:                   192,
		labels:                 344,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.22": {
		m_offset:               48,
		curg:                   192,
		labels:                 344,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.23": {
		m_offset:               48,
		curg:                   192,
		labels:                 352,
		hmap_count:             0,
		hmap_log2_bucket_count: 9,
		hmap_buckets:           16,
	},
	"go1.24": {
		m_offset: 48,
		curg:     192,
		labels:   352,
	},
}
