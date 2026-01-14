// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

// Various used ruby ushift constants
// calculates them here based on RUBY_FL_USHIFT, copying their logic
const (
	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L158
	RUBY_FL_USHIFT = 12

	RUBY_FL_USER0 = 1 << (RUBY_FL_USHIFT + 0)
	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L323-L324
	RUBY_FL_USER1 = 1 << (RUBY_FL_USHIFT + 1)

	// Used for computing embed array flag
	RUBY_FL_USER3 = 1 << (RUBY_FL_USHIFT + 3)
	RUBY_FL_USER4 = 1 << (RUBY_FL_USHIFT + 4)
	RUBY_FL_USER5 = 1 << (RUBY_FL_USHIFT + 5)
	RUBY_FL_USER6 = 1 << (RUBY_FL_USHIFT + 6)
	RUBY_FL_USER7 = 1 << (RUBY_FL_USHIFT + 7)
	RUBY_FL_USER8 = 1 << (RUBY_FL_USHIFT + 8)
	RUBY_FL_USER9 = 1 << (RUBY_FL_USHIFT + 9)

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L102
	RARRAY_EMBED_FLAG = RUBY_FL_USER1

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L114-L115
	RARRAY_EMBED_LEN_MASK = RUBY_FL_USER9 | RUBY_FL_USER8 | RUBY_FL_USER7 | RUBY_FL_USER6 |
		RUBY_FL_USER5 | RUBY_FL_USER4 | RUBY_FL_USER3

	// RARRAY_EMBED_LEN_SHIFT
	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L122-L125
	RARRAY_EMBED_LEN_SHIFT = RUBY_FL_USHIFT + 3
)
