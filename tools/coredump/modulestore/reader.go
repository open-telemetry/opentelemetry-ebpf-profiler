/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package modulestore

import "io"

// ModuleReader allows reading a module from the module store.
type ModuleReader struct {
	io.ReaderAt
	io.Closer
	preferredReadSize uint
	size              uint
}

// PreferredReadSize returns the preferred size and alignment of reads on this reader.
func (m *ModuleReader) PreferredReadSize() uint {
	return m.preferredReadSize
}

// Size returns the uncompressed size of the module.
func (m *ModuleReader) Size() uint {
	return m.size
}
