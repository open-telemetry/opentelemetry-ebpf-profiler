/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package basehash

import (
	"encoding/json"
	"strconv"
)

type Hash64 uint64

func (h *Hash64) String() string {
	return string(marshalQuotedIdentifier(uint64(*h), uint64(*h)))
}

func (h *Hash64) MarshalJSON() ([]byte, error) {
	return marshalQuotedIdentifier(uint64(*h), uint64(*h)), nil
}

func (h *Hash64) UnmarshalJSON(b []byte) error {
	tempHash, err := strconv.ParseUint(string(b)[1:17], 16, 64)
	if err != nil {
		return err
	}
	*h = Hash64(tempHash)
	return nil
}

// Compile-time interface checks
var _ json.Marshaler = (*Hash64)(nil)
var _ json.Unmarshaler = (*Hash64)(nil)
