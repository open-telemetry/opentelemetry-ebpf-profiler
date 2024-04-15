/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package basehash

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromBytes(t *testing.T) {
	_, err := New128FromBytes(nil)
	assert.Error(t, err)

	b := []byte{}
	_, err = New128FromBytes(b)
	assert.Error(t, err)

	b = []byte{1}
	_, err = New128FromBytes(b)
	assert.Error(t, err)

	b = []byte{0, 1, 2, 3, 4, 5, 6, 7}
	_, err = New128FromBytes(b)
	assert.Error(t, err)

	b = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	hash, err := New128FromBytes(b)
	assert.NoError(t, err)
	assert.Equal(t, New128(0x01020304050607, 0x08090A0B0C0D0E0F), hash)
}

func TestEqual(t *testing.T) {
	hash := New128(0xDEC0DE, 0xC0FFEE)

	assert.True(t, hash.Equal(New128(0xDEC0DE, 0xC0FFEE)))
	assert.False(t, hash.Equal(New128(0xDEC0DE, 0)))
	assert.False(t, hash.Equal(New128(0, 0xC0FFEE)))
	assert.False(t, hash.Equal(New128(0xDECADE, 0xCAFE)))
}

func TestLess(t *testing.T) {
	// left.hi == right.hi and left.lo < right.lo
	a, b := New128(0, 1), New128(0, 2)
	assert.True(t, a.Less(b))

	// left.hi == right.hi and left.lo > right.lo
	c, d := New128(0, 2), New128(0, 1)
	assert.False(t, c.Less(d))

	// left.hi == right.hi and left.lo == right.lo
	e, f := New128(0, 2), New128(0, 2)
	assert.False(t, e.Less(f))

	// left.hi < right.hi
	g, h := New128(0, 0), New128(1, 1)
	assert.True(t, g.Less(h))

	// left.hi > right.hi
	i, j := New128(1, 1), New128(0, 0)
	assert.False(t, i.Less(j))
}

func TestIsZero(t *testing.T) {
	assert.True(t, New128(0, 0).IsZero())
	assert.False(t, New128(5550100, 0).IsZero())
	assert.False(t, New128(0, 5550100).IsZero())
	assert.False(t, New128(5550100, 5550100).IsZero())
}

func TestBytes(t *testing.T) {
	hash := New128(0, 0)
	assert.Equal(t, hash.Bytes(), []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0})

	hash = New128(0xDEC0DE, 0xC0FFEE)
	assert.Equal(t, hash.Bytes(), []byte{
		0, 0, 0, 0, 0, 0xDE, 0xC0, 0xDE,
		0, 0, 0, 0, 0, 0xC0, 0xFF, 0xEE})

	hash = New128(0, 0xC0FFEE)
	assert.Equal(t, hash.Bytes(), []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0xC0, 0xFF, 0xEE})

	maxUint64 := ^uint64(0)
	hash = New128(maxUint64, maxUint64)
	assert.Equal(t, hash.Bytes(), []byte{
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF})
}

func TestPutBytes16(t *testing.T) {
	var b [16]byte
	hash := New128(0x0011223344556677, 0x8899AABBCCDDEEFF)
	hash.PutBytes16(&b)

	assert.Equal(t, hash.Bytes(), []byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB,
		0xCC, 0xDD, 0xEE, 0xFF})
}

func TestHash128Format(t *testing.T) {
	h, _ := New128FromBytes([]byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB,
		0xCC, 0xDD, 0xEE, 0xFF})

	tests := map[string]struct {
		formater string
		expected string
	}{
		"v":  {formater: "%v", expected: "{4822678189205111 9843086184167632639}"},
		"d":  {formater: "%d", expected: "{4822678189205111 9843086184167632639}"},
		"x":  {formater: "%x", expected: "112233445566778899aabbccddeeff"},
		"X":  {formater: "%X", expected: "112233445566778899AABBCCDDEEFF"},
		"#v": {formater: "%#v", expected: "0x112233445566778899aabbccddeeff"},
		"#x": {formater: "%#x", expected: "0x112233445566778899aabbccddeeff"},
		"#X": {formater: "%#X", expected: "0x112233445566778899AABBCCDDEEFF"},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			output := fmt.Sprintf(test.formater, h)
			if output != test.expected {
				t.Fatalf("Expected '%s' but got '%s'", test.expected, output)
			}
		})
	}
}

func TestHash128StringNoQuotes(t *testing.T) {
	id := New128(0x0011223344556677, 0x8899AABBCCDDEEFF)
	assert.Equal(t, "00112233445566778899aabbccddeeff", id.StringNoQuotes())
}

func TestNew128FromString(t *testing.T) {
	tests := map[string]struct { //nolint
		stringRepresentation string
		expected             Hash128
		err                  error
	}{
		"hex": {stringRepresentation: "97b7371e9fc83bc7b9ab5ee193a98020",
			expected: Hash128{hi: 10932267225134414791, lo: 13378891440972202016}},
		"hex with prefix": {stringRepresentation: "0x97b7371e9fc83bc7b9ab5ee193a98020",
			expected: Hash128{hi: 10932267225134414791, lo: 13378891440972202016}},
		"uuid": {stringRepresentation: "97b7371e-9fc8-3bc7-b9ab-5ee193a98020",
			expected: Hash128{hi: 10932267225134414791, lo: 13378891440972202016}},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			got, err := New128FromString(tc.stringRepresentation)
			if !errors.Is(err, tc.err) {
				t.Fatalf("Expected '%v' but got '%v'", tc.err, err)
			}
			if !got.Equal(tc.expected) {
				t.Fatalf("Expected %v from '%s' but got %v", tc.expected,
					tc.stringRepresentation, got)
			}
		})
	}
}
