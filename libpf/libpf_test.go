/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import (
	"fmt"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestFileIDSprintf(t *testing.T) {
	var origID FileID
	var err error

	if origID, err = FileIDFromString("600DCAFE4A110000F2BF38C493F5FB92"); err != nil {
		t.Fatalf("Failed to build FileID from string: %v", err)
	}

	marshaled := fmt.Sprintf("%d", origID)
	// nolint:goconst
	expected := "{6921411395851452416 17491761894677412754}"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%s", origID)
	expected = "{%!s(uint64=6921411395851452416) %!s(uint64=17491761894677412754)}"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%v", origID)
	expected = "{6921411395851452416 17491761894677412754}"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%#v", origID)
	expected = "0x600dcafe4a110000f2bf38c493f5fb92"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	fileID := NewFileID(5705163814651576546, 12305932466601883523)

	marshaled = fmt.Sprintf("%x", fileID)
	expected = "4f2cd0431db840e2aac77460f5c07783"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%X", fileID)
	expected = "4F2CD0431DB840E2AAC77460F5C07783"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%#x", fileID)
	expected = "0x4f2cd0431db840e2aac77460f5c07783"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%#X", fileID)
	expected = "0x4F2CD0431DB840E2AAC77460F5C07783"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}
}

func TestFileIDMarshal(t *testing.T) {
	var origID FileID
	var err error

	if origID, err = FileIDFromString("600DCAFE4A110000F2BF38C493F5FB92"); err != nil {
		t.Fatalf("Failed to build FileID from string: %v", err)
	}

	// Test (Un)MarshalJSON
	var data []byte
	if data, err = origID.MarshalJSON(); err != nil {
		t.Fatalf("Failed to marshal FileID: %v", err)
	}

	marshaled := string(data)
	expected := "\"600dcafe4a110000f2bf38c493f5fb92\""
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	var jsonID FileID
	if err = jsonID.UnmarshalJSON(data); err != nil {
		t.Fatalf("Failed to unmarshal FileID: %v", err)
	}

	if jsonID != origID {
		t.Fatalf("new FileID is different to original one. Expected %d, got %d", origID, jsonID)
	}

	// Test (Un)MarshalText
	if data, err = origID.MarshalText(); err != nil {
		t.Fatalf("Failed to marshal FileID: %v", err)
	}

	marshaled = string(data)
	expected = "600dcafe4a110000f2bf38c493f5fb92"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	var textID FileID
	if err = textID.UnmarshalText(data); err != nil {
		t.Fatalf("Failed to unmarshal FileID: %v", err)
	}

	if textID != origID {
		t.Fatalf("new FileID is different to original one. Expected %d, got %d", origID, textID)
	}
}

func TestInvalidFileIDs(t *testing.T) {
	// 15 characters
	if _, err := FileIDFromString("600DCAFE4A11000"); err == nil {
		t.Fatalf("Expected an error")
	}
	// Non-hex characters
	if _, err := FileIDFromString("600DCAFE4A11000G"); err == nil {
		t.Fatalf("Expected an error")
	}
}

func TestFileIDFromBase64(t *testing.T) {
	expected := NewFileID(0x12345678124397ff, 0x87654321877484a8)
	fileIDURLEncoded := "EjRWeBJDl_-HZUMhh3SEqA"
	fileIDStdEncoded := "EjRWeBJDl/+HZUMhh3SEqA"

	actual, err := FileIDFromBase64(fileIDURLEncoded)
	assert.Nil(t, err)
	assert.Equal(t, expected, actual)

	actual, err = FileIDFromBase64(fileIDStdEncoded)
	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func TestFileIDBase64(t *testing.T) {
	expected := "EjRWeBJDl_WHZUMhh3SEng"
	fileID := NewFileID(0x12345678124397f5, 0x876543218774849e)

	assert.Equal(t, fileID.Base64(), expected)
}

func TestTraceHashSprintf(t *testing.T) {
	origHash := NewTraceHash(0x0001C03F8D6B8520, 0xEDEAEEA9460BEEBB)

	marshaled := fmt.Sprintf("%d", origHash)
	// nolint:goconst
	expected := "{492854164817184 17143777342331285179}"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%s", origHash)
	expected = "{%!s(uint64=492854164817184) %!s(uint64=17143777342331285179)}"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%v", origHash)
	// nolint:goconst
	expected = "{492854164817184 17143777342331285179}"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%#v", origHash)
	expected = "0x1c03f8d6b8520edeaeea9460beebb"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	// Values were chosen to test non-zero-padded output
	traceHash := NewTraceHash(42, 100)

	marshaled = fmt.Sprintf("%x", traceHash)
	expected = "2a0000000000000064"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%X", traceHash)
	expected = "2A0000000000000064"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%#x", traceHash)
	expected = "0x2a0000000000000064"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	marshaled = fmt.Sprintf("%#X", traceHash)
	expected = "0x2A0000000000000064"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}
}

func TestTraceHashMarshal(t *testing.T) {
	origHash := NewTraceHash(0x600DF00D, 0xF00D600D)
	var err error

	// Test (Un)MarshalJSON
	var data []byte
	if data, err = origHash.MarshalJSON(); err != nil {
		t.Fatalf("Failed to marshal TraceHash: %v", err)
	}

	marshaled := string(data)
	expected := "\"00000000600df00d00000000f00d600d\""
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	var jsonHash TraceHash
	if err = jsonHash.UnmarshalJSON(data); err != nil {
		t.Fatalf("Failed to unmarshal TraceHash: %v", err)
	}

	if origHash != jsonHash {
		t.Fatalf("new TraceHash is different to original one")
	}

	// Test (Un)MarshalText
	if data, err = origHash.MarshalText(); err != nil {
		t.Fatalf("Failed to marshal TraceHash: %v", err)
	}

	marshaled = string(data)
	expected = "00000000600df00d00000000f00d600d"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	var textHash TraceHash
	if err = textHash.UnmarshalText(data); err != nil {
		t.Fatalf("Failed to unmarshal TraceHash: %v", err)
	}

	if origHash != textHash {
		t.Fatalf("new TraceHash is different to original one. Expected %s, got %s",
			origHash, textHash)
	}
}

func TestCRC32(t *testing.T) {
	crc32, err := ComputeFileCRC32("testdata/crc32_test_data")
	if err != nil {
		t.Fatal(err)
	}

	expectedValue := uint32(0x526B888)
	if uint32(crc32) != expectedValue {
		t.Fatalf("expected CRC32 value 0x%x, got 0x%x", expectedValue, crc32)
	}
}

func TestTraceType(t *testing.T) {
	tests := []struct {
		ty     FrameType
		isErr  bool
		interp InterpType
		str    string
	}{
		{
			ty:     AbortFrame,
			isErr:  true,
			interp: UnknownInterp,
			str:    "abort-marker",
		},
		{
			ty:     PythonFrame,
			isErr:  false,
			interp: Python,
			str:    "python",
		},
		{
			ty:     NativeFrame.Error(),
			isErr:  true,
			interp: Native,
			str:    "native-error",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.isErr, test.ty.IsError())
		assert.Equal(t, test.interp, test.ty.Interpreter())
		assert.Equal(t, test.str, test.ty.String())
	}
}
