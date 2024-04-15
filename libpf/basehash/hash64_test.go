/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package basehash

import (
	"fmt"
	"testing"
)

func TestBaseHash64(t *testing.T) {
	origHash := Hash64(5550100)
	var err error
	var data []byte

	// Test Sprintf
	marshaled := fmt.Sprintf("%x", origHash)
	expected := "54b014"
	if marshaled != expected {
		t.Fatalf("Expected marshaled value %s, got %s", expected, marshaled)
	}

	// Test (Un)MarshalJSON
	if data, err = origHash.MarshalJSON(); err != nil {
		t.Fatalf("Failed to marshal baseHash64: %v", err)
	}

	var newHash Hash64
	if err = newHash.UnmarshalJSON(data); err != nil {
		t.Fatalf("Failed to unmarshal baseHash64: %v", err)
	}

	if newHash != origHash {
		t.Fatalf("New baseHash64 is different to original. Expected %v, got %v", origHash, newHash)
	}
}
