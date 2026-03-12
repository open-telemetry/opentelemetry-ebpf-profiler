package controller

import (
	"testing"
)

func TestParsePIDsFromFileContent(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected []int
	}{
		{"empty", []byte(""), nil},
		{"newlines", []byte("1234\n5678\n"), []int{1234, 5678}},
		{"comma", []byte("1234,5678"), []int{1234, 5678}},
		{"mixed", []byte("1234, 5678\n90"), []int{1234, 5678, 90}},
		{"skip invalid", []byte("1234, 0, -1, abc, 5678"), []int{1234, 5678}},
		{"whitespace", []byte("  1234  \n  5678  "), []int{1234, 5678}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePIDsFromFileContent(tt.data)
			if len(got) != len(tt.expected) {
				t.Errorf("parsePIDsFromFileContent() len = %v, want %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("parsePIDsFromFileContent()[%d] = %v, want %v", i, got[i], tt.expected[i])
				}
			}
		})
	}
}
