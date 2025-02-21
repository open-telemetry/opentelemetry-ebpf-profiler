package ffi

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mycb struct {
	cnt int
}

func (m *mycb) VisitRange(uint64, uint32, uint32, string) {
	m.cnt++
}

func TestRangeExtractor(t *testing.T) {
	f, err := os.Open("/proc/self/exe")
	require.NoError(t, err)

	v := new(mycb)
	err = RangeExtractor(f, v)
	require.NoError(t, err)
	assert.Positive(t, v.cnt)
}
