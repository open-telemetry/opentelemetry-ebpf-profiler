package amd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEndBr64(t *testing.T) {
	res, n := IsEndbr64([]byte{0xF3, 0x0F, 0x1E, 0xFA})
	assert.True(t, res)
	assert.Equal(t, 4, n)

	res, _ = IsEndbr64([]byte{})
	assert.False(t, res)
}
