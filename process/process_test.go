// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"debug/elf"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

//nolint:lll
var testMappings = `55fe82710000-55fe8273c000 r--p 00000000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe8273c000-55fe827be000 r-xp 0002c000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe827be000-55fe82836000 r--p 000ae000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe82836000-55fe8283d000 r--p 00125000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe8283d000-55fe8283e000 rw-p 0012c000 fd:01 1068432                    /tmp/usr_bin_seahorse
7f63c8c3e000-7f63c8de0000 r-xp 00085000 08:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8ebf000-7f63c8fef000 r-xp 0001c000 1fd:01 1075944                   /tmp/usr_lib_x86_64-linux-gnu_libopensc.so.6.0.0`

func TestParseMappings(t *testing.T) {
	mappings, err := parseMappings(strings.NewReader(testMappings))
	require.NoError(t, err)
	assert.NotNil(t, mappings)

	expected := []Mapping{
		{
			Vaddr:      0x55fe82710000,
			Device:     0xfd01,
			Flags:      elf.PF_R,
			Inode:      1068432,
			Length:     0x2c000,
			FileOffset: 0,
			Path:       "/tmp/usr_bin_seahorse",
		},
		{
			Vaddr:      0x55fe8273c000,
			Device:     0xfd01,
			Flags:      elf.PF_R + elf.PF_X,
			Inode:      1068432,
			Length:     0x82000,
			FileOffset: 0x2c000,
			Path:       "/tmp/usr_bin_seahorse",
		},
		{
			Vaddr:      0x55fe827be000,
			Device:     0xfd01,
			Flags:      elf.PF_R,
			Inode:      1068432,
			Length:     0x78000,
			FileOffset: 0xae000,
			Path:       "/tmp/usr_bin_seahorse",
		},
		{
			Vaddr:      0x55fe82836000,
			Device:     0xfd01,
			Flags:      elf.PF_R,
			Inode:      1068432,
			Length:     0x7000,
			FileOffset: 0x125000,
			Path:       "/tmp/usr_bin_seahorse",
		},
		{
			Vaddr:      0x55fe8283d000,
			Device:     0xfd01,
			Flags:      elf.PF_R + elf.PF_W,
			Inode:      1068432,
			Length:     0x1000,
			FileOffset: 0x12c000,
			Path:       "/tmp/usr_bin_seahorse",
		},
		{
			Vaddr:      0x7f63c8c3e000,
			Device:     0x0801,
			Flags:      elf.PF_R + elf.PF_X,
			Inode:      1048922,
			Length:     0x1A2000,
			FileOffset: 544768,
			Path:       "/tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1",
		},
		{
			Vaddr:      0x7f63c8ebf000,
			Device:     0x1fd01,
			Flags:      elf.PF_R + elf.PF_X,
			Inode:      1075944,
			Length:     0x130000,
			FileOffset: 114688,
			Path:       "/tmp/usr_lib_x86_64-linux-gnu_libopensc.so.6.0.0",
		},
	}
	assert.Equal(t, expected, mappings)
}

func TestNewPIDOfSelf(t *testing.T) {
	pr := New(libpf.PID(os.Getpid()))
	assert.NotNil(t, pr)

	mappings, err := pr.GetMappings()
	require.NoError(t, err)
	assert.NotEmpty(t, mappings)
}
