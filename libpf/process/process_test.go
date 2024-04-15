/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package process

import (
	"debug/elf"
	"os"
	"strings"
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"

	"github.com/stretchr/testify/assert"
)

//nolint:lll
var testMappings = `55fe82710000-55fe8273c000 r--p 00000000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe8273c000-55fe827be000 r-xp 0002c000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe827be000-55fe82836000 r--p 000ae000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe82836000-55fe8283d000 r--p 00125000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe8283d000-55fe8283e000 rw-p 0012c000 fd:01 1068432                    /tmp/usr_bin_seahorse
55fe8283e000-55fe8283f000 rw-p 00000000 00:00 0
55fe8365d000-55fe839d6000 rw-p 00000000 00:00 0                          [heap]
7f63b4000000-7f63b4021000 rw-p 00000000 00:00 0
7f63b4021000-7f63b8000000 ---p 00000000 00:00 0
7f63b8000000-7f63b8630000 rw-p 00000000 00:00 0
7f63b8630000-7f63bc000000 ---p 00000000 00:00 0
7f63bc000000-7f63bc025000 rw-p 00000000 00:00 0
7f63bc025000-7f63c0000000 ---p 00000000 00:00 0
7f63c0000000-7f63c0021000 rw-p 00000000 00:00 0
7f63c0021000-7f63c4000000 ---p 00000000 00:00 0
7f63c4000000-7f63c4021000 rw-p 00000000 00:00 0
7f63c4021000-7f63c8000000 ---p 00000000 00:00 0
7f63c8bb9000-7f63c8c3e000 r--p 00000000 fd:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8c3e000-7f63c8de0000 r-xp 00085000 08:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8de0000-7f63c8e6d000 r--p 00227000 fd:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8e6d000-7f63c8e6e000 ---p 002b4000 fd:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8e6e000-7f63c8e9e000 r--p 002b4000 fd:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8e9e000-7f63c8ea0000 rw-p 002e4000 fd:01 1048922                    /tmp/usr_lib_x86_64-linux-gnu_libcrypto.so.1.1
7f63c8ea0000-7f63c8ea3000 rw-p 00000000 00:00 0
7f63c8ea3000-7f63c8ebf000 r--p 00000000 1fd:01 1075944                   /tmp/usr_lib_x86_64-linux-gnu_libopensc.so.6.0.0
7f63c8ebf000-7f63c8fef000 r-xp 0001c000 1fd:01 1075944                   /tmp/usr_lib_x86_64-linux-gnu_libopensc.so.6.0.0
7f63c8fef000-7f63c9063000 r--p 0014c000 1fd:01 1075944                   /tmp/usr_lib_x86_64-linux-gnu_libopensc.so.6.0.0
7f63c9063000-7f63c906f000 r--p 001bf000 1fd:01 1075944                   /tmp/usr_lib_x86_64-linux-gnu_libopensc.so.6.0.0`

func TestParseMappings(t *testing.T) {
	mappings, err := parseMappings(strings.NewReader(testMappings))
	assert.Nil(t, err)
	assert.NotNil(t, mappings)

	expected := []Mapping{
		{
			Vaddr:      0x55fe8273c000,
			Device:     0xfd01,
			Flags:      elf.PF_R + elf.PF_X,
			Inode:      1068432,
			Length:     0x82000,
			FileOffset: 180224,
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
	assert.Nil(t, err)
	assert.Greater(t, len(mappings), 0)
}
