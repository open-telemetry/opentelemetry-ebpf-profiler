// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestReadMethodDynamicName(t *testing.T) {
	const (
		methodDescPtr       = libpf.Address(0x100)
		methodNamePtr       = 0x200
		methodDescFlagsOffs = 0x6
		dynamicMethodName   = "lambda_method1"
	)

	tests := map[string]struct {
		methodNameFieldOffs uint
		wantName            string
	}{
		"friendly name": {
			methodNameFieldOffs: 0x20,
			wantName:            dynamicMethodName,
		},
		"missing cDAC field": {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			memory := make([]byte, 0x400)
			binary.LittleEndian.PutUint16(memory[int(methodDescPtr)+methodDescFlagsOffs:], mcDynamic)
			if tt.methodNameFieldOffs != 0 {
				binary.LittleEndian.PutUint64(
					memory[int(methodDescPtr)+int(tt.methodNameFieldOffs):], methodNamePtr)
				copy(memory[methodNamePtr:], dynamicMethodName+"\x00")
			}

			cdac := dotnetCdac{}
			cdac.Types.MethodDesc.Flags = methodDescFlagsOffs
			cdac.Types.MethodDesc.SizeOf = 0x8
			cdac.Types.DynamicMethodDesc.MethodName = tt.methodNameFieldOffs

			d := &dotnetData{}
			_, err := d.GetOrInit(func() (dotnetCdac, error) {
				return cdac, nil
			})
			require.NoError(t, err)

			instance := &dotnetInstance{
				d:  d,
				rm: remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)},
			}
			method, err := instance.readMethod(methodDescPtr, 0)
			require.NoError(t, err)
			require.NotNil(t, method)
			assert.Equal(t, uint16(mcDynamic), method.classification)
			assert.Equal(t, tt.wantName, method.dynamicName.String())
		})
	}
}

func TestSymbolizeDynamicMethod(t *testing.T) {
	const codeHeaderPtr = libpf.Address(0x1234)

	tests := map[string]struct {
		dynamicName string
		wantName    string
	}{
		"friendly name": {
			dynamicName: "lambda_method1",
			wantName:    "lambda_method1",
		},
		"missing name": {
			wantName: "[stub: dynamic]",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addrToMethod, err := freelru.New[libpf.Address, *dotnetMethod](
				interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
			require.NoError(t, err)
			addrToMethod.Add(codeHeaderPtr, &dotnetMethod{
				classification: mcDynamic,
				dynamicName:    libpf.Intern(tt.dynamicName),
			})

			instance := &dotnetInstance{addrToMethod: addrToMethod}
			ebpfFrame := libpf.NewEbpfFrame(libpf.DotnetFrame, 0, 2, 0)
			ebpfFrame[1] = uint64(codeHeaderPtr)<<5 | codeJIT

			var frames libpf.Frames
			var mapping libpf.FrameMapping
			err = instance.Symbolize(ebpfFrame, &frames, mapping)
			require.NoError(t, err)
			require.Len(t, frames, 1)
			assert.Equal(t, tt.wantName, frames[0].Value().FunctionName.String())
		})
	}
}
