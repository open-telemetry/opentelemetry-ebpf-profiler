// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
)

type attributeStruct struct {
	Key   string
	Value any
}

func TestAttrTableManager(t *testing.T) {
	tests := map[string]struct {
		k                      []ResourceKey
		expectedIndices        [][]int32
		expectedAttributeTable []attributeStruct
	}{
		"empty": {
			k: []ResourceKey{
				{
					ContainerID: libpf.NullString,
					PID:         0,
				},
			},
			expectedIndices: [][]int32{{0}},
			expectedAttributeTable: []attributeStruct{
				{Key: "process.pid", Value: int64(0)},
			},
		},
		"duplicate": {
			k: []ResourceKey{
				{
					ContainerID: libpf.Intern("container1"),
					PID:         1234,
				},
				{
					ContainerID: libpf.Intern("container1"),
					PID:         1234,
				},
			},
			expectedIndices: [][]int32{{0, 1}, {0, 1}},
			expectedAttributeTable: []attributeStruct{
				{Key: "container.id", Value: "container1"},
				{Key: "process.pid", Value: int64(1234)},
			},
		},
		"different": {
			k: []ResourceKey{
				{
					ContainerID: libpf.Intern("container1"),
					PID:         1234,
				},
				{
					ContainerID: libpf.Intern("container2"),
					PID:         6789,
				},
			},
			expectedIndices: [][]int32{{0, 1}, {2, 3}},
			expectedAttributeTable: []attributeStruct{
				{Key: "container.id", Value: "container1"},
				{Key: "process.pid", Value: int64(1234)},
				{Key: "container.id", Value: "container2"},
				{Key: "process.pid", Value: int64(6789)},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			strSet := orderedset.OrderedSet[string]{}
			attrTable := pprofile.NewKeyValueAndUnitSlice()
			mgr := NewAttrTableManager(strSet, attrTable)
			indices := make([][]int32, 0)
			for _, k := range tc.k {
				inner := pcommon.NewInt32Slice()
				mgr.AppendOptionalString(inner, semconv.ContainerIDKey, k.ContainerID.String())
				mgr.AppendInt(inner, semconv.ProcessPIDKey, k.PID)
				indices = append(indices, inner.AsRaw())
			}

			require.Equal(t, tc.expectedIndices, indices)
			require.Equal(t, len(tc.expectedAttributeTable), attrTable.Len())
			strSlice := strSet.ToSlice()

			for i, v := range tc.expectedAttributeTable {
				attr := attrTable.At(i)
				assert.Equal(t, v.Key, strSlice[int(attr.KeyStrindex())])
				assert.Equal(t, v.Value, attr.Value().AsRaw())
			}
		})
	}
}
