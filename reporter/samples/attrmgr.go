// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
)

// SampleAttrProducer provides a hook point to:
//
// - inspect each trace and its meta when it is enqueued in the reporter
// - produce extra meta info
// - attach extra attributes to the trace
type SampleAttrProducer interface {
	// CollectExtraSampleMeta gathers extra sample meta-info and returns it as
	// a pointer to a **hashable** struct.
	CollectExtraSampleMeta(trace *libpf.Trace, meta *TraceEventMeta) any

	// ExtraSampleAttrs is called when the reporter populates the Sample struct
	// before sending it out. Attributes returned from this function are added
	// as Sample attributes. `meta` receives the pointer that was returned from
	// CollectExtraSampleMeta.
	ExtraSampleAttrs(attrMgr *AttrTableManager, meta any) []int32
}

// attrKey is the deduplication key for attribute table entries.
// Unlike a formatted string it does not allocate and cannot collide on
// separators or on an int and its string form.
type attrKey struct {
	key   attribute.Key
	str   string
	num   int64
	isInt bool
}

// AttrTableManager maintains index allocation and deduplication for attribute tables.
type AttrTableManager struct {
	// indices maps attribute keys to indices in the attribute table.
	indices map[attrKey]int32

	// strSet to read and write strings from the string table
	strSet orderedset.OrderedSet[string]

	// attrTable being populated.
	attrTable pprofile.KeyValueAndUnitSlice
}

func NewAttrTableManager(strSet orderedset.OrderedSet[string], attrTable pprofile.KeyValueAndUnitSlice) *AttrTableManager {
	return &AttrTableManager{
		indices:   make(map[attrKey]int32),
		strSet:    strSet,
		attrTable: attrTable,
	}
}

// AppendInt adds the index for the given integer attribute to an attribute index slice.
func (m *AttrTableManager) AppendInt(
	attrs pcommon.Int32Slice, key attribute.Key, value int64,
) {
	k := attrKey{key: key, num: value, isInt: true}
	idx, exists := m.indices[k]
	if !exists {
		idx = m.newEntry(k)
		m.attrTable.At(int(idx)).Value().SetInt(value)
	}
	attrs.Append(idx)
}

// AppendOptionalString adds the index for the given string attribute to an
// attribute index slice if it is non-empty.
func (m *AttrTableManager) AppendOptionalString(
	attrs pcommon.Int32Slice, key attribute.Key, value string,
) {
	if value == "" {
		return
	}

	k := attrKey{key: key, str: value}
	idx, exists := m.indices[k]
	if !exists {
		idx = m.newEntry(k)
		m.attrTable.At(int(idx)).Value().SetStr(value)
	}
	attrs.Append(idx)
}

// newEntry adds an entry for k to the attribute table. The caller sets the value.
func (m *AttrTableManager) newEntry(k attrKey) int32 {
	newIndex := int32(m.attrTable.Len())
	a := m.attrTable.AppendEmpty()
	a.SetKeyStrindex(m.strSet.Add(string(k.key)))
	m.indices[k] = newIndex
	return newIndex
}
