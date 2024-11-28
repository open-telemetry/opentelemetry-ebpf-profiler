package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	common "go.opentelemetry.io/proto/otlp/common/v1"
)

// AttrIndex is an index in the `Profile.attribute_table`.
type AttrIndex = uint64

// AttrTableManager maintains index allocation and deduplication for attribute tables.
type AttrTableManager struct {
	// indices maps compound keys to the indices in the attribute table.
	indices map[string]AttrIndex

	// attrTable being populated.
	attrTable *[]*common.KeyValue
}

func NewAttrTableManager(attrTable *[]*common.KeyValue) *AttrTableManager {
	return &AttrTableManager{
		indices:   make(map[string]AttrIndex),
		attrTable: attrTable,
	}
}

// AppendInt adds the index for the given integer attribute to an attribute index slice.
func (m *AttrTableManager) AppendInt(
	attrs *[]AttrIndex, key attribute.Key, value int64) {
	compound := fmt.Sprintf("%v_%d", key, value)
	val := common.AnyValue{Value: &common.AnyValue_IntValue{IntValue: value}}
	m.appendAny(attrs, key, compound, &val)
}

// AppendOptionalString adds the index for the given string attribute to an
// attribute index slice if it is non-empty.
func (m *AttrTableManager) AppendOptionalString(
	attrs *[]AttrIndex, key attribute.Key, value string) {
	if value == "" {
		return
	}

	compound := fmt.Sprintf("%v_%s", key, value)
	val := common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: value}}
	m.appendAny(attrs, key, compound, &val)
}

func (m *AttrTableManager) appendAny(
	attrs *[]AttrIndex,
	key attribute.Key,
	compoundKey string,
	value *common.AnyValue,
) {
	if attributeIndex, exists := m.indices[compoundKey]; exists {
		*attrs = append(*attrs, attributeIndex)
		return
	}

	newIndex := AttrIndex(len(*m.attrTable))

	*m.attrTable = append(*m.attrTable, &common.KeyValue{
		Key:   string(key),
		Value: value,
	})

	m.indices[compoundKey] = newIndex

	*attrs = append(*attrs, newIndex)
}
