package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"fmt"

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

func (m *AttrTableManager) AddIntAttr(key string, value int64) AttrIndex {
	compound := fmt.Sprintf("%v_%d", key, value)
	val := common.AnyValue{Value: &common.AnyValue_IntValue{IntValue: value}}
	return m.addAnyAttr(key, compound, &val)
}

func (m *AttrTableManager) AddStringAttr(key, value string) AttrIndex {
	compound := fmt.Sprintf("%v_%s", key, value)
	val := common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: value}}
	return m.addAnyAttr(key, compound, &val)
}

func (m *AttrTableManager) addAnyAttr(
	key string,
	compoundKey string,
	value *common.AnyValue,
) AttrIndex {
	if attributeIndex, exists := m.indices[compoundKey]; exists {
		return attributeIndex
	}

	newIndex := AttrIndex(len(*m.attrTable))

	*m.attrTable = append(*m.attrTable, &common.KeyValue{
		Key:   key,
		Value: value,
	})

	m.indices[compoundKey] = newIndex

	return newIndex
}
