package reporter

import (
	"fmt"

	common "go.opentelemetry.io/proto/otlp/common/v1"
	profiles "go.opentelemetry.io/proto/otlp/profiles/v1experimental"
)

// AttrIndex is an index in the `Profile.attribute_table`.
type AttrIndex = uint64

// AttrTableManager maintains the `Profile.attribute_table` field for the
// `profile.Profile` that it was created for. Attributes are automatically
// deduplicated by the manager.
type AttrTableManager struct {
	// indices maps compound keys to the indices in the attribute table.
	indices map[string]AttrIndex

	// profile being built right now.
	profile *profiles.Profile
}

func NewAttrTableManager(profile *profiles.Profile) *AttrTableManager {
	return &AttrTableManager{
		indices: make(map[string]AttrIndex),
		profile: profile,
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

	newIndex := AttrIndex(len(m.profile.AttributeTable))

	m.profile.AttributeTable = append(m.profile.AttributeTable, &common.KeyValue{
		Key:   key,
		Value: value,
	})

	m.indices[compoundKey] = newIndex

	return newIndex
}
