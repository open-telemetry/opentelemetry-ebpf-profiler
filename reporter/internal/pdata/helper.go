package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

// OrderedSet is a set that keeps order of insertion.
type OrderedSet[T comparable] map[T]int32

// Add adds an element to the set and returns its index.
func (os OrderedSet[T]) Add(key T) int32 {
	idx, _ := os.AddWithCheck(key)
	return idx
}

// AddWithCheck adds an element to the set, returns its index and presence state.
func (os OrderedSet[T]) AddWithCheck(key T) (int32, bool) {
	if idx, exists := os[key]; exists {
		return idx, true
	}

	idx := int32(len(os))
	os[key] = idx
	return idx, false
}

// ToSlice returns the elements of the set as a slice, in insertion order.
func (os OrderedSet[T]) ToSlice() []T {
	ret := make([]T, len(os))
	for key, idx := range os {
		ret[idx] = key
	}

	return ret
}

// locationInfo is a helper used to deduplicate Locations.
type locationInfo struct {
	address       uint64
	mappingIndex  int32
	frameType     string
	hasLine       bool
	lineNumber    int64
	functionIndex int32
}

// funcInfo is a helper to construct profile.Function messages.
type funcInfo struct {
	nameIdx     int32
	fileNameIdx int32
}
