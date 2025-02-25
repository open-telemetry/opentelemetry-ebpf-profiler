// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

// Set is a convenience alias for a map with a `Void` key.
type Set[T comparable] map[T]Void

// ToSlice converts the Set keys into a slice.
func (s Set[T]) ToSlice() []T {
	slice := make([]T, 0, len(s))
	for item := range s {
		slice = append(slice, item)
	}
	return slice
}

// MapKeysToSlice creates a slice from a map's keys.
func MapKeysToSlice[K comparable, V any](m map[K]V) []K {
	slice := make([]K, 0, len(m))
	for key := range m {
		slice = append(slice, key)
	}
	return slice
}

// MapValuesToSlice creates a slice from a map's values.
func MapValuesToSlice[K comparable, V any](m map[K]V) []V {
	slice := make([]V, 0, len(m))
	for _, value := range m {
		slice = append(slice, value)
	}
	return slice
}

// SliceToSet creates a set from a slice, deduplicating it.
func SliceToSet[T comparable](s []T) Set[T] {
	set := make(map[T]Void, len(s))
	for _, item := range s {
		set[item] = Void{}
	}
	return set
}

// SliceAllEqual checks whether all items in a slice have a given value.
func SliceAllEqual[T comparable](s []T, value T) bool {
	for _, item := range s {
		if item != value {
			return false
		}
	}

	return true
}

// SlicesEqual checks whether two slices are element-wise equal.
func SlicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// MapSlice returns a new slice by mapping given function over the input slice.
func MapSlice[T, V any](in []T, mapf func(T) V) []V {
	ret := make([]V, len(in))
	for idx := range in {
		ret[idx] = mapf(in[idx])
	}
	return ret
}

// Every returns true if test is true for every element in slice
func Every[T any](in []T, test func(T) bool) bool {
	for _, v := range in {
		if !test(v) {
			return false
		}
	}
	return true
}
