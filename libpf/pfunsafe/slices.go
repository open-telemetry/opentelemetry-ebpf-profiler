package pfunsafe

import "unsafe"

// ByteSliceFromPointer converts a Go struct pointer to []byte to read data into
// data must be a non-nil pointer to a struct
func ByteSliceFromPointer[T any](data *T) []byte {
	return unsafe.Slice(
		(*byte)(unsafe.Pointer(data)),
		int(unsafe.Sizeof(*data)),
	)
}

// ByteSliceFromSlice converts a Go slice to []byte to read data into
func ByteSliceFromSlice[T any](data []T) []byte {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Slice(
		(*byte)(unsafe.Pointer(&data[0])),
		len(data)*int(unsafe.Sizeof(data[0])),
	)
}

// ByteSlice2String converts a byte slice into a string without a heap allocation.
// Be aware that the byte slice and the string share the same memory - which makes
// the string mutable.
func ByteSlice2String(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
