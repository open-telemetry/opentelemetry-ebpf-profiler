// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/libpf"

// GCproto minus first 8 bytes.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_obj.h#L372
// All the pointers (except chunkname) are pointers to extra space at the end of the GCproto object
// so we could try to be clever and read the whole thing at once if we needed to reduce remotememory
// traffic.
type protoRaw struct {
	// nextgc uint64    /*      0      |       8 */
	_      byte   /*      8      |       1 */
	_      byte   /*      9      |       1 */
	_      byte   /*     10      |       1 */
	_      byte   /*     11      |       1 */
	sizebc uint32 /*     12      |       4 */
	_      uint32 /*     16      |       4 */
	/* XXX  4-byte hole      */
	_         uint64        /*     24      |       8 */
	k         libpf.Address /*     32      |       8 */
	_         uint64        /*     40      |       8 */
	sizekgc   uint32        /*     48      |       4 */
	_         uint32        /*     52      |       4 */
	sizept    uint32        /*     56      |       4 */
	sizeuv    uint8         /*     60      |       1 */
	_         uint8         /*     61      |       1 */
	_         uint16        /*     62      |       2 */
	chunkname libpf.Address /*     64      |       8 */
	firstline uint32        /*     72      |       4 */
	numline   uint32        /*     76      |       4 */
	lineinfo  libpf.Address /*     80      |       8 */
	uvinfo    libpf.Address /*     88      |       8 */
	varinfo   libpf.Address /*     96      |       8 */
}
