// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// pfatbuf providers wrappers adding caching to types that implement the `ReaderAt` interface.

package pfatbuf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfatbuf"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

const debugEnabled = false
const pageSize = 1024
const numPages = 8

// Cache implements buffering for random access reads via the `ReaderAt` interface.
type Cache struct {
	name  string
	inner io.ReaderAt

	data     [pageSize * numPages]byte
	pageNum  [numPages]int64
	pageSize [numPages]int
	pageHit  [numPages]uint
	hit      uint
	lastIdx  int

	loads map[int64]uint
}

func (c *Cache) Inner() io.ReaderAt {
	return c.inner
}

func (c *Cache) InitName(name string, rd io.ReaderAt) {
	c.name = name
	c.inner = rd
	c.InvalidateCache()
}

func (c *Cache) Init(rd io.ReaderAt) {
	c.InitName("noname", rd)
}

func (c *Cache) InvalidateCache() {
	for i := range numPages {
		c.pageNum[i] = -1
		c.pageSize[i] = 0
		c.pageHit[i] = uint(i)
	}
	c.hit = numPages
	c.lastIdx = 0
	c.loads = make(map[int64]uint)
}

// findPage fins the page for given offset from cache. If present, the index
// of the cached page along with ok is returned. If not present, the returned
// index is the index which should be reused.
func (c *Cache) getPage(pageNum int64) (int, bool) {
	if c.pageNum[c.lastIdx] == pageNum {
		return c.lastIdx, true
	}
	oldestHit := ^uint(0)
	oldestIdx := 0
	for i := range numPages {
		if c.pageNum[i] == pageNum {
			c.lastIdx = i
			return i, true
		}
		if c.pageHit[i] < oldestHit {
			oldestIdx = i
			oldestHit = c.pageHit[i]
		}
	}
	c.lastIdx = oldestIdx
	return oldestIdx, false
}

func (c *Cache) readPageToIndex(pageNum int64, idx int) error {
	// Read from the underlying reader.
	dataOffs := idx * pageSize
	n, err := c.inner.ReadAt(c.data[dataOffs:dataOffs+pageSize], int64(pageNum*pageSize))
	if err == io.EOF {
		// We speculatively read more than the original caller asked us to,
		// so running into EOF is actually expected for us.
	} else if err != nil {
		c.pageNum[idx] = -1
		return err
	}
	c.pageSize[idx] = n
	c.pageNum[idx] = pageNum
	if c.pageHit[idx] != c.hit {
		c.hit++
		c.pageHit[idx] = c.hit
	}
	if debugEnabled {
		val := c.loads[pageNum]
		if val > 2 {
			fmt.Printf("%s: read page %05d -> %d (%d b) [loads %d]\n", c.name, pageNum, idx, n, val)
			debug.PrintStack()
		}
		c.loads[pageNum] = val + 1
	}
	return nil
}

func (c *Cache) getOrReadPage(pageNum int64) (data []byte, idx int, err error) {
	if pageNum < 0 {
		return nil, 0, fmt.Errorf("negative page %d", pageNum)
	}
	idx, ok := c.getPage(pageNum)
	dataOffs := idx * pageSize
	if !ok {
		if err := c.readPageToIndex(pageNum, idx); err != nil {
			return nil, 0, err
		}
	}
	return c.data[dataOffs : dataOffs+c.pageSize[idx]], idx, nil
}

// ReadAt implements the `ReaderAt` interface.
func (c *Cache) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset value %d given", off)
	}

	// If reading large amounts of data, skip the cache and use inner ReadAt
	// directly. This avoids a single read to trash the whole cache.
	// When using underlying os.File this also reduces the number of syscalls
	// made as the caching logic would split this to ReadAt call per page.
	if uint(len(p)) > pageSize*3/2 {
		return c.inner.ReadAt(p, off)
	}

	writeOffs := 0
	remaining := len(p)
	skipOffs := int(off % pageSize)
	pageNum := off / pageSize

	for {
		data, _, err := c.getOrReadPage(pageNum)
		if err != nil {
			return int(writeOffs), err
		}
		if skipOffs > len(data) {
			return 0, io.EOF
		}

		copyLen := min(remaining, len(data)-skipOffs)
		copy(p[writeOffs:][:copyLen], data[skipOffs:][:copyLen])

		skipOffs = 0
		pageNum++
		writeOffs += copyLen
		remaining -= copyLen
		if remaining == 0 {
			return int(writeOffs), nil
		}
		if len(data) != pageSize {
			return int(writeOffs), io.EOF
		}
	}
}

func (c *Cache) Uint8At(off int64) uint8 {
	pageNum := off / pageSize
	pageOff := int(off % pageSize)

	buf, _, err := c.getOrReadPage(pageNum)
	if err != nil || pageOff+1 > len(buf) {
		return 0
	}
	return buf[pageOff]
}

func (c *Cache) slowUintAt(off int64, sz int, buf []byte, nextPageNum int64) uint64 {
	var mergedBuf [8]byte

	nextBuf, _, err := c.getOrReadPage(nextPageNum)
	if err != nil {
		return 0
	}

	copy(mergedBuf[:], buf)
	remainingBuf := mergedBuf[len(buf):sz]
	copy(remainingBuf, nextBuf)

	return binary.LittleEndian.Uint64(mergedBuf[:])
}

func (c *Cache) Uint16At(off int64) uint16 {
	pageNum := off / pageSize
	pageOff := int(off % pageSize)

	buf, _, err := c.getOrReadPage(pageNum)
	if err != nil || pageOff > len(buf) {
		return 0
	}
	if pageOff+2 <= len(buf) {
		return binary.LittleEndian.Uint16(buf[pageOff:])
	}
	return uint16(c.slowUintAt(off, 2, buf[pageOff:], pageNum+1))
}

func (c *Cache) Uint32At(off int64) uint32 {
	pageNum := off / pageSize
	pageOff := int(off % pageSize)

	buf, _, err := c.getOrReadPage(pageNum)
	if err != nil || pageOff > len(buf) {
		return 0
	}
	if pageOff+4 <= len(buf) {
		return binary.LittleEndian.Uint32(buf[pageOff:])
	}
	return uint32(c.slowUintAt(off, 4, buf[pageOff:], pageNum+1))
}

func (c *Cache) Uint64At(off int64) uint64 {
	pageNum := off / pageSize
	pageOff := int(off % pageSize)

	buf, _, err := c.getOrReadPage(pageNum)
	if err != nil || pageOff > len(buf) {
		return 0
	}
	if pageOff+8 <= len(buf) {
		return binary.LittleEndian.Uint64(buf[pageOff:])
	}
	return c.slowUintAt(off, 8, buf[pageOff:], pageNum+1)
}

func (c *Cache) UnsafeReadAt(n int, off int64) ([]byte, error) {
	if int(off&pageSize)+n >= 2*pageSize {
		return nil, errors.New("too large unsafe read")
	}

	pageOffs := int(off % pageSize)
	pageNum := off / pageSize

	data, idx, err := c.getOrReadPage(pageNum)
	if err != nil {
		return nil, err
	}
	if pageOffs+n <= len(data) {
		return data[pageOffs:], nil
	}

	// Arrange so that two consecutive cache pages form the data.
	dataStart := idx * pageSize
	if idx+1 >= numPages {
		// Copy this page to the previous slot to make room
		prevStart := dataStart - pageSize
		copy(c.data[prevStart:dataStart], c.data[dataStart:])
		c.pageHit[idx-1] = c.pageHit[idx]
		c.pageNum[idx-1] = c.pageNum[idx]
		c.pageSize[idx-1] = c.pageSize[idx]

		idx--
		dataStart = prevStart
	}

	// Read to the next page
	if err = c.readPageToIndex(pageNum+1, idx+1); err != nil {
		return nil, err
	}
	data = c.data[dataStart : dataStart+pageSize+c.pageSize[idx+1]]
	if pageOffs+n <= len(data) {
		return data[pageOffs:], nil
	}

	return nil, io.EOF
}

var ErrStringTooLong = errors.New("string is too long")

func (c *Cache) UnsafeStringAt(off int64, maxSz int) (string, error) {
	pageOff := int(off % pageSize)
	pageNum := off / pageSize

	data, idx, err := c.getOrReadPage(pageNum)
	if err != nil {
		return "", err
	}
	if pageOff > len(data) {
		return "", io.EOF
	}
	data = data[pageOff:]
	if zeroIdx := bytes.IndexByte(data, 0); zeroIdx >= 0 {
		return pfunsafe.ToString(data[:+zeroIdx]), nil
	}
	if maxSz > 0 && len(data) >= maxSz {
		return "", ErrStringTooLong
	}

	// Arrange so that two consecutive cache pages form the data.
	dataStart := idx * pageSize
	if idx+1 >= numPages {
		// Copy this page to the previous slot to make room
		prevStart := dataStart - pageSize
		copy(c.data[prevStart:dataStart], c.data[dataStart:])
		c.pageHit[idx-1] = c.pageHit[idx]
		c.pageNum[idx-1] = c.pageNum[idx]
		c.pageSize[idx-1] = c.pageSize[idx]

		idx--
		dataStart = prevStart
	}

	// Read to the next page
	if err = c.readPageToIndex(pageNum+1, idx+1); err != nil {
		return "", err
	}
	data = c.data[dataStart : dataStart+pageSize+c.pageSize[idx+1]]

	if zeroIdx := bytes.IndexByte(data[pageSize:], 0); zeroIdx >= 0 {
		return pfunsafe.ToString(data[pageOff : pageSize+zeroIdx]), nil
	}
	return "", ErrStringTooLong
}

func (c *Cache) InternStringAt(off int64) (libpf.String, error) {
	str, err := c.UnsafeStringAt(off, 0)
	return libpf.Intern(str), err
}

func (c *Cache) StringAt(off int64) (string, error) {
	if str, err := c.UnsafeStringAt(off, 0); str != "" && err == nil {
		return strings.Clone(str), nil
	} else {
		return str, err
	}
}

func Search(rdr io.ReaderAt, needle []byte, result []byte) (int64, error) {
	var buf [64 * 1024]byte

	fileOffs := int64(0)
	for {
		n, err := rdr.ReadAt(buf[:], fileOffs)
		// process 'n' bytes
		bufOffs := bytes.Index(buf[:n], needle)
		if bufOffs >= 0 {
			if result != nil {
				numCopied := copy(result, buf[bufOffs+len(needle):])
				if numCopied < len(result) {
					n, err = rdr.ReadAt(result[numCopied:], fileOffs+int64(n))
					if err != nil {
						return -1, err
					}
				}
			}
			return fileOffs + int64(bufOffs), nil
		}
		if err != nil {
			return -1, err
		}
		fileOffs += int64(n - len(needle) + 1)
	}
	return -1, io.EOF
}
