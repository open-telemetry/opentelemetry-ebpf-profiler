// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager

import (
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
)

type lruFileIDMapper struct {
	cache *lru.SyncedLRU[host.FileID, libpf.FileID]
}

// identityHash maps the host.FileID to a 32bit value.
// No need to explicitly hash the FileID, since it's already a hash value.
func identityHash(key host.FileID) uint32 {
	return uint32(key)
}

func newFileIDMapper(size int) (*lruFileIDMapper, error) {
	cache, err := lru.NewSynced[host.FileID, libpf.FileID](uint32(size), identityHash)
	if err != nil {
		return nil, err
	}
	return &lruFileIDMapper{cache}, nil
}

func (fm *lruFileIDMapper) Get(key host.FileID) (libpf.FileID, bool) {
	if fileID, ok := fm.cache.Get(key); ok {
		return fileID, true
	}

	log.Warnf("Failed to lookup file ID %#x", key)
	return libpf.FileID{}, false
}

func (fm *lruFileIDMapper) Set(key host.FileID, val libpf.FileID) {
	fm.cache.Add(key, val)
	log.Debugf("Stored file ID mapping %#x -> %#x", key, val)
}

var _ FileIDMapper = (*lruFileIDMapper)(nil)

// MapFileIDMapper implements the FileIDMApper using a map (for testing)
type MapFileIDMapper struct {
	fileMap map[host.FileID]libpf.FileID
}

func NewMapFileIDMapper() *MapFileIDMapper {
	return &MapFileIDMapper{
		fileMap: make(map[host.FileID]libpf.FileID),
	}
}

func (fm *MapFileIDMapper) Get(key host.FileID) (libpf.FileID, bool) {
	if value, ok := fm.fileMap[key]; ok {
		return value, true
	}
	return libpf.FileID{}, true
}

func (fm *MapFileIDMapper) Set(key host.FileID, value libpf.FileID) {
	fm.fileMap[key] = value
}

var _ FileIDMapper = (*MapFileIDMapper)(nil)

// FileIDMapper is responsible for mapping between 64-bit file IDs to 128-bit file IDs. The file ID
// mappings are inserted typically at the same time the files are hashed. The 128-bit file IDs
// are retrieved prior to reporting requests to the collection agent.
type FileIDMapper interface {
	// Get retrieves the 128-bit file ID for the provided 64-bit file ID. Otherwise,
	// the second return value is false.
	Get(pre host.FileID) (libpf.FileID, bool)
	// Set adds a mapping from the 64-bit file ID to the 128-bit file ID.
	Set(pre host.FileID, post libpf.FileID)
}
