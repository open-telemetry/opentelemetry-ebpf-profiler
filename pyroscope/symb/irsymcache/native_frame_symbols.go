package irsymcache

import (
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

const (
	ExecutableCacheLifetime = 1 * time.Hour
	FramesCacheLifetime     = 1 * time.Hour
	FrameMapLifetime        = 1 * time.Hour
)

func SymbolizeNativeFrame(
	resolver samples.NativeSymbolResolver,
	frames *lru.SyncedLRU[
		libpf.FileID,
		*xsync.RWMutex[*lru.LRU[libpf.AddressOrLineno, samples.SourceInfo]],
	],
	mappingName string,
	frameID libpf.FrameID,
	symbolize func(si samples.SourceInfo),
) {
	fileID := frameID.FileID()
	addr := frameID.AddressOrLine()

	frameMetadata := func(symbols []samples.SourceInfoFrame) samples.SourceInfo {
		si := samples.SourceInfo{Frames: symbols}
		if frameMapLock, exists := frames.GetAndRefresh(fileID,
			FramesCacheLifetime); exists {
			frameMap := frameMapLock.WLock()
			defer frameMapLock.WUnlock(&frameMap)
			(*frameMap).AddWithLifetime(addr, si, FramesCacheLifetime)
			return si
		}

		frameMap, _ := lru.New[libpf.AddressOrLineno, samples.SourceInfo](1024,
			func(k libpf.AddressOrLineno) uint32 { return uint32(k) })
		frameMap.SetLifetime(FrameMapLifetime)
		frameMap.Add(addr, si)
		mu := xsync.NewRWMutex(frameMap)
		frames.Add(fileID, &mu)
		return si
	}
	if frameMapLock, exists := frames.GetAndRefresh(frameID.FileID(),
		FramesCacheLifetime); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		si, known := (*frameMap).GetAndRefresh(frameID.AddressOrLine(), FrameMapLifetime)
		if known {
			symbolize(si)
			return
		}
	}

	var (
		symbols []samples.SourceInfoFrame
		err     error
	)
	if mappingName != process.VdsoPathName {
		symbols, err = resolver.ResolveAddress(fileID, uint64(addr))
		if err != nil {
			logrus.Debugf("Failed to symbolize native frame %v:%v: %v", fileID, addr, err)
		}
	}
	symbolize(frameMetadata(symbols))
}
