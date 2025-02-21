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

const FramesCacheLifetime = 1 * time.Hour

func SymbolizeNativeFrame(
	resolver samples.NativeSymbolResolver,
	frames *lru.SyncedLRU[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo]],
	mappingName string,
	frameID libpf.FrameID,
	symbolize func(si samples.SourceInfo),
) {
	fileID := frameID.FileID()
	addr := frameID.AddressOrLine()
	LookupFrame := func(frameID libpf.FrameID) (samples.SourceInfo, bool) {
		known := false
		si := samples.SourceInfo{}
		if frameMapLock, exists := frames.GetAndRefresh(frameID.FileID(),
			FramesCacheLifetime); exists {
			frameMap := frameMapLock.RLock()
			defer frameMapLock.RUnlock(&frameMap)
			si, known = (*frameMap)[frameID.AddressOrLine()]
		}
		return si, known
	}
	frameMetadata := func(symbols []samples.SourceInfoFrame) samples.SourceInfo {
		si := samples.SourceInfo{Frames: symbols}
		if frameMapLock, exists := frames.GetAndRefresh(fileID,
			FramesCacheLifetime); exists {
			frameMap := frameMapLock.WLock()
			defer frameMapLock.WUnlock(&frameMap)

			(*frameMap)[addr] = si
			return si
		}

		v := make(map[libpf.AddressOrLineno]samples.SourceInfo)
		v[addr] = si
		mu := xsync.NewRWMutex(v)
		frames.Add(fileID, &mu)
		return si
	}
	si, known := LookupFrame(frameID)
	if known {
		symbolize(si)
		return
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
