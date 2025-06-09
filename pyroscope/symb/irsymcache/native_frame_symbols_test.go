package irsymcache

import (
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/table"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestNativeFrameSymbols(t *testing.T) {
	resolver, err := NewFSCache(TableTableFactory{
		Options: []table.Option{table.WithLines(), table.WithFiles()},
	}, Options{
		SizeEntries: 1024,
		Path:        t.TempDir(),
	})
	require.NoError(t, err)
	frames, err := lru.NewSynced[
		libpf.FileID,
		*xsync.RWMutex[*lru.LRU[libpf.AddressOrLineno, samples.SourceInfo]],
	](
		1024, libpf.FileID.Hash32)
	require.NoError(t, err)

	reference := testElfRef(testLibcFIle)
	fid := libpf.NewFileID(1, 3)
	err = resolver.ObserveExecutable(fid, reference)
	require.NoError(t, err)
	res := samples.SourceInfo{}
	SymbolizeNativeFrame(resolver, frames, "testmapping",
		libpf.NewFrameID(fid, libpf.AddressOrLineno(0x9bc7e)),
		func(si samples.SourceInfo) {
			res = si
		})
	require.Equal(t, samples.SourceInfo{
		Frames: []samples.SourceInfoFrame{
			{LineNumber: 506,
				FunctionName: "__pthread_cond_wait_common",
				FilePath:     "./nptl/pthread_cond_wait.c"},
			{LineNumber: 652,
				FunctionName: "___pthread_cond_timedwait64",
				FilePath:     "./nptl/pthread_cond_wait.c"},
		},
	}, res)
}
