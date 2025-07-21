package irsymcache

import (
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/grafana/pyroscope/lidia"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestNativeFrameSymbols(t *testing.T) {
	resolver, err := NewFSCache(TableTableFactory{
		Options: []lidia.Option{lidia.WithLines(), lidia.WithFiles()},
	}, Options{
		SizeEntries: 1024,
		Path:        t.TempDir(),
	})
	require.NoError(t, err)
	frames, err := lru.NewSynced[
		libpf.FrameID, samples.SourceInfo,
	](
		1024, libpf.FrameID.Hash32)
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
			{
				FunctionName: "__GI___pthread_cond_timedwait",
			},
		},
	}, res)
}
