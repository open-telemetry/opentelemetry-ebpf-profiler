package irsymcache

import (
	"os"
	"testing"

	"github.com/grafana/pyroscope/lidia"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

var tf = TableTableFactory{[]lidia.Option{
	lidia.WithFiles(), lidia.WithLines(), lidia.WithCRC(),
}}

type testElfOpener struct {
}

func (t testElfOpener) OpenELF(file string) (*pfelf.File, error) {
	return pfelf.Open(file)
}

func (t testElfOpener) OpenRootFSFile(file string) (*os.File, error) {
	return os.Open(file)
}

func TestNewFSCache(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		opt     Options
		wantErr bool
	}{
		{
			name: "valid options",
			opt: Options{
				Path:        tmpDir,
				SizeEntries: 1000,
			},
			wantErr: false,
		},
		{
			name: "invalid path",
			opt: Options{
				Path:        "/nonexistent/path/that/should/fail",
				SizeEntries: 1000,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewFSCache(tf, tt.opt)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, resolver)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resolver)

				err = resolver.Close()
				require.NoError(t, err)
			}
		})
	}
}

const testLibcFIle = "../testdata/64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug"

func TestResolver_ResolveAddress(t *testing.T) {
	origLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		logrus.SetLevel(origLevel)
	})
	type observe struct {
		filepath    string
		fid         libpf.FileID
		expectedErr string
	}
	type lookup struct {
		fid         libpf.FileID
		addr        uint64
		expectedRes []samples.SourceInfoFrame
		expectedErr error
	}
	tests := []struct {
		name      string
		cacheSize uint32
		observes  []observe
		lookups   []lookup
	}{
		{
			name:      "successful lookup",
			cacheSize: 1024,
			observes: []observe{
				{
					filepath: testLibcFIle,
					fid:      libpf.NewFileID(456, 123),
				},
			},
			lookups: []lookup{
				{
					fid:  libpf.NewFileID(456, 123),
					addr: 0x9cbb0,
					expectedRes: []samples.SourceInfoFrame{
						{FunctionName: "__pthread_create_2_1"},
					},
				},
			},
		},
		{
			name:      "unknown file",
			cacheSize: 1024,
			lookups: []lookup{
				{
					fid:         libpf.NewFileID(456, 123),
					addr:        0x9cbb0,
					expectedErr: errUnknownFile,
				},
			},
		},
		{
			name:      "eviction ",
			cacheSize: 1,
			observes: []observe{
				{
					filepath: testLibcFIle,
					fid:      libpf.NewFileID(456, 123),
				},
				{
					filepath: testLibcFIle,
					fid:      libpf.NewFileID(4242, 4242),
				},
			},
			lookups: []lookup{
				{
					fid:         libpf.NewFileID(456, 123),
					addr:        0x9cbb0,
					expectedErr: errUnknownFile,
				},
				{
					fid:  libpf.NewFileID(4242, 4242),
					addr: 0x9cbb0,
					expectedRes: []samples.SourceInfoFrame{
						{FunctionName: "__pthread_create_2_1"},
					},
				},
			},
		},
		{
			name:      "errored",
			cacheSize: 1024,
			observes: []observe{
				{
					filepath:    "unknown/file/path/that/should/fail",
					fid:         libpf.NewFileID(456, 123),
					expectedErr: "no such file or directory",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Log(dir)
			resolver, err := NewFSCache(tf, Options{
				Path:        dir,
				SizeEntries: tt.cacheSize,
			})
			require.NoError(t, err)

			for _, o := range tt.observes {
				reference := testElfRef(o.filepath)
				elfRef := reference
				err = resolver.ObserveExecutable(o.fid, elfRef)
				if o.expectedErr != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), o.expectedErr)
					v, ok := resolver.cache.Get(o.fid)
					assert.True(t, ok)
					assert.Equal(t, erroredMarker, v)
				} else {
					require.NoError(t, err)
					v, ok := resolver.cache.Get(o.fid)
					assert.True(t, ok)
					assert.NotEqual(t, erroredMarker, v)
				}
			}
			for _, l := range tt.lookups {
				var results []samples.SourceInfoFrame
				results, err = resolver.ResolveAddress(l.fid, l.addr)
				t.Logf("resolve %s %x = %+v, %+v", l.fid.StringNoQuotes(), l.addr, results, err)
				if l.expectedErr != nil {
					require.Error(t, err)
					assert.Equal(t, l.expectedErr.Error(), err.Error())
				} else {
					require.NoError(t, err)
					assert.Equal(t, l.expectedRes, results)
				}
			}
			err = resolver.Close()
			require.NoError(t, err)
		})
	}
}

func testElfRef(filepath string) *pfelf.Reference {
	return pfelf.NewReference(filepath, testElfOpener{})
}

func TestResolver_Cleanup(t *testing.T) {
	tmpDir := t.TempDir()

	resolver, err := NewFSCache(tf, Options{
		Path:        tmpDir,
		SizeEntries: 1000,
	})
	require.NoError(t, err)

	elfRef := testElfRef(testLibcFIle)
	fid := libpf.NewFileID(456, 123)
	err = resolver.ObserveExecutable(fid, elfRef)
	require.NoError(t, err)

	resolver.Cleanup()

	assert.Empty(t, resolver.tables)

	err = resolver.Close()
	require.NoError(t, err)
}

func TestResolver_Close(t *testing.T) {
	tmpDir := t.TempDir()

	resolver, err := NewFSCache(tf, Options{
		Path:        tmpDir,
		SizeEntries: 1000,
	})
	require.NoError(t, err)

	elfRef := testElfRef(testLibcFIle)
	fid := libpf.NewFileID(456, 123)
	err = resolver.ObserveExecutable(fid, elfRef)
	require.NoError(t, err)

	err = resolver.Close()
	require.NoError(t, err)
	assert.Empty(t, resolver.tables)

	assert.Nil(t, resolver.shutdown)
}

func BenchmarkCache(b *testing.B) {
	resolver, err := NewFSCache(tf, Options{
		Path:        b.TempDir(),
		SizeEntries: 2048,
	})
	loop := func(b *testing.B, resolver *Resolver, fid libpf.FileID) {
		for i := 0; i < b.N; i++ {
			if resolver.ExecutableKnown(fid) {
				continue
			}
			elfRef := testElfRef(testLibcFIle)
			err = resolver.ObserveExecutable(fid, elfRef)
			if err != nil {
				b.Fatal(err)
			}
		}
	}

	require.NoError(b, err)
	fid := libpf.NewFileID(456, 123)

	elfRef := testElfRef(testLibcFIle)
	err = resolver.ObserveExecutable(fid, elfRef)
	require.NoError(b, err)
	b.ResetTimer()
	loop(b, resolver, fid)
}
