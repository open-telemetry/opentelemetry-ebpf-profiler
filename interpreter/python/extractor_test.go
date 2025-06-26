package python

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

type extractor interface {
	extract(t testing.TB) (elf, debugElf *pfelf.File)
	id() string
	version() uint16
}
type dockerPythonExtractor struct {
	name       string
	debugName  string
	base       string
	dockerfile string
	withDebug  bool
	ver        uint16
}

func (e dockerPythonExtractor) id() string {
	return e.name
}
func (e dockerPythonExtractor) version() uint16 {
	return e.ver
}
func (e dockerPythonExtractor) extract(t testing.TB) (elf, debugElf *pfelf.File) {
	d := filepath.Join("extractorcache", e.name)
	t.Logf("%s %s", e.name, d)
	_, err := os.Stat(d)
	t.Cleanup(func() {
		if t.Failed() {
			_ = os.RemoveAll(d)
		}
	})
	if err != nil {
		err = os.MkdirAll(d, 0o777)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(d, "Dockerfile"), []byte(e.dockerfile), 0o600)
		require.NoError(t, err)
		c := exec.Command("docker", "build",
			"--output=.",
			".")
		buffer := bytes.NewBuffer(nil)
		c.Stderr = buffer
		c.Dir = d
		err = c.Run()
		if err != nil {
			t.Skip(err.Error(), buffer.String())
		}
	}

	es, err := os.ReadDir(d)
	require.NoError(t, err)
	if e.withDebug {
		require.Len(t, es, 3)
	} else {
		require.Len(t, es, 2)
	}
	elfPath, debugElfPath := "", ""
	for _, entry := range es {
		n := entry.Name()
		if n == "Dockerfile" {
			continue
		}
		if strings.Contains(n, ".debug") {
			debugElfPath = n
		} else {
			elfPath = n
		}
	}
	t.Logf("%s %s", elfPath, debugElfPath)

	elfPath = filepath.Join(d, elfPath)

	elf, err = pfelf.Open(elfPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = elf.Close()
	})
	if e.withDebug {
		debugElf, err = pfelf.Open(filepath.Join(d, debugElfPath))
		require.NoError(t, err)
		t.Cleanup(func() {
			debugElf.Close()
		})
	} else {
		s, _ := elf.ReadSymbols()
		if s != nil {
			_, err = s.LookupSymbolAddress("_PyEval_EvalFrameDefault.cold")
			if err == nil {
				debugElf = elf
			}
		}
	}

	return elf, debugElf
}

func alpine(base string, ver uint16) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN apk add python3 python3-dbg
RUN mkdir /out
RUN cp /usr/lib/debug/usr/lib/libpython*1.0.debug /out
RUN cp /usr/lib/libpython*1.0 /out
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        ver,
		debugName:  "",
		name:       "alpine:" + base,
		dockerfile: dockerfile,
		withDebug:  true,
	}
}

func python(base, debugName string, version uint16) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN mkdir /out
RUN cp /usr/local/lib/libpython*1.0 /out
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        version,
		debugName:  debugName,
		base:       base,
		name:       "python:" + base,
		dockerfile: dockerfile,
		withDebug:  false,
	}
}

func debian(base string, ver uint16) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN apt-get update && apt-get -y install  python3 python3-dbg binutils original-awk grep
RUN <<EOF
set -ex
mkdir /out
cp /usr/bin/$(readlink /usr/bin/python3) /out
build_id=$(readelf -n /usr/bin/$(readlink /usr/bin/python3) | grep "Build ID" | awk '{print $3}')
dir_name=$(echo "$build_id" | cut -c1-2)
file_name=$(echo "$build_id" | cut -c3-).debug
debug_file_path="/usr/lib/debug/.build-id/$dir_name/$file_name"
cp $debug_file_path /out/$(readlink /usr/bin/python3).debug
EOF
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        ver,
		debugName:  "",
		name:       "debian:" + base,
		dockerfile: dockerfile,
		withDebug:  true,
	}
}

type storeExtractor struct {
	ver     uint16
	storeID string
}

func (e storeExtractor) id() string {
	return e.storeID
}
func (e storeExtractor) version() uint16 {
	return e.ver
}

func (e storeExtractor) extract(t testing.TB) (elf, debugElf *pfelf.File) {
	s, err := modulestore.InitModuleStore(moduleStoreCachePath)
	require.NoError(t, err)
	parsedID, err := modulestore.IDFromString(e.id())
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	err = s.UnpackModule(parsedID, buf)
	require.NoError(t, err)

	tempFile := filepath.Join(t.TempDir(), e.storeID)
	err = os.WriteFile(tempFile, buf.Bytes(), 0o600)
	require.NoError(t, err)

	elf, err = pfelf.Open(tempFile)
	require.NoError(t, err)
	t.Cleanup(func() {
		elf.Close()
	})
	return elf, nil
}
