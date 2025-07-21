package irsymcache // import "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/irsymcache"

import (
	"debug/elf"
	"os"

	"github.com/grafana/pyroscope/lidia"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

type TableTableFactory struct {
	Options []lidia.Option
}

func (t TableTableFactory) ConvertTable(src, dst *os.File) error {
	e, err := elf.NewFile(src)
	if err != nil {
		return err
	}
	defer e.Close()
	return lidia.CreateLidiaFromELF(e, dst, t.Options...)
}

func (t TableTableFactory) OpenTable(path string) (Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	tt, err := lidia.OpenReader(f, t.Options...)
	if err != nil {
		return nil, err
	}
	return &table{t: tt}, nil
}

func (t TableTableFactory) Name() string {
	return "lidia1"
}

type table struct {
	t *lidia.Table
}

func (t *table) Lookup(addr uint64) ([]samples.SourceInfoFrame, error) {
	frames, err := t.t.Lookup(nil, addr)
	if err != nil || len(frames) == 0 {
		return nil, err
	}
	res := make([]samples.SourceInfoFrame, len(frames))
	for i := range frames {
		res[i] = samples.SourceInfoFrame{
			LineNumber:   libpf.SourceLineno(frames[i].LineNumber),
			FunctionName: frames[i].FunctionName,
			FilePath:     frames[i].FilePath,
		}
	}
	return res, nil
}

func (t *table) Close() {
	t.t.Close()
}
