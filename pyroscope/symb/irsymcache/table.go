package irsymcache // import "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/irsymcache"

import (
	"os"

	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/table"
)

type TableTableFactory struct {
	Options []table.Option
}

func (t TableTableFactory) ConvertTable(src, dst *os.File) error {
	return table.FDToTable(src, dst, t.Options...)
}

func (t TableTableFactory) OpenTable(path string) (Table, error) {
	return table.OpenPath(path, t.Options...)
}

func (t TableTableFactory) Name() string {
	return table.VersionName()
}
