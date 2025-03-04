package table

import (
	"os"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/ffi"
)

func FDToTable(executable, output *os.File, opt ...Option) error {
	sb := newStringBuilder()
	rb := newRangesBuilder()
	lb := newLineTableBuilder()
	rc := &rangeCollector{sb: sb, rb: rb, lb: lb}
	for _, o := range opt {
		o(&rc.opt)
	}

	if err := ffi.RangeExtractor(executable, rc); err != nil {
		return err
	}
	rb.sort()

	err2 := rc.write(output)
	if err2 != nil {
		return err2
	}
	log.Debugf("converted %s -> %s : %d ranges, %d strings",
		executable.Name(),
		output.Name(),
		len(rb.entries),
		len(sb.unique))

	return nil
}
