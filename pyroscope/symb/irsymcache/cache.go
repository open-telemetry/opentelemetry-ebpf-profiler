package irsymcache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

var errTTL = 5 * time.Minute
var errUnknownFile = errors.New("unknown file")
var erroredMarker = "errored"

type Table interface {
	Lookup(addr uint64) ([]samples.SourceInfoFrame, error)
	Close()
}

type TableFactory interface {
	ConvertTable(src *os.File, dst *os.File) error
	OpenTable(path string) (Table, error)
	Name() string
}

func NewTableFactory() TableFactory {
	return TableTableFactory{}
}

type Resolver struct {
	logger   *logrus.Entry
	f        TableFactory
	mutex    sync.Mutex
	cacheDir string
	// todo make cache lookups / stores not allocate
	cache *ristretto.Cache[string, string]

	jobs     chan convertJob
	tables   map[libpf.FileID]Table
	shutdown chan struct{}
	wg       sync.WaitGroup
}

func (c *Resolver) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, table := range c.tables {
		table.Close()
	}
	clear(c.tables)
}

type convertJob struct {
	src *os.File
	dst *os.File

	result chan error
}

type Options struct {
	Path string
	Size int
}

func NewFSCache(impl TableFactory, opt Options) (*Resolver, error) {
	l := logrus.WithField("component", "irsymtab")
	l.WithFields(logrus.Fields{
		"path": opt.Path,
		"size": opt.Size,
	}).Info()

	shutdown := make(chan struct{})
	res := &Resolver{
		logger:   l,
		f:        impl,
		cacheDir: opt.Path,
		jobs:     make(chan convertJob, 1),
		shutdown: shutdown,
		tables:   make(map[libpf.FileID]Table),
	}
	res.cacheDir = filepath.Join(res.cacheDir, impl.Name())

	if err := os.MkdirAll(res.cacheDir, 0o700); err != nil {
		return nil, err
	}

	cache, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 10000,
		MaxCost:     int64(opt.Size),
		BufferItems: 64,
		OnEvict: func(item *ristretto.Item[string]) {
			if item.Value == erroredMarker {
				return
			}
			id, err := libpf.FileIDFromString(item.Value)
			if err != nil {
				l.Error(err)
				return
			}
			filePath := res.tableFilePath(id)
			l.WithFields(logrus.Fields{
				"file": filePath,
			}).Debug("symbcache evicting")
			if err = os.Remove(filePath); err != nil {
				l.Error(err)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	res.cache = cache

	err = filepath.Walk(res.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		filename := filepath.Base(path)
		id, err := libpf.FileIDFromString(filename)
		if err != nil {
			return nil
		}
		id2 := id.StringNoQuotes()
		if filename != id2 {
			return nil
		}
		res.cache.Set(filename, filename, info.Size())
		return nil
	})
	if err != nil {
		return nil, err
	}

	res.wg.Add(1)
	go func() {
		defer res.wg.Done()
		convertLoop(res, shutdown)
	}()

	return res, nil
}

func convertLoop(res *Resolver, shutdown <-chan struct{}) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		select {
		case <-shutdown:
			for len(res.jobs) > 0 {
				job := <-res.jobs
				job.result <- res.convertSync(job.src, job.dst)
			}
			return
		case job := <-res.jobs:
			job.result <- res.convertSync(job.src, job.dst)
		}
	}
}

func (c *Resolver) Observe(fid libpf.FileID, elfRef *pfelf.Reference) error {
	o, ok := elfRef.ELFOpener.(pfelf.RootFSOpener)
	if !ok {
		return nil
	}
	if elfRef.FileName() == process.VdsoPathName {
		return nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	_, known := c.cache.Get(fid.StringNoQuotes())
	if known {
		return nil
	}
	pid := 0
	if pp, ok := elfRef.ELFOpener.(process.Process); ok {
		pid = int(pp.PID())
	}
	l := c.logger.WithFields(logrus.Fields{
		"fid": fid.StringNoQuotes(),
		"elf": elfRef.FileName(),
		"pid": pid,
	})
	t1 := time.Now()
	err := c.convert(l, fid, elfRef, o)
	if err != nil {
		l.WithError(err).WithField("duration", time.Since(t1)).Error("conversion failed")
		c.cache.SetWithTTL(fid.StringNoQuotes(), erroredMarker, 128*1024, errTTL)
		c.cache.Wait()
	} else {
		l.WithField("duration", time.Since(t1)).Debug("converted")
	}
	return err
}

func (c *Resolver) convert(
	l *logrus.Entry,
	fid libpf.FileID,
	elfRef *pfelf.Reference,
	o pfelf.RootFSOpener,
) error {
	var err error
	var dst *os.File
	var src *os.File

	tableFilePath := c.tableFilePath(fid)
	info, err := os.Stat(tableFilePath)
	if err == nil && info != nil {
		return nil
	}

	elf, err := c.getElf(l, elfRef)
	if err != nil {
		return err
	}
	defer elf.Close()
	debugLinkFileName := elf.DebuglinkFileName(elfRef.FileName(), elfRef)
	if debugLinkFileName != "" {
		src, err = o.OpenRootFSFile(debugLinkFileName)
		if err != nil {
			l.WithError(err).Debug("open debug file")
		} else {
			defer src.Close()
		}
	}
	if src == nil {
		src = elf.OSFile()
	}
	if src == nil {
		return errors.New("failed to open elf os file")
	}

	dst, err = os.Create(tableFilePath)
	if err != nil {
		return err
	}
	defer dst.Close()

	err = c.convertAsync(src, dst)

	if err != nil {
		_ = os.Remove(tableFilePath)
		return err
	}

	sz := 0
	stat, _ := dst.Stat()
	if stat != nil {
		sz = int(stat.Size())
	}

	c.cache.Set(fid.StringNoQuotes(), fid.StringNoQuotes(), int64(sz))
	c.cache.Wait()

	return nil
}

func (c *Resolver) getElf(l *logrus.Entry, elfRef *pfelf.Reference) (*pfelf.File, error) {
	elf, err := elfRef.GetELF()
	if err == nil {
		return elf, nil
	}
	// todo why is this happening? mostly on my firefox sleeping processes
	if !errors.Is(err, syscall.ESRCH) && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	p, ok := elfRef.ELFOpener.(process.Process)
	if !ok {
		return nil, err
	}
	_, _ = p.GetMappings() // todo we have the mapping 3 stack frames above
	l.WithField("proc", fmt.Sprintf("%+v", p)).Debug("Get mappings")
	openELF, err := p.OpenELF(elfRef.FileName())
	if err != nil {
		l.WithError(err).Error("DEBUG ESRCH open elf")
		return nil, err
	}

	return openELF, err
}

func (c *Resolver) convertAsync(src, dst *os.File) error {
	job := convertJob{src: src, dst: dst, result: make(chan error)}
	c.jobs <- job
	return <-job.result
}

func (c *Resolver) convertSync(src, dst *os.File) error {
	return c.f.ConvertTable(src, dst)
}

func (c *Resolver) tableFilePath(fid libpf.FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

func (c *Resolver) ResolveAddress(
	fid libpf.FileID,
	addr uint64,
) ([]samples.SourceInfoFrame, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	v, known := c.cache.Get(fid.StringNoQuotes())

	if !known || v == erroredMarker {
		return nil, errUnknownFile
	}
	t, ok := c.tables[fid]
	if ok {
		return t.Lookup(addr)
	}
	path := c.tableFilePath(fid)
	t, err := c.f.OpenTable(path)
	if err != nil {
		_ = os.Remove(path)
		c.cache.Del(fid.StringNoQuotes())
		return nil, err
	}
	c.tables[fid] = t
	return t.Lookup(addr)
}

func (c *Resolver) Close() error {
	c.mutex.Lock()
	if c.shutdown != nil {
		close(c.shutdown)
		c.shutdown = nil
	}
	c.mutex.Unlock()

	c.wg.Wait()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, table := range c.tables {
		table.Close()
	}
	clear(c.tables)
	return nil
}
