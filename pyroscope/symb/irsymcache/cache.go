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

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

var errUnknownFile = errors.New("unknown file")

type cachedMarker int

var cached cachedMarker = 1
var erroredMarker cachedMarker = 2

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
	cacheDir string
	cache    *lru.SyncedLRU[libpf.FileID, cachedMarker]
	jobs     chan convertJob
	wg       sync.WaitGroup

	mutex    sync.Mutex
	tables   map[libpf.FileID]Table
	shutdown chan struct{}
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
	Path        string
	SizeEntries uint32
}

func NewFSCache(impl TableFactory, opt Options) (*Resolver, error) {
	l := logrus.WithField("component", "irsymtab")
	l.WithFields(logrus.Fields{
		"path": opt.Path,
		"size": opt.SizeEntries,
	}).Debug()

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

	cache, err := lru.NewSynced[libpf.FileID, cachedMarker](
		opt.SizeEntries,
		func(id libpf.FileID,
		) uint32 {
			return id.Hash32()
		})
	cache.SetOnEvict(func(id libpf.FileID, marker cachedMarker) {
		if marker == erroredMarker {
			return
		}
		filePath := res.tableFilePath(id)
		l.WithFields(logrus.Fields{
			"file": filePath,
		}).Debug("symbcache evicting")
		if err = os.Remove(filePath); err != nil {
			l.Error(err)
		}
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
		res.cache.Add(id, cached)
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

func (c *Resolver) ExecutableKnown(id libpf.FileID) bool {
	_, known := c.cache.Get(id)
	return known
}

func (c *Resolver) ObserveExecutable(fid libpf.FileID, elfRef *pfelf.Reference) error {
	o, ok := elfRef.ELFOpener.(pfelf.RootFSOpener)
	if !ok {
		return nil
	}
	if elfRef.FileName() == process.VdsoPathName {
		c.cache.Add(fid, cached)
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
		c.cache.Add(fid, erroredMarker)
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
	c.cache.Add(fid, cached)
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
	v, known := c.cache.Get(fid)

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
		c.cache.Remove(fid)
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
