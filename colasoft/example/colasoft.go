package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/colasoft"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"golang.org/x/sys/unix"
)

type (
	SampleAttrProducer struct {
		extra map[libpf.TraceHash]*libpf.Trace
	}
)

var _ colasoft.SymbolReporter = (*SampleAttrProducer)(nil)

func (s *SampleAttrProducer) CollectExtraSampleMeta(trace *libpf.Trace, meta *samples.TraceEventMeta) any {
	log.Debugf("\tCollectExtraSampleMeta: %x", meta.Timestamp)
	s.extra[trace.Hash] = trace
	return trace.Hash
}

func (s *SampleAttrProducer) ExtraSampleAttrs(attrMgr *samples.AttrTableManager, meta any) []int32 {
	key := meta.(libpf.TraceHash)
	log.Debugf("\tExtraSampleAttrs: %x", key)
	trace := s.extra[key]
	fts := make([]string, 0)
	for _, ft := range trace.FrameTypes {
		fts = append(fts, ft.String())
	}
	slice := pcommon.NewInt32Slice()
	attrMgr.AppendOptionalString(slice, `frame.type`, strings.Join(fts, ","))
	attrMgr.AppendOptionalString(slice, `random.uuid`, uuid.NewString())
	return slice.AsRaw()
}

func (s *SampleAttrProducer) ExecutableKnown(fileID libpf.FileID) bool {
	log.Infof("executable known: %s", fileID.Base64())
	return false
}
func (s *SampleAttrProducer) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	log.Infof("executable metadata: fileid(%s), filename(%s), type(%s)",
		args.FileID.Base64(), args.FileName, args.Interp)
}

func (s *SampleAttrProducer) ConsumeProfilesFunc(_ context.Context, tds map[uint32]pprofile.Profiles) error {
	for pid, td := range tds {
		log.Infof("consume profile(%d): %d", pid, td.SampleCount())
		type Func struct {
			Filename, Symbol string
		}
		td.ResourceProfiles().RemoveIf(func(profiles pprofile.ResourceProfiles) bool {
			profiles.ScopeProfiles().RemoveIf(func(profiles pprofile.ScopeProfiles) bool {
				profiles.Profiles().RemoveIf(func(prof pprofile.Profile) bool {
					stringTable := make(map[string]int, prof.StringTable().Len())
					for i := 0; i < prof.StringTable().Len(); i++ {
						stringTable[prof.StringTable().At(i)] = i
					}
					stable := prof.StringTable()
					atable := prof.AttributeTable()
					funcMaps := make(map[Func]int)
					for i := 0; i < prof.FunctionTable().Len(); i++ {
						f := prof.FunctionTable().At(i)
						function := Func{
							Filename: stable.At(int(f.FilenameStrindex())),
							Symbol:   stable.At(int(f.NameStrindex())),
						}
						funcMaps[function] = i
					}

					locations := prof.LocationTable()
					for i := 0; i < locations.Len(); i++ {
						loc := locations.At(i)
						if loc.Line().Len() > 0 {
							continue
						}
						line := loc.Line().AppendEmpty()
						var fileID libpf.FileID
						for j := 0; j < loc.AttributeIndices().Len(); j++ {
							attr := atable.At(int(loc.AttributeIndices().At(j)))
							if attr.Key() != "profile.location.fileID" {
								continue
							}
							fileID, _ = libpf.FileIDFromBase64(attr.Value().AsString())
						}
						line.SetLine(0) // TODO: function line number
						var f Func
						f.Symbol = fmt.Sprintf("0x%x", loc.Address())
						if !fileID.IsZero() {
							f.Filename = fileID.ToUUIDString()
						}
						filename := slices.Index(stable.AsRaw(), f.Filename)
						name := slices.Index(stable.AsRaw(), f.Symbol)
						if filename == -1 {
							filename = stable.Len()
							stable.Append(f.Filename)
						}
						if name == -1 {
							name = stable.Len()
							stable.Append(f.Symbol)
						}
						if _, ok := funcMaps[f]; !ok {
							funcMaps[f] = prof.FunctionTable().Len()
							empty := prof.FunctionTable().AppendEmpty()
							empty.SetFilenameStrindex(int32(filename))
							empty.SetNameStrindex(int32(name))
						}
						line.SetFunctionIndex(int32(funcMaps[f]))
					}

					period := prof.PeriodType()
					log.Infof("profile(%s): period(%s, %s)", prof.ProfileID(),
						stable.At(int(period.TypeStrindex())), stable.At(int(period.UnitStrindex())))
					for i := 0; i < prof.Sample().Len(); i++ {
						sample := prof.Sample().At(i)
						log.Infof("sample(%d): %d, (%d~%d)", i, sample.Value(), sample.LocationsStartIndex(), sample.LocationsLength())
						for j := int32(0); j < sample.LocationsLength(); j++ {
							idx := prof.LocationIndices().At(int(sample.LocationsStartIndex() + j))
							loc := locations.At(int(idx))
							fmt.Printf("\t\tloc(0x%x)", loc.Address())
							for h := 0; h < loc.AttributeIndices().Len(); h++ {
								attr := atable.At(int(loc.AttributeIndices().At(h)))
								fmt.Printf(" %s=%s", attr.Key(), attr.Value().AsString())
							}
							for h := 0; h < loc.Line().Len(); h++ {
								line := loc.Line().At(h)
								f := prof.FunctionTable().At(int(line.FunctionIndex()))
								filename := stable.At(int(f.FilenameStrindex()))
								name := stable.At(int(f.NameStrindex()))
								fmt.Printf(" %s:%s:%d", filename, name, line.Line())
							}
							fmt.Printf("\n")
						}
					}
					return false
				})
				return false
			})
			return false
		})
		jm := new(pprofile.JSONMarshaler)
		if content, err := jm.MarshalProfiles(td); err != nil {
			return err
		} else {
			filename := filepath.Join(os.TempDir(), fmt.Sprintf("pprofile-%d.json", pid))
			return os.WriteFile(filename, content, os.ModePerm)
		}
	}
	return nil
}

func main() {
	// TODO: FATA[0000] failed to start off-cpu profiling: creating tracefs event (arch-specific fallback for "finish_task_switch.isra.0.cold"): creating probe entry on tracefs: token __x64_finish_task_switch.isra.0.cold: not found: write /sys/kernel/tracing/kprobe_events: no such file or directory
	log.SetLevel(log.InfoLevel)

	attrs := &SampleAttrProducer{extra: make(map[libpf.TraceHash]*libpf.Trace)}
	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer cancel()

	c := colasoft.NewCollector(attrs)
	if err := c.Start(ctx, 20, 0, time.Second*5, nil, 5000, time.Minute, true, false, []libpf.PID{}, 1024*512); err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
	c.Stop()
}
