package hotspotmem

import (
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	profilesv1 "go.opentelemetry.io/proto/otlp/profiles/v1development"
	"google.golang.org/protobuf/proto"
)

var libPath = filepath.Join("/tmp/", "otlp-hotspot-mem-profile", "hotspot_profiler.so")

func ExtractEmbeddedLibrary(tmpPath string) error {
	dir := filepath.Join(tmpPath, "otlp-hotspot-mem-profile")
	lib := filepath.Join(dir, "hotspot_profiler.so")
	if len(embeddedLibLinux) == 0 {
		return fmt.Errorf("library for %s/%s is not embedded (file size is 0)", runtime.GOOS, runtime.GOARCH)
	}
	if info, err := os.Stat(lib); err == nil && info.Size() == int64(len(embeddedLibLinux)) {
		return nil
	}
	_ = os.Remove(dir)
	_ = os.MkdirAll(dir, 0755)
	if err := os.WriteFile(lib, embeddedLibLinux, 0755); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("failed to write library to %s: %w", lib, err)
	}
	return nil
}

// OTLPProfilerConfig OTLP profiler 配置
type OTLPProfilerConfig struct {
	PID           int           // Java 进程 PID
	AllocInterval uint64        // 内存分配采样间隔，以字节为单位
	DumpInterval  time.Duration // dump 间隔
}

// OTLPProfileData OTLP profile 数据
type OTLPProfileData struct {
	Timestamp    time.Time
	ProfilesData *profilesv1.ProfilesData
}

// StartMemAllocProfilingOTLP 启动内存分配 profiling（OTLP 格式）
func StartMemAllocProfilingOTLP(ctx context.Context, config *OTLPProfilerConfig, cha chan map[uint32]pprofile.Profiles) error {
	// 设置默认值
	if config.AllocInterval == 0 {
		config.AllocInterval = 512 * 1024
	}
	if config.DumpInterval == 0 {
		config.DumpInterval = 5 * time.Second
	}

	// 创建 JVM attacher
	attacher, err := NewJVMAttacher(config.PID)
	if err != nil {
		return fmt.Errorf("failed to create JVM attacher: %w", err)
	}

	// 启动 profiling
	startCmd := fmt.Sprintf("start,event=alloc,alloc=%d", config.AllocInterval)
	log.Tracef("Starting hotspot mem profiling with command: %s", startCmd)
	// 不需要手动停止，过一分钟后会自动退出
	response, err := attacher.loadAgent(startCmd)
	if err != nil {
		return fmt.Errorf("failed to start profiling: %w", err)
	}
	log.Tracef("start hot spot mem profiling: %s", response)

	// 启动 dump 协程
	go func() {
		ticker := time.NewTicker(config.DumpInterval)
		defer ticker.Stop()
		writeTmpFile := fmt.Sprintf("%s/asprof.%d.%d.pb", "/tmp/", os.Getpid(), config.PID)
		WriteTmpLog := fmt.Sprintf("%s/asprof-log.%d.%d.txt", "/tmp/", os.Getpid(), config.PID)
		readTmpFile := fmt.Sprintf("%s/asprof.%d.%d.pb", attacher.tmpPath, os.Getpid(), config.PID)
		readTmpLog := fmt.Sprintf("%s/asprof-log.%d.%d.txt", attacher.tmpPath, os.Getpid(), config.PID)
		for {
			select {
			case <-ctx.Done():
				log.Tracef("Context cancelled, stopping hotspot mem profiling")
				return

			case <-ticker.C:
				// Dump profile data
				timestamp := time.Now()
				var data OTLPProfileData
				data.Timestamp = timestamp
				// 构建 dump 命令（OTLP 格式）
				dumpCmd := fmt.Sprintf("dump,file=%s,otlp,log=%s", writeTmpFile, WriteTmpLog)
				log.Tracef("Sending hotspot mem profiling dump command: %s", dumpCmd)
				// 执行 dump 命令
				_, err := attacher.loadAgent(dumpCmd)
				if err != nil {
					log.Infof(" Failed to dump hotspot profile: %v", err)
					return
				}
				// 等待文件写入完成, 动态库会把数据写入文件，然后我们读出来解析，
				// 暂时先这样最简单，
				// 如果要通过其他方式得改动态库代码。
				time.Sleep(200 * time.Millisecond)

				if _, err := os.Stat(readTmpFile); os.IsNotExist(err) {
					log.Errorf("unable to read hotspot mem profiling dump data, data file does not exist: %s", readTmpFile)
					// 检查日志文件
					if logData, err := os.ReadFile(readTmpLog); err == nil {
						log.Errorf("hotspot mem profiling lib: %s", string(logData))
					}
					_ = os.Remove(readTmpLog)
					continue
				}

				// 读取临时文件
				fileData, dumpErr := os.ReadFile(readTmpFile)
				_ = os.Remove(readTmpFile)
				_ = os.Remove(readTmpLog)
				if dumpErr != nil {
					log.Errorf("Failed to read hotspot mem profiling dump file: %v", err)
					continue
				}
				// 解析 通用 OTLP protobuf 数据
				profilesData := &profilesv1.ProfilesData{}
				if err := proto.Unmarshal(fileData, profilesData); err != nil {
					log.Errorf("Failed to unmarshal OTLP data: %v", err)
					continue
				}
				data.ProfilesData = profilesData
				tds := ConvertOtlpData(data, uint32(config.PID))

				select {
				case cha <- tds:
				case <-ctx.Done():
					return
				default:
					log.Warnf("drop hot spot mem profiling data, cause channel overflow...")
				}
			}
		}
	}()
	return nil
}

// mkProfileID 从generate.go直接copy过来的
func mkProfileID() []byte {
	profileID := make([]byte, 16)
	_, err := rand.Read(profileID)
	if err != nil {
		return []byte("opentelemetry-ebpf-profiler")
	}
	return profileID
}

func ConvertOtlpData(data OTLPProfileData, pid uint32) map[uint32]pprofile.Profiles {
	tds := make(map[uint32]pprofile.Profiles)
	profiles := pprofile.NewProfiles()

	rp := profiles.ResourceProfiles().AppendEmpty()
	sp := rp.ScopeProfiles().AppendEmpty()
	profile := sp.Profiles().AppendEmpty()
	profile.SetProfileID(pprofile.ProfileID(mkProfileID()))
	var typeStrIndex, unitStrIndex int32
	t := []uint64{uint64(data.Timestamp.UnixNano())}
	slices.DeleteFunc(data.ProfilesData.GetResourceProfiles(), func(profiles *profilesv1.ResourceProfiles) bool {
		slices.DeleteFunc(profiles.GetScopeProfiles(), func(profiles *profilesv1.ScopeProfiles) bool {
			slices.DeleteFunc(profiles.GetProfiles(), func(p *profilesv1.Profile) bool {
				st := profile.SampleType().AppendEmpty()
				if len(p.GetSampleType()) > 0 {
					typeStrIndex = p.GetSampleType()[0].GetTypeStrindex()
					unitStrIndex = p.GetSampleType()[0].GetUnitStrindex()
					st.SetTypeStrindex(typeStrIndex)
					st.SetUnitStrindex(unitStrIndex)
				}
				slices.DeleteFunc(p.GetSample(), func(sample *profilesv1.Sample) bool {
					s := profile.Sample().AppendEmpty()
					s.SetLocationsStartIndex(sample.LocationsStartIndex)
					s.SetLocationsLength(sample.LocationsLength)
					s.TimestampsUnixNano().Append(t...)
					s.Value().Append([]int64{sample.Value[1], sample.Value[0], -1, -1}...)
					return false
				})
				profile.LocationIndices().Append(p.GetLocationIndices()...)
				profile.SetPeriod(p.GetPeriod())
				profile.PeriodType().SetTypeStrindex(p.PeriodType.GetTypeStrindex())
				profile.PeriodType().SetUnitStrindex(p.PeriodType.GetUnitStrindex())
				return false
			})
			return false
		})
		return false
	})
	for _, mapping := range data.ProfilesData.Dictionary.GetMappingTable() {
		m := profile.MappingTable().AppendEmpty()
		m.AttributeIndices().Append(mapping.GetAttributeIndices()...)
	}

	for _, l := range data.ProfilesData.Dictionary.GetLocationTable() {
		_l := profile.LocationTable().AppendEmpty()
		_l.SetMappingIndex(l.GetMappingIndex())
		_l.SetAddress(l.Address)
		_l.AttributeIndices().Append(l.GetAttributeIndices()...)
		for _, line := range l.GetLine() {
			_line := _l.Line().AppendEmpty()
			_line.SetFunctionIndex(line.GetFunctionIndex())
			_line.SetLine(line.GetLine())
		}
	}

	for _, f := range data.ProfilesData.Dictionary.FunctionTable {
		_f := profile.FunctionTable().AppendEmpty()
		_f.SetNameStrindex(f.GetNameStrindex())
		_f.SetFilenameStrindex(f.GetFilenameStrindex())
	}
	sb := data.ProfilesData.Dictionary.GetStringTable()
	sb[typeStrIndex] = "heap"
	sb[unitStrIndex] = "bytes"
	profile.StringTable().Append(data.ProfilesData.Dictionary.StringTable...)
	profile.SetTime(pcommon.Timestamp(t[0]))
	profile.PeriodType().SetTypeStrindex(typeStrIndex)
	profile.PeriodType().SetUnitStrindex(unitStrIndex)

	tds[pid] = profiles
	return tds
}
