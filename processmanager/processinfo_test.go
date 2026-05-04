package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/plugins"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type TestInstance struct {
	plugins.InstanceStubs
	info libc.LibcInfo
}

func (ti *TestInstance) UpdateLibcInfo(handler plugins.EbpfHandler, pid libpf.PID, info libc.LibcInfo) error {
	ti.info = info
	return nil
}

func (ti *TestInstance) Detach(handler plugins.EbpfHandler, pid libpf.PID) error {
	return nil
}

func TestAssignLibcInfoMergesLibcInfo(t *testing.T) {
	assert := assert.New(t)

	pid := libpf.PID(1)
	odid := util.OnDiskFileIdentifier{
		DeviceID: 1,
		InodeNum: 1,
	}

	interp := TestInstance{}

	pm := ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]plugins.Instance{
			pid: {
				odid: &interp,
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {},
		},
	}

	libcInfoWithTSD := libc.LibcInfo{
		libc.TSDInfo{
			Offset:     8,
			Multiplier: 8,
			Indirect:   0,
		},
		libc.DTVInfo{},
	}
	pm.assignLibcInfo(pid, &libcInfoWithTSD)

	assert.Equal(libcInfoWithTSD, interp.info)

	libcInfoWithDTV := libc.LibcInfo{
		libc.TSDInfo{},
		libc.DTVInfo{
			Offset:     -8,
			Multiplier: 16,
		},
	}

	merged := libcInfoWithTSD
	merged.Merge(libcInfoWithDTV)

	pm.assignLibcInfo(pid, &libcInfoWithDTV)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)

	pm.assignLibcInfo(pid, &merged)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)
}
