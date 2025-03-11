package discovery

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/stretchr/testify/require"
)

func TestCGroupMatching(t *testing.T) {
	type testcase = struct {
		containerID, cgroup, expectedCID string
	}
	testcases := []testcase{
		{
			//nolint:lll
			containerID: "containerd://a534eb629135e43beb13213976e37bb2ab95cba4c0d1d0b4e27c6bc4d8091b83",
			//nolint:lll
			cgroup:      "12:cpuset:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod471203d1_984f_477e_9c35_db96487ffe5e.slice/cri-containerd-a534eb629135e43beb13213976e37bb2ab95cba4c0d1d0b4e27c6bc4d8091b83.scope",
			expectedCID: "a534eb629135e43beb13213976e37bb2ab95cba4c0d1d0b4e27c6bc4d8091b83",
		},
		{
			containerID: "cri-o://0ecc7949cbaf17e883264ea1055f60b184a7cb264fd759c4a692e1155086fe2d",
			//nolint:lll
			cgroup:      "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podb57320a0_e7eb_4ac8_a791_4c4472796867.slice/crio-0ecc7949cbaf17e883264ea1055f60b184a7cb264fd759c4a692e1155086fe2d.scope",
			expectedCID: "0ecc7949cbaf17e883264ea1055f60b184a7cb264fd759c4a692e1155086fe2d",
		},
		{
			//nolint:lll
			containerID: "docker://656959d9ee87a0b131c601ce9d9f8f76b1dda60e8608c503b5979d849cbdc714",
			//nolint:lll
			cgroup:      "0::/../../kubepods-besteffort-pod88f6f4e3_59c0_4ce8_9ecf_391c8b5a60ad.slice/docker-656959d9ee87a0b131c601ce9d9f8f76b1dda60e8608c503b5979d849cbdc714.scope",
			expectedCID: "656959d9ee87a0b131c601ce9d9f8f76b1dda60e8608c503b5979d849cbdc714",
		},
		{
			//nolint:lll
			containerID: "containerd://47e320f795efcec1ecf2001c3a09c95e3701ed87de8256837b70b10e23818251",
			//nolint:lll
			cgroup:      "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf9a04ecc_1875_491b_926c_d2f64757704e.slice/cri-containerd-47e320f795efcec1ecf2001c3a09c95e3701ed87de8256837b70b10e23818251.scope",
			expectedCID: "47e320f795efcec1ecf2001c3a09c95e3701ed87de8256837b70b10e23818251",
		},
		{
			//nolint:lll
			containerID: "docker://7edda1de1e0d1d366351e478359cf5fa16bb8ab53063a99bb119e56971bfb7e2",
			//nolint:lll
			cgroup:      "11:devices:/kubepods/besteffort/pod85adbef3-622f-4ef2-8f60-a8bdf3eb6c72/7edda1de1e0d1d366351e478359cf5fa16bb8ab53063a99bb119e56971bfb7e2",
			expectedCID: "7edda1de1e0d1d366351e478359cf5fa16bb8ab53063a99bb119e56971bfb7e2",
		},
		{
			containerID: "",
			cgroup:      "0::/../../user.slice/user-501.slice/session-3.scope",
			expectedCID: "",
		},
	}
	for i, tc := range testcases {
		idx := i
		t.Run(fmt.Sprintf("testcase %d %s", i, tc.cgroup), func(t *testing.T) {
			k8sCID := string(getContainerIDFromK8S(tc.containerID))
			require.Equal(t, tc.expectedCID, k8sCID)

			cache, err := freelru.NewSynced[libpf.PID, string](1024,
				func(pid libpf.PID) uint32 { return uint32(pid) })
			require.NoError(t, err)
			cgroupCID, err := libpf.LookupCgroupFromReader(
				cache, libpf.PID(idx), bytes.NewReader([]byte(tc.cgroup)))
			require.NoError(t, err)
			require.Equal(t, tc.expectedCID, cgroupCID)
		})
	}
}

func TestTargetFinder(t *testing.T) {
	options := TargetsOptions{
		Targets: []DiscoveredTarget{
			map[string]string{
				//nolint:lll
				"__meta_kubernetes_pod_container_id":   "containerd://9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f",
				"__meta_kubernetes_namespace":          "foo",
				"__meta_kubernetes_pod_container_name": "bar",
			},
			map[string]string{
				//nolint:lll
				"__container_id__":                     "57ac76ffc93d7e7735ca186bc67115656967fc8aecbe1f65526c4c48b033e6a5",
				"__meta_kubernetes_namespace":          "qwe",
				"__meta_kubernetes_pod_container_name": "asd",
			},
		},
		TargetsOnly:   true,
		DefaultTarget: nil,
	}
	cgroups, err := freelru.New[libpf.PID, string](1024,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	require.NoError(t, err)
	cgroups.Add(1801264, "9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f")
	cgroups.Add(489323, "57ac76ffc93d7e7735ca186bc67115656967fc8aecbe1f65526c4c48b033e6a5")
	tf := NewTargetProducer(cgroups, options)

	target := tf.FindTarget(1801264)
	require.NotNil(t, target)
	require.Equal(t, "ebpf/foo/bar", target.labels.Get("service_name"))

	target = tf.FindTarget(489323)
	require.NotNil(t, target)
	require.Equal(t, "ebpf/qwe/asd", target.labels.Get("service_name"))

	tf.Update(options)

	target2 := tf.FindTarget(489323)
	require.NotNil(t, target2)
	require.Same(t, target2, target)

	target = tf.FindTarget(239)
	require.Nil(t, target)
}

func TestPreferPIDOverContainerID(t *testing.T) {
	options := TargetsOptions{
		Targets: []DiscoveredTarget{
			map[string]string{
				//nolint:lll
				"__meta_kubernetes_pod_container_id":   "containerd://9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f",
				"__meta_kubernetes_namespace":          "foo",
				"__meta_kubernetes_pod_container_name": "bar",
				"__process_pid__":                      "1801264",
				"exe":                                  "/bin/bash",
			},
			map[string]string{
				//nolint:lll
				"__meta_kubernetes_pod_container_id":   "containerd://9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f",
				"__meta_kubernetes_namespace":          "foo",
				"__meta_kubernetes_pod_container_name": "bar",
				"__process_pid__":                      "1801265",
				"exe":                                  "/bin/dash",
			},
		},
		TargetsOnly:   true,
		DefaultTarget: nil,
	}

	cgroups, err := freelru.New[libpf.PID, string](1024,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	require.NoError(t, err)
	tf := NewTargetProducer(cgroups, options)

	target := tf.FindTarget(1801264)
	require.NotNil(t, target)
	require.Equal(t, "ebpf/foo/bar", target.labels.Get("service_name"))
	require.Equal(t, "/bin/bash", target.labels.Get("exe"))

	target = tf.FindTarget(1801265)
	require.NotNil(t, target)
	require.Equal(t, "ebpf/foo/bar", target.labels.Get("service_name"))
	require.Equal(t, "/bin/dash", target.labels.Get("exe"))

	tf.Update(options)

	target2 := tf.FindTarget(1801265)
	require.NotNil(t, target2)
	require.Same(t, target2, target)
}

func BenchmarkFindTargetCacheCIDOnly(b *testing.B) {
	options := TargetsOptions{
		Targets: []DiscoveredTarget{
			map[string]string{
				//nolint:lll
				"__meta_kubernetes_pod_container_id":   "containerd://9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f",
				"__meta_kubernetes_namespace":          "foo",
				"__meta_kubernetes_pod_container_name": "bar",
			},
		},
		TargetsOnly:   true,
		DefaultTarget: nil,
	}
	cgroups, err := freelru.New[libpf.PID, string](1024,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	require.NoError(b, err)
	cgroups.Add(1801264, "9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f")
	tp := NewTargetProducer(cgroups, options)

	for i := 0; i < b.N; i++ {
		t := tp.FindTarget(1801264)
		if t == nil {
			b.FailNow()
		}
	}
}
