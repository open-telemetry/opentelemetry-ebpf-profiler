/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package containermetadata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/containerd/containerd"
	"github.com/docker/docker/client"
	lru "github.com/elastic/go-freelru"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractContainerIDFromFile(t *testing.T) {
	containerIDCache, err := lru.NewSynced[util.PID, containerIDEntry](
		containerIDCacheSize, util.PID.Hash32)
	require.NoError(t, err)

	tests := []struct {
		name           string
		cgroupname     string
		expContainerID string
		pid            util.PID
		expEnv         containerEnvironment
		customHandler  *handler
	}{
		{
			name:           "dockerv1",
			cgroupname:     "testdata/cgroupv1docker",
			expContainerID: "ffdd6f676b96f53ce556815731ca2a89d23c800f37d29976155d8c68e384337e",
			expEnv:         envDocker,
		},
		{
			name:           "kubernetesv1",
			cgroupname:     "testdata/cgroupv1kubernetes",
			expContainerID: "ed89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
			expEnv:         envKubernetes,
		},
		{
			name:           "altkubernetesv1",
			cgroupname:     "testdata/cgroupv1altkubernetes",
			expContainerID: "af24eca41b7e02d7f8991153fbc255cb7e9b79e812bdbe6d8b95538b59417e2b",
			expEnv:         envKubernetes,
		},
		{
			name:           "crikubernetesv1-a",
			cgroupname:     "testdata/cgroupv1crikubernetes",
			expContainerID: "5dab0ec4aebed0b17e8b783c11b859f43da98335fd4973a396ed7bbdab6659f3",
			expEnv:         envKubernetes,
		},
		{
			name:           "crikubernetesv1-b",
			cgroupname:     "testdata/cgroupv1crikubernetes2",
			expContainerID: "5dab0ec4aebed0b17e8b783c11b859f43da98335fd4973a396ed7bbdab6659f3",
			expEnv:         envKubernetes,
		},
		{
			name:           "crikubernetesv1-c",
			cgroupname:     "testdata/cgroupv1crikubernetes3",
			expContainerID: "2b78f9fa3929001b038625607be8a97af3fb9066246513e5c15343fb52dd99d9",
			expEnv:         envKubernetes,
		},
		{
			name:           "dockerpodsv1",
			cgroupname:     "testdata/cgroupv1dockerpods",
			expContainerID: "dd89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
			expEnv:         envDocker | envKubernetes,
		},
		{
			name:           "dockerv2",
			cgroupname:     "testdata/cgroupv2docker",
			expContainerID: "8ae5d36793164a2374bd9b4ceb81c6ca57a9152bdc69eafa9ce7919d22efff0d",
			expEnv:         envDocker,
		},
		{
			name:           "kubernetesv2",
			cgroupname:     "testdata/cgroupv2kubernetes",
			expContainerID: "ed89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
			expEnv:         envKubernetes,
		},
		{
			name:           "altkubernetesv2",
			cgroupname:     "testdata/cgroupv2altkubernetes",
			expContainerID: "6fb31c47139f555a77f6dea60260eb38006755059cec4dfac8766310306dd3ee",
			expEnv:         envKubernetes,
		},
		{
			name:           "dockerpodsv2",
			cgroupname:     "testdata/cgroupv2dockerpods",
			expContainerID: "dd89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
			expEnv:         envDocker | envKubernetes,
		},
		{
			name:           "lxc payload",
			cgroupname:     "testdata/lxcpayload",
			expContainerID: "hermes",
			expEnv:         envLxc,
		},
		{
			name:           "lxc monitor",
			cgroupname:     "testdata/lxcmonitor",
			expContainerID: "hermes",
			expEnv:         envLxc,
		},
		{
			name:           "containerd",
			cgroupname:     "testdata/containerdRedis",
			expContainerID: "11:perf_event:/containerd-namespace/redis-server-id",
			expEnv:         envContainerd,
		},
		{
			name:           "buildkit",
			cgroupname:     "testdata/buildkit",
			expContainerID: "vy53ljgivqn5q9axwrx1mf40l",
			expEnv:         envDockerBuildkit,
		},
		{
			name:           "minikube",
			cgroupname:     "testdata/cgroupv2minikube-docker",
			expContainerID: "90b200f66e7a7c6d3ee264d905001c37b7dd9d08e2d35aa669c2a8b092fe1a64",
			expEnv:         envDocker,
			customHandler: &handler{
				containerIDCache: containerIDCache,

				// In minikube environment k8 client is not available
				dockerClient:     &client.Client{},
				containerdClient: &containerd.Client{},
			},
		},
	}

	defaultHandler := &handler{
		containerIDCache: containerIDCache,

		// Use dummy clients to trigger the regex match in the test.
		dockerClient:     &client.Client{},
		kubeClientSet:    &kubernetes.Clientset{},
		containerdClient: &containerd.Client{},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			h := defaultHandler
			if test.customHandler != nil {
				h = test.customHandler
			}
			containerID, env, err := h.extractContainerIDFromFile(test.cgroupname)
			require.NoError(t, err)
			assert.Equal(t, test.expContainerID, containerID)
			assert.Equal(t, test.expEnv, env)
		})
	}
}

func TestGetKubernetesPodMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		clientset        kubernetes.Interface
		pid              util.PID
		expContainerID   string
		expContainerName string
		expPodName       string
		err              error
	}{
		{
			name: "findMatchingPod",
			clientset: fake.NewSimpleClientset(&corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:        "testpod-abc123-sldfj293",
					Namespace:   "default",
					Annotations: map[string]string{},
					OwnerReferences: []v1.OwnerReference{
						{
							Kind: "ReplicaSet",
							Name: "testpod-abc123",
						},
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "testcontainer-ab1c",
							ContainerID: "docker://" +
								"ed89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
						},
					},
				},
			}, &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:        "testpod-def456",
					Namespace:   "default",
					Annotations: map[string]string{},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "testcontainer-de2f",
							ContainerID: "docker://" +
								"def9697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
						},
					},
				},
			}),
			pid:              1,
			expContainerID:   "ed89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
			expContainerName: "testcontainer-ab1c",
			expPodName:       "testpod",
		},
		{
			name: "matchingPodNotFound",
			clientset: fake.NewSimpleClientset(&corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:        "testpod-abc123",
					Namespace:   "default",
					Annotations: map[string]string{},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "testcontainer-ab1c",
							ContainerID: "docker://" +
								"abc9697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
						},
					},
				},
			}, &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:        "testpod-def456",
					Namespace:   "default",
					Annotations: map[string]string{},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "testcontainer-de2f",
							ContainerID: "docker://" +
								"def9697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
						},
					},
				},
			}),
			pid:            1,
			expContainerID: "ed89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997",
			err: errors.New("failed to get kubernetes pod metadata, failed to " +
				"find matching kubernetes pod/container metadata for containerID, " +
				"ed89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe1997"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			containerMetadataCache, err := lru.NewSynced[string, ContainerMetadata](
				containerMetadataCacheSize, hashString)
			require.NoError(t, err)

			containerIDCache, err := lru.NewSynced[util.PID, containerIDEntry](
				containerIDCacheSize, util.PID.Hash32)
			require.NoError(t, err)

			instance := &handler{
				containerMetadataCache: containerMetadataCache,
				kubeClientSet:          test.clientset,
				dockerClient:           nil,
				containerIDCache:       containerIDCache,
			}
			instance.deferredPID, err = lru.NewSynced[util.PID, libpf.Void](1024,
				func(u util.PID) uint32 { return uint32(u) })
			require.NoError(t, err)

			cgroup = "testdata/cgroupv%dkubernetes"
			meta, err := instance.GetContainerMetadata(test.pid)
			if test.err != nil {
				require.Error(t, err)
				assert.Equal(t, ContainerMetadata{}, meta)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.expContainerName, meta.ContainerName)
			assert.Equal(t, test.expPodName, meta.PodName)

			if test.err == nil {
				// check the item has been added correctly to the container metadata cache
				value, ok := instance.containerMetadataCache.Get(test.expContainerID)
				assert.True(t, ok, "container metadata should be in the container metadata cache")
				assert.Equal(t, test.expContainerID, value.containerID)
				assert.Equal(t, test.expContainerName, value.ContainerName)
				assert.Equal(t, test.expPodName, value.PodName)
			}
		})
	}
}

func BenchmarkGetKubernetesPodMetadata(b *testing.B) {
	for i := 0; i < b.N; i++ {
		clientset := fake.NewSimpleClientset()
		containerMetadataCache, err := lru.NewSynced[string, ContainerMetadata](
			containerMetadataCacheSize, hashString)
		require.NoError(b, err)

		containerIDCache, err := lru.NewSynced[util.PID, containerIDEntry](
			containerIDCacheSize, util.PID.Hash32)
		require.NoError(b, err)

		instance := &handler{
			containerMetadataCache: containerMetadataCache,
			kubeClientSet:          clientset,
			dockerClient:           nil,
			containerIDCache:       containerIDCache,
		}
		instance.deferredPID, err = lru.NewSynced[util.PID, libpf.Void](1024,
			func(u util.PID) uint32 { return uint32(u) })
		require.NoError(b, err)

		for j := 100; j < 700; j++ {
			testPod := fmt.Sprintf("testpod-abc%d", j)

			pod := &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:        testPod,
					Namespace:   "default",
					Annotations: map[string]string{},
					OwnerReferences: []v1.OwnerReference{
						{
							Kind: "ReplicaSet",
							Name: testPod,
						},
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: fmt.Sprintf("testcontainer-%d", j),
							ContainerID: "docker://" + fmt.Sprintf(
								"%dd89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe19",
								j),
						},
					},
				},
			}

			file, err := os.CreateTemp("", "test_containermetadata_cgroup*")
			require.NoError(b, err)
			defer os.Remove(file.Name()) // nolint: gocritic

			_, err = fmt.Fprintf(file,
				"0::/kubepods/besteffort/poda9c80282-3f6b-4d5b-84d5-a137a6668011/"+
					"%dd89697807a981b82f6245ac3a13be232c1e13435d52bc3f53060d61babe19", j)
			require.NoError(b, err)

			cgroup = "/tmp/test_containermetadata_cgroup%d"
			opts := v1.CreateOptions{}
			clientsetPod, err := clientset.CoreV1().Pods("default").Create(
				context.Background(), pod, opts)
			require.NoError(b, err)
			instance.putCache(clientsetPod)

			split := strings.Split(file.Name(), "test_containermetadata_cgroup")
			pid, err := strconv.Atoi(split[1])
			require.NoError(b, err)

			_, err = instance.GetContainerMetadata(util.PID(pid))
			require.NoError(b, err)
		}
	}
}
