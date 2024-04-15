/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// containermetadata provides functionality for retrieving the kubernetes pod and container
// metadata or the docker container metadata for a particular PID.
// For kubernetes it uses the shared informer from the k8s client-go API
// (https://github.com/kubernetes/client-go/blob/master/tools/cache/shared_informer.go). Through
// the shared informer we are notified of changes in the state of pods in the Kubernetes
// cluster and can add the pod container metadata to the cache.
// As a backup to the kubernetes shared informer and to find the docker container metadata for
// each pid received (if it is not already in the container caches), it will retrieve the container
// id from the /proc/PID/cgroup and retrieve the metadata for the containerID.
package containermetadata

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/periodiccaller"
	"github.com/elastic/otel-profiling-agent/libpf/stringutil"
	"github.com/elastic/otel-profiling-agent/metrics"
)

const (
	dockerHost            = "DOCKER_HOST"
	kubernetesServiceHost = "KUBERNETES_SERVICE_HOST"
	kubernetesNodeName    = "KUBERNETES_NODE_NAME"
	genericNodeName       = "NODE_NAME"

	// There is a limit of 110 Pods per node (but can be overridden)
	kubernetesPodsPerNode = 110
	// From experience, usually there are no more than 10 containers (including sidecar
	// containers) in a single Pod.
	kubernetesContainersPerPod = 10
	// We're setting the default cache size according to Kubernetes best practices,
	// in order to reduce the number of Kubernetes API calls at runtime.
	containerMetadataCacheSize = kubernetesPodsPerNode * kubernetesContainersPerPod

	// containerIDCacheSize defines the size of the cache which maps a process to container ID
	// information. Its perfect size would be the number of processes running on the system.
	containerIDCacheSize = 1024
)

var (
	kubePattern       = regexp.MustCompile(`\d+:.*:/.*/*kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	dockerKubePattern = regexp.MustCompile(`\d+:.*:/.*/*docker/pod[^/]+/([0-9a-f]{64})`)
	altKubePattern    = regexp.MustCompile(
		`\d+:.*:/.*/*kubepods.*?/[^/]+/docker-([0-9a-f]{64})`)
	// The systemd cgroupDriver needs a different regex pattern:
	systemdKubePattern    = regexp.MustCompile(`\d+:.*:/.*/*kubepods-.*([0-9a-f]{64})`)
	dockerPattern         = regexp.MustCompile(`\d+:.*:/.*/*docker[-|/]([0-9a-f]{64})`)
	dockerBuildkitPattern = regexp.MustCompile(`\d+:.*:/.*/*docker/buildkit/([0-9a-z]+)`)
	lxcPattern            = regexp.MustCompile(`\d+::/lxc\.(monitor|payload)\.([a-zA-Z]+)/`)
	containerdPattern     = regexp.MustCompile(`\d+:.+:/([a-zA-Z0-9_-]+)/+([a-zA-Z0-9_-]+)`)

	containerIDPattern = regexp.MustCompile(`.+://([0-9a-f]{64})`)

	cgroup = "/proc/%d/cgroup"
)

// Handler does the retrieval of container metadata for a particular pid.
type Handler struct {
	// Counters to keep track how often external APIs are called.
	kubernetesClientQueryCount atomic.Uint64
	dockerClientQueryCount     atomic.Uint64
	containerdClientQueryCount atomic.Uint64

	// the kubernetes node name used to retrieve the pod information.
	nodeName string
	// containerMetadataCache provides a cache to quickly retrieve the pod metadata for a
	// particular container id. It caches the pod name and container name metadata. Locked LRU.
	containerMetadataCache *lru.SyncedLRU[string, ContainerMetadata]

	// containerIDCache stores per process container ID information.
	containerIDCache *lru.SyncedLRU[libpf.OnDiskFileIdentifier, containerIDEntry]

	kubeClientSet kubernetes.Interface
	dockerClient  *client.Client

	containerdClient *containerd.Client
}

// ContainerMetadata contains the container and/or pod metadata.
type ContainerMetadata struct {
	containerID   string
	PodName       string
	ContainerName string
}

// hashString is a helper function for containerMetadataCache
// xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// containerEnvironment specifies a used container technology.
type containerEnvironment uint16

// List of known container technologies we can handle.
const (
	envUndefined  containerEnvironment = 0
	envKubernetes containerEnvironment = 1 << iota
	envDocker
	envLxc
	envContainerd
	envDockerBuildkit
)

// isContainerEnvironment tests if env is target.
func isContainerEnvironment(env, target containerEnvironment) bool {
	return target&env == target
}

// containerIDEntry stores the information we fetch from the cgroup information of the process.
type containerIDEntry struct {
	containerID string
	env         containerEnvironment
}

// GetHandler returns a new Handler instance used for retrieving container metadata.
func GetHandler(ctx context.Context, monitorInterval time.Duration) (*Handler, error) {
	containerIDCache, err := lru.NewSynced[libpf.OnDiskFileIdentifier, containerIDEntry](
		containerIDCacheSize, libpf.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to create container id cache: %v", err)
	}

	instance := &Handler{
		containerIDCache: containerIDCache,
		dockerClient:     getDockerClient(),
		containerdClient: getContainerdClient(),
	}

	if os.Getenv(kubernetesServiceHost) != "" {
		err = createKubernetesClient(ctx, instance)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client %v", err)
		}
	} else {
		log.Infof("Environment variable %s not set", kubernetesServiceHost)
		instance.containerMetadataCache, err = lru.NewSynced[string, ContainerMetadata](
			containerMetadataCacheSize, hashString)
		if err != nil {
			return nil, fmt.Errorf("unable to create container metadata cache: %v", err)
		}
	}

	log.Debugf("Container metadata handler: %v", instance)

	periodiccaller.Start(ctx, monitorInterval, func() {
		metrics.AddSlice([]metrics.Metric{
			{
				ID: metrics.IDKubernetesClientQuery,
				Value: metrics.MetricValue(
					instance.kubernetesClientQueryCount.Swap(0)),
			},
			{
				ID: metrics.IDDockerClientQuery,
				Value: metrics.MetricValue(
					instance.dockerClientQueryCount.Swap(0)),
			},
			{
				ID: metrics.IDContainerdClientQuery,
				Value: metrics.MetricValue(
					instance.containerdClientQueryCount.Swap(0)),
			},
		})
	})

	return instance, nil
}

// getPodsPerNode returns the number of pods per node.
// Depending on the configuration of the kubernetes environment, we may not be allowed to query
// for the allocatable information of the nodes.
func getPodsPerNode(ctx context.Context, instance *Handler) (int, error) {
	instance.kubernetesClientQueryCount.Add(1)
	nodeList, err := instance.kubeClientSet.CoreV1().Nodes().List(ctx, v1.ListOptions{
		FieldSelector: "spec.nodeName=" + instance.nodeName,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get kubernetes nodes for '%s': %v",
			instance.nodeName, err)
	}

	if len(nodeList.Items) == 0 {
		return 0, fmt.Errorf("empty node list")
	}

	// With the ListOptions filter in place, there should be only one node listed in the
	// return we get from the API.
	quantity, ok := nodeList.Items[0].Status.Allocatable[corev1.ResourcePods]
	if !ok {
		return 0, fmt.Errorf("failed to get allocatable information from %s",
			nodeList.Items[0].Name)
	}

	return int(quantity.Value()), nil
}

func getContainerMetadataCache(ctx context.Context, instance *Handler) (
	*lru.SyncedLRU[string, ContainerMetadata], error) {
	cacheSize := containerMetadataCacheSize

	podsPerNode, err := getPodsPerNode(ctx, instance)
	if err != nil {
		log.Infof("Failed to get pods per node: %v", err)
	} else {
		cacheSize *= podsPerNode
	}

	return lru.NewSynced[string, ContainerMetadata](
		uint32(cacheSize), hashString)
}

func createKubernetesClient(ctx context.Context, instance *Handler) error {
	log.Debugf("Create Kubernetes client")

	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in cluster configuration for Kubernetes: %v", err)
	}
	instance.kubeClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	k, ok := instance.kubeClientSet.(*kubernetes.Clientset)
	if !ok {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	instance.nodeName, err = getNodeName()
	if err != nil {
		return fmt.Errorf("failed to get kubernetes node name; %v", err)
	}

	instance.containerMetadataCache, err = getContainerMetadataCache(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to create container metadata cache: %v", err)
	}

	// Create the shared informer factory and use the client to connect to
	// Kubernetes and get notified of new pods that are created in the specified node.
	factory := informers.NewSharedInformerFactoryWithOptions(k, 0,
		informers.WithTweakListOptions(func(options *v1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + instance.nodeName
		}))
	informer := factory.Core().V1().Pods().Informer()

	// Kubernetes serves a utility to handle API crashes
	defer runtime.HandleCrash()

	handle, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("Received unknown object in AddFunc handler: %#v", obj)
				return
			}
			instance.putCache(pod)
		},
		UpdateFunc: func(oldObj any, newObj any) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				log.Errorf("Received unknown object in UpdateFunc handler: %#v",
					newObj)
				return
			}
			instance.putCache(pod)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to attach event handler: %v", err)
	}

	// Shutdown the informer when the context attached to this Handler expires
	stopper := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopper)
		if err := informer.RemoveEventHandler(handle); err != nil {
			log.Errorf("Failed to remove event handler: %v", err)
		}
	}()
	// Run the informer
	go informer.Run(stopper)

	return nil
}

func getContainerdClient() *containerd.Client {
	knownContainerdSockets := []string{"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/docker/containerd/containerd.sock"}

	for _, socket := range knownContainerdSockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		opt := containerd.WithTimeout(3 * time.Second)
		if c, err := containerd.New(socket, opt); err == nil {
			return c
		}
	}
	log.Infof("Can't connect Containerd client to %v", knownContainerdSockets)
	return nil
}

func getDockerClient() *client.Client {
	// /var/run/docker.sock is the default socket used by client.NewEnvClient().
	knownDockerSockets := []string{"/var/run/docker.sock"}

	// If the default socket is not available check if DOCKER_HOST is set to a different socket.
	envDockerSocket := os.Getenv(dockerHost)
	if envDockerSocket != "" {
		knownDockerSockets = append(knownDockerSockets, envDockerSocket)
	}

	for _, socket := range knownDockerSockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		if c, err := client.NewClientWithOpts(
			client.FromEnv,
			client.WithAPIVersionNegotiation(),
		); err == nil {
			return c
		}
	}
	log.Infof("Can't connect Docker client to %v", knownDockerSockets)
	return nil
}

// putCache updates the container id metadata cache for the provided pod.
func (h *Handler) putCache(pod *corev1.Pod) {
	log.Debugf("Update container metadata cache for pod %s", pod.Name)
	podName := getPodName(pod)

	for i := range pod.Status.ContainerStatuses {
		var containerID string
		var err error
		if containerID, err = matchContainerID(
			pod.Status.ContainerStatuses[i].ContainerID); err != nil {
			log.Debugf("failed to get kubernetes container metadata: %v", err)
			continue
		}

		h.containerMetadataCache.Add(containerID, ContainerMetadata{
			containerID:   containerID,
			PodName:       podName,
			ContainerName: pod.Status.ContainerStatuses[i].Name,
		})
	}
}

func getPodName(pod *corev1.Pod) string {
	podName := pod.Name

	for j := range pod.OwnerReferences {
		if strings.HasPrefix(podName, pod.OwnerReferences[j].Name) {
			switch pod.OwnerReferences[j].Kind {
			case "ReplicaSet":
				// For replicaSet the Owner references Name contains the replicaset version
				// ie 'deployment-replicaset' which we want to remove.
				lastIndex := strings.LastIndex(pod.OwnerReferences[j].Name, "-")
				if lastIndex < 0 {
					// pod.OwnerReferences[j].Name does not contain a '-' so
					// we take the full name as PodName and avoid to panic.
					podName = pod.OwnerReferences[j].Name
				} else {
					podName = pod.OwnerReferences[j].Name[:lastIndex]
				}
			default:
				podName = pod.OwnerReferences[j].Name
			}
		}
	}

	return podName
}

func matchContainerID(containerIDStr string) (string, error) {
	containerIDParts := containerIDPattern.FindStringSubmatch(containerIDStr)
	if len(containerIDParts) != 2 {
		return "", fmt.Errorf("could not get string submatch for container id %v",
			containerIDStr)
	}
	return containerIDParts[1], nil
}

func getNodeName() (string, error) {
	nodeName := os.Getenv(kubernetesNodeName)
	if nodeName != "" {
		return nodeName, nil
	}
	log.Debugf("%s not set", kubernetesNodeName)

	// The Elastic manifest for kubernetes uses NODE_NAME instead of KUBERNETES_NODE_NAME.
	// Therefore, we check for both environment variables.
	nodeName = os.Getenv(genericNodeName)
	if nodeName == "" {
		return "", fmt.Errorf("kubernetes node name not configured")
	}

	return nodeName, nil
}

// GetContainerMetadata returns the pod name and container name metadata associated with the
// provided pid. Returns an empty object if no container metadata exists.
func (h *Handler) GetContainerMetadata(pid libpf.PID) (ContainerMetadata, error) {
	// Fast path, check container metadata has been cached
	// For kubernetes pods, the shared informer may have updated
	// the container id to container metadata cache, so retrieve the container ID for this pid.
	pidContainerID, env, err := h.lookupContainerID(pid)
	if err != nil {
		return ContainerMetadata{}, fmt.Errorf("failed to get container id for pid %d", pid)
	}
	if envUndefined == env {
		// We were not able to identify a container technology for the given PID.
		return ContainerMetadata{}, nil
	}

	// Fast path, check if the containerID metadata has been cached
	if data, ok := h.containerMetadataCache.Get(pidContainerID); ok {
		return data, nil
	}

	// For kubernetes pods this route should happen rarely, this means that we are processing a
	// trace but the shared informer has been delayed in updating the container id metadata cache.
	// If it is not a kubernetes pod then we need to look up the container id in the configured
	// client.
	if isContainerEnvironment(env, envKubernetes) && h.kubeClientSet != nil {
		return h.getKubernetesPodMetadata(pidContainerID)
	} else if isContainerEnvironment(env, envDocker) && h.dockerClient != nil {
		return h.getDockerContainerMetadata(pidContainerID)
	} else if isContainerEnvironment(env, envContainerd) && h.containerdClient != nil {
		return h.getContainerdContainerMetadata(pidContainerID)
	} else if isContainerEnvironment(env, envDockerBuildkit) {
		// If DOCKER_BUILDKIT is set we can not retrieve information about this container
		// from the docker socket. Therefore, we populate container ID and container name
		// with the information we have.
		return ContainerMetadata{
			containerID:   pidContainerID,
			ContainerName: pidContainerID,
		}, nil
	} else if isContainerEnvironment(env, envLxc) {
		// As lxc does not use different identifiers we populate container ID and container
		// name of metadata with the same information.
		return ContainerMetadata{
			containerID:   pidContainerID,
			ContainerName: pidContainerID,
		}, nil
	}

	return ContainerMetadata{}, fmt.Errorf("failed to handle unknown container technology %d", env)
}

func (h *Handler) getKubernetesPodMetadata(pidContainerID string) (
	ContainerMetadata, error) {
	log.Debugf("Get kubernetes pod metadata for container id %v", pidContainerID)

	h.kubernetesClientQueryCount.Add(1)
	pods, err := h.kubeClientSet.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{
		FieldSelector: "spec.nodeName=" + h.nodeName,
	})
	if err != nil {
		return ContainerMetadata{}, fmt.Errorf("failed to retrieve kubernetes pods, %v", err)
	}

	for j := range pods.Items {
		podName := getPodName(&pods.Items[j])
		containers := pods.Items[j].Status.ContainerStatuses
		for i := range containers {
			var containerID string
			if containers[i].ContainerID == "" {
				continue
			}
			if containerID, err = matchContainerID(containers[i].ContainerID); err != nil {
				log.Error(err)
				continue
			}
			if containerID == pidContainerID {
				containerMetadata := ContainerMetadata{
					containerID:   containerID,
					PodName:       podName,
					ContainerName: containers[i].Name,
				}
				h.containerMetadataCache.Add(containerID, containerMetadata)

				return containerMetadata, nil
			}
		}
	}

	return ContainerMetadata{},
		fmt.Errorf("failed to find matching kubernetes pod/container metadata for "+
			"containerID '%v' in %d pods", pidContainerID, len(pods.Items))
}

func (h *Handler) getDockerContainerMetadata(pidContainerID string) (
	ContainerMetadata, error) {
	log.Debugf("Get docker container metadata for container id %v", pidContainerID)

	h.dockerClientQueryCount.Add(1)
	containers, err := h.dockerClient.ContainerList(context.Background(),
		container.ListOptions{})
	if err != nil {
		return ContainerMetadata{}, fmt.Errorf("failed to list docker containers, %v", err)
	}

	for i := range containers {
		if containers[i].ID == pidContainerID {
			// remove / prefix from container name
			containerName := strings.TrimPrefix(containers[i].Names[0], "/")
			metadata := ContainerMetadata{
				containerID:   containers[i].ID,
				ContainerName: containerName,
			}
			h.containerMetadataCache.Add(pidContainerID, metadata)
			return metadata, nil
		}
	}

	return ContainerMetadata{},
		fmt.Errorf("failed to find matching container metadata for containerID, %v",
			pidContainerID)
}

func (h *Handler) getContainerdContainerMetadata(pidContainerID string) (
	ContainerMetadata, error) {
	log.Debugf("Get containerd container metadata for container id %v", pidContainerID)

	// Avoid heap allocations here - do not use strings.SplitN()
	var fields [4]string // allocate the array on the stack with capacity 3
	n := stringutil.SplitN(pidContainerID, "/", fields[:])

	if n < 3 {
		return ContainerMetadata{},
			fmt.Errorf("unexpected format of containerd identifier: %s",
				pidContainerID)
	}

	h.containerdClientQueryCount.Add(1)
	ctx := namespaces.WithNamespace(context.Background(), fields[1])
	containers, err := h.containerdClient.Containers(ctx)
	if err != nil {
		return ContainerMetadata{},
			fmt.Errorf("failed to get containerd containers in namespace '%s': %v",
				fields[1], err)
	}

	for _, container := range containers {
		if container.ID() == fields[2] {
			// Containerd does not differentiate between the name and the ID of a
			// container. So we both options to the same value.
			return ContainerMetadata{
				containerID:   fields[2],
				ContainerName: fields[2],
				PodName:       fields[1],
			}, nil
		}
	}

	return ContainerMetadata{},
		fmt.Errorf("failed to find matching container metadata for containerID, %v",
			pidContainerID)
}

// lookupContainerID looks up a process ID from the host PID namespace,
// returning its container ID and the used container technology.
func (h *Handler) lookupContainerID(pid libpf.PID) (containerID string, env containerEnvironment,
	err error) {
	cgroupFilePath := fmt.Sprintf(cgroup, pid)

	fileIdentifier, err := libpf.GetOnDiskFileIdentifier(cgroupFilePath)
	if err != nil {
		return "", envUndefined, nil
	}

	if entry, exists := h.containerIDCache.Get(fileIdentifier); exists {
		return entry.containerID, entry.env, nil
	}

	containerID, env, err = h.extractContainerIDFromFile(cgroupFilePath)
	if err != nil {
		return "", envUndefined, err
	}

	// Store the result in the cache.
	h.containerIDCache.Add(fileIdentifier, containerIDEntry{
		containerID: containerID,
		env:         env,
	})

	return containerID, env, nil
}

func (h *Handler) extractContainerIDFromFile(cgroupFilePath string) (
	containerID string, env containerEnvironment, err error) {
	f, err := os.Open(cgroupFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debugf("%s does not exist anymore. "+
				"Failed to get container id", cgroupFilePath)
			return "", envUndefined, nil
		}
		return "", envUndefined, fmt.Errorf("failed to get container id from %s: %v",
			cgroupFilePath, err)
	}
	defer f.Close()

	containerID = ""
	env = envUndefined

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)

	var parts []string
	for scanner.Scan() {
		line := scanner.Text()

		if h.kubeClientSet != nil {
			parts = dockerKubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= (envKubernetes | envDocker)
				break
			}
			parts = kubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= envKubernetes
				break
			}
			parts = altKubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= envKubernetes
				break
			}
			parts = systemdKubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= envKubernetes
				break
			}
		}

		if h.dockerClient != nil {
			if parts = dockerPattern.FindStringSubmatch(line); parts != nil {
				containerID = parts[1]
				env |= envDocker
				break
			}
			if parts = dockerBuildkitPattern.FindStringSubmatch(line); parts != nil {
				containerID = parts[1]
				env |= envDockerBuildkit
				break
			}
		}

		if h.containerdClient != nil {
			if parts = containerdPattern.FindStringSubmatch(line); parts != nil {
				// Forward the complete match as containerID so, we can extract later
				// the exact containerd namespace and container ID from it.
				containerID = parts[0]
				env |= envContainerd
				break
			}
		}

		if parts = lxcPattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[2]
			env |= envLxc
			break
		}
	}

	return containerID, env, nil
}
