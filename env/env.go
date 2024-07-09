/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package env

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/otel-profiling-agent/hostmetadata/azure"
	"github.com/elastic/otel-profiling-agent/hostmetadata/ec2"
	"github.com/elastic/otel-profiling-agent/hostmetadata/gce"
	"github.com/elastic/otel-profiling-agent/pfnamespaces"
	"github.com/elastic/otel-profiling-agent/util"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"

	gcp "cloud.google.com/go/compute/metadata"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	ec2imds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/libpf"
)

type Environment struct {
	// environment indicates the cloud/virtualization environment in which the agent is running. It
	// can be set in the configuration file, or it will be automatically determined. It is used in
	// the computation of the host ID. If it is specified in the configuration file then the machine
	// ID must also be specified.
	envType EnvironmentType

	// machineID specifies a unique identifier for the host on which the agent is running. It can be
	// set in the configuration file, or it will be automatically determined. It is used in the
	// computation of the host ID. If it is specified in the configuration file then the environment
	// must also be specified.
	machineID uint64
}

// EnvironmentType indicates the environment, the agent is running on.
type EnvironmentType uint8

// The EnvironmentType part in hostID is 0xF. So values should not exceed this limit.
const (
	envUnspec EnvironmentType = iota // envUnspec indicates we can't identify the environment
	envHardware
	envLXC
	envKVM
	envDocker
	envGCP
	envAzure
	envAWS
)

func (e EnvironmentType) String() string {
	switch e {
	case envUnspec:
		return "unspecified"
	case envHardware:
		return "hardware"
	case envLXC:
		return "lxc"
	case envKVM:
		return "kvm"
	case envDocker:
		return "docker"
	case envGCP:
		return "gcp"
	case envAzure:
		return "azure"
	case envAWS:
		// nolint: goconst
		return "aws"
	default:
		return fmt.Sprintf("unknown environment %d", e)
	}
}

var strToEnv = map[string]EnvironmentType{
	"hardware": envHardware,
	"lxc":      envLXC,
	"kvm":      envKVM,
	"docker":   envDocker,
	"gcp":      envGCP,
	"azure":    envAzure,
	"aws":      envAWS,
}

func NewEnvironment(envName string, machine string) (*Environment, error) {
	var envType EnvironmentType
	var machineID uint64
	var err error

	if envName != "" {
		// The environment type (aws/gcp/bare metal) is overridden vs. the default auto-detect.
		envType, err = environmentTypeFromString(envName)
		if err != nil {
			return nil, fmt.Errorf("invalid envType '%s': %s", envName, err)
		}

		// If the envType is overridden, the machine ID also needs to be overridden.
		machineID, err = strconv.ParseUint(machine, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid machine ID '%s': %s", machine, err)
		}
		if machineID == 0 {
			return nil, errors.New(
				"the machine ID must be specified with the envType (and non-zero)")
		}

		log.Debugf("User provided envType (%s) and machine ID (0x%x)", envType,
			machineID)
	} else {
		log.Info("Automatically determining environment and machine ID ...")
		envType, machineID, err = getEnvironmentAndMachineID()
		if err != nil {
			return nil, err
		}
		log.Infof("Environment: %s, machine ID: 0x%x", envType, machineID)
	}

	return &Environment{
		envType:   envType,
		machineID: machineID,
	}, nil
}

// HostID returns the unique host identifier.
func (e *Environment) HostID() uint64 {
	// Parts of the hostID:
	// 0xf000000000000000 - environment identifier
	// 0x0fffffffffffffff - machine id
	return (uint64(e.envType&0xf) << 60) | (e.machineID & 0x0fffffffffffffff)
}

func (e *Environment) AddMetadata(result map[string]string) {
	// Here we can gather more metadata, which may be dependent on the cloud provider, container
	// technology, container orchestration stack, etc.
	switch e.envType {
	case envGCP:
		gce.AddMetadata(result)
	case envAzure:
		ec2.AddMetadata(result)
	case envAWS:
		azure.AddMetadata(result)
	default:
	}
}

// environmentTypeFromString converts a string to an environment specifier.
// The matching is case-insensitive.
func environmentTypeFromString(envStr string) (EnvironmentType, error) {
	if env, ok := strToEnv[strings.ToLower(envStr)]; ok {
		return env, nil
	}

	return envUnspec, fmt.Errorf("unknown environment type: %s", envStr)
}

// readFile reads in a given file and returns its content as a string
func readFile(file string) (string, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", file, err)
	}
	return string(bytes), nil
}

// CheckCgroups is used to detect if we are running containerized in docker, lxc, or kvm.
func checkCGroups() (EnvironmentType, error) {
	data, err := readFile("/proc/1/cgroup")
	if err != nil {
		return envUnspec, fmt.Errorf("failed to read /proc/1/cgroup: %s", err)
	}

	switch {
	case strings.Contains(data, "docker"):
		return envDocker, nil
	case strings.Contains(data, "lxc"):
		return envLXC, nil
	case strings.Contains(data, "kvm"):
		return envKVM, nil
	}

	return envHardware, nil
}

// getFamily returns the address family of the given IP.
func getFamily(ip net.IP) uint8 {
	if ip.To4() != nil {
		return unix.AF_INET
	}

	return unix.AF_INET6
}

func getInterfaceIndexFromIP(conn *rtnetlink.Conn, ip net.IP) (index int, err error) {
	routeMsg := rtnetlink.RouteMessage{
		Attributes: rtnetlink.RouteAttributes{
			Dst: ip,
		},
		Family: getFamily(ip),
	}

	msgs, err := conn.Route.Get(&routeMsg)
	if err != nil {
		return -1, fmt.Errorf("failed to get route: %s", err)
	}
	if len(msgs) == 0 {
		return -1, errors.New("empty routing table")
	}

	return int(msgs[0].Attributes.OutIface), nil
}

func hwAddrToUint64(hwAddr net.HardwareAddr) uint64 {
	if len(hwAddr) < 8 {
		hwAddr = append(hwAddr, make(net.HardwareAddr, 8-len(hwAddr))...)
	}
	return binary.LittleEndian.Uint64(hwAddr)
}

// getMACFromRouting returns the MAC address of network interface of CA traffic routing.
func getMACFromRouting(destination string) (mac uint64, err error) {
	addrs, err := net.LookupIP(destination)
	if err != nil {
		return 0, fmt.Errorf("failed to look up IP: %s", err)
	}
	if len(addrs) == 0 {
		return 0, errors.New("failed to look up IP: no address")
	}

	// Dial a connection to the rtnetlink socket
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return 0, errors.New("failed to connect to netlink layer")
	}
	defer conn.Close()

	seenIfaces := make(libpf.Set[int])
	for _, ip := range addrs {
		ifaceIndex, err := getInterfaceIndexFromIP(conn, ip)
		if err != nil {
			log.Warnf("Failed to get interface index for %s: %v", ip, err)
			continue
		}

		if _, ok := seenIfaces[ifaceIndex]; ok {
			continue
		}
		seenIfaces[ifaceIndex] = libpf.Void{}

		iface, err := net.InterfaceByIndex(ifaceIndex)
		if err != nil {
			log.Warnf("Failed to get outgoing interface for %s: %v", ip, err)
			continue
		}

		hwAddr := iface.HardwareAddr
		if len(hwAddr) == 0 {
			continue
		}

		return hwAddrToUint64(hwAddr), nil
	}

	return 0, errors.New("failed to retrieve MAC from routing interface")
}

// getMACFromSystem returns a MAC address by iterating over all system
// network interfaces (in increasing ifindex order therefore prioritizing physical
// interfaces) and selecting an address belonging to a non-loopback interface.
func getMACFromSystem() (mac uint64, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	// The reason for sorting by ifindex here, is that it doesn't change when
	// an interface is set to up/down. Therefore by prioritizing interfaces in
	// increasing ifindex order, we're prioritizing physical/hardware
	// interfaces (since the ifindex for these is usually assigned at boot,
	// while temporary/tunnel interfaces are usually created later, post
	// system-networking-is-up).

	// Don't rely on net.Interfaces/RTM_GETLINK ifindex sorting
	sort.SliceStable(ifaces, func(i, j int) bool {
		return ifaces[i].Index < ifaces[j].Index
	})

	macs := make([]uint64, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		hwAddr := iface.HardwareAddr
		if iface.Flags&net.FlagUp != 0 {
			// Return the MAC address belonging to the first non-loopback
			// network interface encountered that is UP.
			return hwAddrToUint64(hwAddr), nil
		}
		macs = append(macs, hwAddrToUint64(hwAddr))
	}

	if len(macs) > 0 {
		// Since no usable MAC addresses belonging to network interfaces
		// that are UP were found, return an address from a network interface
		// that is not UP.
		return macs[0], nil
	}

	return 0, errors.New("failed to find a MAC")
}

// getNonCloudEnvironmentAndMachineID tries to detect if the agent is running in a
// virtualized environment or on hardware. It returns a machineID and a environment
// specific identifier.
// TODO(PF-1007): move to a random ID (possibly persisted on the filesystem).
func getNonCloudEnvironmentAndMachineID() (uint64, EnvironmentType, error) {
	var env EnvironmentType
	var err error
	var id, mac uint64

	if env, err = checkCGroups(); err != nil {
		return 0, env, err
	}

	if id, err = getMachineID(); err != nil {
		return 0, env, err
	}

	// Cloned VMs or container images might have the same machine ID.
	// We add an XOR of the MAC addresses to get a unique ID.
	// Extract the MAC address from the root network namespace, because the MAC address visible in
	// some containerized environments may not be enough to guarantee unicity.
	// We need to do this from a dedicated thread to avoid affecting other threads
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// LockOSThread ensures the thread exits after the goroutine exits, avoiding namespace
		// leakage in other goroutines.
		runtime.LockOSThread()
		var ns int
		ns, err = pfnamespaces.EnterNamespace(1, "net")
		if err != nil {
			err = fmt.Errorf("unable to enter PID 1 network namespace: %v", err)
			return
		}
		defer unix.Close(ns)

		mac, err = getMACFromRouting("example.com")
		if err != nil {
			log.Warnf("%v", err)
			mac, err = getMACFromSystem()
		}
	}()
	wg.Wait()
	if err != nil {
		return 0, env, err
	}

	log.Debugf("Using MAC: 0x%X", mac)
	id ^= mac

	return id, env, err
}

// idFromString generates a number, that will be part of the hostID, from a given string.
func idFromString(s string) uint64 {
	return util.HashString(s)
}

// gcpInfo collects information about the GCP environment
// https://cloud.google.com/compute/docs/storing-retrieving-metadata
func gcpInfo() (uint64, EnvironmentType, error) {
	instanceID, err := gcp.InstanceID()
	if err != nil {
		return 0, envGCP, fmt.Errorf("failed to get GCP metadata: %w", err)
	}
	return idFromString(instanceID), envGCP, nil
}

// awsInfo collects information about the AWS environment
func awsInfo() (uint64, EnvironmentType, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return 0, envAWS, fmt.Errorf("failed to prepare aws configuration: %v", err)
	}

	client := ec2imds.NewFromConfig(cfg)
	document, err := client.GetInstanceIdentityDocument(context.Background(), nil)
	if err != nil {
		return 0, envAWS, fmt.Errorf("failed to fetch instance document: %v", err)
	}

	return idFromString(document.InstanceID), envAWS, nil
}

// AzureInstanceMetadata as provided by
// https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
// It is needed to decode the json encoded return by Azure.
type AzureInstanceMetadata struct {
	Location       string `json:"location"`
	Name           string `json:"name"`
	SubscriptionID string `json:"subscriptionId"`
	Tags           string `json:"tags"`
	Version        string `json:"version"`
	VMID           string `json:"vmId"`
	Zone           string `json:"zone"`
}

// azureInfo collects information about the Azure environment
func azureInfo() (uint64, EnvironmentType, error) {
	var m AzureInstanceMetadata
	c := &http.Client{Timeout: 3 * time.Second}

	req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/metadata/instance/compute",
		http.NoBody)
	req.Header.Add("Metadata", "True")
	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("api-version", "2020-09-01")
	req.URL.RawQuery = q.Encode()

	resp, err := c.Do(req)
	if err != nil {
		return 0, envAzure, fmt.Errorf("failed to get azure metadata: %s", err)
	}
	defer resp.Body.Close()

	rawJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, envAzure, fmt.Errorf("failed to read azure response: %s", err)
	}
	if err = json.Unmarshal(rawJSON, &m); err != nil {
		return 0, envAzure, fmt.Errorf("failed to unmarshal JSON response: %s", err)
	}
	return idFromString(m.VMID), envAzure, nil
}

// getMachineID returns the id according to
// http://man7.org/linux/man-pages/man5/machine-id.5.html
func getMachineID() (uint64, error) {
	var id uint64 = 42
	var err error
	var data string

	for _, file := range []string{"/var/lib/dbus/machine-id", "/etc/machine-id"} {
		data, err = readFile(file)
		if err != nil {
			continue
		}
		return idFromString(data), nil
	}
	return id, err
}

// environmentTester represents a function, which returns a unique identifier for this environment,
// an environment specific EnvironmentType or an error otherwise.
type environmentTester func() (uint64, EnvironmentType, error)

func getEnvironmentAndMachineID() (EnvironmentType, uint64, error) {
	var env EnvironmentType
	var machineID uint64

	// environmentTests is a list of functions, that can be used to check the environment.
	// The order of the list matters. So gcpInfo will be called first, followed by
	// awsInfo and azureInfo.
	environmentTests := []environmentTester{gcpInfo, awsInfo, azureInfo}

	var wg sync.WaitGroup
	for _, envTest := range environmentTests {
		wg.Add(1)
		go func(testEnv environmentTester) {
			defer wg.Done()
			mID, envT, err := testEnv()
			if err != nil {
				log.Debugf("Environment tester (%s) failed: %s", envT, err)
				return
			}
			machineID = mID
			env = envT
		}(envTest)
	}
	wg.Wait()

	if env == envUnspec {
		var err error
		// the environment check getNonCloudEnvironmentAndMachineID is not part of
		// environmentTests, as it is our last resort in identifiying the environment.
		machineID, env, err = getNonCloudEnvironmentAndMachineID()
		if env == envUnspec || err != nil {
			return envUnspec, 0, fmt.Errorf(
				"failed to determine environment and machine ID: %s", err)
		}
	}

	return env, machineID, nil
}
