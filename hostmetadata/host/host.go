/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/elastic/otel-profiling-agent/pfnamespaces"

	"github.com/jsimonetti/rtnetlink"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/libpf"
)

// Host metadata keys
// Changing these values is a customer-visible change.
const (
	// TODO: Change to semconv / ECS names
	KeyKernelVersion      = "profiling.host.kernel_version"
	KeyKernelProcVersion  = "profiling.host.kernel_proc_version"
	KeyHostname           = "profiling.host.name"
	KeyArchitecture       = "host.arch"
	KeyArchitectureCompat = "profiling.host.machine"
	KeyIPAddress          = "profiling.host.ip"

	// Prefix for all the sysctl keys
	keyPrefixSysctl = "profiling.host.sysctl."

	keyTags = "profiling.host.tags"
)

// Various sysctls we are interested in.
// net.* sysctls must be read from the root network namespace.
var sysctls = []string{
	"net.core.bpf_jit_enable",
	"kernel.bpf_stats_enabled",
	"kernel.unprivileged_bpf_disabled",
}

var (
	validTagRegex = regexp.MustCompile(`^[a-zA-Z0-9-:._]+$`)
	validatedTags string
)

// AddMetadata adds host metadata to the result map, that is common across all environments.
// The IP address and hostname (part of the returned metadata) are evaluated in the context of
// PID 1's namespaces, in order to make the information agnostic to any container solutions.
// This may not be the best thing to do in some scenarios, but still seems to be the most sensible
// default.
func AddMetadata(caEndpoint string, result map[string]string) error {
	// Extract the host part of the endpoint
	// Remove the port from the endpoint in case it is present
	host, _, err := net.SplitHostPort(caEndpoint)
	if err != nil {
		host = caEndpoint
	}

	if validatedTags != "" {
		result[keyTags] = validatedTags
	}

	// Get /proc/version. This is better than the information returned by `uname`, as it contains
	// the version of the compiler that compiled the kernel.
	kernelProcVersion, err := os.ReadFile("/proc/version")
	if err != nil {
		return fmt.Errorf("unable to read /proc/version: %v", err)
	}
	result[KeyKernelProcVersion] = sanitizeString(kernelProcVersion)

	info, err := readCPUInfo()
	if err != nil {
		return fmt.Errorf("unable to read CPU information: %v", err)
	}

	dedupCPUInfo(result, info)

	// The rest of the metadata needs CAP_SYS_ADMIN to be collected, so we check that first
	hasCapSysAdmin, err := hasCapSysAdmin()
	if err != nil {
		return err
	}

	// We need to call the `setns` syscall to extract information (network route, hostname) from
	// different namespaces.
	// However, `setns` doesn't know about goroutines, it operates on OS threads.
	// Therefore, the below code needs to take extra steps to make sure no other code (outside of
	// this function) will execute in a different namespace.
	//
	// To do this, we use `runtime.LockOSThread()`, which we call from a separate goroutine.
	// runtime.LockOSThread() ensures that the thread executing the goroutine will be terminated
	// when the goroutine exits, which makes it impossible for the entered namespaces to be used in
	// a different context than the below code.
	//
	// It would be doable without a goroutine, by saving and restoring the namespaces before calling
	// runtime.UnlockOSThread(), but error handling makes things complicated and unsafe/dangerous.
	// The below implementation is always safe to run even in the presence of errors.
	//
	// The only downside is that calling this function comes at the cost of sacrificing an OS
	// thread, which will likely force the Go runtime to launch a new thread later. This should be
	// acceptable if it doesn't happen too often.
	var wg sync.WaitGroup
	wg.Add(1)

	// Error result of the below goroutine. May contain multiple combined errors.
	var errResult error

	go func() {
		defer wg.Done()

		if hasCapSysAdmin {
			// Before entering a different namespace, lock the current goroutine to a thread.
			// Note that we do *not* call runtime.UnlockOSThread(): this ensures the current thread
			// will exit after the goroutine finishes, which makes it impossible for other
			// goroutines to enter a different namespace.
			runtime.LockOSThread()

			// Try to enter root namespaces. If that fails, continue anyway as we might be able to
			// gather some metadata.
			utsFD, netFD := tryEnterRootNamespaces()

			// Any errors were already logged by the above function.
			if utsFD != -1 {
				defer unix.Close(utsFD)
			}
			if netFD != -1 {
				defer unix.Close(netFD)
			}
		} else {
			log.Warnf("No CAP_SYS_ADMIN capability, collecting metadata from " +
				"current process namespaces")
		}

		// Add sysctls to the result map
		for _, sysctl := range sysctls {
			sysctlValue, err2 := getSysctl(sysctl)
			if err2 != nil {
				errResult = errors.Join(errResult, err2)
				continue
			}
			result[keyPrefixSysctl+sysctl] = sanitizeString(sysctlValue)
		}

		// Get IP address
		var ip net.IP
		ip, err = getSourceIPAddress(host)
		if err != nil {
			errResult = errors.Join(errResult, err)
		} else {
			result[KeyIPAddress] = ip.String()
		}

		// Get uname-related metadata: hostname and kernel version
		uname := &unix.Utsname{}
		if err = unix.Uname(uname); err != nil {
			errResult = errors.Join(errResult, fmt.Errorf("error calling uname: %v", err))
		} else {
			result[KeyKernelVersion] = sanitizeString(uname.Release[:])
			result[KeyHostname] = sanitizeString(uname.Nodename[:])

			machine := sanitizeString(uname.Machine[:])

			// Keep sending the old field for compatibility between old collectors and new agents.
			result[KeyArchitectureCompat] = machine

			// Convert to OTEL semantic conventions.
			// Machine values other than x86_64, aarch64 are not converted.
			switch machine {
			case "x86_64":
				result[KeyArchitecture] = "amd64"
			case "aarch64":
				result[KeyArchitecture] = "arm64"
			default:
				result[KeyArchitecture] = machine
			}
		}
	}()

	wg.Wait()

	if errResult != nil {
		return errResult
	}

	return nil
}

// ValidTagRegex returns the regular expression used to validate user-specified tags.
func ValidTagRegex() *regexp.Regexp {
	return validTagRegex
}

const keySuffixCPUSocketID = "socketIDs"

func keySocketID(prefix string) string {
	return fmt.Sprintf("%s/%s", prefix, keySuffixCPUSocketID)
}

// dedupCPUInfo transforms cpuInfo values into a more compact form and populates result map.
// The resulting keys and values generated from a cpuInfo key K with socket IDs 0,1,2,3
// and values V, V, V1, V2 will be of the form:
//
//	"K": "V;V1;V2"
//	"K/socketIDs": "0,1;2;3"
//
// The character ';' is used as a separator for distinct values since is it highly unlikely
// that it will occur as part of the values themselves, most of which are numeric.
// TODO: Investigate alternative encoding schemes such as JSON.
func dedupCPUInfo(result map[string]string, info cpuInfo) {
	for key, socketValues := range info {
		// A map from CPU info values to their associated socket ids
		uniques := map[string]libpf.Set[string]{}

		// Gather all unique values and their socket ids for this key
		for socketID, socketValue := range socketValues {
			sid := strconv.Itoa(socketID)
			if _, ok := uniques[socketValue]; !ok {
				uniques[socketValue] = libpf.Set[string]{}
			}
			uniques[socketValue][sid] = libpf.Void{}
		}
		values := libpf.MapKeysToSlice(uniques)
		result[key] = strings.Join(values, ";")

		// Gather all socketIDs, combine them and write them to result
		socketIDs := make([]string, 0, len(values))
		for _, v := range values {
			sids := uniques[v].ToSlice()
			sort.Slice(sids, func(a, b int) bool {
				intA, _ := strconv.Atoi(sids[a])
				intB, _ := strconv.Atoi(sids[b])
				return intA < intB
			})
			socketIDs = append(socketIDs, strings.Join(sids, ","))
		}
		result[keySocketID(key)] = strings.Join(socketIDs, ";")
	}
}

func sanitizeString(str []byte) string {
	// Trim byte array from 0x00 bytes
	return string(bytes.Trim(str, "\x00"))
}

func addressFamily(ip net.IP) (uint8, error) {
	if ip.To4() != nil {
		return unix.AF_INET, nil
	}
	if len(ip) == net.IPv6len {
		return unix.AF_INET6, nil
	}
	return 0, fmt.Errorf("invalid IP address: %v", ip)
}

// getSourceIPAddress returns the source IP address for the traffic destined to the specified
// domain.
func getSourceIPAddress(domain string) (net.IP, error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, errors.New("unable to open netlink connection")
	}
	defer conn.Close()

	dstIPs, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve %s: %v", domain, err)
	}
	if len(dstIPs) == 0 {
		return nil, fmt.Errorf("unable to resolve %s: no IP address", domain)
	}

	var srcIP net.IP
	var lastError error
	found := false

	// We might get multiple IP addresses, check all of them as some may not be routable (like an
	// IPv6 address on an IPv4 network).
	for _, ip := range dstIPs {
		addressFamily, err := addressFamily(ip)
		if err != nil {
			return nil, fmt.Errorf("unable to get address family for %s: %v", ip.String(), err)
		}

		req := &rtnetlink.RouteMessage{
			Family: addressFamily,
			Table:  unix.RT_TABLE_MAIN,
			Attributes: rtnetlink.RouteAttributes{
				Dst: ip,
			},
		}

		routes, err := conn.Route.Get(req)
		if err != nil {
			lastError = fmt.Errorf("unable to get route to %s (%s): %v", domain, ip.String(), err)
			continue
		}

		if len(routes) == 0 {
			continue
		}
		if len(routes) > 1 {
			// More than 1 route!
			// This doesn't look like this should ever happen (even in the presence of overlapping
			// routes with same metric, this will return a single route).
			// May be a leaky abstraction/artifact from the way the netlink API works?
			// Regardless, this seems ok to ignore, but log just in case.
			log.Warnf("Found multiple (%d) routes to %v; first 2 routes: %#v and %#v",
				len(routes), domain, routes[0], routes[1])
		}

		// Sanity-check the result, in case the source address is left uninitialized
		if len(routes[0].Attributes.Src) == 0 {
			lastError = fmt.Errorf(
				"unable to get route to %s (%s): no source IP address", domain, ip.String())
			continue
		}

		srcIP = routes[0].Attributes.Src
		found = true
		break
	}

	if !found {
		return nil, fmt.Errorf("no route found to %s: %v", domain, lastError)
	}

	log.Debugf("Traffic to %v is routed from %v", domain, srcIP.String())
	return srcIP, nil
}

func hasCapSysAdmin() (bool, error) {
	caps, err := capability.NewPid2(0) // 0 == current process
	if err != nil {
		return false, errors.New("unable to get process capabilities")
	}
	err = caps.Load()
	if err != nil {
		return false, errors.New("unable to load process capabilities")
	}
	return caps.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN), nil
}

// getSysctl returns the value of a particular sysctl (eg: "net.core.bpf_jit_enable").
func getSysctl(sysctl string) ([]byte, error) {
	// "net.core.bpf_jit_enable" => /proc/sys/net/core/bpf_jit_enable
	path := "/proc/sys/" + strings.ReplaceAll(sysctl, ".", "/")

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open %v: %v", path, err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %v", path, err)
	}

	if len(contents) == 0 {
		return []byte{}, nil
	}

	// Remove the trailing newline if present
	length := len(contents)
	if contents[length-1] == 0x0a {
		contents = contents[:length-1]
	}

	return contents, nil
}

// SetTags parses and validates user-specified tags and sets them for use in host metadata.
// Each tag must match ValidTagRegex with ';' used as a separator.
// Tags that can't be validated are dropped.
func SetTags(tags string) {
	if tags == "" {
		validatedTags = ""
		return
	}

	splitTags := strings.Split(tags, ";")
	validTags := make([]string, 0, len(splitTags))

	for _, tag := range splitTags {
		if !validTagRegex.MatchString(tag) {
			log.Warnf("Rejected user-specified tag '%s' since it doesn't match regexp '%v'",
				tag, validTagRegex)
		} else {
			validTags = append(validTags, tag)
		}
	}

	validatedTags = strings.Join(validTags, ";")
	log.Debugf("Validated tags: %s", validatedTags)
}

// tryEnterRootNamespaces tries to enter PID 1's UTS and network namespaces.
// It returns the file descriptor associated to each, or -1 if the namespace cannot be entered.
func tryEnterRootNamespaces() (utsFD, netFD int) {
	netFD, err := pfnamespaces.EnterNamespace(1, "net")
	if err != nil {
		log.Errorf(
			"Unable to enter root network namespace, host metadata may be incorrect: %v", err)
		netFD = -1
	}

	utsFD, err = pfnamespaces.EnterNamespace(1, "uts")
	if err != nil {
		log.Errorf("Unable to enter root UTS namespace, host metadata may be incorrect: %v", err)
		utsFD = -1
	}

	return utsFD, netFD
}
