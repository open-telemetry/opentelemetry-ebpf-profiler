package profilingreceiver

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer"
	log "github.com/sirupsen/logrus"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
)

func getKernelVersion() (string, error) {
	major, minor, patch, err := tracer.GetCurrentKernelVersion()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
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

func resolveDestination(domain string) ([]net.IP, error) {
	dstIPs, err := net.LookupIP(domain)
	if err == nil {
		return dstIPs, nil
	}

	// domain seems not to be a DNS value.
	// Try to interpret it as IP.
	host, _, err := net.SplitHostPort(domain)
	if err != nil {
		return []net.IP{}, err
	}
	return net.LookupIP(host)
}

// getSourceIPAddress returns the source IP address for the traffic destined to the specified
// domain.
func getSourceIPAddress(domain string) (net.IP, error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, errors.New("unable to open netlink connection")
	}
	defer conn.Close()

	dstIPs, err := resolveDestination(domain)
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

// runInRootNS executes fetcher in the root namespace.
func runInRootNS(fetcher func() error) error {
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

	// Error result of the below goroutine. May contain multiple combined errors.
	var errResult error

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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

		if utsFD == -1 || netFD == -1 {
			log.Warnf("Missing capabilities to enter root namespace, fetching information from " +
				"current process namespaces")
		}

		errResult = fetcher()
	}()

	wg.Wait()

	return errResult
}

// tryEnterRootNamespaces tries to enter PID 1's UTS and network namespaces.
// It returns the file descriptor associated to each, or -1 if the namespace cannot be entered.
func tryEnterRootNamespaces() (utsFD, netFD int) {
	netFD, err := enterNamespace(1, "net")
	if err != nil {
		log.Errorf(
			"Unable to enter root network namespace, host metadata may be incorrect: %v", err)
		netFD = -1
	}

	utsFD, err = enterNamespace(1, "uts")
	if err != nil {
		log.Errorf("Unable to enter root UTS namespace, host metadata may be incorrect: %v", err)
		utsFD = -1
	}

	return utsFD, netFD
}

// enterNamespace enters a new namespace of the specified type, inherited from the provided PID.
// The returned file descriptor must be closed with unix.Close().
// Note that this function affects the OS thread calling this function, which will likely impact
// more than one goroutine unless you also use runtime.LockOSThread.
func enterNamespace(pid int, nsType string) (int, error) {
	var nsTypeInt int
	switch nsType {
	case "net":
		nsTypeInt = syscall.CLONE_NEWNET
	case "uts":
		nsTypeInt = syscall.CLONE_NEWUTS
	default:
		return -1, fmt.Errorf("unsupported namespace type: %s", nsType)
	}

	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	err = unix.Setns(fd, nsTypeInt)
	if err != nil {
		// Close namespace and return the error
		return -1, errors.Join(err, unix.Close(fd))
	}

	return fd, nil
}
