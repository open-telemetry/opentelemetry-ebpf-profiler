package helpers // import "go.opentelemetry.io/ebpf-profiler/internal/helpers"

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/jsimonetti/rtnetlink"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

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

// GetHostnameAndSourceIP returns the hostname and source IP address for the traffic destined to
// the specified domain.
func GetHostnameAndSourceIP(domain string) (hostname, sourceIP string, err error) {
	err = runInRootNS(func() error {
		var joinedErr error

		if name, hostnameErr := os.Hostname(); hostnameErr == nil {
			hostname = name
		} else {
			joinedErr = fmt.Errorf("failed to get hostname: %v", hostnameErr)
		}

		if srcIP, ipErr := getSourceIPAddress(domain); ipErr == nil {
			sourceIP = srcIP.String()
		} else {
			joinedErr = errors.Join(joinedErr,
				fmt.Errorf("failed to get source IP: %v", ipErr))
		}

		return joinedErr
	})

	return hostname, sourceIP, err
}
