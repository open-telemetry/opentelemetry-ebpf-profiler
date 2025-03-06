package helpers

import (
	"go.opentelemetry.io/ebpf-profiler/internal/helpers"
)

func GetKernelVersion() (string, error) {
	return helpers.GetKernelVersion()
}

func GetHostnameAndSourceIP(domain string) (hostname, sourceIP string, err error) {
	return helpers.GetHostnameAndSourceIP(domain)
}
