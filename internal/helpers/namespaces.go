package helpers // import "go.opentelemetry.io/ebpf-profiler/internal/helpers"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

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
