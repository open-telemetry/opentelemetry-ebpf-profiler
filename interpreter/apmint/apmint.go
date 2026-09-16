// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package apmint implements a pseudo interpreter handler that detects APM agent
// libraries, establishes socket connections with them and notifies them about
// the stack traces that we collected for their process. This allows the APM
// agent to associate stack traces with APM traces / transactions / spans.
package apmint // import "go.opentelemetry.io/ebpf-profiler/interpreter/apmint"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tls"
)

const (
	// serviceNameMaxLength defines the maximum allowed length of service names.
	serviceNameMaxLength = 128
	// serviceEnvMaxLength defines the maximum allowed length of service environments.
	serviceEnvMaxLength = 128
	// socketPathMaxLength defines the maximum length of the APM agent socket path.
	socketPathMaxLength = 1024

	// procStorageExport defines the name of the process storage ELF export.
	procStorageExport = "elastic_apm_profiling_correlation_process_storage_v1"
	// tlsExport defines the name of the thread info TLS export.
	tlsExport = "elastic_apm_profiling_correlation_tls_v1"
)

var dsoRegex = regexp.MustCompile(`.*/elastic-jvmti-linux-([\w-]*)\.so`)

// apmProcessStorage represents a subset of the information present in the
// APM process storage.
//
// https://github.com/elastic/apm/blob/bd5fa9c1/specs/agents/universal-profiling-integration.md#process-storage-layout
//
//nolint:lll
type apmProcessStorage struct {
	ServiceName     string
	TraceSocketPath string
}

func GetLoader(_ Config) interpreter.Loader {
	return interpreter.NewLoader(loader, []interpreter.InterpreterResource{
		{MapName: BPFMapName},
	})
}

func loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !isPotentialAgentLib(info.FileName()) {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Resolve process storage symbol.
	procStorageSym, err := ef.LookupSymbol(procStorageExport)
	if err != nil {
		if errors.Is(err, libpf.ErrSymbolNotFound) {
			// APM<->profiling integration not supported by agent.
			return nil, nil
		}

		return nil, err
	}
	if procStorageSym.Size != 8 {
		return nil, fmt.Errorf("process storage export has wrong size %d", procStorageSym.Size)
	}

	tlsSym, err := ef.LookupSymbol(tlsExport)
	if err != nil {
		return nil, fmt.Errorf("failed to locate %s: %w", tlsExport, err)
	}
	tlsVar, err := tls.Resolve(ef, tlsSym)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", tlsExport, err)
	}

	log.Debugf("APM integration TLS variable: %v", tlsVar)

	return &data{
		tlsVar:           tlsVar,
		procStorageElfVA: libpf.Address(procStorageSym.Address),
	}, nil
}

type data struct {
	tlsVar           tls.Var
	procStorageElfVA libpf.Address
}

var _ interpreter.Data = &data{}

func (d data) String() string {
	return "APM integration"
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	procStorage, err := readProcStorage(rm, bias+d.procStorageElfVA)
	if err != nil {
		return nil, fmt.Errorf("failed to read APM correlation process storage: %s", err)
	}

	var procInfo support.ApmIntProcInfo
	var pendingTLS *tls.VarLocation
	if loc, err := d.tlsVar.Locate(rm, bias); err != nil {
		return nil, fmt.Errorf("failed to locate APM correlation TLS variable: %w", err)
	} else if tlsInfo, err := loc.VarInfo(libc.DTVInfo{}); err == nil {
		procInfo.Tls = tlsInfo
	} else if errors.Is(err, tls.ErrNeedDTV) {
		// Dynamic TLS, so UpdateLibcInfo completes it once the DTV arrives and
		// eBPF skips the correlation read until then.
		pendingTLS = &loc
	} else {
		return nil, fmt.Errorf("unusable APM correlation TLS variable %v: %w", loc, err)
	}
	if err = ebpf.UpdateProcData(libpf.APMInt, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	// Establish socket connection with the agent.
	socket, err := openAPMAgentSocket(pid, procStorage.TraceSocketPath)
	if err != nil {
		if err2 := ebpf.DeleteProcData(libpf.APMInt, pid); err2 != nil {
			log.Errorf("Failed to remove APM information for PID %d: %v", pid, err2)
		}
		return nil, fmt.Errorf("failed to open APM agent socket: %v", err)
	}

	log.Debugf("PID %d apm.service.name: %s, trace socket: %s",
		pid, procStorage.ServiceName, procStorage.TraceSocketPath)

	return &Instance{
		serviceName: procStorage.ServiceName,
		socket:      socket,
		procInfo:    &procInfo,
		pendingTLS:  pendingTLS,
	}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {
}

type Instance struct {
	serviceName string
	socket      *apmAgentSocket

	// procInfo is kept for re-insertion once pendingTLS resolves.
	procInfo *support.ApmIntProcInfo

	// pendingTLS is where the correlation variable lives while it waits for the
	// DTV layout, nil once described or when there is nothing to wait for.
	pendingTLS *tls.VarLocation

	interpreter.InstanceStubs
}

var _ interpreter.Instance = &Instance{}

// UpdateLibcInfo completes a correlation variable in dynamic TLS, which needs
// the DTV layout the process C library defines.
func (i *Instance) UpdateLibcInfo(ebpf interpreter.EbpfHandler, pid libpf.PID,
	libcInfo libc.LibcInfo) error {
	if i.pendingTLS == nil {
		return nil
	}
	if !libcInfo.HasDTVInfo() {
		// May still arrive from a different DSO.
		return nil
	}

	tlsInfo, err := i.pendingTLS.VarInfo(libcInfo.DTVInfo)
	if err != nil {
		return err
	}
	i.procInfo.Tls = tlsInfo
	if err = ebpf.UpdateProcData(libpf.APMInt, pid, unsafe.Pointer(i.procInfo)); err != nil {
		return err
	}
	i.pendingTLS = nil
	log.Debugf("PID %d: located the APM correlation variable via the DTV", pid)
	return nil
}

// Detach implements the interpreter.Instance interface.
func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.APMInt, pid)
}

// NotifyAPMAgent sends out collected traces to the connected APM agent.
func (i *Instance) NotifyAPMAgent(
	pid libpf.PID, rawTrace *libpf.EbpfTrace, umTraceHash libpf.TraceHash, count uint16,
) {
	if rawTrace.APMTransactionID == libpf.InvalidAPMSpanID || i.socket == nil {
		return
	}

	log.Debugf("Reporting %dx trace hash %s -> TX %s for PID %d",
		count, umTraceHash.StringNoQuotes(),
		hex.EncodeToString(rawTrace.APMTransactionID[:]), pid)

	msg := traceCorrMsg{
		MessageType:      1,
		MinorVersion:     1,
		APMTraceID:       rawTrace.APMTraceID,
		APMTransactionID: rawTrace.APMTransactionID,
		StackTraceID:     umTraceHash,
		Count:            count,
	}

	if err := i.socket.SendMessage(msg.Serialize()); err != nil {
		log.Debugf("Failed to send trace mappings to APM agent: %v", err)
	}
}

// APMServiceName returns the service name advertised by the APM agent.
func (i *Instance) APMServiceName() string {
	return i.serviceName
}

// isPotentialAgentLib checks whether the given path looks like a Java APM agent library.
func isPotentialAgentLib(path string) bool {
	return dsoRegex.MatchString(path)
}

// nextString reads the next `utf8-str` from memory and updates addr accordingly.
//
// https://github.com/elastic/apm/blob/bd5fa9c1/specs/agents/universal-profiling-integration.md#general-memory-layout
//
//nolint:lll
func nextString(rm remotememory.RemoteMemory, addr *libpf.Address, maxLen int) (string, error) {
	length := int(rm.Uint32(*addr))
	*addr += 4

	if length == 0 {
		return "", nil
	}

	if length > maxLen {
		return "", fmt.Errorf("APM string length %d exceeds maximum length of %d", length, maxLen)
	}

	raw := make([]byte, length)
	if _, err := rm.ReadAt(raw, int64(*addr)); err != nil {
		return "", errors.New("failed to read memory")
	}

	*addr += libpf.Address(length)
	return pfunsafe.ToString(raw), nil
}

// readProcStorage reads the APM process storage from memory.
//
// https://github.com/elastic/apm/blob/bd5fa9c1/specs/agents/universal-profiling-integration.md#process-storage-layout
//
//nolint:lll
func readProcStorage(
	rm remotememory.RemoteMemory,
	procStorageAddr libpf.Address,
) (*apmProcessStorage, error) {
	readPtr := rm.Ptr(procStorageAddr)
	if readPtr == 0 {
		return nil, errors.New("failed to read Java agent process state pointer")
	}

	// Skip `layout-minor-version` field: not relevant until values != 1 exist.
	// The specification guarantees that the struct can only be extended by adding
	// new fields after the old ones.
	readPtr += 2

	serviceName, err := nextString(rm, &readPtr, serviceNameMaxLength)
	if err != nil {
		return nil, err
	}

	// Currently not used by us.
	_, err = nextString(rm, &readPtr, serviceEnvMaxLength)
	if err != nil {
		return nil, err
	}

	socketPath, err := nextString(rm, &readPtr, socketPathMaxLength)
	if err != nil {
		return nil, err
	}

	return &apmProcessStorage{
		ServiceName:     serviceName,
		TraceSocketPath: socketPath,
	}, nil
}
