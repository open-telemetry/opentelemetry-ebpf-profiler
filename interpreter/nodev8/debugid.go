// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// debugIDRegex matches the debug ID magic comment per the ECMA-426 spec:
// https://github.com/tc39/ecma426/blob/main/proposals/debug-id.md
// Pattern: //# debugId=550e8400-e29b-41d4-a716-446655440000
var debugIDRegex = regexp.MustCompile(`(?m)^//# debugId=([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$`)

// uuidToFileID converts a UUID to a FileID by splitting into two uint64s.
func uuidToFileID(u uuid.UUID) libpf.FileID {
	hi := binary.BigEndian.Uint64(u[0:8])
	lo := binary.BigEndian.Uint64(u[8:16])
	return libpf.NewFileID(hi, lo)
}

// readFileTail reads the last maxBytes of a file, or the entire file if smaller.
func readFileTail(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()
	readSize := min(fileSize, maxBytes)

	if _, err := file.Seek(fileSize-readSize, io.SeekStart); err != nil {
		return nil, err
	}

	buf := make([]byte, readSize)
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// extractDebugIDFromFile reads the debug ID magic comment from a JavaScript file's tail.
func extractDebugIDFromFile(pid libpf.PID, filePath string) libpf.FileID {
	filePath = strings.TrimPrefix(filePath, "file://")
	containerPath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "root", filePath)

	log.Debugf("V8: extracting debug ID from %s", containerPath)

	buf, err := readFileTail(containerPath, 1024)
	if err != nil {
		log.Debugf("V8: failed to read %s: %v", containerPath, err)
		return libpf.FileID{}
	}

	// Search for the debug ID pattern
	matches := debugIDRegex.FindSubmatch(buf)
	if len(matches) < 2 {
		log.Debugf("V8: no debug ID in %s", filePath)
		return libpf.FileID{}
	}

	debugIDStr := string(matches[1])
	parsedUUID, err := uuid.Parse(debugIDStr)
	if err != nil {
		log.Debugf("V8: invalid debug ID %s in %s: %v", debugIDStr, filePath, err)
		return libpf.FileID{}
	}

	log.Debugf("V8: debug ID %s from %s", debugIDStr, filePath)
	return uuidToFileID(parsedUUID)
}

// extractDebugID extracts and caches the debug ID for a JavaScript file, returns executable metadata if found.
func (i *v8Instance) extractDebugID(fileName libpf.String) libpf.FileID {
	if cachedFileID, ok := i.fileToDebugID.Get(fileName); ok {
		return cachedFileID
	}

	log.Debugf("V8: debug ID cache miss for %s", fileName)
	fileID := extractDebugIDFromFile(i.pid, fileName.String())
	i.fileToDebugID.Add(fileName, fileID)

	return fileID
}
