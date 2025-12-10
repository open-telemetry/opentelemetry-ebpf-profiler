// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// debugIDRegex matches the debug ID magic comment at the end of JS files
// Pattern: //# debugId=550e8400-e29b-41d4-a716-446655440000
var debugIDRegex = regexp.MustCompile(`//# debugId=([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})`)

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
	containerPath := fmt.Sprintf("/proc/%d/root%s", pid, filePath)

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

	// If we found a debug ID, report it as executable metadata
	if fileID != (libpf.FileID{}) && i.reporter != nil && !i.reporter.ExecutableKnown(fileID) {
		log.Debugf("V8: reporting metadata for %s, debug ID %v", fileName, fileID)
		i.reporter.ExecutableMetadata(&reporter.ExecutableMetadataArgs{
			FileID:     fileID,
			FileName:   fileName.String(),
			GnuBuildID: fileID.ToUUIDString(),
			Interp:     libpf.V8,
		})
	}

	return fileID
}
