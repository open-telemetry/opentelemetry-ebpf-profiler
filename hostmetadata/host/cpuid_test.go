/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"os"
	"runtime"
	"testing"

	"github.com/klauspost/cpuid/v2"
	"github.com/stretchr/testify/assert"
)

func TestCPUID_DetectAllCPUIDs(t *testing.T) {
	coreIDs, err := ParseCPUCoreIDs(CPUOnlinePath)
	if err != nil {
		t.Fatalf("expected to read available CPUs, got error: %v", err)
	}

	detected, err := runCPUIDOnAllCores(coreIDs)

	assert.Nil(t, err)
	assert.Equal(t, runtime.NumCPU(), len(detected))
	assert.Equal(t, cpuid.CPU.PhysicalCores, detected[0].PhysicalCores)
	assert.Equal(t, cpuid.CPU.LogicalCores, detected[0].LogicalCores)
	assert.NotEmpty(t, detected[len(coreIDs)-1].Cache.L2)
}

func TestCPUID_ParseOnlineCPUCoreIDs(t *testing.T) {
	const onlineValuesSample = `0,3-6,8-11`

	f := prepareFakeCPUOnlineFile(t, onlineValuesSample)
	defer os.Remove(f.Name())

	coreIDs, err := ParseCPUCoreIDs(f.Name())
	assert.Nil(t, err)
	assert.Equal(t, 9, len(coreIDs))
}

func prepareFakeCPUOnlineFile(t *testing.T, content string) *os.File {
	f, err := os.CreateTemp("", "sys_device_cpu_online")
	if err != nil {
		t.Fatalf("could not create temporary file: %v", err)
	}
	_ = os.WriteFile(f.Name(), []byte(content), os.ModePerm)
	return f
}
