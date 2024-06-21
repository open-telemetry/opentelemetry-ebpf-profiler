//go:build amd64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package process

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

const currentMachine = elf.EM_X86_64

func (sp *ptraceProcess) getThreadInfo(tid int) (ThreadInfo, error) {
	prStatus := make([]byte, 28*8)
	if err := ptraceGetRegset(tid, int(elf.NT_PRSTATUS), prStatus); err != nil {
		return ThreadInfo{}, fmt.Errorf("failed to get LWP %d thread info: %v", tid, err)
	}
	return ThreadInfo{
		LWP:    uint32(tid),
		GPRegs: prStatus,
		TPBase: binary.LittleEndian.Uint64(prStatus[21*8:]),
	}, nil
}
