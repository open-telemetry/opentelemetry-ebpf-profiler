// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm // import "go.opentelemetry.io/ebpf-profiler/asm/arm"

import (
	"fmt"

	ah "go.opentelemetry.io/ebpf-profiler/armhelpers"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	aa "golang.org/x/arch/arm64/arm64asm"
)

// branchTarget represents a branch target to be analyzed
type branchTarget struct {
	addr  uint64
	depth int
}

// ExtractTLSOffsetFromCodeARM64 extracts the TLS offset by analyzing ARM64 assembly code.
// It looks for the pattern: MRS Xn, TPIDR_EL0 followed by ADD Xn, Xn, #offset or LDR [Xn, #offset].
func ExtractTLSOffsetFromCodeARM64(code []byte, baseAddr uint64, ef *pfelf.File) (int64, error) {
	const maxDepth = 5
	const maxIterations = 100

	// Work queue for branches to follow
	queue := []branchTarget{{addr: baseAddr, depth: 0}}
	visited := make(map[uint64]bool)

	iterations := 0
	foundMRS := false

	for len(queue) > 0 && iterations < maxIterations {
		iterations++

		// Pop from queue
		current := queue[0]
		queue = queue[1:]

		// Check if already visited or depth exceeded
		if visited[current.addr] || current.depth > maxDepth {
			continue
		}
		visited[current.addr] = true

		var codeToAnalyze []byte
		var codeBaseAddr uint64

		if current.addr == baseAddr {
			codeToAnalyze = code
			codeBaseAddr = baseAddr
		} else {
			targetCode := make([]byte, 256)
			err := ef.GetRemoteMemory().Read(libpf.Address(current.addr), targetCode)
			if err != nil {
				continue
			}
			codeToAnalyze = targetCode
			codeBaseAddr = current.addr
		}

		var tpReg int

		for offs := 0; offs < len(codeToAnalyze)-4; offs += 4 {
			inst, err := aa.Decode(codeToAnalyze[offs:])
			if err != nil {
				continue
			}

			// Check for MRS Xn, TPIDR_EL0 (system register S3_3_C13_C0_2)
			if inst.Op == aa.MRS && inst.Args[1].String() == "S3_3_C13_C0_2" {
				reg, ok := ah.Xreg2num(inst.Args[0])
				if !ok {
					continue
				}
				tpReg = reg
				foundMRS = true

				// Look ahead for ADD or LDR using this register
				for j := offs + 4; j < len(codeToAnalyze)-4 && j < offs+64; j += 4 {
					nextInst, err := aa.Decode(codeToAnalyze[j:])
					if err != nil {
						continue
					}

					// Check for ADD Xd, Xn, #imm
					if nextInst.Op == aa.ADD {
						destReg, destOk := ah.Xreg2num(nextInst.Args[0])
						srcReg, srcOk := ah.Xreg2num(nextInst.Args[1])
						imm, immOk := ah.DecodeImmediate(nextInst.Args[2])

						if destOk && srcOk && immOk && srcReg == tpReg {
							if imm > 0 && imm < 0x1000 {
								return int64(imm), nil
							}
							// Track the new register holding TP+offset
							tpReg = destReg
						}
					}

					// Check for LDR Xm, [Xn, #imm]
					if nextInst.Op == aa.LDR {
						// Args[1] is MemImmediate
						if mem, ok := nextInst.Args[1].(aa.MemImmediate); ok {
							baseReg, regOk := ah.Xreg2num(mem.Base)
							imm, immOk := ah.DecodeImmediate(mem)

							if regOk && immOk && baseReg == tpReg {
								if imm > 0 && imm < 0x1000 {
									return int64(imm), nil
								}
							}
						}
					}
				}
			}

			// Check for unconditional branch and add to queue
			if inst.Op == aa.B {
				if pcrel, ok := inst.Args[0].(aa.PCRel); ok {
					targetAddr := int64(codeBaseAddr) + int64(offs) + int64(pcrel)

					if targetAddr > 0 && targetAddr < 0x100000000 && !visited[uint64(targetAddr)] {
						queue = append(queue, branchTarget{
							addr:  uint64(targetAddr),
							depth: current.depth + 1,
						})
					}
				}
			}
		}

		// If we found MRS in this block but no valid offset, continue to next block
		if foundMRS {
			// We found MRS but didn't return, meaning no valid offset was found in this block
			// Continue with other blocks in the queue
			continue
		}
	}

	if !foundMRS {
		return 0, fmt.Errorf("could not find MRS TPIDR_EL0 instruction")
	}
	return 0, fmt.Errorf("found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset")
}
