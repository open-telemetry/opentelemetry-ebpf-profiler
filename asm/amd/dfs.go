package amd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/ebpf-profiler/asm/dfs"
	"golang.org/x/arch/x86/x86asm"
)

func Explore(ef io.ReaderAt, d *dfs.DFS, indirectJumps map[uint64]struct{}) error {
	for {
		it := d.PeekUnexplored()

		if it == nil {
			break
		}
		const blockLimit = 8 * 1024 // 2700 observed
		if d.BasicBlockCount() >= blockLimit {
			return errors.New("too many blocks")
		}

		codeBuf := [16]byte{}
		for {
			pos, explored := it.Position()
			if explored {
				break
			}

			if _, err := ef.ReadAt(codeBuf[:], int64(pos)); err != nil {
				return err
			}
			if ok, sz := DecodeSkippable(codeBuf[:]); ok {
				if err := d.AddInstruction(it, sz, true); err != nil {
					return err
				}
				continue
			}
			insn, err := x86asm.Decode(codeBuf[:], 64)
			if err != nil {
				return err
			}
			rip := pos
			jump := IsJump(insn.Op)
			conditionalJump := !(insn.Op == x86asm.JMP || insn.Op == x86asm.RET)
			ud := insn.Op == x86asm.UD0 || insn.Op == x86asm.UD1 || insn.Op == x86asm.UD2
			mayFallThrough := !jump || conditionalJump
			if err = d.AddInstruction(it, insn.Len, mayFallThrough); err != nil {
				return err
			}
			prevRIP := rip
			rip += uint64(insn.Len)
			if insn.Op == x86asm.CALL && it.CallDoesNotReturn() {
				it.MarkExplored()
			}
			if jump {
				it.MarkExplored()
				if conditionalJump {
					e := d.AddBasicBlock(rip)
					d.AddEdge(it, e, dfs.EdgeTypeFallThrough)
				}
				if insn.Op != x86asm.RET {
					switch typed := insn.Args[0].(type) {
					case x86asm.Rel:
						dst := uint64(int64(rip) + int64(typed))
						to := d.AddBasicBlock(dst)
						d.AddEdge(it, to, dfs.EdgeTypeJump)
					case x86asm.Reg, x86asm.Mem:
						if indirectJumps != nil {
							indirectJumps[prevRIP] = struct{}{}
						}
					default:
						return fmt.Errorf("unhandled jump: %s %s",
							hex.EncodeToString(codeBuf[:]), insn.String())
					}
				}
				break
			}
			if ud {
				it.MarkExplored()
				break
			}
		}
	}
	return nil
}
