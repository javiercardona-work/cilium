// SPDX-License-Identifier: MIT

package features

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestProgramHelperInstructions(t *testing.T) {
	t.Run("set retval gets a scalar argument", func(t *testing.T) {
		insns := programHelperInstructions(asm.FnSetRetval)
		if len(insns) != 4 {
			t.Fatalf("got %d instructions, want 4", len(insns))
		}

		want := asm.Mov.Imm(asm.R1, 0)
		got := insns[0]
		if got.OpCode != want.OpCode || got.Dst != want.Dst || got.Src != want.Src || got.Offset != want.Offset || got.Constant != want.Constant {
			t.Fatalf("got first instruction %v, want %v", got, want)
		}
	})

	t.Run("other helpers keep the context argument", func(t *testing.T) {
		insns := programHelperInstructions(asm.FnGetNetnsCookie)
		if len(insns) != 3 {
			t.Fatalf("got %d instructions, want 3", len(insns))
		}
		if !insns[0].IsBuiltinCall() || insns[0].Constant != int64(asm.FnGetNetnsCookie) {
			t.Fatalf("got first instruction %v, want %v", insns[0], asm.FnGetNetnsCookie.Call())
		}
	})
}
