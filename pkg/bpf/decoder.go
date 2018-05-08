// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"bytes"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// DecodeProgram translates an array of BPF instructions into text format.
func DecodeProgram(program []linux.BPFInstruction) (string, error) {
	var ret bytes.Buffer
	for line, s := range program {
		ret.WriteString(fmt.Sprintf("%v: ", line))
		if err := decode(s, line, &ret); err != nil {
			return "", err
		}
		ret.WriteString("\n")
	}
	return ret.String(), nil
}

// Decode translates BPF instruction into text format.
func Decode(inst linux.BPFInstruction) (string, error) {
	var ret bytes.Buffer
	err := decode(inst, -1, &ret)
	return ret.String(), err
}

func decode(inst linux.BPFInstruction, line int, w *bytes.Buffer) error {
	var err error
	switch inst.OpCode & instructionClassMask {
	case Ld:
		err = decodeLd(inst, w)
	case Ldx:
		err = decodeLdx(inst, w)
	case St:
		w.WriteString(fmt.Sprintf("M[%v] <- A", inst.K))
	case Stx:
		w.WriteString(fmt.Sprintf("M[%v] <- X", inst.K))
	case Alu:
		err = decodeAlu(inst, w)
	case Jmp:
		err = decodeJmp(inst, line, w)
	case Ret:
		err = decodeRet(inst, w)
	case Misc:
		err = decodeMisc(inst, w)
	default:
		return fmt.Errorf("invalid BPF instruction: %v", inst)
	}
	return err
}

// A <- P[k:4]
func decodeLd(inst linux.BPFInstruction, w *bytes.Buffer) error {
	w.WriteString("A <- ")

	switch inst.OpCode & loadModeMask {
	case Imm:
		w.WriteString(fmt.Sprintf("%v", inst.K))
	case Abs:
		w.WriteString(fmt.Sprintf("P[%v:", inst.K))
		if err := decodeLdSize(inst, w); err != nil {
			return err
		}
		w.WriteString("]")
	case Ind:
		w.WriteString(fmt.Sprintf("P[X+%v:", inst.K))
		if err := decodeLdSize(inst, w); err != nil {
			return err
		}
		w.WriteString("]")
	case Mem:
		w.WriteString(fmt.Sprintf("M[%v]", inst.K))
	case Len:
		w.WriteString("len")
	default:
		return fmt.Errorf("invalid BPF LD instruction: %v", inst)
	}
	return nil
}

func decodeLdSize(inst linux.BPFInstruction, w *bytes.Buffer) error {
	switch inst.OpCode & loadSizeMask {
	case W:
		w.WriteString("4")
	case H:
		w.WriteString("2")
	case B:
		w.WriteString("1")
	default:
		return fmt.Errorf("Invalid BPF LD size: %v", inst)
	}
	return nil
}

// X <- P[k:4]
func decodeLdx(inst linux.BPFInstruction, w *bytes.Buffer) error {
	w.WriteString("X <- ")

	switch inst.OpCode & loadModeMask {
	case Imm:
		w.WriteString(fmt.Sprintf("%v", inst.K))
	case Mem:
		w.WriteString(fmt.Sprintf("M[%v]", inst.K))
	case Len:
		w.WriteString("len")
	case Msh:
		w.WriteString(fmt.Sprintf("4*(P[%v:1]&0xf)", inst.K))
	default:
		return fmt.Errorf("invalid BPF LDX instruction: %v", inst)
	}
	return nil
}

// A <- A + k
func decodeAlu(inst linux.BPFInstruction, w *bytes.Buffer) error {
	code := inst.OpCode & aluMask
	if code == Neg {
		w.WriteString("A <- -A")
		return nil
	}

	w.WriteString("A <- A ")
	switch code {
	case Add:
		w.WriteString("+ ")
	case Sub:
		w.WriteString("- ")
	case Mul:
		w.WriteString("* ")
	case Div:
		w.WriteString("/ ")
	case Or:
		w.WriteString("| ")
	case And:
		w.WriteString("& ")
	case Lsh:
		w.WriteString("<< ")
	case Rsh:
		w.WriteString(">> ")
	case Mod:
		w.WriteString("% ")
	case Xor:
		w.WriteString("^ ")
	default:
		return fmt.Errorf("invalid BPF ALU instruction: %v", inst)
	}
	return decodeSource(inst, w)
}

func decodeSource(inst linux.BPFInstruction, w *bytes.Buffer) error {
	switch inst.OpCode & srcAluJmpMask {
	case K:
		w.WriteString(fmt.Sprintf("%v", inst.K))
	case X:
		w.WriteString("X")
	default:
		return fmt.Errorf("invalid BPF ALU/JMP source instruction: %v", inst)
	}
	return nil
}

// pc += (A > k) ? jt : jf
func decodeJmp(inst linux.BPFInstruction, line int, w *bytes.Buffer) error {
	code := inst.OpCode & jmpMask

	w.WriteString("pc += ")
	if code == Ja {
		w.WriteString(printJmpTarget(inst.K, line))
	} else {
		w.WriteString("(A ")
		switch code {
		case Jeq:
			w.WriteString("== ")
		case Jgt:
			w.WriteString("> ")
		case Jge:
			w.WriteString(">= ")
		case Jset:
			w.WriteString("& ")
		default:
			return fmt.Errorf("invalid BPF ALU instruction: %v", inst)
		}
		if err := decodeSource(inst, w); err != nil {
			return err
		}
		w.WriteString(
			fmt.Sprintf(") ? %s : %s",
				printJmpTarget(uint32(inst.JumpIfTrue), line),
				printJmpTarget(uint32(inst.JumpIfFalse), line)))
	}
	return nil
}

func printJmpTarget(target uint32, line int) string {
	if line == -1 {
		return fmt.Sprintf("%v", target)
	}
	return fmt.Sprintf("%v [%v]", target, int(target)+line+1)
}

// ret k
func decodeRet(inst linux.BPFInstruction, w *bytes.Buffer) error {
	w.WriteString("ret ")

	code := inst.OpCode & srcRetMask
	switch code {
	case K:
		w.WriteString(fmt.Sprintf("%v", inst.K))
	case A:
		w.WriteString("A")
	default:
		return fmt.Errorf("invalid BPF RET source instruction: %v", inst)
	}
	return nil
}

func decodeMisc(inst linux.BPFInstruction, w *bytes.Buffer) error {
	code := inst.OpCode & miscMask
	switch code {
	case Tax:
		w.WriteString("X <- A")
	case Txa:
		w.WriteString("A <- X")
	default:
		return fmt.Errorf("invalid BPF ALU/JMP source instruction: %v", inst)
	}
	return nil
}
