// Copyright 2022 The gVisor Authors.
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

package checkescape

import (
	"fmt"
	"strconv"
	"strings"
)

// fixOffset accounts for the output of arm64 `go tool objdump`. Objdump gives
// the instruction offset rather than the byte offset. The offset confuses
// checkescape, as it looks like the branch is to random memory.
//
// When appropriate, we re-parse the instruction ourselves and return the
// correct offset.
func fixOffset(fields []string, target string) (string, error) {
	// We're looking for a line that looks something like:
	//   iptables.go:320   0x211214        97f9b198          CALL -413288(PC)
	// In this case, target is passed as -413288(PC). The byte offset of this
	// instruction should be -1653152.

	// Make sure we're dealing with a PC offset.
	if !strings.HasSuffix(target, "(PC)") {
		return target, nil // Not a relative branch.
	}

	// Examine the opcode to ensure it's a BL instruction. See the ARM
	// documentation here:
	// https://developer.arm.com/documentation/ddi0596/2020-12/Base-Instructions/BL--Branch-with-Link-?lang=en
	const (
		opcodeBits = 0xfc000000
		blOpcode   = 0x94000000
	)
	instr64, err := strconv.ParseUint(fields[2], 16, 32)
	if err != nil {
		return "", err
	}
	instr := uint32(instr64)
	if instr&opcodeBits != blOpcode {
		return target, nil // Not a BL.
	}
	// Per documentation, the offset is formed via:
	//   - Take the lower 26 bits
	//   - Append 2 zero bits (this is what objdump omits)
	//   - Sign extend out to 64 bits
	offset := int64(int32(instr<<6) >> 4)

	// Parse the PC, removing the leading "0x".
	pc, err := strconv.ParseUint(fields[1][len("0x"):], 16, 64)
	if err != nil {
		return "", err
	}
	// PC is always the next instruction.
	pc += 8
	return fmt.Sprintf("0x%x", pc+uint64(offset)), nil
}
