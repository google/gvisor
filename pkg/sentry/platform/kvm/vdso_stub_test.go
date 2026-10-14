// Copyright 2026 The gVisor Authors.
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

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	disasmInsnLineRE = regexp.MustCompile(`^\s*[0-9a-fA-F]+:\s+(.+)$`)
	disasmSymbolRE   = regexp.MustCompile(`\s*<[^>]+>`)
)

// disasmBytes disassembles buf[startOff:endOff] as instructions at image
// offset startOff using objdump (with -b binary -m <arch>), returning one
// normalized assembly line per instruction.
func disasmBytes(t *testing.T, arch string, buf []byte, startOff, endOff int) []string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "vdso.bin")
	if err := os.WriteFile(binPath, buf, 0600); err != nil {
		t.Fatalf("failed to write temporary binary: %v", err)
	}

	cmd := exec.Command(
		"objdump",
		"-b", "binary",
		"-m", arch,
		"-D",
		"--no-show-raw-insn",
		fmt.Sprintf("--start-address=%#x", startOff),
		fmt.Sprintf("--stop-address=%#x", endOff),
		binPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v failed: %v\nOutput:\n%s", cmd, err, out)
	}

	var insns []string
	for _, line := range strings.Split(string(out), "\n") {
		m := disasmInsnLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		insn := m[1]
		// Strip trailing comments ("# ..." on x86 or "// ..." on arm64).
		// Note: arm64 immediates use "#<num>" without a space after '#'.
		if idx := strings.Index(insn, "# "); idx >= 0 {
			insn = insn[:idx]
		}
		if idx := strings.Index(insn, "//"); idx >= 0 {
			insn = insn[:idx]
		}
		// Strip symbol/offset annotations like "<.data+0xfbd>".
		insn = disasmSymbolRE.ReplaceAllString(insn, "")
		insn = strings.Join(strings.Fields(insn), " ")
		if insn != "" {
			insns = append(insns, insn)
		}
	}
	return insns
}
