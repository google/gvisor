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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	objcopyPath      = flag.String("objcopy", "", "Path to the declared LLVM objcopy")
	objdumpPath      = flag.String("objdump", "", "Path to the declared LLVM objdump")
	disasmInsnLineRE = regexp.MustCompile(`^\s*[0-9a-fA-F]+:\s+(.+)$`)
	disasmSymbolRE   = regexp.MustCompile(`\s*<[^>]+>`)
)

// disasmBytes disassembles buf[startOff:endOff] as instructions at image
// offset startOff using the declared LLVM tools, returning one normalized
// assembly line per instruction. The ELF wrapper preserves the byte offsets
// so PC-relative branches are checked against their actual destinations.
func disasmBytes(t *testing.T, format string, buf []byte, startOff, endOff int) []string {
	t.Helper()
	if *objcopyPath == "" || *objdumpPath == "" {
		t.Fatal("both --objcopy and --objdump are required")
	}
	binPath := filepath.Join(t.TempDir(), "vdso.bin")
	if err := os.WriteFile(binPath, buf, 0600); err != nil {
		t.Fatalf("failed to write temporary binary: %v", err)
	}

	elfPath := binPath + ".o"
	cmd := exec.CommandContext(t.Context(),
		*objcopyPath,
		"--input-target=binary",
		"--output-target="+format,
		"--rename-section=.data=.text,alloc,load,readonly,code",
		binPath, elfPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v failed: %v\nOutput:\n%s", cmd, err, out)
	}
	cmd = exec.CommandContext(t.Context(),
		*objdumpPath,
		"--disassemble",
		"--no-show-raw-insn",
		fmt.Sprintf("--start-address=%#x", startOff),
		fmt.Sprintf("--stop-address=%#x", endOff),
		elfPath,
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
