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

package backtrace

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestDumpStack(t *testing.T) {
	frame := regexp.MustCompile(`^([0-9]+): \[0x[0-9a-f]+(?: <[^>]+>)?\]$`)
	// Exercise both initialization and reuse of the unwinder state.
	for range 2 {
		output, err := dumpStack()
		if err != nil {
			t.Fatalf("dumpStack(): %v", err)
		}
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) < 2 || len(lines) > 256 {
			t.Fatalf("stack trace has %d frames, want 2 to 256:\n%s", len(lines), output)
		}
		for i, line := range lines {
			match := frame.FindStringSubmatch(line)
			if match == nil {
				t.Fatalf("invalid stack frame %q in:\n%s", line, output)
			}
			number, err := strconv.Atoi(match[1])
			if err != nil || number != len(lines)-i {
				t.Fatalf("frame number %q, want %d in:\n%s", match[1], len(lines)-i, output)
			}
		}
	}
}
