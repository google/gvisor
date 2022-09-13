// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tools

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
)

// Syscallbench makes 'syscallbench' commands and parses output.
type Syscallbench struct {
	Loops int // total number of loops
}

// MakeCmd makes commands for Syscallbench.
func (s *Syscallbench) MakeCmd(b *testing.B) []string {
	cmd := []string{"syscallbench"}
	cmd = append(cmd, fmt.Sprintf("--loops=%d", s.Loops))
	return cmd
}

// Report reports the relevant metrics for Syscallbench.
func (s *Syscallbench) Report(b *testing.B, output string) {
	b.Helper()
	result, err := s.parseResult(output)
	if err != nil {
		b.Fatalf("parsing result from %s failed: %v", output, err)
	}
	ReportCustomMetric(b, result, "per_syscall_time" /*metric name*/, "ns" /*unit*/)
}

var syscallbenchRegexp = regexp.MustCompile(`(\d*.?\d*)\s*ns/syscall\n`)

// parseResult reports the per_syscall_time in ns.
func (s *Syscallbench) parseResult(data string) (float64, error) {
	match := syscallbenchRegexp.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0.0, fmt.Errorf("could not find ns/syscall: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}
