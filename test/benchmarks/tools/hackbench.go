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

// Hackbench makes 'hackbench' commands and parses their output.
type Hackbench struct {
	IpcMode     string // ipc mode: pipe, socket(default)
	ProcessMode string // process mode: thread, process(default)
}

// MakeCmd makes commands for Hackbench.
func (s *Hackbench) MakeCmd(b *testing.B) []string {
	cmd := []string{"hackbench"}
	// ipc mode
	if s.IpcMode == "pipe" {
		cmd = append(cmd, "--pipe")
	}
	// group num
	cmd = append(cmd, "--groups=10")
	// process mode
	if s.ProcessMode == "thread" {
		cmd = append(cmd, "--threads")
	} else {
		cmd = append(cmd, "--process")
	}
	// loops
	cmd = append(cmd, fmt.Sprintf("--loops=%d", b.N))
	return cmd
}

// Report reports the relevant metrics for Hackbench.
func (s *Hackbench) Report(b *testing.B, output string) {
	b.Helper()
	result, err := s.parseResult(output)
	if err != nil {
		b.Fatalf("parsing result from %s failed: %v", output, err)
	}
	ReportCustomMetric(b, result, "execution_time" /*metric name*/, "s" /*unit*/)
	ReportCustomMetric(b, result/float64(b.N), "execution_time_per_loop" /*metric name*/, "s" /*unit*/)
}

var hackbenchRegexp = regexp.MustCompile(`Time:\s*(\d*.?\d*)\n`)

func (s *Hackbench) parseResult(data string) (float64, error) {
	match := hackbenchRegexp.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0.0, fmt.Errorf("could not find Time: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}
