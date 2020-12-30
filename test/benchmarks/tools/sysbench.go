// Copyright 2020 The gVisor Authors.
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

package tools

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
)

// Sysbench represents a 'sysbench' command.
type Sysbench interface {
	// MakeCmd constructs the relevant command line.
	MakeCmd(*testing.B) []string

	// Report reports relevant custom metrics.
	Report(*testing.B, string)
}

// SysbenchBase is the top level struct for sysbench and holds top-level arguments
// for sysbench. See: 'sysbench --help'
type SysbenchBase struct {
	// Threads is the number of threads for the test.
	Threads int
}

// baseFlags returns top level flags.
func (s *SysbenchBase) baseFlags(b *testing.B) []string {
	var ret []string
	if s.Threads > 0 {
		ret = append(ret, fmt.Sprintf("--threads=%d", s.Threads))
	}
	ret = append(ret, "--time=0") // Ensure events is used.
	ret = append(ret, fmt.Sprintf("--events=%d", b.N))
	return ret
}

// SysbenchCPU is for 'sysbench [flags] cpu run' and holds CPU specific arguments.
type SysbenchCPU struct {
	SysbenchBase
}

// MakeCmd makes commands for SysbenchCPU.
func (s *SysbenchCPU) MakeCmd(b *testing.B) []string {
	cmd := []string{"sysbench"}
	cmd = append(cmd, s.baseFlags(b)...)
	cmd = append(cmd, "cpu", "run")
	return cmd
}

// Report reports the relevant metrics for SysbenchCPU.
func (s *SysbenchCPU) Report(b *testing.B, output string) {
	b.Helper()
	result, err := s.parseEvents(output)
	if err != nil {
		b.Fatalf("parsing CPU events from %s failed: %v", output, err)
	}
	ReportCustomMetric(b, result, "cpu_events" /*metric name*/, "events_per_second" /*unit*/)
}

var cpuEventsPerSecondRE = regexp.MustCompile(`events per second:\s*(\d*.?\d*)\n`)

// parseEvents parses cpu events per second.
func (s *SysbenchCPU) parseEvents(data string) (float64, error) {
	match := cpuEventsPerSecondRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0.0, fmt.Errorf("could not find events per second: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

// SysbenchMemory is for 'sysbench [FLAGS] memory run' and holds Memory specific arguments.
type SysbenchMemory struct {
	SysbenchBase
	BlockSize     int    // size of test memory block in megabytes [1].
	TotalSize     int    // size of data to transfer in gigabytes [100].
	Scope         string // memory access scope {global, local} [global].
	HugeTLB       bool   // allocate memory from HugeTLB [off].
	OperationType string // type of memory ops {read, write, none} [write].
	AccessMode    string // access mode {seq, rnd} [seq].
}

// MakeCmd makes commands for SysbenchMemory.
func (s *SysbenchMemory) MakeCmd(b *testing.B) []string {
	cmd := []string{"sysbench"}
	cmd = append(cmd, s.flags(b)...)
	cmd = append(cmd, "memory", "run")
	return cmd
}

// flags makes flags for SysbenchMemory cmds.
func (s *SysbenchMemory) flags(b *testing.B) []string {
	cmd := s.baseFlags(b)
	if s.BlockSize != 0 {
		cmd = append(cmd, fmt.Sprintf("--memory-block-size=%dM", s.BlockSize))
	}
	if s.TotalSize != 0 {
		cmd = append(cmd, fmt.Sprintf("--memory-total-size=%dG", s.TotalSize))
	}
	if s.Scope != "" {
		cmd = append(cmd, fmt.Sprintf("--memory-scope=%s", s.Scope))
	}
	if s.HugeTLB {
		cmd = append(cmd, "--memory-hugetlb=on")
	}
	if s.OperationType != "" {
		cmd = append(cmd, fmt.Sprintf("--memory-oper=%s", s.OperationType))
	}
	if s.AccessMode != "" {
		cmd = append(cmd, fmt.Sprintf("--memory-access-mode=%s", s.AccessMode))
	}
	return cmd
}

// Report reports the relevant metrics for SysbenchMemory.
func (s *SysbenchMemory) Report(b *testing.B, output string) {
	b.Helper()
	result, err := s.parseOperations(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	ReportCustomMetric(b, result, "memory_operations" /*metric name*/, "ops_per_second" /*unit*/)
}

var memoryOperationsRE = regexp.MustCompile(`Total\s+operations:\s+\d+\s+\((\s*\d+\.\d+\s*)\s+per\s+second\)`)

// parseOperations parses memory operations per second form sysbench memory ouput.
func (s *SysbenchMemory) parseOperations(data string) (float64, error) {
	match := memoryOperationsRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0.0, fmt.Errorf("couldn't find memory operations per second: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

// SysbenchMutex is for 'sysbench [FLAGS] mutex run' and holds Mutex specific arguments.
type SysbenchMutex struct {
	SysbenchBase
	Num   int // total size of mutex array [4096].
	Locks int // number of mutex locks per thread [50000].
	Loops int // number of loops to do outside mutex lock [10000].
}

// MakeCmd makes commands for SysbenchMutex.
func (s *SysbenchMutex) MakeCmd(b *testing.B) []string {
	cmd := []string{"sysbench"}
	cmd = append(cmd, s.flags(b)...)
	cmd = append(cmd, "mutex", "run")
	return cmd
}

// flags makes flags for SysbenchMutex commands.
func (s *SysbenchMutex) flags(b *testing.B) []string {
	var cmd []string
	cmd = append(cmd, s.baseFlags(b)...)
	if s.Num > 0 {
		cmd = append(cmd, fmt.Sprintf("--mutex-num=%d", s.Num))
	}
	if s.Locks > 0 {
		cmd = append(cmd, fmt.Sprintf("--mutex-locks=%d", s.Locks))
	}
	if s.Loops > 0 {
		cmd = append(cmd, fmt.Sprintf("--mutex-loops=%d", s.Loops))
	}
	return cmd
}

// Report parses and reports relevant sysbench mutex metrics.
func (s *SysbenchMutex) Report(b *testing.B, output string) {
	b.Helper()

	result, err := s.parseExecutionTime(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	ReportCustomMetric(b, result, "average_execution_time" /*metric name*/, "s" /*unit*/)

	result, err = s.parseDeviation(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	ReportCustomMetric(b, result, "stddev_execution_time" /*metric name*/, "s" /*unit*/)

	result, err = s.parseLatency(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	ReportCustomMetric(b, result/1000, "average_latency" /*metric name*/, "s" /*unit*/)
}

var executionTimeRE = regexp.MustCompile(`execution time \(avg/stddev\):\s*(\d*.?\d*)/(\d*.?\d*)`)

// parseExecutionTime parses threads fairness average execution time from sysbench output.
func (s *SysbenchMutex) parseExecutionTime(data string) (float64, error) {
	match := executionTimeRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0.0, fmt.Errorf("could not find execution time average: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

// parseDeviation parses threads fairness stddev time from sysbench output.
func (s *SysbenchMutex) parseDeviation(data string) (float64, error) {
	match := executionTimeRE.FindStringSubmatch(data)
	if len(match) < 3 {
		return 0.0, fmt.Errorf("could not find execution time deviation: %s", data)
	}
	return strconv.ParseFloat(match[2], 64)
}

var averageLatencyRE = regexp.MustCompile(`avg:[^\n^\d]*(\d*\.?\d*)`)

// parseLatency parses latency from sysbench output.
func (s *SysbenchMutex) parseLatency(data string) (float64, error) {
	match := averageLatencyRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0.0, fmt.Errorf("could not find average latency: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}
