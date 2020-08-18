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
	"strings"
	"testing"
)

var warmup = "sysbench --threads=8 --memory-total-size=5G memory run > /dev/null &&"

// Sysbench represents a 'sysbench' command.
type Sysbench interface {
	MakeCmd() []string // Makes a sysbench command.
	flags() []string
	Report(*testing.B, string) // Reports results contained in string.
}

// SysbenchBase is the top level struct for sysbench and holds top-level arguments
// for sysbench. See: 'sysbench --help'
type SysbenchBase struct {
	Threads int // number of Threads for the test.
	Time    int // time limit for test in seconds.
}

// baseFlags returns top level flags.
func (s *SysbenchBase) baseFlags() []string {
	var ret []string
	if s.Threads > 0 {
		ret = append(ret, fmt.Sprintf("--threads=%d", s.Threads))
	}
	if s.Time > 0 {
		ret = append(ret, fmt.Sprintf("--time=%d", s.Time))
	}
	return ret
}

// SysbenchCPU is for 'sysbench [flags] cpu run' and holds CPU specific arguments.
type SysbenchCPU struct {
	Base     SysbenchBase
	MaxPrime int // upper limit for primes generator [10000].
}

// MakeCmd makes commands for SysbenchCPU.
func (s *SysbenchCPU) MakeCmd() []string {
	cmd := []string{warmup, "sysbench"}
	cmd = append(cmd, s.flags()...)
	cmd = append(cmd, "cpu run")
	return []string{"sh", "-c", strings.Join(cmd, " ")}
}

// flags makes flags for SysbenchCPU cmds.
func (s *SysbenchCPU) flags() []string {
	cmd := s.Base.baseFlags()
	if s.MaxPrime > 0 {
		return append(cmd, fmt.Sprintf("--cpu-max-prime=%d", s.MaxPrime))
	}
	return cmd
}

// Report reports the relevant metrics for SysbenchCPU.
func (s *SysbenchCPU) Report(b *testing.B, output string) {
	b.Helper()
	result, err := s.parseEvents(output)
	if err != nil {
		b.Fatalf("parsing CPU events from %s failed: %v", output, err)
	}
	b.ReportMetric(result, "cpu_events_per_second")
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
	Base          SysbenchBase
	BlockSize     string // size of test memory block [1K].
	TotalSize     string // size of data to transfer [100G].
	Scope         string // memory access scope {global, local} [global].
	HugeTLB       bool   // allocate memory from HugeTLB [off].
	OperationType string // type of memory ops {read, write, none} [write].
	AccessMode    string // access mode {seq, rnd} [seq].
}

// MakeCmd makes commands for SysbenchMemory.
func (s *SysbenchMemory) MakeCmd() []string {
	cmd := []string{warmup, "sysbench"}
	cmd = append(cmd, s.flags()...)
	cmd = append(cmd, "memory run")
	return []string{"sh", "-c", strings.Join(cmd, " ")}
}

// flags makes flags for SysbenchMemory cmds.
func (s *SysbenchMemory) flags() []string {
	cmd := s.Base.baseFlags()
	if s.BlockSize != "" {
		cmd = append(cmd, fmt.Sprintf("--memory-block-size=%s", s.BlockSize))
	}
	if s.TotalSize != "" {
		cmd = append(cmd, fmt.Sprintf("--memory-total-size=%s", s.TotalSize))
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
	b.ReportMetric(result, "operations_per_second")
}

var memoryOperationsRE = regexp.MustCompile(`Total\soperations:\s+\d*\s*\((\d*\.\d*)\sper\ssecond\)`)

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
	Base  SysbenchBase
	Num   int // total size of mutex array [4096].
	Locks int // number of mutex locks per thread [50K].
	Loops int // number of loops to do outside mutex lock [10K].
}

// MakeCmd makes commands for SysbenchMutex.
func (s *SysbenchMutex) MakeCmd() []string {
	cmd := []string{warmup, "sysbench"}
	cmd = append(cmd, s.flags()...)
	cmd = append(cmd, "mutex run")
	return []string{"sh", "-c", strings.Join(cmd, " ")}
}

// flags makes flags for SysbenchMutex commands.
func (s *SysbenchMutex) flags() []string {
	var cmd []string
	cmd = append(cmd, s.Base.baseFlags()...)
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
	b.ReportMetric(result, "average_execution_time_secs")

	result, err = s.parseDeviation(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	b.ReportMetric(result, "stdev_execution_time_secs")

	result, err = s.parseLatency(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	b.ReportMetric(result/1000, "average_latency_secs")
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
