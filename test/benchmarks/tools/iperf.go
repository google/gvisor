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

// Iperf is for the client side of `iperf`.
type Iperf struct {
	Num      int // Number of bytes to send in KB.
	Parallel int // Number of parallel threads.
}

// MakeCmd returns a iperf client command.
func (i *Iperf) MakeCmd(host string, port int) []string {
	cmd := []string{"iperf"}
	cmd = append(cmd, "--format", "K") // Output in KBytes.
	cmd = append(cmd, "--realtime")    // Measured in realtime.
	cmd = append(cmd, "--len", "128K") // Length of data buffer per request.
	n := i.Num
	if i.Parallel > 0 {
		// Must be at least 1, otherwise iperf will complain about having nothing to transmit.
		n = max(i.Num/i.Parallel, 1)
	}
	cmd = append(cmd, "--num", fmt.Sprintf("%dK", n)) // Number of requests to send.
	cmd = append(cmd, "--client", host)
	cmd = append(cmd, "--port", fmt.Sprintf("%d", port))
	if i.Parallel > 0 {
		cmd = append(cmd, "--parallel", fmt.Sprintf("%d", i.Parallel))
	}
	return cmd
}

// Report parses output from iperf client and reports metrics.
func (i *Iperf) Report(b *testing.B, output string) {
	b.Helper()
	// Parse bandwidth and report it.
	bW, err := i.bandwidth(output)
	if err != nil {
		b.Fatalf("failed to parse bandwitdth from %s: %v", output, err)
	}
	b.SetBytes(128 * 1024) // Measure Bytes/sec for b.N, although below is iperf output.
	ReportCustomMetric(b, bW*1024, "bandwidth" /*metric name*/, "bytes_per_second" /*unit*/)
}

// bandwidth parses the Bandwidth number from an iperf report. A sample is below.
func (i *Iperf) bandwidth(data string) (float64, error) {
	re := regexp.MustCompile(`\[\s*\d+\][^\n]+\s+(\d+\.?\d*)\s+KBytes/sec`)
	match := re.FindStringSubmatch(data)
	if len(match) < 1 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}
