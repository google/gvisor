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
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Iperf is for the client side of `iperf`.
type Iperf struct {
	Time int
}

// MakeCmd returns a iperf client command.
func (i *Iperf) MakeCmd(ip net.IP, port int) []string {
	// iperf report in Kb realtime
	return strings.Split(fmt.Sprintf("iperf -f K --realtime --time %d --client %s --port %d", i.Time, ip, port), " ")
}

// Report parses output from iperf client and reports metrics.
func (i *Iperf) Report(b *testing.B, output string) {
	b.Helper()
	// Parse bandwidth and report it.
	bW, err := i.bandwidth(output)
	if err != nil {
		b.Fatalf("failed to parse bandwitdth from %s: %v", output, err)
	}
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
