// Copyright 2024 The gVisor Authors.
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

// ReportTriton reports the relevant metrics for Triton's perf_analyzer tool.
func ReportTriton(b *testing.B, output string) {
	b.Helper()
	throughput, latency, err := parseMetrics(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	ReportCustomMetric(b, throughput, "throughput" /*metric name*/, "infer_sec" /*unit*/)
	ReportCustomMetric(b, latency, "latency" /*metric name*/, "usec" /*unit*/)
}

var perfMetrics = regexp.MustCompile(`Concurrency:\s+\d+,\s+throughput:\s+(\d+\.\d+)\s+infer\/sec,\s+latency\s+(\d+)\s+usec`)

func parseMetrics(content string) (throughput float64, latency float64, err error) {
	matches := perfMetrics.FindStringSubmatch(content)
	if len(matches) != 3 {
		return 0, 0, fmt.Errorf("failed to parse metrics from %s", content)
	}

	throughput, err = strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse throughput from %s: %v", matches[1], err)
	}
	latency, err = strconv.ParseFloat(matches[2], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse latency from %s: %v", matches[2], err)
	}
	return throughput, latency, nil
}
