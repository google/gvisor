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

// Hey is for the client application 'hey'.
type Hey struct {
	Requests    int // Note: requests cannot be less than concurrency.
	Concurrency int
	Doc         string
}

// MakeCmd returns a 'hey' command.
func (h *Hey) MakeCmd(host string, port int) []string {
	c := h.Concurrency
	if c > h.Requests {
		c = h.Requests
	}
	return []string{
		"hey",
		"-n", fmt.Sprintf("%d", h.Requests),
		"-c", fmt.Sprintf("%d", c),
		fmt.Sprintf("http://%s:%d/%s", host, port, h.Doc),
	}
}

// Report parses output from 'hey' and reports metrics.
func (h *Hey) Report(b *testing.B, output string) {
	b.Helper()
	requests, err := h.parseRequestsPerSecond(output)
	if err != nil {
		b.Fatalf("failed to parse requests per second: %v", err)
	}
	ReportCustomMetric(b, requests, "requests_per_second" /*metric name*/, "QPS" /*unit*/)

	ave, err := h.parseAverageLatency(output)
	if err != nil {
		b.Fatalf("failed to parse average latency: %v", err)
	}
	ReportCustomMetric(b, ave, "average_latency" /*metric name*/, "s" /*unit*/)
}

var heyReqPerSecondRE = regexp.MustCompile(`Requests/sec:\s*(\d+\.?\d+?)\s+`)

// parseRequestsPerSecond finds requests per second from 'hey' output.
func (h *Hey) parseRequestsPerSecond(data string) (float64, error) {
	match := heyReqPerSecondRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var heyAverageLatencyRE = regexp.MustCompile(`Average:\s*(\d+\.?\d+?)\s+secs`)

// parseHeyAverageLatency finds Average Latency in seconds form 'hey' output.
func (h *Hey) parseAverageLatency(data string) (float64, error) {
	match := heyAverageLatencyRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get average latency match%d : %s", len(match), data)
	}
	return strconv.ParseFloat(match[1], 64)
}
