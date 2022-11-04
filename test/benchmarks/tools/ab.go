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

// ApacheBench is for the client application ApacheBench.
type ApacheBench struct {
	Requests    int
	Concurrency int
	Doc         string
	// TODO(zkoopmans): support KeepAlive and pass option to enable.
}

// MakeCmd makes an ApacheBench command.
func (a *ApacheBench) MakeCmd(host string, port int) []string {
	path := fmt.Sprintf("http://%s:%d/%s", host, port, a.Doc)
	// See apachebench (ab) for flags.
	cmd := fmt.Sprintf("ab -n %d -c %d %s", a.Requests, a.Concurrency, path)
	return []string{"sh", "-c", cmd}
}

// Report parses and reports metrics from ApacheBench output.
func (a *ApacheBench) Report(b *testing.B, output string) {
	// Parse and report custom metrics.
	transferRate, err := a.parseTransferRate(output)
	if err != nil {
		b.Logf("failed to parse transferrate: %v", err)
	}
	b.ReportMetric(transferRate*1024, "transfer_rate_b/s") // Convert from Kb/s to b/s.
	ReportCustomMetric(b, transferRate*1024, "transfer_rate" /*metric name*/, "bytes_per_second" /*unit*/)

	latency, err := a.parseLatency(output)
	if err != nil {
		b.Logf("failed to parse latency: %v", err)
	}
	b.ReportMetric(latency/1000, "mean_latency_secs") // Convert from ms to s.
	ReportCustomMetric(b, latency/1000, "mean_latency" /*metric name*/, "s" /*unit*/)

	reqPerSecond, err := a.parseRequestsPerSecond(output)
	if err != nil {
		b.Logf("failed to parse requests per second: %v", err)
	}
	b.ReportMetric(reqPerSecond, "requests_per_second")
	ReportCustomMetric(b, reqPerSecond, "requests_per_second" /*metric name*/, "QPS" /*unit*/)
}

var transferRateRE = regexp.MustCompile(`Transfer rate:\s+(\d+\.?\d+?)\s+\[Kbytes/sec\]\s+received`)

// parseTransferRate parses transfer rate from ApacheBench output.
func (a *ApacheBench) parseTransferRate(data string) (float64, error) {
	match := transferRateRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var latencyRE = regexp.MustCompile(`Total:\s+\d+\s+(\d+)\s+(\d+\.?\d+?)\s+\d+\s+\d+\s`)

// parseLatency parses latency from ApacheBench output.
func (a *ApacheBench) parseLatency(data string) (float64, error) {
	match := latencyRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var requestsPerSecondRE = regexp.MustCompile(`Requests per second:\s+(\d+\.?\d+?)\s+`)

// parseRequestsPerSecond parses requests per second from ApacheBench output.
func (a *ApacheBench) parseRequestsPerSecond(data string) (float64, error) {
	match := requestsPerSecondRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}
