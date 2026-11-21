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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"testing"
)

// Quote latency so Hey's NaN when all requests fail remains valid JSON.
const heyOutputTemplate = `{
  "requests_per_second": {{.Rps}},
  "average_latency_seconds": "{{.Average}}",
  "errors": {{jsonify .ErrorDist}}
}`

type heyReport struct {
	RequestsPerSecond float64        `json:"requests_per_second"`
	AverageLatency    *float64       `json:"average_latency_seconds,string"`
	Errors            map[string]int `json:"errors"`
}

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
		"-o", heyOutputTemplate,
		"-n", fmt.Sprintf("%d", h.Requests),
		"-c", fmt.Sprintf("%d", c),
		fmt.Sprintf("http://%s:%d/%s", host, port, h.Doc),
	}
}

// Report reports metrics from the output of heyOutputTemplate.
func (h *Hey) Report(b *testing.B, output []byte) {
	b.Helper()
	var report heyReport
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		b.Fatalf("failed to parse hey output: %v\n%s", err, output)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		b.Fatalf("unexpected trailing hey output: %s", output)
	}
	if report.Errors == nil || len(report.Errors) != 0 {
		b.Fatalf("hey request error accounting is missing or reports errors: %s", output)
	}
	if report.RequestsPerSecond <= 0 {
		b.Fatalf("invalid hey request rate: %v", report.RequestsPerSecond)
	}
	if report.AverageLatency == nil || *report.AverageLatency < 0 || math.IsNaN(*report.AverageLatency) || math.IsInf(*report.AverageLatency, 0) {
		b.Fatalf("invalid hey average latency in output: %s", output)
	}
	ReportCustomMetric(b, report.RequestsPerSecond, "requests_per_second" /*metric name*/, "QPS" /*unit*/)
	ReportCustomMetric(b, *report.AverageLatency, "average_latency" /*metric name*/, "s" /*unit*/)
}
