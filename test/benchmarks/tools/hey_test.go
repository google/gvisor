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

import "testing"

// Hey exits successfully even when some requests fail. Valid statistics in that
// report must not become benchmark metrics.
func TestHeyRequestErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		output      []byte
		wantFailure bool
		wantQPS     float64
		wantAverage float64
	}{
		{name: "success", output: []byte(`{
  "requests_per_second":1748.6965652976414,
  "average_latency_seconds":"0.0010728662499999999",
  "errors":{}
}`), wantQPS: 1748.6965652976414, wantAverage: 0.0010728662499999999},
		{name: "partialFailure", output: []byte(`{
  "requests_per_second":1.9987641301593322,
  "average_latency_seconds":"0.0007179025",
  "errors":{"Get \"http://127.0.0.1:34035/mixed\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)":2}
}`), wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failed := false
			result := testing.Benchmark(func(b *testing.B) {
				b.StopTimer()
				defer func() { failed = b.Failed() }()
				hey := Hey{}
				hey.Report(b, tc.output)
			})
			if failed != tc.wantFailure {
				t.Fatalf("Report failed: got %t, want %t", failed, tc.wantFailure)
			}
			if failed {
				if len(result.Extra) != 0 {
					t.Fatalf("Report emitted metrics for failed requests: %v", result.Extra)
				}
			} else {
				if got := result.Extra["requests_per_second.QPS"]; got != tc.wantQPS {
					t.Errorf("requests per second: got %g, want %g", got, tc.wantQPS)
				}
				if got := result.Extra["average_latency.s"]; got != tc.wantAverage {
					t.Errorf("average latency: got %g, want %g", got, tc.wantAverage)
				}
			}
		})
	}
}
