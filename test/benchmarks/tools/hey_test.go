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

// TestHey checks the Hey parsers on sample output.
func TestHey(t *testing.T) {
	sampleData := `
	Summary:
          Total:	2.2391 secs
          Slowest:	1.6292 secs
          Fastest:	0.0066 secs
          Average:	0.5351 secs
          Requests/sec:	89.3202

          Total data:	841200 bytes
          Size/request:	4206 bytes

        Response time histogram:
          0.007 [1]	|
          0.169 [0]	|
          0.331 [149]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
          0.493 [0]	|
          0.656 [0]	|
          0.818 [0]	|
          0.980 [0]	|
          1.142 [0]	|
          1.305 [0]	|
          1.467 [49]	|■■■■■■■■■■■■■
          1.629 [1]	|


        Latency distribution:
          10% in 0.2149 secs
          25% in 0.2449 secs
          50% in 0.2703 secs
          75% in 1.3315 secs
          90% in 1.4045 secs
          95% in 1.4232 secs
          99% in 1.4362 secs

        Details (average, fastest, slowest):
          DNS+dialup:	0.0002 secs, 0.0066 secs, 1.6292 secs
          DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
          req write:	0.0000 secs, 0.0000 secs, 0.0012 secs
          resp wait:	0.5225 secs, 0.0064 secs, 1.4346 secs
          resp read:	0.0122 secs, 0.0001 secs, 0.2006 secs

        Status code distribution:
          [200]	200 responses
	`
	hey := Hey{}
	want := 89.3202
	got, err := hey.parseRequestsPerSecond(sampleData)
	if err != nil {
		t.Fatalf("failed to parse request per second with: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	want = 0.5351
	got, err = hey.parseAverageLatency(sampleData)
	if err != nil {
		t.Fatalf("failed to parse average latency with: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}
}
