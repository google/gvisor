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

package parsers

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/tools/bigquery"
)

func TestParseLine(t *testing.T) {
	testCases := []struct {
		name string
		data string
		want *bigquery.Benchmark
	}{
		{
			name: "Iperf",
			data: "BenchmarkIperf/Upload-6 1	11094914892 ns/op	4751711232 bandwidth.bytes_per_second",
			want: &bigquery.Benchmark{
				Name: "BenchmarkIperf",
				Condition: []*bigquery.Condition{
					{
						Name:  "iterations",
						Value: "1",
					},
					{
						Name:  "GOMAXPROCS",
						Value: "6",
					},
					{
						Name:  "Upload",
						Value: "Upload",
					},
				},
				Metric: []*bigquery.Metric{
					{
						Name:   "ns/op",
						Unit:   "ns/op",
						Sample: 11094914892.0,
					},
					{
						Name:   "bandwidth",
						Unit:   "bytes_per_second",
						Sample: 4751711232.0,
					},
				},
			},
		},
		{
			name: "Ruby",
			data: "BenchmarkRuby/server_threads.1-6 1	1397875880 ns/op	0.00710 average_latency.s 140 requests_per_second.QPS",
			want: &bigquery.Benchmark{
				Name: "BenchmarkRuby",
				Condition: []*bigquery.Condition{
					{
						Name:  "iterations",
						Value: "1",
					},
					{
						Name:  "GOMAXPROCS",
						Value: "6",
					},
					{
						Name:  "server_threads",
						Value: "1",
					},
				},
				Metric: []*bigquery.Metric{
					{
						Name:   "ns/op",
						Unit:   "ns/op",
						Sample: 1397875880.0,
					},
					{
						Name:   "average_latency",
						Unit:   "s",
						Sample: 0.00710,
					},
					{
						Name:   "requests_per_second",
						Unit:   "QPS",
						Sample: 140.0,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLine(tc.data)
			if err != nil {
				t.Fatalf("parseLine failed with: %v", err)
			}

			if !cmp.Equal(tc.want, got, nil) {
				for i := range got.Condition {
					t.Logf("Metric: want: %+v got:%+v", got.Condition[i], tc.want.Condition[i])
				}

				for i := range got.Metric {
					t.Logf("Metric: want: %+v got:%+v", got.Metric[i], tc.want.Metric[i])
				}

				t.Fatalf("Compare failed want: %+v got: %+v", tc.want, got)
			}
		})

	}
}

func TestParseOutput(t *testing.T) {
	testCases := []struct {
		name          string
		data          string
		numBenchmarks int
		numMetrics    int
		numConditions int
	}{
		{
			name: "Startup",
			data: `
				BenchmarkStartupEmpty
				BenchmarkStartupEmpty-6                2         766377884 ns/op	1 allocs/op
				BenchmarkStartupNode
				BenchmarkStartupNode-6                 1        1752158409 ns/op	1 allocs/op
			`,
			numBenchmarks: 2,
			numMetrics:    1,
			numConditions: 2,
		},
		{
			name: "Ruby",
			data: `BenchmarkRuby
BenchmarkRuby/server_threads.1
BenchmarkRuby/server_threads.1-6 1	1397875880 ns/op 0.00710 average_latency.s 140 requests_per_second.QPS
BenchmarkRuby/server_threads.5
BenchmarkRuby/server_threads.5-6 1	1416003331 ns/op	0.00950 average_latency.s 465 requests_per_second.QPS`,
			numBenchmarks: 2,
			numMetrics:    3,
			numConditions: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite, err := ParseOutput(tc.data, "", false)
			if err != nil {
				t.Fatalf("parseOutput failed: %v", err)
			} else if len(suite.Benchmarks) != tc.numBenchmarks {
				t.Fatalf("NumBenchmarks failed want: %d got: %d %+v", tc.numBenchmarks, len(suite.Benchmarks), suite.Benchmarks)
			}

			for _, bm := range suite.Benchmarks {
				if len(bm.Metric) != tc.numMetrics {
					t.Fatalf("NumMetrics failed want: %d got: %d %+v", tc.numMetrics, len(bm.Metric), bm.Metric)
				}

				if len(bm.Condition) != tc.numConditions {
					t.Fatalf("NumConditions failed want: %d got: %d %+v", tc.numConditions, len(bm.Condition), bm.Condition)
				}
			}
		})
	}
}
