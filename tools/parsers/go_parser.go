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

// Package parsers holds parsers to parse Benchmark test output.
//
// Parsers parse Benchmark test output and place it in BigQuery
// structs for sending to BigQuery databases.
package parsers

import (
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/test/benchmarks/tools"
	"gvisor.dev/gvisor/tools/bigquery"
)

// ParseOutput expects golang benchmark output and returns a struct formatted
// for BigQuery.
func ParseOutput(output string, name string, official bool) (*bigquery.Suite, error) {
	suite := bigquery.NewSuite(name, official)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		bm, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse line '%s': %v", line, err)
		}
		if bm != nil {
			suite.Benchmarks = append(suite.Benchmarks, bm)
		}
	}
	return suite, nil
}

// parseLine handles parsing a benchmark line into a bigquery.Benchmark.
//
// Example: "BenchmarkRuby/server_threads.1-6 1	1397875880 ns/op 140 requests_per_second.QPS"
//
// This function will return the following benchmark:
//
//		*bigquery.Benchmark{
//			Name: BenchmarkRuby
//		 []*bigquery.Condition{
//				{Name: server_threads, 1}
//				{Name: GOMAXPROCS, 6}
//		 }
//		 []*bigquery.Metric{
//				{Name: ns/op, Unit: ns/op, Sample: 1397875880}
//				{Name: requests_per_second, Unit: QPS, Sample: 140 }
//		 }
//	 }
func parseLine(line string) (*bigquery.Benchmark, error) {
	fields := strings.Fields(line)

	// Check if this line is a Benchmark line. Otherwise ignore the line.
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "Benchmark") {
		return nil, nil
	}

	iters, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("expecting number of runs, got %s: %v", fields[1], err)
	}

	nameComponents, params, err := tools.NameToParameters(fields[0])
	if err != nil {
		return nil, fmt.Errorf("parse name/params: %v", err)
	}

	// Treat the first name component as the benchmark name, and all other
	// components as conditions with key = value.
	bm := bigquery.NewBenchmark(nameComponents[0], iters)
	for _, c := range nameComponents[1:] {
		bm.AddCondition(c, c)
	}
	for _, p := range params {
		bm.AddCondition(p.Name, p.Value)
	}

	for i := 1; i < len(fields)/2; i++ {
		value := fields[2*i]
		metric := fields[2*i+1]
		if err := makeMetric(bm, value, metric); err != nil {
			return nil, fmt.Errorf("makeMetric on metric %q value: %s: %v", metric, value, err)
		}
	}
	return bm, nil
}

// makeMetric parses metrics and adds them to the passed Benchmark.
func makeMetric(bm *bigquery.Benchmark, value, metric string) error {
	switch metric {
	// Ignore most output from golang benchmarks.
	case "MB/s", "B/op", "allocs/op":
		return nil
	case "ns/op":
		val, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("ParseFloat %s: %v", value, err)
		}
		bm.AddMetric(metric /*metric name*/, metric /*unit*/, val /*sample*/)
	default:
		m, err := tools.ParseCustomMetric(value, metric)
		if err != nil {
			return fmt.Errorf("ParseCustomMetric %s: %v ", metric, err)
		}
		bm.AddMetric(m.Name, m.Unit, m.Sample)
	}
	return nil
}
