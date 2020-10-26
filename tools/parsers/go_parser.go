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
	suite := bigquery.NewSuite(name)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		bm, err := parseLine(line, official)
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
// *bigquery.Benchmark{
//	Name: BenchmarkRuby
//  []*bigquery.Condition{
//		{Name: GOMAXPROCS, 6}
//		{Name: server_threads, 1}
//  }
//  []*bigquery.Metric{
//		{Name: ns/op, Unit: ns/op, Sample: 1397875880}
//		{Name: requests_per_second, Unit: QPS, Sample: 140 }
//  }
//}
func parseLine(line string, official bool) (*bigquery.Benchmark, error) {
	fields := strings.Fields(line)

	// Check if this line is a Benchmark line. Otherwise ignore the line.
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "Benchmark") {
		return nil, nil
	}

	iters, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("expecting number of runs, got %s: %v", fields[1], err)
	}

	name, params, err := parseNameParams(fields[0])
	if err != nil {
		return nil, fmt.Errorf("parse name/params: %v", err)
	}

	bm := bigquery.NewBenchmark(name, iters, official)
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

// parseNameParams parses the Name, GOMAXPROCS, and Params from the test.
// Field here should be of the format TESTNAME/PARAMS-GOMAXPROCS.
// Parameters will be separated by a "/" with individual params being
// "name.value".
func parseNameParams(field string) (string, []*tools.Parameter, error) {
	var params []*tools.Parameter
	// Remove GOMAXPROCS from end.
	maxIndex := strings.LastIndex(field, "-")
	if maxIndex < 0 {
		return "", nil, fmt.Errorf("GOMAXPROCS not found: %s", field)
	}
	maxProcs := field[maxIndex+1:]
	params = append(params, &tools.Parameter{
		Name:  "GOMAXPROCS",
		Value: maxProcs,
	})

	remainder := field[0:maxIndex]
	index := strings.Index(remainder, "/")
	if index == -1 {
		return remainder, params, nil
	}

	name := remainder[0:index]
	p := remainder[index+1:]

	ps, err := tools.NameToParameters(p)
	if err != nil {
		return "", nil, fmt.Errorf("NameToParameters %s: %v", field, err)
	}
	params = append(params, ps...)
	return name, params, nil
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
