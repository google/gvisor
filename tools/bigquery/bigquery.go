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

// Package bigquery defines a BigQuery schema for benchmarks.
//
// This package contains a schema for BigQuery and methods for publishing
// benchmark data into tables.
package bigquery

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	bq "cloud.google.com/go/bigquery"
	"google.golang.org/api/option"
)

// Suite is the top level structure for a benchmark run. BigQuery
// will infer the schema from this.
type Suite struct {
	Name       string       `bq:"name"`
	Conditions []*Condition `bq:"conditions"`
	Benchmarks []*Benchmark `bq:"benchmarks"`
	Official   bool         `bq:"official"`
	Timestamp  time.Time    `bq:"timestamp"`
}

func (s *Suite) String() string {
	var sb strings.Builder
	s.debugString(&sb, "")
	return sb.String()
}

// writeLine writes a line of text to the given string builder with a prefix.
func writeLine(sb *strings.Builder, prefix string, format string, values ...any) {
	if prefix != "" {
		sb.WriteString(prefix)
	}
	sb.WriteString(fmt.Sprintf(format, values...))
	sb.WriteString("\n")
}

// debugString writes debug information to the given string builder with the
// given prefix.
func (s *Suite) debugString(sb *strings.Builder, prefix string) {
	writeLine(sb, prefix, "Benchmark suite %s:", s.Name)
	writeLine(sb, prefix, "Timestamp: %v", s.Timestamp)
	if !s.Official {
		writeLine(sb, prefix, " **** NOTE: Data is not official. **** ")
	}
	if numConditions := len(s.Conditions); numConditions == 0 {
		writeLine(sb, prefix, "Conditions: None.")
	} else {
		writeLine(sb, prefix, "Conditions (%d):", numConditions)
		for _, condition := range s.Conditions {
			condition.debugString(sb, prefix+"  ")
		}
	}
	if numBenchmarks := len(s.Benchmarks); numBenchmarks == 0 {
		writeLine(sb, prefix, "Benchmarks: None.")
	} else {
		writeLine(sb, prefix, "Benchmarks (%d):", numBenchmarks)
		for _, benchmark := range s.Benchmarks {
			benchmark.debugString(sb, prefix+"  ")
		}
	}
	sb.WriteString(fmt.Sprintf("End of data for benchmark suite %s.", s.Name))
}

// Benchstat returns a benchstat-formatted output string.
// See https://pkg.go.dev/golang.org/x/perf/cmd/benchstat
// `includeConditions` contains names of `Condition`s that should be included
// as part of the benchmark name.
func (s *Suite) Benchstat(includeConditions []string) string {
	var sb strings.Builder
	benchmarkNames := make([]string, 0, len(s.Benchmarks))
	benchmarks := make(map[string]*Benchmark, len(s.Benchmarks))
	for _, bm := range s.Benchmarks {
		if _, found := benchmarks[bm.Name]; !found {
			benchmarkNames = append(benchmarkNames, bm.Name)
			benchmarks[bm.Name] = bm
		}
	}
	sort.Strings(benchmarkNames)
	includeConditionsMap := make(map[string]bool, len(includeConditions))
	for _, condName := range includeConditions {
		includeConditionsMap[condName] = true
	}
	for _, bmName := range benchmarkNames {
		benchmarks[bmName].benchstat(&sb, s.Name, includeConditionsMap, s.Conditions)
	}
	return sb.String()
}

// Benchmark represents an individual benchmark in a suite.
type Benchmark struct {
	Name      string       `bq:"name"`
	Condition []*Condition `bq:"cond"`
	Metric    []*Metric    `bq:"metric"`
}

// String implements the String method for Benchmark
func (bm *Benchmark) String() string {
	var sb strings.Builder
	bm.debugString(&sb, "")
	return sb.String()
}

// debugString writes debug information to the given string builder with the
// given prefix.
func (bm *Benchmark) debugString(sb *strings.Builder, prefix string) {
	writeLine(sb, prefix, "Benchmark: %s", bm.Name)
	if numConditions := len(bm.Condition); numConditions == 0 {
		writeLine(sb, prefix, "  Conditions: None.")
	} else {
		writeLine(sb, prefix, "  Conditions (%d):", numConditions)
		for _, condition := range bm.Condition {
			condition.debugString(sb, prefix+"    ")
		}
	}
	if numMetrics := len(bm.Metric); numMetrics == 0 {
		writeLine(sb, prefix, "  Metrics: None.")
	} else {
		writeLine(sb, prefix, "  Metrics (%d):", numMetrics)
		for _, metric := range bm.Metric {
			metric.debugString(sb, prefix+"    ")
		}
	}
}

// noSpaceRe is used to remove whitespace characters in `noSpace`.
var noSpaceRe = regexp.MustCompile("\\s+")

// noSpace replaces whitespace characters from `s` with "_".
func noSpace(s string) string {
	return noSpaceRe.ReplaceAllString(s, "_")
}

// benchstat produces benchmark-formatted output for this Benchmark.
func (bm *Benchmark) benchstat(sb *strings.Builder, suiteName string, includeConditions map[string]bool, suiteConditions []*Condition) {
	var conditionsStr string
	conditionNames := make([]string, 0, len(suiteConditions)+len(bm.Condition))
	conditionMap := make(map[string]string, len(suiteConditions)+len(bm.Condition))
	for _, c := range suiteConditions {
		cName := noSpace(c.Name)
		if _, found := conditionMap[cName]; !found && includeConditions[cName] {
			conditionNames = append(conditionNames, cName)
			conditionMap[cName] = noSpace(c.Value)
		}
	}
	for _, c := range bm.Condition {
		cName := noSpace(c.Name)
		if _, found := conditionMap[cName]; !found && includeConditions[cName] {
			conditionNames = append(conditionNames, cName)
			conditionMap[cName] = noSpace(c.Value)
		}
	}
	sort.Strings(conditionNames)
	var conditionsBuilder strings.Builder
	if len(conditionNames) > 0 {
		conditionsBuilder.WriteByte('{')
		for i, condName := range conditionNames {
			if i != 0 {
				conditionsBuilder.WriteByte(',')
			}
			conditionsBuilder.WriteString(condName)
			conditionsBuilder.WriteByte('=')
			conditionsBuilder.WriteString(conditionMap[condName])
		}
		conditionsBuilder.WriteByte('}')
	}
	conditionsStr = conditionsBuilder.String()
	for _, m := range bm.Metric {
		if !strings.HasPrefix(suiteName, "Benchmark") {
			// benchstat format requires all benchmark names to start with "Benchmark".
			sb.WriteString("Benchmark")
		}
		sb.WriteString(noSpace(suiteName))
		if suiteName != bm.Name {
			sb.WriteByte('/')
			sb.WriteString(noSpace(bm.Name))
		}
		sb.WriteString(conditionsStr)
		sb.WriteByte('/')
		sb.WriteString(noSpace(m.Name))
		sb.WriteString(" 1 ") // 1 sample
		sb.WriteString(fmt.Sprintf("%f", m.Sample))
		sb.WriteByte(' ')
		sb.WriteString(noSpace(m.Unit))
		sb.WriteByte('\n')
	}
}

// AddMetric adds a metric to an existing Benchmark.
func (bm *Benchmark) AddMetric(metricName, unit string, sample float64) {
	m := &Metric{
		Name:   metricName,
		Unit:   unit,
		Sample: sample,
	}
	bm.Metric = append(bm.Metric, m)
}

// AddCondition adds a condition to an existing Benchmark.
func (bm *Benchmark) AddCondition(name, value string) {
	bm.Condition = append(bm.Condition, NewCondition(name, value))
}

// NewBenchmark initializes a new benchmark.
func NewBenchmark(name string, iters int) *Benchmark {
	return &Benchmark{
		Name:   name,
		Metric: make([]*Metric, 0),
		Condition: []*Condition{
			{
				Name:  "iterations",
				Value: strconv.Itoa(iters),
			},
		},
	}
}

// Condition represents qualifiers for the benchmark or suite. For example:
// Get_Pid/1/real_time would have Benchmark Name "Get_Pid" with "1"
// and "real_time" parameters as conditions. Suite conditions include
// information such as the CL number and platform name.
type Condition struct {
	Name  string `bq:"name"`
	Value string `bq:"value"`
}

// NewCondition returns a new Condition with the given name and value.
func NewCondition(name, value string) *Condition {
	return &Condition{
		Name:  name,
		Value: value,
	}
}

func (c *Condition) String() string {
	var sb strings.Builder
	c.debugString(&sb, "")
	return sb.String()
}

// debugString writes debug information to the given string builder with the
// given prefix.
func (c *Condition) debugString(sb *strings.Builder, prefix string) {
	writeLine(sb, prefix, "Condition: %s = %s", c.Name, c.Value)
}

// Metric holds the actual metric data and unit information for this benchmark.
type Metric struct {
	Name   string  `bq:"name"`
	Unit   string  `bq:"unit"`
	Sample float64 `bq:"sample"`
}

func (m *Metric) String() string {
	var sb strings.Builder
	m.debugString(&sb, "")
	return sb.String()
}

// debugString writes debug information to the given string builder with the
// given prefix.
func (m *Metric) debugString(sb *strings.Builder, prefix string) {
	writeLine(sb, prefix, "Metric %s: %f %s", m.Name, m.Sample, m.Unit)
}

// InitBigQuery initializes a BigQuery dataset/table in the project. If the dataset/table already exists, it is not duplicated.
func InitBigQuery(ctx context.Context, projectID, datasetID, tableID string, opts []option.ClientOption) error {
	client, err := bq.NewClient(ctx, projectID, opts...)
	if err != nil {
		return fmt.Errorf("failed to initialize client on project %s: %v", projectID, err)
	}
	defer client.Close()

	dataset := client.Dataset(datasetID)
	if err := dataset.Create(ctx, nil); err != nil && !checkDuplicateError(err) {
		return fmt.Errorf("failed to create dataset: %s: %v", datasetID, err)
	}

	table := dataset.Table(tableID)
	schema, err := bq.InferSchema(Suite{})
	if err != nil {
		return fmt.Errorf("failed to infer schema: %v", err)
	}

	if err := table.Create(ctx, &bq.TableMetadata{Schema: schema}); err != nil && !checkDuplicateError(err) {
		return fmt.Errorf("failed to create table: %s: %v", tableID, err)
	}
	return nil
}

// NewBenchmarkWithMetric creates a new sending to BigQuery, initialized with a
// single iteration and single metric.
func NewBenchmarkWithMetric(name, metric, unit string, value float64) *Benchmark {
	b := NewBenchmark(name, 1)
	b.AddMetric(metric, unit, value)
	return b
}

// NewSuite initializes a new Suite.
func NewSuite(name string, official bool) *Suite {
	return &Suite{
		Name:       name,
		Timestamp:  time.Now().UTC(),
		Benchmarks: make([]*Benchmark, 0),
		Conditions: make([]*Condition, 0),
		Official:   official,
	}
}

// SendBenchmarks sends the slice of benchmarks to the BigQuery dataset/table.
func SendBenchmarks(ctx context.Context, suite *Suite, projectID, datasetID, tableID string, opts []option.ClientOption) error {
	client, err := bq.NewClient(ctx, projectID, opts...)
	if err != nil {
		return fmt.Errorf("failed to initialize client on project: %s: %v", projectID, err)
	}
	defer client.Close()

	uploader := client.Dataset(datasetID).Table(tableID).Uploader()
	if err = uploader.Put(ctx, suite); err != nil {
		return fmt.Errorf("failed to upload benchmarks %s to project %s, table %s.%s: %v", suite.Name, projectID, datasetID, tableID, err)
	}

	return nil
}

// BigQuery will error "409" for duplicate tables and datasets.
func checkDuplicateError(err error) bool {
	return strings.Contains(err.Error(), "googleapi: Error 409: Already Exists")
}
