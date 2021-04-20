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

// Benchmark represents an individual benchmark in a suite.
type Benchmark struct {
	Name      string       `bq:"name"`
	Condition []*Condition `bq:"condition"`
	Metric    []*Metric    `bq:"metric"`
}

// Condition represents qualifiers for the benchmark or suite. For example:
// Get_Pid/1/real_time would have Benchmark Name "Get_Pid" with "1"
// and "real_time" parameters as conditions. Suite conditions include
// information such as the CL number and platform name.
type Condition struct {
	Name  string `bq:"name"`
	Value string `bq:"value"`
}

// Metric holds the actual metric data and unit information for this benchmark.
type Metric struct {
	Name   string  `bq:"name"`
	Unit   string  `bq:"unit"`
	Sample float64 `bq:"sample"`
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

// AddCondition adds a condition to an existing Benchmark.
func (bm *Benchmark) AddCondition(name, value string) {
	bm.Condition = append(bm.Condition, &Condition{
		Name:  name,
		Value: value,
	})
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
