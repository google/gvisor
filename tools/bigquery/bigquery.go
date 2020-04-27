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
	"strings"
	"time"

	bq "cloud.google.com/go/bigquery"
)

// Benchmark is the top level structure of recorded benchmark data. BigQuery
// will infer the schema from this.
type Benchmark struct {
	Name      string    `bq:"name"`
	Timestamp time.Time `bq:"timestamp"`
	Official  bool      `bq:"official"`
	Metric    []*Metric `bq:"metric"`
	Metadata  *Metadata `bq:"metadata"`
}

// Metric holds the actual metric data and unit information for this benchmark.
type Metric struct {
	Name   string  `bq:"name"`
	Unit   string  `bq:"unit"`
	Sample float64 `bq:"sample"`
}

// Metadata about this benchmark.
type Metadata struct {
	CL          string `bq:"changelist"`
	IterationID string `bq:"iteration_id"`
	PendingCL   string `bq:"pending_cl"`
	Workflow    string `bq:"workflow"`
	Platform    string `bq:"platform"`
	Gofer       string `bq:"gofer"`
}

// InitBigQuery initializes a BigQuery dataset/table in the project. If the dataset/table already exists, it is not duplicated.
func InitBigQuery(ctx context.Context, projectID, datasetID, tableID string) error {
	client, err := bq.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to initialize client on project %s: %v", projectID, err)
	}
	defer client.Close()

	dataset := client.Dataset(datasetID)
	if err := dataset.Create(ctx, nil); err != nil && !checkDuplicateError(err) {
		return fmt.Errorf("failed to create dataset: %s: %v", datasetID, err)
	}

	table := dataset.Table(tableID)
	schema, err := bq.InferSchema(Benchmark{})
	if err != nil {
		return fmt.Errorf("failed to infer schema: %v", err)
	}

	if err := table.Create(ctx, &bq.TableMetadata{Schema: schema}); err != nil && !checkDuplicateError(err) {
		return fmt.Errorf("failed to create table: %s: %v", tableID, err)
	}
	return nil
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
func NewBenchmark(name string, official bool) *Benchmark {
	return &Benchmark{
		Name:      name,
		Timestamp: time.Now().UTC(),
		Official:  official,
		Metric:    make([]*Metric, 0),
	}
}

// SendBenchmarks sends the slice of benchmarks to the BigQuery dataset/table.
func SendBenchmarks(ctx context.Context, benchmarks []*Benchmark, projectID, datasetID, tableID string) error {
	client, err := bq.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("Failed to initialize client on project: %s: %v", projectID, err)
	}
	defer client.Close()

	uploader := client.Dataset(datasetID).Table(tableID).Uploader()
	if err = uploader.Put(ctx, benchmarks); err != nil {
		return fmt.Errorf("failed to upload benchmarks to proejct %s, table %s.%s: %v", projectID, datasetID, tableID, err)
	}

	return nil
}

// BigQuery will error "409" for duplicate tables and datasets.
func checkDuplicateError(err error) bool {
	return strings.Contains(err.Error(), "googleapi: Error 409: Already Exists")
}
