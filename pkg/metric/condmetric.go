// Copyright 2022 The gVisor Authors.
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

package metric

import (
	"fmt"

	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

// FakeUint64Metric is a type that implements all the methods of a Uint64Metric
// as a no-op.
type FakeUint64Metric struct{}

// FakeDistributionMetric is a type that implements all the methods of a
// DistributionMetric as a no-op.
type FakeDistributionMetric struct{}

// FakeTimerMetric is a type that implements all the methods of a TimerMetric
// as a no-op.
type FakeTimerMetric struct{}

// FakeTimedOperation is a type that implements all the methods of a
// TimedOperation as a no-op.
type FakeTimedOperation struct{}

// Value from a FakeUint64Metric always returns a meaningless value.
//
//go:nosplit
func (m *FakeUint64Metric) Value(fieldValues ...*FieldValue) uint64 {
	return 0
}

// Increment on a FakeUint64Metric does nothing.
//
//go:nosplit
func (m *FakeUint64Metric) Increment(fieldValues ...*FieldValue) {}

// Decrement on a FakeUint64Metric does nothing.
//
//go:nosplit
func (m *FakeUint64Metric) Decrement(fieldValues ...*FieldValue) {}

// IncrementBy on a FakeUint64Metric does nothing.
//
//go:nosplit
func (m *FakeUint64Metric) IncrementBy(v uint64, fieldValues ...*FieldValue) {}

// Set on a FakeUint64Metric does nothing.
//
//go:nosplit
func (m *FakeUint64Metric) Set(v uint64, fieldValues ...*FieldValue) {}

// AddSample on a FakeUint64Metric does nothing.
//
//go:nosplit
func (d *FakeDistributionMetric) AddSample(sample int64, fields ...*FieldValue) {}

// Start on a FakeUint64Metric returns a FakeTimedOperation struct, which does
// nothing and does not keep the time.
//
//go:nosplit
func (t *FakeTimerMetric) Start(fields ...*FieldValue) FakeTimedOperation {
	return FakeTimedOperation{}
}

// Finish on a FakeTimedOperation does nothing.
//
//go:nosplit
func (o FakeTimedOperation) Finish(extraFields ...*FieldValue) {}

// FakeMetricBuilder is a type used to produce conditionally compiled metrics.
// Methods of this struct produce fake, inactive metrics.
type FakeMetricBuilder struct{}

// NewUint64Metric creates a fake Uint64 metric.
func (b *FakeMetricBuilder) NewUint64Metric(name string, metadata Uint64Metadata) (*FakeUint64Metric, error) {
	return &FakeUint64Metric{}, nil
}

// MustCreateNewUint64Metric creates a fake Uint64 metric.
func (b *FakeMetricBuilder) MustCreateNewUint64Metric(name string, metadata Uint64Metadata) *FakeUint64Metric {
	return &FakeUint64Metric{}
}

// NewDistributionMetric creates a fake distribution metric.
func (b *FakeMetricBuilder) NewDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) (*FakeDistributionMetric, error) {
	return &FakeDistributionMetric{}, nil
}

// MustCreateNewDistributionMetric creates a fake distribution metric.
func (b *FakeMetricBuilder) MustCreateNewDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) *FakeDistributionMetric {
	return &FakeDistributionMetric{}
}

// NewTimerMetric creates a fake timer metric.
func (b *FakeMetricBuilder) NewTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) (*FakeTimerMetric, error) {
	return &FakeTimerMetric{}, nil
}

// MustCreateNewTimerMetric creates a fake timer metric.
func (b *FakeMetricBuilder) MustCreateNewTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) *FakeTimerMetric {
	return &FakeTimerMetric{}
}

// RealMetricBuilder is a type used to produce conditionally compiled metrics.
// Methods of this struct produce real active metrics.
type RealMetricBuilder struct{}

// NewUint64Metric calls the generic metric.NewUint64Metric to produce a real
// Uint64 metric.
func (b *RealMetricBuilder) NewUint64Metric(name string, metadata Uint64Metadata) (*Uint64Metric, error) {
	m, err := NewUint64Metric(name, metadata)
	if err != nil {
		return m, err
	}
	definedProfilingMetrics = append(definedProfilingMetrics, m.name)
	return m, err
}

// MustCreateNewUint64Metric creates a real Uint64 metric or panics if unable to
// do so.
func (b *RealMetricBuilder) MustCreateNewUint64Metric(name string, metadata Uint64Metadata) *Uint64Metric {
	m, err := b.NewUint64Metric(name, metadata)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %s", name, err))
	}
	return m
}

// NewDistributionMetric calls the generic metric.NewDistributionMetric to
// produce a real distribution metric.
func (b *RealMetricBuilder) NewDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) (*DistributionMetric, error) {
	return NewDistributionMetric(name, sync, bucketer, unit, description, fields...)
}

// MustCreateNewDistributionMetric creates a real distribution metric or panics
// if unable to do so.
func (b *RealMetricBuilder) MustCreateNewDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) *DistributionMetric {
	return MustCreateNewDistributionMetric(name, sync, bucketer, unit, description, fields...)
}

// NewTimerMetric calls the generic metric.NewTimerMetric to produce a real timer
// metric.
func (b *RealMetricBuilder) NewTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) (*TimerMetric, error) {
	return NewTimerMetric(name, nanoBucketer, description, fields...)
}

// MustCreateNewTimerMetric creates a real timer metric or panics if unable to
// do so.
func (b *RealMetricBuilder) MustCreateNewTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) *TimerMetric {
	return MustCreateNewTimerMetric(name, nanoBucketer, description, fields...)
}
