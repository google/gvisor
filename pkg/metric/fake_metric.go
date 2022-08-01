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

import pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"

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
func (m *FakeUint64Metric) Value(fieldValues ...string) uint64 {
	return 0
}

// Increment on a FakeUint64Metric does nothing.
//
//go:nosplit
func (m *FakeUint64Metric) Increment(fieldValues ...string) {}

// IncrementBy on a FakeUint64Metric does nothing.
//
//go:nosplit
func (m *FakeUint64Metric) IncrementBy(v uint64, fieldValues ...string) {}

// AddSample on a FakeUint64Metric does nothing.
//
//go:nosplit
func (d *FakeDistributionMetric) AddSample(sample int64, fields ...string) {}

// Start on a FakeUint64Metric returns a FakeTimedOperation struct, which does
// nothing and does not keep the time.
//
//go:nosplit
func (t *FakeTimerMetric) Start(fields ...string) FakeTimedOperation {
	return FakeTimedOperation{}
}

// Finish on a FakeTimedOperation does nothing.
//
//go:nosplit
func (o FakeTimedOperation) Finish(extraFields ...string) {}

// NewFakeUint64Metric is equivalent to NewUint64Metric except it creates a
// FakeUint64Metric
func NewFakeUint64Metric(name string, sync bool, units pb.MetricMetadata_Units, description string, fields ...Field) (*FakeUint64Metric, error) {
	return &FakeUint64Metric{}, nil
}

// MustCreateNewFakeUint64Metric is equivalent to MustCreateNewUint64Metric
// except it creates a FakeUint64Metric.
func MustCreateNewFakeUint64Metric(name string, sync bool, description string, fields ...Field) *FakeUint64Metric {
	return &FakeUint64Metric{}
}

// NewFakeDistributionMetric is equivalent to NewDistributionMetric except
// it creates a FakeDistributionMetric.
func NewFakeDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) (*FakeDistributionMetric, error) {
	return &FakeDistributionMetric{}, nil
}

// MustCreateNewFakeDistributionMetric is equivalent to
// MustCreateNewDistributionMetric except it creates a FakeDistributionMetric.
func MustCreateNewFakeDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) *FakeDistributionMetric {
	return &FakeDistributionMetric{}
}

// NewFakeTimerMetric is equivalent to NewTimerMetric except it creates a
// FakeTimerMetric.
func NewFakeTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) (*FakeTimerMetric, error) {
	return &FakeTimerMetric{}, nil
}

// MustCreateNewFakeTimerMetric is equivalent to MustCreateNewTimerMetric
// except it creates a FakeTimerMetric.
func MustCreateNewFakeTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) *FakeTimerMetric {
	return &FakeTimerMetric{}
}
