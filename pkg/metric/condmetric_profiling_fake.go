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

//go:build !condmetric_profiling
// +build !condmetric_profiling

package metric

// ProfilingUint64Metric is a metric type that is registered and used only when
// the "condmetric_profiling" go tag is specified when building runsc.
//
// Otherwise it is exactly like a Uint64Metric.
type ProfilingUint64Metric = FakeUint64Metric

// ProfilingDistributionMetric is a metric type that is registered and used only
// when the "condmetric_profiling" go tag is specified when building runsc.
//
// Otherwise it is exactly like a DistributionMetric.
type ProfilingDistributionMetric = FakeDistributionMetric

// ProfilingTimerMetric is a metric type that is registered and used only when
// the "condmetric_profiling" go tag is specified when building runsc.
//
// Otherwise it is exactly like a TimerMetric.
type ProfilingTimerMetric = FakeTimerMetric

// NewProfilingUint64Metric is equivalent to NewUint64Metric except it creates a
// ProfilingUint64Metric
var NewProfilingUint64Metric = NewFakeUint64Metric

// MustCreateNewProfilingUint64Metric is equivalent to MustCreateNewUint64Metric
// except it creates a ProfilingUint64Metric.
var MustCreateNewProfilingUint64Metric = MustCreateNewFakeUint64Metric

// NewProfilingDistributionMetric is equivalent to NewDistributionMetric except
// it creates a ProfilingDistributionMetric.
var NewProfilingDistributionMetric = NewFakeDistributionMetric

// MustCreateNewProfilingDistributionMetric is equivalent to
// MustCreateNewDistributionMetric except it creates a
// ProfilingDistributionMetric.
var MustCreateNewProfilingDistributionMetric = MustCreateNewFakeDistributionMetric

// NewProfilingTimerMetric is equivalent to NewTimerMetric except it creates a
// ProfilingTimerMetric.
var NewProfilingTimerMetric = NewFakeTimerMetric

// MustCreateNewProfilingTimerMetric is equivalent to MustCreateNewTimerMetric
// except it creates a ProfilingTimerMetric.
var MustCreateNewProfilingTimerMetric = MustCreateNewFakeTimerMetric
