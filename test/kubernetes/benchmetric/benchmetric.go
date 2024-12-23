// Copyright 2024 The gVisor Authors.
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

// Package benchmetric provides utilities for benchmark metrics.
// This includes printing benchstat-formatted metrics and measuring container
// timing.
package benchmetric

import (
	"context"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"
)

// MetricValue represents an individual metric value.
type MetricValue interface {
	// ToBenchstat formats a metric value according to golang's benchmark format.
	ToBenchstat() string
}

// metricValue is an individual metric value.
// It implements `MetricValue`.
type metricValue struct {
	// value is value printed for this metric.
	// *testing.B expects a float64, so we use the same.
	value float64
	// unit is for storing information about the metric.
	unit string
}

// ToBenchstat implements `MetricValue.ToBenchstat`.
func (m *metricValue) ToBenchstat() string {
	return fmt.Sprintf("%f\t%s", m.value, m.unit)
}

// String returns a human-friendly string representation.
func (m *metricValue) String() string {
	return m.ToBenchstat()
}

// value is a constructor for `MetricValue`.
// It panics when given non-idiomatic unit names.
// See https://golang.org/design/14313-benchmark-format and
// https://pkg.go.dev/golang.org/x/perf/cmd/benchstat.
//
//   - All durations must be in "sec" or "ns".
//   - If there is a duration, it must be the last component.
//   - Valid unit separators are dashes and slashes only.
//   - The bandwidth unit must be "B" which means bytes.
//
// Benchmarks are expected to use more specific helpers below that
// add additional unit naming constraints.
func value(v float64, unit string) MetricValue {
	lowercaseUnit := strings.ToLower(unit)
	switch {
	case strings.Contains(unit, "_"):
		panic(fmt.Sprintf("unit names must not contain underscores; use dashes instead: %q", unit))
	case strings.Contains(lowercaseUnit, "byte") || strings.Contains(lowercaseUnit, "bit"):
		panic("do not use 'bytes' or 'bits' as unit, or any larger unit like kilobyte/megabyte; use 'B' for bytes")
	case strings.Contains(lowercaseUnit, "kb") || strings.Contains(lowercaseUnit, "kib") || strings.Contains(lowercaseUnit, "mb") || strings.Contains(lowercaseUnit, "mib") || strings.Contains(lowercaseUnit, "gb") || strings.Contains(lowercaseUnit, "gib"):
		panic("do not use KB/KiB/MB/MiB/GB/GiB; instead use 'B' for bytes")
	case strings.Contains(lowercaseUnit, "ms") || strings.Contains(lowercaseUnit, "us") || strings.Contains(lowercaseUnit, "μs") || strings.Contains(lowercaseUnit, "usec") || strings.Contains(lowercaseUnit, "milli") || strings.Contains(lowercaseUnit, "micro"):
		panic("use either 'ns' or 'sec' as basic time unit, not milliseconds nor microseconds")
	case strings.HasSuffix(lowercaseUnit, "-s") || strings.HasSuffix(lowercaseUnit, "s") || strings.Contains(lowercaseUnit, "second"):
		panic("use either 'ns' or 'sec' as basic time unit, not 's' or 'second'")
	case lowercaseUnit == "qps" || lowercaseUnit == "rps" || lowercaseUnit == "tps":
		panic("use 'req/sec' instead of 'qps'/'rps'/'tps' as a unit name")
	case strings.HasSuffix(lowercaseUnit, "ps") && lowercaseUnit != "ops":
		panic("use 'something/sec' instead of 'ps' as a unit suffix for 'per second'")
	default:
		// Nothing.
	}
	return &metricValue{
		value: v,
		unit:  unit,
	}
}

// BenchmarkDuration is a MetricValue for a benchmark's overall duration.
func BenchmarkDuration(duration time.Duration) MetricValue {
	return value(duration.Seconds(), "sec")
}

// RequestsPerSecond is a MetricValue for requests per second.
func RequestsPerSecond(rps float64) MetricValue {
	return Rate(rps, "req")
}

// BytesPerSecond is a MetricValue for bandwidth.
func BytesPerSecond(bytesPerSecond float64) MetricValue {
	return Rate(bytesPerSecond, "B")
}

// Rate is a MetricValue representing a rate of events happening.
// The rate must be given in per-second terms.
func Rate(perSecond float64, event string) MetricValue {
	if strings.HasSuffix(event, "/sec") || strings.HasSuffix(event, "/ns") || strings.HasSuffix(event, "/s") {
		panic("please do not specify a time unit")
	}
	return value(perSecond, fmt.Sprintf("%s/sec", event))
}

// SpecificDuration is a MetricValue for the duration of a specific subset
// of a benchmark.
// Do not specify a time unit in `subset` or the function will panic.
func SpecificDuration(duration time.Duration, subset string) MetricValue {
	if subset == "" {
		panic("must specify `subset`")
	}
	if strings.HasSuffix(subset, "-sec") || strings.HasSuffix(subset, "-ns") || strings.HasSuffix(subset, "-s") {
		panic("please do not specify a time unit")
	}
	return value(duration.Seconds(), fmt.Sprintf("%s-sec", subset))
}

// SpecificBytes is a MetricValue for an absolute number of bytes.
// Do not specify the "byte" or "B" prefix in `subset` or the function will
// panic.
func SpecificBytes(bytes float64, subset string) MetricValue {
	if subset == "" {
		panic("must specify `subset`")
	}
	if strings.HasSuffix(subset, "B") || strings.HasSuffix(subset, "byte") {
		panic("please do not specify a byte unit")
	}
	return value(bytes, fmt.Sprintf("%s-B", subset))
}

// Count is a MetricValue for a quantity counted by a benchmark.
func Count(numberOfTimes uint64, thingBeingCounted string) MetricValue {
	if strings.Contains(thingBeingCounted, "/") {
		panic("use `Rate` for rates, not `Count`")
	}
	if !strings.HasSuffix(thingBeingCounted, "s") {
		panic("`thingBeingCounted` must be plural")
	}
	return value(float64(numberOfTimes), fmt.Sprintf("%s-num", thingBeingCounted))
}

// Checksum is a MetricValue for a checksum that is not expected to change
// over iterations or variants of the benchmark.
func Checksum(h hash.Hash32, thingBeingChecksummed string) MetricValue {
	if strings.Contains(thingBeingChecksummed, "hash") || strings.Contains(thingBeingChecksummed, "checksum") {
		panic("`thingBeingChecksummed` must not contain 'hash' or 'checksum'")
	}
	return value(float64(h.Sum32()), fmt.Sprintf("%s-checksum", thingBeingChecksummed))
}

// Recorder records benchmark data. The Recorder is a singleton.
type Recorder interface {
	// Record records one or more values associated with a benchmark.
	// The benchmark is assumed to have a single iteration.
	Record(ctx context.Context, name string, values ...MetricValue) error
	// RecordIters records one or more values associated with a benchmark,
	// with an explicitly-specified number of iterations.
	RecordIters(ctx context.Context, name string, iters int, values ...MetricValue) error
}

// Singleton control variables for `GetRecorder`.
var (
	recorder     Recorder
	recorderErr  error
	recorderFn   = newRecorder
	recorderOnce sync.Once
)

type recorderContextKeyType int

const recorderContextKey recorderContextKeyType = iota

// WithRecorder returns a context with the given `Recorder`.
func WithRecorder(ctx context.Context, recorder Recorder) context.Context {
	return context.WithValue(ctx, recorderContextKey, recorder)
}

// GetRecorder returns the benchmark's `Recorder` singleton.
func GetRecorder(ctx context.Context) (Recorder, error) {
	if ctx.Value(recorderContextKey) != nil {
		return ctx.Value(recorderContextKey).(Recorder), nil
	}
	recorderOnce.Do(func() {
		recorder, recorderErr = recorderFn(ctx)
	})
	return recorder, recorderErr
}
