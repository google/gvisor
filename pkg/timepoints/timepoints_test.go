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

package timepoints

import (
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
)

// metricGetValues is a function type that returns all metrics registered for
// given metric name.
type metricGetValues = func(name string) []uint64

// setupMetricRegistration mimics a simple metric collection library, and
// provides closures for registering new metrics, and retrieving values from
// those registered metrics.
//
// Returned closures are not thread-safe.
func setupMetricRegistration() (MetricRegistration, metricGetValues) {
	metricMap := make(map[string][]uint64)
	register := func(name string) MetricSetValue {
		setValue := func(m uint64) {
			metrics := metricMap[name]
			metricMap[name] = append(metrics, m)
		}
		return setValue
	}
	getValues := func(name string) []uint64 {
		metrics, _ := metricMap[name]
		return metrics
	}
	return register, getValues
}

// testOpWithTimepoints creates an Operation with a specified amount of
// registered TimePoints.
func testOpWithTimepoints(t *testing.T, opName string, captureThreshold, numTimePoints int, successRate float32) (*Operation, []*TimePoint) {
	t.Helper()

	op := NewOperation(opName, captureThreshold, successRate)
	ts := make([]*TimePoint, numTimePoints)
	for i := 0; i < numTimePoints; i++ {
		tp, err := op.RegisterTimePoint(fmt.Sprintf("stage%d", i))
		if err != nil {
			t.Errorf("RegisterTimePoint(stage%d): got %v, expected nil", i, err)
		}
		ts[i] = tp
	}

	return op, ts
}

func TestUsage(t *testing.T) {
	type testCase struct {
		name             string
		numTimepoints    int
		captureThreshold int
		successRate      float32
		numRuns          int
		workFn           func(_ int, op *Operation, ts []*TimePoint)
		checkFn          func(t *testing.T, op *Operation, getValues metricGetValues)
	}

	simpleWorkFn := func(_ int, op *Operation, ts []*TimePoint) {
		cap := op.CaptureStart()
		ts[0].Record(cap)

		// Do some busy work...
		sum := 0
		for j := 0; j < 1000; j++ {
			sum++
			sync.Goyield()
		}

		ts[1].Record(cap)
		op.CaptureSuccess(cap)
	}

	tests := []testCase{
		{
			name:             "simpleRun",
			numTimepoints:    2,
			captureThreshold: 100,
			successRate:      1.0,
			numRuns:          100,
			workFn:           simpleWorkFn,
			checkFn: func(t *testing.T, op *Operation, getValues metricGetValues) {
				op.FlushToMetrics()
				m := getValues(op.MetricNameForTimepoints(1))
				if len(m) == 0 || m[0] == 0 {
					t.Errorf("did not generate valid metric '%s'", op.MetricNameForTimepoints(1))
				}
			},
		},
		{
			name:             "respectSuccessThreshold",
			numTimepoints:    2,
			captureThreshold: 100,
			successRate:      0.75,
			numRuns:          74,
			workFn:           simpleWorkFn,
			checkFn: func(t *testing.T, op *Operation, getValues metricGetValues) {
				op.FlushToMetrics()
				m := getValues(op.MetricNameForTimepoints(1))
				if len(m) > 0 {
					t.Errorf("len(m) is %d, expected 0", len(m))
				}
			},
		},
		{
			name:             "automaticMetricGeneration",
			numTimepoints:    2,
			captureThreshold: 100,
			successRate:      1.0,
			numRuns:          301,
			workFn:           simpleWorkFn,
			checkFn: func(t *testing.T, op *Operation, getValues metricGetValues) {
				m := getValues(op.MetricNameForTimepoints(1))
				if len(m) != 3 {
					t.Errorf("len(m) is %d, expected 3", len(m))
				}
			},
		},
		{
			name:             "timeAccuracy",
			numTimepoints:    2,
			captureThreshold: 1,
			successRate:      1.0,
			numRuns:          2,
			workFn: func(i int, op *Operation, ts []*TimePoint) {
				cap := op.CaptureStart()
				ts[0].Record(cap)

				if i == 0 {
					time.Sleep(1 * time.Millisecond)
				} else {
					time.Sleep(10 * time.Millisecond)
				}

				ts[1].Record(cap)
				op.CaptureSuccess(cap)
			},
			checkFn: func(t *testing.T, op *Operation, getValues metricGetValues) {
				op.FlushToMetrics()
				m := getValues(op.MetricNameForTimepoints(1))
				if len(m) != 2 {
					t.Errorf("len(m) is %d, expected 2", len(m))
				}
				if m[0] < uint64((1*time.Millisecond).Nanoseconds()) || m[0] >= uint64((10*time.Millisecond).Nanoseconds()) {
					t.Errorf("bad metric value %d, expected %d < value < %d", m[0], (1 * time.Millisecond).Nanoseconds(), (10 * time.Millisecond).Nanoseconds())
				}
				if m[1] < uint64((10 * time.Millisecond).Nanoseconds()) {
					t.Errorf("bad metric value %d, expected value > %d", m[1], (10 * time.Millisecond).Nanoseconds())
				}
			},
		},
		{
			name:             "ignoreUnsuccessfulCaptures",
			numTimepoints:    2,
			captureThreshold: 2,
			successRate:      0.5,
			numRuns:          1,
			workFn: func(i int, op *Operation, ts []*TimePoint) {
				cap := op.CaptureStart()
				ts[0].Record(cap)

				if i == 0 {
					time.Sleep(1 * time.Millisecond)
				} else {
					time.Sleep(20 * time.Millisecond)
				}

				ts[1].Record(cap)
				if i == 0 {
					op.CaptureSuccess(cap)
				}
			},
			checkFn: func(t *testing.T, op *Operation, getValues metricGetValues) {
				op.FlushToMetrics()

				m := getValues(op.MetricNameForTimepoints(1))
				if len(m) != 1 {
					t.Errorf("len(m) is %d, expected 1", len(m))
				}
				if m[0] < uint64((1*time.Millisecond).Nanoseconds()) || m[0] >= uint64((10*time.Millisecond).Nanoseconds()) {
					t.Errorf("bad metric value %d, expected %d < value < %d", m[0], (1 * time.Millisecond).Nanoseconds(), (10 * time.Millisecond).Nanoseconds())
				}

			},
		},
		{
			name:             "retriggerSameTimepoint",
			numTimepoints:    3,
			captureThreshold: 100,
			successRate:      1.0,
			numRuns:          100,
			workFn: func(i int, op *Operation, ts []*TimePoint) {
				cap := op.CaptureStart()
				ts[0].Record(cap)

				sumOuter, sumInner := 0, 0
				for j := 0; j < 5; j++ {
					for k := 0; k < 200; k++ {
						sumInner++
						sync.Goyield()
					}
					ts[1].Record(cap)
					sumOuter += sumInner
				}

				ts[2].Record(cap)
				op.CaptureSuccess(cap)
			},
			checkFn: func(t *testing.T, op *Operation, getValues metricGetValues) {
				op.FlushToMetrics()
				m1 := getValues(op.MetricNameForTimepoints(1))
				if len(m1) == 0 || m1[0] == 0 {
					t.Errorf("did not generate valid metric '%s'", op.MetricNameForTimepoints(1))
				}
				m2 := getValues(op.MetricNameForTimepoints(2))
				if len(m2) == 0 || m2[0] == 0 {
					t.Errorf("did not generate valid metric '%s'", op.MetricNameForTimepoints(2))
				}
				// delta(t0, t1) should have one extra loop not accounted for in delta(t1, t2)
				if !(m1[0] > m2[0]) {
					t.Errorf("want m1 > m2, got m1=%d, m2=%d", m1, m2)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			op, ts := testOpWithTimepoints(t, "TestOp", test.captureThreshold, test.numTimepoints, test.successRate)
			register, getValues := setupMetricRegistration()
			if err := op.Activate(register); err != nil {
				t.Fatalf("failed op.Activate: %v", err)
			}

			for i := 0; i < test.numRuns; i++ {
				test.workFn(i, op, ts)
			}

			test.checkFn(t, op, getValues)
		})
	}
}

// naiveFibonacci is here just to do some busy work in the benchmark.
func naiveFibonacci(n int) int {
	if n == 1 {
		return 1
	} else if n < 1 {
		return 0
	}
	return naiveFibonacci(n-1) + naiveFibonacci(n-2)
}

const (
	fibToCompute    = 14
	numComputations = 10000
)

var (
	factorialOp    = NewOperation(fmt.Sprintf("Fibonacci(%d)", fibToCompute), 100, 1.0)
	factorialStart = factorialOp.MustRegisterTimePoint("start")
	factorialEnd   = factorialOp.MustRegisterTimePoint("end")
)

func workload() []int {
	results := [numComputations]int{}
	for j := 0; j < numComputations; j++ {
		results[j] = naiveFibonacci(fibToCompute)
	}
	return results[:]
}

func workloadWithTimePoints() []int {
	results := [numComputations]int{}
	for j := 0; j < numComputations; j++ {
		cap := factorialOp.CaptureStart()
		factorialStart.Record(cap)

		results[j] = naiveFibonacci(fibToCompute)

		factorialEnd.Record(cap)
		factorialOp.CaptureSuccess(cap)
	}
	return results[:]
}

func BenchmarkWorkloadNoTimePoints(b *testing.B) {
	for i := 0; i < b.N; i++ {
		workload()
	}
}

func BenchmarkWorkloadWithTimePointsNotEnabled(b *testing.B) {
	factorialOp.Deactivate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workloadWithTimePoints()
	}
}

func BenchmarkWorkloadWithTimePointsEnabled(b *testing.B) {
	factorialOp.Activate(func(name string) MetricSetValue {
		// Don't worry about overhead of calling into metric pkg.
		return func(_ uint64) {}
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workloadWithTimePoints()
	}
}
