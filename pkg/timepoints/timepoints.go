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

// Package timepoints provides an interface to quickly and easily capture
// timestamps across multiple steps of identifiable instances of operations.
package timepoints

import (
	"fmt"
	"slices"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// Operation is an abstraction for storing timestamps that would correspond to
// various execution points of an operation.
//
// An "operation" for the purposes of this package has the following requirements:
//  1. It is composed of at least 2 steps/timepoints.
//  2. Each timepoint that makes an operation is triggered at least once.
//  3. It is a _sequential_ series of steps that has a well-known start and end;
//     - CaptureStart must be called at the start of every capture;
//     - CaptureSuccessful must only be called if every registered step in the
//     operation has been recorded.
//
// Once an Operation has accumulated `maxCaptures` worth of timestamps, the
// timestamp buffers are flushed and are used to produce metric results.
// Upon FlushToMetrics, metrics will only be generated if the ratio of successful
// captures is greater than `minSuccessRate`.
type Operation struct {
	name           string
	initialized    atomicbitops.Bool
	maxCaptures    int32
	minSuccessRate float32

	mu               *sync.Mutex
	numCaptures      int32
	numGenerations   uint32
	finishedCaptures bitmap.Bitmap
	bufs             []*TimePoint
	metrics          []MetricSetValue
}

// NewOperation creates an inactive Operation. An inactive operation does not
// allocate buffers for timestamps or processes Captures until Operation.Activate
// is called.
func NewOperation(name string, maxCaptures int, minSuccessRate float32) *Operation {
	if maxCaptures < 1 {
		panic(fmt.Sprintf("Operation \"%s\" has invalid value for maxCaptures: %d", name, maxCaptures))
	}
	if minSuccessRate < 0.0 || minSuccessRate > 1.0 {
		panic(fmt.Sprintf("Operation \"%s\" has invalid value for minSuccessRate: got %f, expected 0.0 <= minSuccessRate <= 1.0", name, minSuccessRate))
	}
	return &Operation{
		name:             name,
		initialized:      atomicbitops.FromBool(false),
		maxCaptures:      int32(maxCaptures),
		minSuccessRate:   minSuccessRate,
		mu:               &sync.Mutex{},
		finishedCaptures: bitmap.New(uint32(maxCaptures)),
	}
}

func (op *Operation) lockTimePointBufs() {
	for _, b := range op.bufs {
		b.mu.Lock()
	}
}

func (op *Operation) unlockTimePointBufs() {
	for _, b := range op.bufs {
		b.mu.Unlock()
	}
}

// MetricNameForTimepoints returns the formatted metric name that will be used
// to report avg delta between timepoint indexed at idx, and the one preceding it.
func (op *Operation) MetricNameForTimepoints(idx int) string {
	return fmt.Sprintf("/timepoints/%s/%d_to_%d/%d_run_avg_ns", op.name, idx-1, idx, op.maxCaptures)
}

// MetricNameForTotalAvg returns the formatted metric name that will be used
// to report avg delta for the entire operation.
func (op *Operation) MetricNameForTotalAvg() string {
	return fmt.Sprintf("/timepoints/%s/%d_run_avg_ns", op.name, op.maxCaptures)
}

// Capture is used to track a single instance of an Operation across multiple
// TimePoints.
type Capture struct {
	id         int32
	generation uint32
}

const (
	// InvalidCaptureID is zero so that an uninitialized Capture struct does
	// not cause timestamp captures to be taken. This is so that users who
	// don't need anything to do with this pkg are not being forced to use it.
	InvalidCaptureID   int32 = 0
	captureIndexOffset int32 = 1
)

func (cap Capture) toIndex() int32 {
	return cap.id - captureIndexOffset
}

// Reserved special metric indices.
const (
	metricTotalOperationAvg = iota
	numSpecialMetrics
)

// MetricSetValue is a function that takes a uint64 representing a nanosecond
// duration. It will be called by the timepoint pkg to report metrics generated
// by measuring differences between timepoints.
type MetricSetValue = func(uint64)

// MetricRegistration is a function that takes a Name string, and returns a
// function matching MetricSetValue. It  will be called by the timepoint pkg to
// register a new named metric.
type MetricRegistration = func(string) MetricSetValue

// Activate enables timepoint Captures to start being captured, instead of being
// no-ops.
func (op *Operation) Activate(register MetricRegistration) error {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.lockTimePointBufs()
	defer op.unlockTimePointBufs()

	if len(op.bufs) < 2 {
		return fmt.Errorf("failed to initialize operation \"%s\": not enough registered TimePoints", op.name)
	}

	numAvgMetrics := len(op.bufs) - 1
	op.metrics = make([]MetricSetValue, numAvgMetrics+numSpecialMetrics)

	op.metrics[metricTotalOperationAvg] = register(op.MetricNameForTotalAvg())

	for i, b := range op.bufs {
		b.ts = make([]timeTuple, op.maxCaptures)
		if i > 0 {
			idx := numSpecialMetrics + i - 1
			op.metrics[idx] = register(op.MetricNameForTimepoints(i))
		}
	}

	op.initialized.Store(true)
	return nil
}

// Deactivate stops any further captures from generating timestamps.
//
// Likely only useful in tests.
func (op *Operation) Deactivate() {
	op.initialized.Store(false)
}

// CaptureStart creates a new Capture.
func (op *Operation) CaptureStart() Capture {
	if !op.initialized.Load() {
		return Capture{
			id:         InvalidCaptureID,
			generation: 0,
		}
	}

	op.mu.Lock()
	defer op.mu.Unlock()

	if op.numCaptures == op.maxCaptures {
		op.flushToMetricsLocked()
	}
	cap := Capture{
		id:         op.numCaptures + captureIndexOffset,
		generation: op.numGenerations,
	}
	op.numCaptures++
	return cap
}

// CaptureSuccess logs that all timepoints in a capture have been captured.
//
//go:nosplit
func (op *Operation) CaptureSuccess(cap Capture) {
	if !op.initialized.Load() {
		return
	}

	op.mu.Lock()
	defer op.mu.Unlock()

	if cap.generation != op.numGenerations {
		return
	}
	op.finishedCaptures.Add(uint32(cap.toIndex()))
}

// FlushToMetrics uses captured timepoints to generate aggregation metrics.
func (op *Operation) FlushToMetrics() {
	if !op.initialized.Load() {
		return
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	op.flushToMetricsLocked()
}

func (op *Operation) flushToMetricsLocked() {
	op.lockTimePointBufs()
	defer op.unlockTimePointBufs()

	if op.finishedCaptures.IsEmpty() {
		log.Warningf("Called FlushToMetrics on Operation \"%s\" without any captures", op.name)
		return
	}

	// Initially the list of timepoints is unsorted, since registration
	// time could vary.
	op.maybeSortMetricsLocked()

	n := uint64(op.finishedCaptures.GetNumOnes())
	if n < uint64(op.minSuccessRate*float32(op.maxCaptures)) {
		log.Infof("timepoints: Operation \"%s\" did not generate metric at generation %d: did not meet success rate", op.name, op.numGenerations)
	} else {
		op.generateMetricsLocked()
	}

	// Reset for next generation.
	op.numGenerations++
	for _, tp := range op.bufs {
		tp.newGeneration(op.numGenerations)
	}
	op.numCaptures = 0
	op.finishedCaptures = bitmap.New(uint32(op.maxCaptures))
}

func (op *Operation) maybeSortMetricsLocked() {
	first, err := op.finishedCaptures.FirstOne(0)
	if err != nil {
		panic(fmt.Sprintf("unreachable: %v", err))
	}
	if op.numGenerations == 0 {
		slices.SortFunc(op.bufs, func(a, b *TimePoint) int {
			if a.ts[first].firstTS < b.ts[first].firstTS {
				return -1
			} else if a.ts[first].firstTS > b.ts[first].firstTS {
				return 1
			}
			return 0
		})
	}

}

func (op *Operation) generateMetricsLocked() {
	entireOpSum := uint64(0)
	numReportedAvgs := len(op.bufs) - 1
	sums := make([]uint64, numReportedAvgs)
	op.finishedCaptures.ForEach(0, uint32(op.maxCaptures), func(i uint32) bool {
		entireOpSum += uint64(op.bufs[numReportedAvgs].ts[i].lastTS - op.bufs[0].ts[i].firstTS)
		for j := 0; j < numReportedAvgs; j++ {
			sums[j] += uint64(op.bufs[j+1].ts[i].lastTS - op.bufs[j].ts[i].firstTS)
		}
		return true
	})
	n := uint64(op.finishedCaptures.GetNumOnes())
	op.metrics[metricTotalOperationAvg](entireOpSum / n)

	for i, sum := range sums {
		idx := numSpecialMetrics + i
		op.metrics[idx](sum / n)
	}
}

type timeTuple struct {
	firstTS, lastTS int64
}

//go:nosplit
func (tt *timeTuple) captureTS(ts int64) {
	if tt.firstTS == 0 {
		tt.firstTS = ts
	}
	// Always capture lastTs to simplify generating metrics.
	tt.lastTS = ts
}

// TimePoint represents a point in an operation at which a timestamp will be
// captured.
type TimePoint struct {
	name        string
	maxCaptures int32

	mu         *sync.Mutex
	generation uint32
	ts         []timeTuple
}

func newTimePoint(name string, maxCaptures int32) *TimePoint {
	return &TimePoint{
		name:        name,
		maxCaptures: maxCaptures,
		mu:          &sync.Mutex{},
	}
}

func (tp *TimePoint) newGeneration(g uint32) {
	tp.generation = g
	for i := int32(0); i < tp.maxCaptures; i++ {
		tp.ts[i] = timeTuple{0, 0}
	}
}

// RegisterTimePoint registers a new TimePoint for an Operation.
func (op *Operation) RegisterTimePoint(name string) (*TimePoint, error) {
	op.mu.Lock()
	defer op.mu.Unlock()

	if op.numCaptures != 0 || op.numGenerations != 0 {
		return nil, fmt.Errorf("captures for Operation \"%s\" already started, can't register TimePoint \"%s\"", op.name, name)
	}

	s := newTimePoint(name, op.maxCaptures)
	op.bufs = append(op.bufs, s)
	return s, nil
}

// MustRegisterTimePoint registers a new TimePoint, but panics if an error is
// encountered.
func (op *Operation) MustRegisterTimePoint(name string) *TimePoint {
	s, err := op.RegisterTimePoint(name)
	if err != nil {
		panic(err)
	}
	return s
}

// Record records a timestamp.
//
//go:nosplit
func (tp *TimePoint) Record(cap Capture) {
	if cap.id <= InvalidCaptureID {
		return
	}

	ts := gohacks.Nanotime()
	tp.mu.Lock()
	defer tp.mu.Unlock()

	idx := cap.toIndex()
	if cap.generation != tp.generation || idx >= tp.maxCaptures {
		return
	}

	tp.ts[idx].captureTS(ts)
}
