// Copyright 2018 Google Inc.
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

// Package metric provides primitives for collecting metrics.
package metric

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/eventchannel"
	"gvisor.googlesource.com/gvisor/pkg/log"
	pb "gvisor.googlesource.com/gvisor/pkg/metric/metric_go_proto"
)

var (
	// ErrNameInUse indicates that another metric is already defined for
	// the given name.
	ErrNameInUse = errors.New("metric name already in use")

	// ErrInitializationDone indicates that the caller tried to create a
	// new metric after initialization.
	ErrInitializationDone = errors.New("metric cannot be created after initialization is complete")
)

// Uint64Metric encapsulates a uint64 that represents some kind of metric to be
// monitored.
//
// All metrics must be cumulative, meaning that their values will only increase
// over time.
//
// Metrics are not saved across save/restore and thus reset to zero on restore.
//
// TODO: Support non-cumulative metrics.
// TODO: Support metric fields.
//
type Uint64Metric struct {
	// metadata describes the metric. It is immutable.
	metadata *pb.MetricMetadata

	// value is the actual value of the metric. It must be accessed
	// atomically.
	value uint64
}

var (
	// initialized indicates that all metrics are registered. allMetrics is
	// immutable once initialized is true.
	initialized bool

	// allMetrics are the registered metrics.
	allMetrics = makeMetricSet()
)

// Initialize sends a metric registration event over the event channel.
//
// Precondition:
//  * All metrics are registered.
//  * Initialize/Disable has not been called.
func Initialize() {
	if initialized {
		panic("Initialize/Disable called more than once")
	}
	initialized = true

	m := pb.MetricRegistration{}
	for _, v := range allMetrics.m {
		m.Metrics = append(m.Metrics, v.metadata)
	}
	eventchannel.Emit(&m)
}

// Disable sends an empty metric registration event over the event channel,
// disabling metric collection.
//
// Precondition:
//  * All metrics are registered.
//  * Initialize/Disable has not been called.
func Disable() {
	if initialized {
		panic("Initialize/Disable called more than once")
	}
	initialized = true

	m := pb.MetricRegistration{}
	if err := eventchannel.Emit(&m); err != nil {
		panic("unable to emit metric disable event: " + err.Error())
	}
}

// NewUint64Metric creates a new metric with the given name.
//
// Metrics must be statically defined (i.e., at startup). NewUint64Metric will
// return an error if called after Initialized.
//
// Preconditions:
//  * name must be globally unique.
//  * Initialize/Disable have not been called.
func NewUint64Metric(name string, sync bool, description string) (*Uint64Metric, error) {
	if initialized {
		return nil, ErrInitializationDone
	}

	if _, ok := allMetrics.m[name]; ok {
		return nil, ErrNameInUse
	}

	m := &Uint64Metric{
		metadata: &pb.MetricMetadata{
			Name:        name,
			Description: description,
			Cumulative:  true,
			Sync:        sync,
			Type:        pb.MetricMetadata_UINT64,
		},
	}
	allMetrics.m[name] = m
	return m, nil
}

// MustCreateNewUint64Metric calls NewUint64Metric and panics if it returns an
// error.
func MustCreateNewUint64Metric(name string, sync bool, description string) *Uint64Metric {
	m, err := NewUint64Metric(name, sync, description)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %v", name, err))
	}
	return m
}

// Value returns the current value of the metric.
func (m *Uint64Metric) Value() uint64 {
	return atomic.LoadUint64(&m.value)
}

// Increment increments the metric by 1.
func (m *Uint64Metric) Increment() {
	atomic.AddUint64(&m.value, 1)
}

// IncrementBy increments the metric by v.
func (m *Uint64Metric) IncrementBy(v uint64) {
	atomic.AddUint64(&m.value, v)
}

// metricSet holds named metrics.
type metricSet struct {
	m map[string]*Uint64Metric
}

// makeMetricSet returns a new metricSet.
func makeMetricSet() metricSet {
	return metricSet{
		m: make(map[string]*Uint64Metric),
	}
}

// Values returns a snapshot of all values in m.
func (m *metricSet) Values() metricValues {
	vals := make(metricValues)
	for k, v := range m.m {
		vals[k] = v.Value()
	}
	return vals
}

// metricValues contains a copy of the values of all metrics.
type metricValues map[string]uint64

var (
	// emitMu protects metricsAtLastEmit and ensures that all emitted
	// metrics are strongly ordered (older metrics are never emitted after
	// newer metrics).
	emitMu sync.Mutex

	// metricsAtLastEmit contains the state of the metrics at the last emit event.
	metricsAtLastEmit metricValues
)

// EmitMetricUpdate emits a MetricUpdate over the event channel.
//
// Only metrics that have changed since the last call are emitted.
//
// EmitMetricUpdate is thread-safe.
//
// Preconditions:
//  * Initialize has been called.
func EmitMetricUpdate() {
	emitMu.Lock()
	defer emitMu.Unlock()

	snapshot := allMetrics.Values()

	m := pb.MetricUpdate{}
	for k, v := range snapshot {
		// On the first call metricsAtLastEmit will be empty. Include
		// all metrics then.
		if prev, ok := metricsAtLastEmit[k]; !ok || prev != v {
			m.Metrics = append(m.Metrics, &pb.MetricValue{
				Name:  k,
				Value: &pb.MetricValue_Uint64Value{v},
			})
		}
	}

	metricsAtLastEmit = snapshot
	if len(m.Metrics) == 0 {
		return
	}

	log.Debugf("Emitting metrics: %v", m)
	eventchannel.Emit(&m)
}
