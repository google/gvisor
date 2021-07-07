// Copyright 2018 The gVisor Authors.
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
	"sort"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// ErrNameInUse indicates that another metric is already defined for
	// the given name.
	ErrNameInUse = errors.New("metric name already in use")

	// ErrInitializationDone indicates that the caller tried to create a
	// new metric after initialization.
	ErrInitializationDone = errors.New("metric cannot be created after initialization is complete")

	// WeirdnessMetric is a metric with fields created to track the number
	// of weird occurrences such as time fallback, partial_result, vsyscall
	// count, watchdog startup timeouts and stuck tasks.
	WeirdnessMetric = MustCreateNewUint64Metric("/weirdness", true /* sync */, "Increment for weird occurrences of problems such as time fallback, partial result, vsyscalls invoked in the sandbox, watchdog startup timeouts and stuck tasks.",
		Field{
			name:          "weirdness_type",
			allowedValues: []string{"time_fallback", "partial_result", "vsyscall_count", "watchdog_stuck_startup", "watchdog_stuck_tasks"},
		})

	// SuspiciousOperationsMetric is a metric with fields created to detect
	// operations such as opening an executable file to write from a gofer.
	SuspiciousOperationsMetric = MustCreateNewUint64Metric("/suspicious_operations", true /* sync */, "Increment for suspicious operations such as opening an executable file to write from a gofer.",
		Field{
			name:          "operation_type",
			allowedValues: []string{"opened_write_execute_file"},
		})
)

// InitStage is the name of a Sentry initialization stage.
type InitStage string

// List of all Sentry initialization stages.
var (
	InitRestoreConfig InitStage = "restore_config"
	InitExecConfig    InitStage = "exec_config"
	InitRestore       InitStage = "restore"
	InitCreateProcess InitStage = "create_process"
	InitTaskStart     InitStage = "task_start"

	// allStages is the list of allowed stages.
	allStages = []InitStage{
		InitRestoreConfig,
		InitExecConfig,
		InitRestore,
		InitCreateProcess,
		InitTaskStart,
	}
)

// Uint64Metric encapsulates a uint64 that represents some kind of metric to be
// monitored. We currently support metrics with at most one field.
//
// Metrics are not saved across save/restore and thus reset to zero on restore.
//
// TODO(b/67298427): Support metric fields.
type Uint64Metric struct {
	// value is the actual value of the metric. It must be accessed atomically.
	value uint64

	// numFields is the number of metric fields. It is immutable once
	// initialized.
	numFields int

	// mu protects the below fields.
	mu sync.RWMutex `state:"nosave"`

	// fields is the map of fields in the metric.
	fields map[string]uint64
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
func Initialize() error {
	if initialized {
		return errors.New("metric.Initialize called after metric.Initialize or metric.Disable")
	}

	m := pb.MetricRegistration{}
	for _, v := range allMetrics.m {
		m.Metrics = append(m.Metrics, v.metadata)
	}
	m.Stages = make([]string, 0, len(allStages))
	for _, s := range allStages {
		m.Stages = append(m.Stages, string(s))
	}
	if err := eventchannel.Emit(&m); err != nil {
		return fmt.Errorf("unable to emit metric initialize event: %w", err)
	}

	initialized = true
	return nil
}

// Disable sends an empty metric registration event over the event channel,
// disabling metric collection.
//
// Precondition:
//  * All metrics are registered.
//  * Initialize/Disable has not been called.
func Disable() error {
	if initialized {
		return errors.New("metric.Disable called after metric.Initialize or metric.Disable")
	}

	m := pb.MetricRegistration{}
	if err := eventchannel.Emit(&m); err != nil {
		return fmt.Errorf("unable to emit metric disable event: %w", err)
	}

	initialized = true
	return nil
}

type customUint64Metric struct {
	// metadata describes the metric. It is immutable.
	metadata *pb.MetricMetadata

	// value returns the current value of the metric for the given set of
	// fields. It takes a variadic number of field values as argument.
	value func(fieldValues ...string) uint64
}

// Field contains the field name and allowed values for the metric which is
// used in registration of the metric.
type Field struct {
	// name is the metric field name.
	name string

	// allowedValues is the list of allowed values for the field.
	allowedValues []string
}

// RegisterCustomUint64Metric registers a metric with the given name.
//
// Register must only be called at init and will return and error if called
// after Initialized.
//
// Preconditions:
// * name must be globally unique.
// * Initialize/Disable have not been called.
// * value is expected to accept exactly len(fields) arguments.
func RegisterCustomUint64Metric(name string, cumulative, sync bool, units pb.MetricMetadata_Units, description string, value func(...string) uint64, fields ...Field) error {
	if initialized {
		return ErrInitializationDone
	}

	if _, ok := allMetrics.m[name]; ok {
		return ErrNameInUse
	}

	allMetrics.m[name] = customUint64Metric{
		metadata: &pb.MetricMetadata{
			Name:        name,
			Description: description,
			Cumulative:  cumulative,
			Sync:        sync,
			Type:        pb.MetricMetadata_TYPE_UINT64,
			Units:       units,
		},
		value: value,
	}

	// Metrics can exist without fields.
	if l := len(fields); l > 1 {
		return fmt.Errorf("%d fields provided, must be <= 1", l)
	}

	for _, field := range fields {
		allMetrics.m[name].metadata.Fields = append(allMetrics.m[name].metadata.Fields, &pb.MetricMetadata_Field{
			FieldName:     field.name,
			AllowedValues: field.allowedValues,
		})
	}
	return nil
}

// MustRegisterCustomUint64Metric calls RegisterCustomUint64Metric for metrics
// without fields and panics if it returns an error.
func MustRegisterCustomUint64Metric(name string, cumulative, sync bool, description string, value func(...string) uint64, fields ...Field) {
	if err := RegisterCustomUint64Metric(name, cumulative, sync, pb.MetricMetadata_UNITS_NONE, description, value, fields...); err != nil {
		panic(fmt.Sprintf("Unable to register metric %q: %s", name, err))
	}
}

// NewUint64Metric creates and registers a new cumulative metric with the given
// name.
//
// Metrics must be statically defined (i.e., at init).
func NewUint64Metric(name string, sync bool, units pb.MetricMetadata_Units, description string, fields ...Field) (*Uint64Metric, error) {
	m := Uint64Metric{
		numFields: len(fields),
	}

	if m.numFields == 1 {
		m.fields = make(map[string]uint64)
		for _, fieldValue := range fields[0].allowedValues {
			m.fields[fieldValue] = 0
		}
	}
	return &m, RegisterCustomUint64Metric(name, true /* cumulative */, sync, units, description, m.Value, fields...)
}

// MustCreateNewUint64Metric calls NewUint64Metric and panics if it returns an
// error.
func MustCreateNewUint64Metric(name string, sync bool, description string, fields ...Field) *Uint64Metric {
	m, err := NewUint64Metric(name, sync, pb.MetricMetadata_UNITS_NONE, description, fields...)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %s", name, err))
	}
	return m
}

// MustCreateNewUint64NanosecondsMetric calls NewUint64Metric and panics if it
// returns an error.
func MustCreateNewUint64NanosecondsMetric(name string, sync bool, description string) *Uint64Metric {
	m, err := NewUint64Metric(name, sync, pb.MetricMetadata_UNITS_NANOSECONDS, description)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %s", name, err))
	}
	return m
}

// Value returns the current value of the metric for the given set of fields.
func (m *Uint64Metric) Value(fieldValues ...string) uint64 {
	if m.numFields != len(fieldValues) {
		panic(fmt.Sprintf("Number of fieldValues %d is not equal to the number of metric fields %d", len(fieldValues), m.numFields))
	}

	switch m.numFields {
	case 0:
		return atomic.LoadUint64(&m.value)
	case 1:
		m.mu.RLock()
		defer m.mu.RUnlock()

		fieldValue := fieldValues[0]
		if _, ok := m.fields[fieldValue]; !ok {
			panic(fmt.Sprintf("Metric does not allow to have field value %s", fieldValue))
		}
		return m.fields[fieldValue]
	default:
		panic("Sentry metrics do not support more than one field")
	}
}

// Increment increments the metric field by 1.
func (m *Uint64Metric) Increment(fieldValues ...string) {
	m.IncrementBy(1, fieldValues...)
}

// IncrementBy increments the metric by v.
func (m *Uint64Metric) IncrementBy(v uint64, fieldValues ...string) {
	if m.numFields != len(fieldValues) {
		panic(fmt.Sprintf("Number of fieldValues %d is not equal to the number of metric fields %d", len(fieldValues), m.numFields))
	}

	switch m.numFields {
	case 0:
		atomic.AddUint64(&m.value, v)
		return
	case 1:
		fieldValue := fieldValues[0]
		m.mu.Lock()
		defer m.mu.Unlock()

		if _, ok := m.fields[fieldValue]; !ok {
			panic(fmt.Sprintf("Metric does not allow to have field value %s", fieldValue))
		}
		m.fields[fieldValue] += v
	default:
		panic("Sentry metrics do not support more than one field")
	}
}

// stageTiming contains timing data for an initialization stage.
type stageTiming struct {
	stage   InitStage
	started time.Time
	// ended is the zero time when the stage has not ended yet.
	ended time.Time
}

// inProgress returns whether this stage hasn't ended yet.
func (s stageTiming) inProgress() bool {
	return !s.started.IsZero() && s.ended.IsZero()
}

// metricSet holds metric data.
type metricSet struct {
	// Map of metrics.
	m map[string]customUint64Metric

	// mu protects the fields below.
	mu sync.RWMutex

	// Information about the stages reached by the Sentry. Only appended to, so
	// reading a shallow copy of the slice header concurrently is safe.
	finished []stageTiming

	// The current stage in progress.
	currentStage stageTiming
}

// makeMetricSet returns a new metricSet.
func makeMetricSet() metricSet {
	return metricSet{
		m:        make(map[string]customUint64Metric),
		finished: make([]stageTiming, 0, len(allStages)),
	}
}

// Values returns a snapshot of all values in m.
func (m *metricSet) Values() metricValues {
	m.mu.Lock()
	stages := m.finished[:]
	m.mu.Unlock()

	vals := metricValues{
		m:      make(map[string]interface{}, len(m.m)),
		stages: stages,
	}

	for k, v := range m.m {
		fields := v.metadata.GetFields()
		switch len(fields) {
		case 0:
			vals.m[k] = v.value()
		case 1:
			values := fields[0].GetAllowedValues()
			fieldsMap := make(map[string]uint64)
			for _, fieldValue := range values {
				fieldsMap[fieldValue] = v.value(fieldValue)
			}
			vals.m[k] = fieldsMap
		default:
			panic(fmt.Sprintf("Unsupported number of metric fields: %d", len(fields)))
		}
	}
	return vals
}

// metricValues contains a copy of the values of all metrics.
type metricValues struct {
	// m is a map with key as metric name and value can be either uint64 or
	// map[string]uint64 to support metrics with one field.
	m map[string]interface{}

	// Information on when initialization stages were reached. Does not include
	// the currently-ongoing stage, if any.
	stages []stageTiming
}

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
// * Initialize has been called.
func EmitMetricUpdate() {
	emitMu.Lock()
	defer emitMu.Unlock()

	snapshot := allMetrics.Values()

	m := pb.MetricUpdate{}
	// On the first call metricsAtLastEmit will be empty. Include all
	// metrics then.
	for k, v := range snapshot.m {
		prev, ok := metricsAtLastEmit.m[k]
		switch t := v.(type) {
		case uint64:
			// Metric exists and value did not change.
			if ok && prev.(uint64) == t {
				continue
			}

			m.Metrics = append(m.Metrics, &pb.MetricValue{
				Name:  k,
				Value: &pb.MetricValue_Uint64Value{Uint64Value: t},
			})
		case map[string]uint64:
			for fieldValue, metricValue := range t {
				// Emit data on the first call only if the field
				// value has been incremented. For all other
				// calls, emit data if the field value has been
				// changed from the previous emit.
				if (!ok && metricValue == 0) || (ok && prev.(map[string]uint64)[fieldValue] == metricValue) {
					continue
				}

				m.Metrics = append(m.Metrics, &pb.MetricValue{
					Name:        k,
					FieldValues: []string{fieldValue},
					Value:       &pb.MetricValue_Uint64Value{Uint64Value: metricValue},
				})
			}
		}
	}

	for s := len(metricsAtLastEmit.stages); s < len(snapshot.stages); s++ {
		newStage := snapshot.stages[s]
		m.StageTiming = append(m.StageTiming, &pb.StageTiming{
			Stage: string(newStage.stage),
			Started: &timestamppb.Timestamp{
				Seconds: newStage.started.Unix(),
				Nanos:   int32(newStage.started.Nanosecond()),
			},
			Ended: &timestamppb.Timestamp{
				Seconds: newStage.ended.Unix(),
				Nanos:   int32(newStage.ended.Nanosecond()),
			},
		})
	}

	metricsAtLastEmit = snapshot
	if len(m.Metrics) == 0 && len(m.StageTiming) == 0 {
		return
	}

	if log.IsLogging(log.Debug) {
		sort.Slice(m.Metrics, func(i, j int) bool {
			return m.Metrics[i].Name < m.Metrics[j].Name
		})
		log.Debugf("Emitting metrics:")
		for _, metric := range m.Metrics {
			log.Debugf("%s: %+v", metric.Name, metric.Value)
		}
		for _, stage := range m.StageTiming {
			duration := time.Duration(stage.Ended.Seconds-stage.Started.Seconds)*time.Second + time.Duration(stage.Ended.Nanos-stage.Started.Nanos)*time.Nanosecond
			log.Debugf("Stage %s took %v", stage.GetStage(), duration)
		}
	}

	if err := eventchannel.Emit(&m); err != nil {
		log.Warningf("Unable to emit metrics: %s", err)
	}
}

// StartStage should be called when an initialization stage is started.
// It returns a function that must be called to indicate that the stage ended.
// Alternatively, future calls to StartStage will implicitly indicate that the
// previous stage ended.
// Stage information will be emitted in the next call to EmitMetricUpdate after
// a stage has ended.
//
// This function may (and is expected to) be called prior to final
// initialization of this metric library, as it has to capture early stages
// of Sentry initialization.
func StartStage(stage InitStage) func() {
	now := time.Now()
	allMetrics.mu.Lock()
	defer allMetrics.mu.Unlock()
	if allMetrics.currentStage.inProgress() {
		endStage(now)
	}
	allMetrics.currentStage.stage = stage
	allMetrics.currentStage.started = now
	return func() {
		now := time.Now()
		allMetrics.mu.Lock()
		defer allMetrics.mu.Unlock()
		// The current stage may have been ended by another call to StartStage, so
		// double-check prior to clearing the current stage.
		if allMetrics.currentStage.inProgress() && allMetrics.currentStage.stage == stage {
			endStage(now)
		}
	}
}

// endStage marks allMetrics.currentStage as ended, adding it to the list of
// finished stages. It assumes allMetrics.mu is locked.
func endStage(when time.Time) {
	allMetrics.currentStage.ended = when
	allMetrics.finished = append(allMetrics.finished, allMetrics.currentStage)
	allMetrics.currentStage = stageTiming{}
}
