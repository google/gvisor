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
	"math"
	re "regexp"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// ErrNameInUse indicates that another metric is already defined for
	// the given name.
	ErrNameInUse = errors.New("metric name already in use")

	// ErrInitializationDone indicates that the caller tried to create a
	// new metric after initialization.
	ErrInitializationDone = errors.New("metric cannot be created after initialization is complete")

	// ErrFieldValueContainsIllegalChar indicates that the value of a metric
	// field had an invalid character in it.
	ErrFieldValueContainsIllegalChar = errors.New("metric field value contains illegal character")

	// ErrFieldHasNoAllowedValues indicates that the field needs to define some
	// allowed values to be a valid and useful field.
	ErrFieldHasNoAllowedValues = errors.New("metric field does not define any allowed values")

	// ErrTooManyFieldCombinations indicates that the number of unique
	// combinations of fields is too large to support.
	ErrTooManyFieldCombinations = errors.New("metric has too many combinations of allowed field values")
)

// Weirdness metric type constants.
var (
	WeirdnessTypeTimeFallback         = FieldValue{"time_fallback"}
	WeirdnessTypePartialResult        = FieldValue{"partial_result"}
	WeirdnessTypeVsyscallCount        = FieldValue{"vsyscall_count"}
	WeirdnessTypeWatchdogStuckStartup = FieldValue{"watchdog_stuck_startup"}
	WeirdnessTypeWatchdogStuckTasks   = FieldValue{"watchdog_stuck_tasks"}
)

// Suspicious operations metric type constants.
var (
	SuspiciousOperationsTypeOpenedWriteExecuteFile = FieldValue{"opened_write_execute_file"}
)

// List of global metrics that are used in multiple places.
var (
	// WeirdnessMetric is a metric with fields created to track the number
	// of weird occurrences such as time fallback, partial_result, vsyscall
	// count, watchdog startup timeouts and stuck tasks.
	WeirdnessMetric = MustCreateNewUint64Metric(
		"/weirdness",
		Uint64Metadata{
			Cumulative:  true,
			Sync:        true,
			Description: "Increment for weird occurrences of problems such as time fallback, partial result, vsyscalls invoked in the sandbox, watchdog startup timeouts and stuck tasks.",
			Fields: []Field{
				NewField("weirdness_type",
					&WeirdnessTypeTimeFallback,
					&WeirdnessTypePartialResult,
					&WeirdnessTypeVsyscallCount,
					&WeirdnessTypeWatchdogStuckStartup,
					&WeirdnessTypeWatchdogStuckTasks,
				),
			},
		})

	// SuspiciousOperationsMetric is a metric with fields created to detect
	// operations such as opening an executable file to write from a gofer.
	SuspiciousOperationsMetric = MustCreateNewUint64Metric(
		"/suspicious_operations",
		Uint64Metadata{
			Cumulative:  true,
			Sync:        true,
			Description: "Increment for suspicious operations such as opening an executable file to write from a gofer.",
			Fields: []Field{
				NewField("operation_type",
					&SuspiciousOperationsTypeOpenedWriteExecuteFile,
				),
			},
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
// monitored.
//
// Metrics are not saved across save/restore and thus reset to zero on restore.
type Uint64Metric struct {
	name string

	// fields is the map of field-value combination index keys to Uint64 counters.
	fields []atomicbitops.Uint64

	// fieldMapper is used to generate index keys for the fields array (above)
	// based on field value combinations, and vice-versa.
	fieldMapper fieldMapper
}

var (
	// initialized indicates that all metrics are registered. allMetrics is
	// immutable once initialized is true.
	initialized atomicbitops.Bool

	// allMetrics are the registered metrics.
	allMetrics = makeMetricSet()
)

// Initialize sends a metric registration event over the event channel.
//
// Precondition:
//   - All metrics are registered.
//   - Initialize/Disable has not been called.
func Initialize() error {
	if initialized.Load() {
		return errors.New("metric.Initialize called after metric.Initialize or metric.Disable")
	}

	m := pb.MetricRegistration{}
	for _, v := range allMetrics.uint64Metrics {
		m.Metrics = append(m.Metrics, v.metadata)
	}
	for _, v := range allMetrics.distributionMetrics {
		m.Metrics = append(m.Metrics, v.metadata)
	}
	m.Stages = make([]string, 0, len(allStages))
	for _, s := range allStages {
		m.Stages = append(m.Stages, string(s))
	}
	allMetrics.registration = &m
	if err := eventchannel.Emit(&m); err != nil {
		return fmt.Errorf("unable to emit metric initialize event: %w", err)
	}

	if initialized.Swap(true) {
		return errors.New("raced with another call to metric.Initialize or metric.Disable")
	}
	return nil
}

// ErrNotYetInitialized is returned by GetMetricRegistration if metrics are not yet initialized.
var ErrNotYetInitialized = errors.New("metrics are not yet initialized")

// GetMetricRegistration returns the metric registration data for all registered metrics.
// Must be called after Initialize().
// Returns ErrNotYetInitialized if metrics are not yet initialized.
func GetMetricRegistration() (*pb.MetricRegistration, error) {
	if !initialized.Load() {
		return nil, ErrNotYetInitialized
	}
	if allMetrics.registration == nil {
		return nil, errors.New("metrics are disabled")
	}
	return allMetrics.registration, nil
}

// Disable sends an empty metric registration event over the event channel,
// disabling metric collection.
//
// Precondition:
//   - All metrics are registered.
//   - Initialize/Disable has not been called.
func Disable() error {
	if initialized.Load() {
		return errors.New("metric.Disable called after metric.Initialize or metric.Disable")
	}

	m := pb.MetricRegistration{}
	if err := eventchannel.Emit(&m); err != nil {
		return fmt.Errorf("unable to emit empty metric registration event (metrics disabled): %w", err)
	}

	if initialized.Swap(true) {
		return errors.New("raced with another call to metric.Initialize or metric.Disable")
	}
	return nil
}

// Uint64Metadata is the metadata for a uint64 metric.
type Uint64Metadata struct {
	Cumulative  bool
	Sync        bool
	Unit        pb.MetricMetadata_Units
	Description string
	Fields      []Field
}

type customUint64Metric struct {
	// metadata describes the metric. It is immutable.
	metadata *pb.MetricMetadata

	// prometheusMetric describes the metric in Prometheus format. It is immutable.
	prometheusMetric *prometheus.Metric

	// fields is the set of fields of the metric.
	fields []Field

	// value returns the current value of the metric for the given set of
	// fields. It takes a variadic number of field values as argument.
	value func(fieldValues ...*FieldValue) uint64

	// forEachNonZero calls the given function on each possible field value of
	// the metric where the metric's value is non-zero.
	// The passed-in function should not allocate new memory, and may not save
	// or modify `fields` directly, as the slice memory is reused across calls.
	// `forEachNonZero` does not guarantee that it will be called on a
	// consistent snapshot of this metric's values.
	// `forEachNonZero` may be nil.
	forEachNonZero func(f func(fields []*FieldValue, val uint64))
}

// FieldValue is a string that can be used as a value for a Field.
// It must be referred to by address when the Field is created and when its
// metric value is modified. This ensures that the same FieldValue reference
// is used, which in turn enables the metric code to use the address of a
// FieldValue as comparison operator, rather than doing string comparisons.
type FieldValue struct {
	Value string
}

// fieldMapperMapThreshold is the number of field values after which we switch
// to using map lookups when looking up field values.
// This value was determined using benchmarks to see which is fastest.
const fieldMapperMapThreshold = 48

// Field contains the field name and allowed values for the metric which is
// used in registration of the metric.
type Field struct {
	// name is the metric field name.
	name string

	// values is the list of values for the field.
	// `values` is always populated but not always used for lookup. It depends
	// on the number of allowed field values. `values` is used for lookups on
	// fields with small numbers of field values.
	values []*FieldValue

	// valuesPtrMap is a map version of `values`. For each item in `values`,
	// its pointer is mapped to its index within `values`.
	// `valuesPtrMap` is used for fields with large numbers of possible values.
	// For fields with small numbers of field values, it is nil.
	// This map allows doing faster string matching than a normal string map,
	// as it avoids the string hashing step that normal string maps need to do.
	valuesPtrMap map[*FieldValue]int
}

// toProto returns the proto definition of this field, for use in metric
// metadata.
func (f Field) toProto() *pb.MetricMetadata_Field {
	allowedValues := make([]string, len(f.values))
	for i, v := range f.values {
		allowedValues[i] = v.Value
	}
	return &pb.MetricMetadata_Field{
		FieldName:     f.name,
		AllowedValues: allowedValues,
	}
}

// NewField defines a new Field that can be used to break down a metric.
// The set of allowedValues must be unique strings wrapped with `FieldValue`.
// The *same* `FieldValue` pointers must be used during metric modifications.
// In practice, in most cases, this means you should declare these
// `FieldValue`s as package-level `var`s, and always use the address of these
// package-level `var`s during metric modifications.
func NewField(name string, allowedValues ...*FieldValue) Field {
	// Verify that all string values have a unique value.
	strMap := make(map[string]bool, len(allowedValues))
	for _, v := range allowedValues {
		if strMap[v.Value] {
			panic(fmt.Sprintf("found duplicate field value: %q", v))
		}
		strMap[v.Value] = true
	}

	if useMap := len(allowedValues) > fieldMapperMapThreshold; !useMap {
		return Field{
			name:   name,
			values: allowedValues,
		}
	}

	valuesPtrMap := make(map[*FieldValue]int, len(allowedValues))
	for i, v := range allowedValues {
		valuesPtrMap[v] = i
	}
	return Field{
		name:         name,
		values:       allowedValues,
		valuesPtrMap: valuesPtrMap,
	}
}

// fieldMapper provides multi-dimensional fields to a single unique integer key
type fieldMapper struct {
	// fields is a list of Field objects, which importantly include individual
	// Field names which are used to perform the keyToMultiField function; and
	// allowedValues for each field type which are used to perform the lookup
	// function.
	fields []Field

	// numFieldCombinations is the number of unique keys for all possible field
	// combinations.
	numFieldCombinations int
}

// newFieldMapper returns a new fieldMapper for the given set of fields.
func newFieldMapper(fields ...Field) (fieldMapper, error) {
	numFieldCombinations := 1
	for _, f := range fields {
		// Disallow fields with no possible values. We could also ignore them
		// instead, but passing in a no-allowed-values field is probably a mistake.
		if len(f.values) == 0 {
			return fieldMapper{nil, 0}, ErrFieldHasNoAllowedValues
		}
		numFieldCombinations *= len(f.values)

		// Sanity check, could be useful in case someone dynamically generates too
		// many fields accidentally.
		if numFieldCombinations > math.MaxUint32 || numFieldCombinations < 0 {
			return fieldMapper{nil, 0}, ErrTooManyFieldCombinations
		}
	}

	return fieldMapper{
		fields:               fields,
		numFieldCombinations: numFieldCombinations,
	}, nil
}

// lookupSingle looks up a single key for a single field within fieldMapper.
// It is used internally within lookupConcat.
// It returns the updated `idx` and `remainingCombinationBucket` values.
// +checkescape:all
//
//go:nosplit
func (m fieldMapper) lookupSingle(fieldIndex int, fieldValue *FieldValue, idx, remainingCombinationBucket int) (int, int) {
	field := m.fields[fieldIndex]
	numValues := len(field.values)

	// Are we doing a linear search?
	if field.valuesPtrMap == nil {
		// We scan by pointers only. This means the caller must pass the same
		// FieldValue pointer as the one used in `NewField`.
		for valIdx, allowedVal := range field.values {
			if fieldValue == allowedVal {
				remainingCombinationBucket /= numValues
				idx += remainingCombinationBucket * valIdx
				return idx, remainingCombinationBucket
			}
		}
		panic("invalid field value or did not reuse the same FieldValue pointer as passed in NewField")
	}

	// Use map lookup instead.

	// Match using FieldValue pointer.
	// This avoids the string hashing step that string maps otherwise do.
	valIdx, found := field.valuesPtrMap[fieldValue]
	if found {
		remainingCombinationBucket /= numValues
		idx += remainingCombinationBucket * valIdx
		return idx, remainingCombinationBucket
	}

	panic("invalid field value or did not reuse the same FieldValue pointer as passed in NewField")
}

// lookupConcat looks up a key within the fieldMapper where the fields are
// the concatenation of two list of fields.
// The returned key is an index that can be used to access to map created by
// makeMap().
// This *must* be called with the correct number of fields, or it will panic.
// +checkescape:all
//
//go:nosplit
func (m fieldMapper) lookupConcat(fields1, fields2 []*FieldValue) int {
	if (len(fields1) + len(fields2)) != len(m.fields) {
		panic("invalid field lookup depth")
	}
	idx := 0
	remainingCombinationBucket := m.numFieldCombinations
	for i, val := range fields1 {
		idx, remainingCombinationBucket = m.lookupSingle(i, val, idx, remainingCombinationBucket)
	}

	numFields1 := len(fields1)
	for i, val := range fields2 {
		idx, remainingCombinationBucket = m.lookupSingle(i+numFields1, val, idx, remainingCombinationBucket)
	}

	return idx
}

// lookup looks up a key within the fieldMapper.
// The returned key is an index that can be used to access to map created by
// makeMap().
// This *must* be called with the correct number of fields, or it will panic.
// +checkescape:all
//
//go:nosplit
func (m fieldMapper) lookup(fields ...*FieldValue) int {
	return m.lookupConcat(fields, nil)
}

// numKeys returns the total number of key-to-field-combinations mappings
// defined by the fieldMapper.
//
//go:nosplit
func (m fieldMapper) numKeys() int {
	return m.numFieldCombinations
}

// makeDistributionSampleMap creates a two dimensional array, where:
//   - The first level corresponds to unique field value combinations and is
//     accessed using index "keys" made by fieldMapper.
//   - The second level corresponds to buckets within a metric. The number of
//     buckets is specified by numBuckets.
func (m fieldMapper) makeDistributionSampleMap(numBuckets int) [][]atomicbitops.Uint64 {
	samples := make([][]atomicbitops.Uint64, m.numKeys())
	for i := range samples {
		samples[i] = make([]atomicbitops.Uint64, numBuckets)
	}
	return samples
}

// keyToMultiField is the reverse of lookup/lookupConcat. The returned list of
// field values corresponds to the same order of fields that were passed in to
// newFieldMapper.
func (m fieldMapper) keyToMultiField(key int) []string {
	depth := len(m.fields)
	if depth == 0 && key == 0 {
		return nil
	}
	fieldValues := make([]string, depth)
	remainingCombinationBucket := m.numFieldCombinations
	for i := 0; i < depth; i++ {
		remainingCombinationBucket /= len(m.fields[i].values)
		fieldValues[i] = m.fields[i].values[key/remainingCombinationBucket].Value
		key = key % remainingCombinationBucket
	}
	return fieldValues
}

// keyToMultiFieldInPlace does the operation described in `keyToMultiField`
// but modifies `fieldValues` in-place. It must already be of size
// `len(m.fields)`.
//
//go:nosplit
func (m fieldMapper) keyToMultiFieldInPlace(key int, fieldValues []*FieldValue) {
	if len(m.fields) == 0 {
		return
	}
	depth := len(m.fields)
	remainingCombinationBucket := m.numFieldCombinations
	for i := 0; i < depth; i++ {
		remainingCombinationBucket /= len(m.fields[i].values)
		fieldValues[i] = m.fields[i].values[key/remainingCombinationBucket]
		key = key % remainingCombinationBucket
	}
}

// nameToPrometheusName transforms a path-style metric name (/foo/bar) into a Prometheus-style
// metric name (foo_bar).
func nameToPrometheusName(name string) string {
	return strings.ReplaceAll(strings.TrimPrefix(name, "/"), "/", "_")
}

var validMetricNameRegexp = re.MustCompile("^(?:/[_\\w]+)+$")

// verifyName verifies that the given metric name is a valid path-style metric
// name.
func verifyName(name string) error {
	if !strings.HasPrefix(name, "/") {
		return fmt.Errorf("metric name must start with a '/': %q", name)
	}
	if !validMetricNameRegexp.MatchString(name) {
		return fmt.Errorf("invalid metric name: %q", name)
	}
	return nil
}

// RegisterCustomUint64Metric registers a metric with the given name.
//
// Register must only be called at init and will return and error if called
// after Initialized.
//
// Preconditions:
//   - name must be globally unique.
//   - Initialize/Disable have not been called.
//   - value is expected to accept exactly len(fields) arguments.
func RegisterCustomUint64Metric(name string, metadata Uint64Metadata, value func(...*FieldValue) uint64) error {
	if initialized.Load() {
		return ErrInitializationDone
	}

	if _, ok := allMetrics.uint64Metrics[name]; ok {
		return ErrNameInUse
	}
	if _, ok := allMetrics.distributionMetrics[name]; ok {
		return ErrNameInUse
	}

	promType := prometheus.TypeGauge
	if metadata.Cumulative {
		promType = prometheus.TypeCounter
	}

	allMetrics.uint64Metrics[name] = customUint64Metric{
		metadata: &pb.MetricMetadata{
			Name:           name,
			PrometheusName: nameToPrometheusName(name),
			Description:    metadata.Description,
			Cumulative:     metadata.Cumulative,
			Sync:           metadata.Sync,
			Type:           pb.MetricMetadata_TYPE_UINT64,
			Units:          metadata.Unit,
		},
		prometheusMetric: &prometheus.Metric{
			Name: nameToPrometheusName(name),
			Help: metadata.Description,
			Type: promType,
		},
		fields: metadata.Fields,
		value:  value,
	}

	// Metrics can exist without fields.
	if l := len(metadata.Fields); l > 1 {
		return fmt.Errorf("%d fields provided, must be <= 1", l)
	}

	for _, field := range metadata.Fields {
		allMetrics.uint64Metrics[name].metadata.Fields = append(allMetrics.uint64Metrics[name].metadata.Fields, field.toProto())
	}
	return nil
}

// MustRegisterCustomUint64Metric calls RegisterCustomUint64Metric for metrics
// without fields and panics if it returns an error.
func MustRegisterCustomUint64Metric(name string, metadata Uint64Metadata, value func(...*FieldValue) uint64) {
	if err := RegisterCustomUint64Metric(name, metadata, value); err != nil {
		panic(fmt.Sprintf("Unable to register metric %q: %s", name, err))
	}
}

// NewUint64Metric creates and registers a new cumulative metric with the given
// name.
//
// Metrics must be statically defined (i.e., at init).
func NewUint64Metric(name string, metadata Uint64Metadata) (*Uint64Metric, error) {
	if err := verifyName(name); err != nil {
		return nil, err
	}
	f, err := newFieldMapper(metadata.Fields...)
	if err != nil {
		return nil, err
	}
	m := Uint64Metric{
		name:        name,
		fieldMapper: f,
		fields:      make([]atomicbitops.Uint64, f.numKeys()),
	}
	if err := RegisterCustomUint64Metric(name, metadata, m.Value); err != nil {
		return nil, err
	}
	cm := allMetrics.uint64Metrics[name]
	cm.forEachNonZero = m.forEachNonZero
	allMetrics.uint64Metrics[name] = cm
	return &m, nil
}

// MustCreateNewUint64Metric calls NewUint64Metric and panics if it returns
// an error.
func MustCreateNewUint64Metric(name string, metadata Uint64Metadata) *Uint64Metric {
	m, err := NewUint64Metric(name, metadata)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %s", name, err))
	}
	return m
}

// Value returns the current value of the metric for the given set of fields.
// This must be called with the correct number of field values or it will panic.
//
//go:nosplit
func (m *Uint64Metric) Value(fieldValues ...*FieldValue) uint64 {
	key := m.fieldMapper.lookupConcat(fieldValues, nil)
	return m.fields[key].Load()
}

// forEachNonZero iterates over each field combination and calls the given
// function whenever this metric's value is not zero.
func (m *Uint64Metric) forEachNonZero(f func(fieldValues []*FieldValue, value uint64)) {
	numCombinations := m.fieldMapper.numKeys()
	if len(m.fieldMapper.fields) == 0 {
		// Special-case the "there are no fields" case for speed and to avoid
		// allocating a slice.
		if val := m.fields[0].Load(); val != 0 {
			f(nil, val)
		}
		return
	}
	var fieldValues []*FieldValue
	for k := 0; k < numCombinations; k++ {
		val := m.fields[k].Load()
		if val == 0 {
			continue
		}
		if fieldValues == nil {
			fieldValues = make([]*FieldValue, len(m.fieldMapper.fields))
		}
		m.fieldMapper.keyToMultiFieldInPlace(k, fieldValues)
		f(fieldValues, val)
	}
}

// Increment increments the metric by 1.
// This must be called with the correct number of field values or it will panic.
//
//go:nosplit
func (m *Uint64Metric) Increment(fieldValues ...*FieldValue) {
	m.IncrementBy(1, fieldValues...)
}

// Decrement decrements the metric by 1.
// This must be called with the correct number of field values or it will panic.
//
//go:nosplit
func (m *Uint64Metric) Decrement(fieldValues ...*FieldValue) {
	m.IncrementBy(0xFFFFFFFFFFFFFFFF, fieldValues...)
}

// IncrementBy increments the metric by v.
// It is also possible to use this function to decrement the metric by using
// a two's-complement int64 representation of the negative number to add.
// This must be called with the correct number of field values or it will panic.
//
//go:nosplit
func (m *Uint64Metric) IncrementBy(v uint64, fieldValues ...*FieldValue) {
	key := m.fieldMapper.lookupConcat(fieldValues, nil)
	m.fields[key].Add(v)
}

// Set sets the metric to v.
// This must be called with the correct number of field values or it will panic.
//
//go:nosplit
func (m *Uint64Metric) Set(v uint64, fieldValues ...*FieldValue) {
	key := m.fieldMapper.lookupConcat(fieldValues, nil)
	m.fields[key].Store(v)
}

// Bucketer is an interface to bucket values into finite, distinct buckets.
type Bucketer interface {
	// NumFiniteBuckets is the number of finite buckets in the distribution.
	// This is only called once and never expected to return a different value.
	NumFiniteBuckets() int

	// LowerBound takes the index of a bucket (within [0, NumBuckets()]) and
	// returns the inclusive lower bound of that bucket.
	// In other words, the lowest value of `x` for which `BucketIndex(x) == i`
	// should be `x = LowerBound(i)`.
	// The upper bound of a bucket is the lower bound of the next bucket.
	// The last bucket (with `bucketIndex == NumFiniteBuckets()`) is infinite,
	// i.e. it has no upper bound (but it still has a lower bound).
	LowerBound(bucketIndex int) int64

	// BucketIndex takes a sample and returns the index of the bucket that the
	// sample should fall into.
	// Must return either:
	//   - A value within [0, NumBuckets() -1] if the sample falls within a
	//     finite bucket
	//   - NumBuckets() if the sample falls within the last (infinite) bucket
	//   - '-1' if the sample is lower than what any bucket can represent, i.e.
	//     the sample should be in the implicit "underflow" bucket.
	// This function must be go:nosplit-compatible and have no escapes.
	// +checkescape:all
	BucketIndex(sample int64) int
}

// ExponentialBucketer implements Bucketer, with the first bucket starting
// with 0 as lowest bound with `Width` width, and each subsequent bucket being
// wider by a scaled exponentially-growing series, until `NumFiniteBuckets`
// buckets exist.
type ExponentialBucketer struct {
	// numFinitebuckets is the total number of finite buckets in the scheme.
	numFiniteBuckets int

	// width is the size of the first (0-th) finite bucket.
	width float64

	// scale is a factor applied uniformly to the exponential growth portion
	// of the bucket size.
	scale float64

	// growth is the exponential growth factor for finite buckets.
	// The n-th bucket is `growth` times wider than the (n-1)-th bucket.
	// Bucket sizes are floored, so `width` and `growth` must be large enough
	// such that the second bucket is actually wider than the first after
	// flooring (unless, of course, fixed-width buckets are what's desired).
	growth float64

	// growthLog is math.Log(growth).
	growthLog float64

	// maxSample is the max sample value which can be represented in a finite
	// bucket.
	maxSample int64

	// lowerbounds is a precomputed set of lower bounds of the buckets.
	// The "underflow" bucket has no lower bound, so it is not included here.
	// lowerBounds[0] is the lower bound of the first finite bucket, which is
	// also the upper bound of the underflow bucket.
	// lowerBounds[numFiniteBuckets] is the lower bound of the overflow bucket.
	lowerBounds []int64
}

// Minimum/maximum finite buckets for exponential bucketers.
const (
	exponentialMinBuckets = 1
	exponentialMaxBuckets = 100
)

// NewExponentialBucketer returns a new Bucketer with exponential buckets.
func NewExponentialBucketer(numFiniteBuckets int, width uint64, scale, growth float64) *ExponentialBucketer {
	if numFiniteBuckets < exponentialMinBuckets || numFiniteBuckets > exponentialMaxBuckets {
		panic(fmt.Sprintf("number of finite buckets must be in [%d, %d]", exponentialMinBuckets, exponentialMaxBuckets))
	}
	if scale < 0 || growth < 0 {
		panic(fmt.Sprintf("scale and growth for exponential buckets must be >0, got scale=%f and growth=%f", scale, growth))
	}
	b := &ExponentialBucketer{
		numFiniteBuckets: numFiniteBuckets,
		width:            float64(width),
		scale:            scale,
		growth:           growth,
		growthLog:        math.Log(growth),
		lowerBounds:      make([]int64, numFiniteBuckets+1),
	}
	b.lowerBounds[0] = 0
	for i := 1; i <= numFiniteBuckets; i++ {
		b.lowerBounds[i] = int64(b.width*float64(i) + b.scale*math.Pow(b.growth, float64(i-1)))
		if b.lowerBounds[i] < 0 {
			panic(fmt.Sprintf("encountered bucket width overflow at bucket %d", i))
		}
	}
	b.maxSample = b.lowerBounds[numFiniteBuckets] - 1
	return b
}

// NumFiniteBuckets implements Bucketer.NumFiniteBuckets.
func (b *ExponentialBucketer) NumFiniteBuckets() int {
	return int(b.numFiniteBuckets)
}

// LowerBound implements Bucketer.LowerBound.
func (b *ExponentialBucketer) LowerBound(bucketIndex int) int64 {
	return b.lowerBounds[bucketIndex]
}

// BucketIndex implements Bucketer.BucketIndex.
// +checkescape:all
//
//go:nosplit
func (b *ExponentialBucketer) BucketIndex(sample int64) int {
	if sample < 0 {
		return -1
	}
	if sample == 0 {
		return 0
	}
	if sample > b.maxSample {
		return b.numFiniteBuckets
	}
	// Do a binary search. For the number of buckets we expect to deal with in
	// this code (a few dozen at most), this may be faster than computing a
	// logarithm. We can't use recursion because this would violate go:nosplit.
	lowIndex := 0
	highIndex := b.numFiniteBuckets
	for {
		pivotIndex := (highIndex + lowIndex) >> 1
		lowerBound := b.lowerBounds[pivotIndex]
		if sample < lowerBound {
			highIndex = pivotIndex
			continue
		}
		upperBound := b.lowerBounds[pivotIndex+1]
		if sample >= upperBound {
			lowIndex = pivotIndex
			continue
		}
		return pivotIndex
	}
}

// Verify that ExponentialBucketer implements Bucketer.
var _ = (Bucketer)((*ExponentialBucketer)(nil))

// DistributionMetric represents a distribution of values in finite buckets.
// It also separately keeps track of min/max in order to ascertain whether the
// buckets can faithfully represent the range of values encountered in the
// distribution.
type DistributionMetric struct {
	// exponentialBucketer is the bucketing scheme used for this metric.
	// Because we need DistributionMetric.AddSample to be go:nosplit-compatible,
	// we cannot use an interface reference here, as we would not be able to call
	// it in AddSample. Instead, we need one field per Bucketer implementation,
	// and we call whichever one is in use in AddSample.
	exponentialBucketer *ExponentialBucketer

	// metadata is the metadata about this metric. It is immutable.
	metadata *pb.MetricMetadata

	// prometheusMetric describes the metric in Prometheus format. It is immutable.
	prometheusMetric *prometheus.Metric

	// fieldsToKey converts a multi-dimensional fields to a single string to use
	// as key for `samples`.
	fieldsToKey fieldMapper

	// samples is the number of samples that fell within each bucket.
	// It is mapped by the concatenation of the fields using `fieldsToKey`.
	// The value is a list of bucket sample counts, with the 0-th being the
	// "underflow bucket", i.e. the bucket of samples which cannot fall into
	// any bucket that the bucketer supports.
	// The i-th value is the number of samples that fell into the bucketer's
	// (i-1)-th finite bucket.
	// The last value is the number of samples that fell into the bucketer's
	// last (i.e. infinite) bucket.
	samples [][]atomicbitops.Uint64

	// statistics is a set of statistics about each distribution.
	// It is mapped by the concatenation of the fields using `fieldsToKey`.
	statistics []distributionStatistics
}

// NewDistributionMetric creates and registers a new distribution metric.
func NewDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) (*DistributionMetric, error) {
	if err := verifyName(name); err != nil {
		return nil, err
	}
	if initialized.Load() {
		return nil, ErrInitializationDone
	}
	if _, ok := allMetrics.uint64Metrics[name]; ok {
		return nil, ErrNameInUse
	}
	if _, ok := allMetrics.distributionMetrics[name]; ok {
		return nil, ErrNameInUse
	}

	var exponentialBucketer *ExponentialBucketer
	if expBucketer, ok := bucketer.(*ExponentialBucketer); ok {
		exponentialBucketer = expBucketer
	} else {
		return nil, fmt.Errorf("unsupported bucketer implementation: %T", bucketer)
	}
	fieldsToKey, err := newFieldMapper(fields...)
	if err != nil {
		return nil, err
	}

	numFiniteBuckets := bucketer.NumFiniteBuckets()
	samples := fieldsToKey.makeDistributionSampleMap(numFiniteBuckets + 2)
	protoFields := make([]*pb.MetricMetadata_Field, len(fields))
	for i, f := range fields {
		protoFields[i] = f.toProto()
	}
	lowerBounds := make([]int64, numFiniteBuckets+1)
	for i := 0; i <= numFiniteBuckets; i++ {
		lowerBounds[i] = bucketer.LowerBound(i)
	}
	allMetrics.distributionMetrics[name] = &DistributionMetric{
		exponentialBucketer: exponentialBucketer,
		fieldsToKey:         fieldsToKey,
		samples:             samples,
		statistics:          make([]distributionStatistics, fieldsToKey.numKeys()),
		metadata: &pb.MetricMetadata{
			Name:                          name,
			PrometheusName:                nameToPrometheusName(name),
			Description:                   description,
			Cumulative:                    false,
			Sync:                          sync,
			Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
			Units:                         unit,
			Fields:                        protoFields,
			DistributionBucketLowerBounds: lowerBounds,
		},
		prometheusMetric: &prometheus.Metric{
			Name: nameToPrometheusName(name),
			Type: prometheus.TypeHistogram,
			Help: description,
		},
	}
	return allMetrics.distributionMetrics[name], nil
}

// MustCreateNewDistributionMetric creates and registers a distribution metric.
// If an error occurs, it panics.
func MustCreateNewDistributionMetric(name string, sync bool, bucketer Bucketer, unit pb.MetricMetadata_Units, description string, fields ...Field) *DistributionMetric {
	distrib, err := NewDistributionMetric(name, sync, bucketer, unit, description, fields...)
	if err != nil {
		panic(err)
	}
	return distrib
}

// distributionStatistics is a set of useful statistics for a distribution.
// As metric update operations must be non-blocking, this uses a bunch of
// atomic numbers rather than a mutex.
type distributionStatistics struct {
	// sampleCount is the total number of samples.
	sampleCount atomicbitops.Uint64

	// sampleSum is the sum of samples.
	sampleSum atomicbitops.Int64

	// sumOfSquaredDeviations is the running sum of squared deviations from the
	// mean of each sample.
	// This quantity is useful as part of Welford's online algorithm:
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	sumOfSquaredDeviations atomicbitops.Float64

	// min and max are the minimum and maximum samples ever recorded.
	min, max atomicbitops.Int64
}

// Update updates the distribution statistics with the given sample.
// This function must be non-blocking, i.e. no mutexes.
// As a result, it is not entirely accurate when it races with itself,
// though the imprecision should be fairly small and should not practically
// matter for distributions with more than a handful of records.
func (s *distributionStatistics) Update(sample int64) {
	newSampleCount := s.sampleCount.Add(1)
	newSampleSum := s.sampleSum.Add(sample)

	if newSampleCount > 1 {
		// Not the first sample of the distribution.
		floatSample := float64(sample)
		oldMean := float64(newSampleSum-sample) / float64(newSampleCount-1)
		newMean := float64(newSampleSum) / float64(newSampleCount)
		devSquared := (floatSample - oldMean) * (floatSample - newMean)
		s.sumOfSquaredDeviations.Add(devSquared)

		// Update min and max.
		// We optimistically load racily here in the hope that it passes the CaS
		// operation. If it doesn't, we'll load it atomically, so this is not a
		// race.
		sync.RaceDisable()
		for oldMin := s.min.RacyLoad(); sample < oldMin && !s.min.CompareAndSwap(oldMin, sample); oldMin = s.min.Load() {
		}
		for oldMax := s.max.RacyLoad(); sample > oldMax && !s.max.CompareAndSwap(oldMax, sample); oldMax = s.max.Load() {
		}
		sync.RaceEnable()
	} else {
		// We are the first sample, so set the min and max to the current sample.
		// See above for why disabling race detection is safe here as well.
		sync.RaceDisable()
		if !s.min.CompareAndSwap(0, sample) {
			for oldMin := s.min.RacyLoad(); sample < oldMin && !s.min.CompareAndSwap(oldMin, sample); oldMin = s.min.Load() {
			}
		}
		if !s.max.CompareAndSwap(0, sample) {
			for oldMax := s.max.RacyLoad(); sample > oldMax && !s.max.CompareAndSwap(oldMax, sample); oldMax = s.max.Load() {
			}
		}
		sync.RaceEnable()
	}
}

// distributionStatisticsSnapshot an atomically-loaded snapshot of
// distributionStatistics.
type distributionStatisticsSnapshot struct {
	// sampleCount is the total number of samples.
	sampleCount uint64

	// sampleSum is the sum of samples.
	sampleSum int64

	// sumOfSquaredDeviations is the running sum of squared deviations from the
	// mean of each sample.
	// This quantity is useful as part of Welford's online algorithm:
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	sumOfSquaredDeviations float64

	// min and max are the minimum and maximum samples ever recorded.
	min, max int64
}

// Load generates a consistent snapshot of the distribution statistics.
func (s *distributionStatistics) Load() distributionStatisticsSnapshot {
	// We start out reading things racily, but will verify each of them
	// atomically later in this function, so this is OK. Disable the race
	// checker for this part of the function.
	sync.RaceDisable()
	snapshot := distributionStatisticsSnapshot{
		sampleCount:            s.sampleCount.RacyLoad(),
		sampleSum:              s.sampleSum.RacyLoad(),
		sumOfSquaredDeviations: s.sumOfSquaredDeviations.RacyLoad(),
		min:                    s.min.RacyLoad(),
		max:                    s.max.RacyLoad(),
	}
	sync.RaceEnable()

	// Now verify that we loaded an atomic snapshot of the statistics.
	// This relies on the fact that each update should at least change the
	// count statistic, so we should be able to tell if anything changed based
	// on whether we have an exact match with the currently-loaded values.
	// If not, we reload that value and try again until all is consistent.
retry:
	if sampleCount := s.sampleCount.Load(); sampleCount != snapshot.sampleCount {
		snapshot.sampleCount = sampleCount
		goto retry
	}
	if sampleSum := s.sampleSum.Load(); sampleSum != snapshot.sampleSum {
		snapshot.sampleSum = sampleSum
		goto retry
	}
	if ssd := s.sumOfSquaredDeviations.Load(); ssd != snapshot.sumOfSquaredDeviations {
		snapshot.sumOfSquaredDeviations = ssd
		goto retry
	}
	if min := s.min.Load(); min != snapshot.min {
		snapshot.min = min
		goto retry
	}
	if max := s.max.Load(); max != snapshot.max {
		snapshot.max = max
		goto retry
	}
	return snapshot
}

// AddSample adds a sample to the distribution.
// This *must* be called with the correct number of fields, or it will panic.
// +checkescape:all
//
//go:nosplit
func (d *DistributionMetric) AddSample(sample int64, fields ...*FieldValue) {
	d.addSampleByKey(sample, d.fieldsToKey.lookup(fields...))
}

// addSampleByKey works like AddSample, with the field key already known.
// +checkescape:all
//
//go:nosplit
func (d *DistributionMetric) addSampleByKey(sample int64, key int) {
	bucket := d.exponentialBucketer.BucketIndex(sample)
	d.samples[key][bucket+1].Add(1)
	d.statistics[key].Update(sample)
}

// Minimum number of buckets for NewDurationBucket.
const durationMinBuckets = 3

// NewDurationBucketer returns a Bucketer well-suited for measuring durations in
// nanoseconds. Useful for NewTimerMetric.
// minDuration and maxDuration are conservative estimates of the minimum and
// maximum durations expected to be accurately measured by the Bucketer.
func NewDurationBucketer(numFiniteBuckets int, minDuration, maxDuration time.Duration) Bucketer {
	if numFiniteBuckets < durationMinBuckets {
		panic(fmt.Sprintf("duration bucketer must have at least %d buckets, got %d", durationMinBuckets, numFiniteBuckets))
	}
	minNs := minDuration.Nanoseconds()
	exponentCoversNs := float64(maxDuration.Nanoseconds()-int64(numFiniteBuckets-durationMinBuckets)*minNs) / float64(minNs)
	exponent := math.Log(exponentCoversNs) / math.Log(float64(numFiniteBuckets-durationMinBuckets))
	minNs = int64(float64(minNs) / exponent)
	return NewExponentialBucketer(numFiniteBuckets, uint64(minNs), float64(minNs), exponent)
}

// TimerMetric wraps a distribution metric with convenience functions for
// latency measurements, which is a popular specialization of distribution
// metrics.
type TimerMetric struct {
	DistributionMetric
}

// NewTimerMetric provides a convenient way to measure latencies.
// The arguments are the same as `NewDistributionMetric`, except:
//   - `nanoBucketer`: Same as `NewDistribution`'s `bucketer`, expected to hold
//     durations in nanoseconds. Adjust parameters accordingly.
//     NewDurationBucketer may be helpful here.
func NewTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) (*TimerMetric, error) {
	distrib, err := NewDistributionMetric(name, false, nanoBucketer, pb.MetricMetadata_UNITS_NANOSECONDS, description, fields...)
	if err != nil {
		return nil, err
	}
	return &TimerMetric{
		DistributionMetric: *distrib,
	}, nil
}

// MustCreateNewTimerMetric creates and registers a timer metric.
// If an error occurs, it panics.
func MustCreateNewTimerMetric(name string, nanoBucketer Bucketer, description string, fields ...Field) *TimerMetric {
	timer, err := NewTimerMetric(name, nanoBucketer, description, fields...)
	if err != nil {
		panic(err)
	}
	return timer
}

// TimedOperation is used by TimerMetric to keep track of the time elapsed
// between an operation starting and stopping.
type TimedOperation struct {
	// metric is a reference to the timer metric for the operation.
	metric *TimerMetric

	// partialFields is a prefix of the fields used in this operation.
	// The rest of the fields is provided in TimedOperation.Finish.
	partialFields []*FieldValue

	// startedNs is the number of nanoseconds measured in TimerMetric.Start().
	startedNs int64
}

// Start starts a timer measurement for the given combination of fields.
// It returns a TimedOperation which can be passed around as necessary to
// measure the duration of the operation.
// Once the operation is finished, call Finish on the TimedOperation.
// The fields passed to Start may be partially specified; if so, the remaining
// fields must be passed to TimedOperation.Finish. This is useful for cases
// where which path an operation took is only known after it happens. This
// path can be part of the fields passed to Finish.
// +checkescape:all
//
//go:nosplit
func (t *TimerMetric) Start(fields ...*FieldValue) TimedOperation {
	return TimedOperation{
		metric:        t,
		partialFields: fields,
		startedNs:     CheapNowNano(),
	}
}

// Finish marks an operation as finished and records its duration.
// `extraFields` is the rest of the fields appended to the fields passed to
// `TimerMetric.Start`. The concatenation of these two must be the exact
// number of fields that the underlying metric has.
// +checkescape:all
//
//go:nosplit
func (o TimedOperation) Finish(extraFields ...*FieldValue) {
	ended := CheapNowNano()
	fieldKey := o.metric.fieldsToKey.lookupConcat(o.partialFields, extraFields)
	o.metric.addSampleByKey(ended-o.startedNs, fieldKey)
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
	// Metric registration data for all the metrics below.
	registration *pb.MetricRegistration

	// Map of uint64 metrics.
	uint64Metrics map[string]customUint64Metric

	// Map of distribution metrics.
	distributionMetrics map[string]*DistributionMetric

	// mu protects the fields below.
	mu sync.RWMutex

	// Information about the stages reached by the Sentry. Only appended to, so
	// reading a shallow copy of the slice header concurrently is safe.
	finished []stageTiming

	// The current stage in progress.
	currentStage stageTiming
}

// makeMetricSet returns a new metricSet.
func makeMetricSet() *metricSet {
	return &metricSet{
		uint64Metrics:       make(map[string]customUint64Metric),
		distributionMetrics: make(map[string]*DistributionMetric),
		finished:            make([]stageTiming, 0, len(allStages)),
	}
}

// Values returns a snapshot of all values in m.
func (m *metricSet) Values() metricValues {
	m.mu.Lock()
	stages := m.finished[:]
	m.mu.Unlock()

	vals := metricValues{
		uint64Metrics:            make(map[string]any, len(m.uint64Metrics)),
		distributionMetrics:      make(map[string][][]uint64, len(m.distributionMetrics)),
		distributionTotalSamples: make(map[string][]uint64, len(m.distributionMetrics)),
		distributionStatistics:   make(map[string][]distributionStatisticsSnapshot, len(m.distributionMetrics)),
		stages:                   stages,
	}
	for k, v := range m.uint64Metrics {
		fields := v.fields
		switch len(fields) {
		case 0:
			vals.uint64Metrics[k] = v.value()
		case 1:
			fieldsMap := make(map[*FieldValue]uint64)
			if v.forEachNonZero != nil {
				v.forEachNonZero(func(fieldValues []*FieldValue, val uint64) {
					fieldsMap[fieldValues[0]] = val
				})
			} else {
				for _, fieldValue := range fields[0].values {
					fieldsMap[fieldValue] = v.value(fieldValue)
				}
			}
			vals.uint64Metrics[k] = fieldsMap
		default:
			panic(fmt.Sprintf("Unsupported number of metric fields: %d", len(fields)))
		}
	}
	for name, metric := range m.distributionMetrics {
		fieldKeysToValues := make([][]uint64, len(metric.samples))
		fieldKeysToTotalSamples := make([]uint64, len(metric.samples))
		fieldKeysToStatistics := make([]distributionStatisticsSnapshot, len(metric.samples))
		for fieldKey, samples := range metric.samples {
			samplesSnapshot := snapshotDistribution(samples)
			totalSamples := uint64(0)
			for _, bucket := range samplesSnapshot {
				totalSamples += bucket
			}
			if totalSamples == 0 {
				// No samples recorded for this combination of field, so leave
				// the maps for this fieldKey as nil. This lessens the memory cost
				// of distributions with unused field combinations.
				fieldKeysToTotalSamples[fieldKey] = 0
				fieldKeysToStatistics[fieldKey] = distributionStatisticsSnapshot{}
				fieldKeysToValues[fieldKey] = nil
			} else {
				fieldKeysToTotalSamples[fieldKey] = totalSamples
				fieldKeysToStatistics[fieldKey] = metric.statistics[fieldKey].Load()
				fieldKeysToValues[fieldKey] = samplesSnapshot
			}
		}
		vals.distributionMetrics[name] = fieldKeysToValues
		vals.distributionTotalSamples[name] = fieldKeysToTotalSamples
		vals.distributionStatistics[name] = fieldKeysToStatistics
	}
	return vals
}

// metricValues contains a copy of the values of all metrics.
type metricValues struct {
	// uint64Metrics is a map of uint64 metrics,
	// with key as metric name. Value can be either uint64, or map[*FieldValue]uint64
	// to support metrics with one field.
	uint64Metrics map[string]any

	// distributionMetrics is a map of distribution metrics.
	// The first key level is the metric name.
	// The second key level is an index ID corresponding to the combination of
	// field values. The index is decoded to field strings using keyToMultiField.
	// The slice value is the number of samples in each bucket of the
	// distribution, with the first (0-th) element being the underflow bucket
	// and the last element being the "infinite" (overflow) bucket.
	// The slice value may also be nil for field combinations with no samples.
	// This saves memory by avoiding storing anything for unused field
	// combinations.
	distributionMetrics map[string][][]uint64

	// distributionTotalSamples is the total number of samples for each
	// distribution metric and field values.
	// It allows performing a quick diff between snapshots without having to
	// iterate over all the buckets individually, so that distributions with
	// no new samples are not retransmitted.
	distributionTotalSamples map[string][]uint64

	// distributionStatistics is a set of statistics about the samples.
	distributionStatistics map[string][]distributionStatisticsSnapshot

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
//   - Initialize has been called.
func EmitMetricUpdate() {
	emitMu.Lock()
	defer emitMu.Unlock()

	snapshot := allMetrics.Values()

	m := pb.MetricUpdate{}
	// On the first call metricsAtLastEmit will be empty. Include all
	// metrics then.
	for k, v := range snapshot.uint64Metrics {
		prev, ok := metricsAtLastEmit.uint64Metrics[k]
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
		case map[*FieldValue]uint64:
			for fieldValue, metricValue := range t {
				// Emit data on the first call only if the field
				// value has been incremented. For all other
				// calls, emit data if the field value has been
				// changed from the previous emit.
				if (!ok && metricValue == 0) || (ok && prev.(map[*FieldValue]uint64)[fieldValue] == metricValue) {
					continue
				}

				m.Metrics = append(m.Metrics, &pb.MetricValue{
					Name:        k,
					FieldValues: []string{fieldValue.Value},
					Value:       &pb.MetricValue_Uint64Value{Uint64Value: metricValue},
				})
			}
		default:
			panic(fmt.Sprintf("unsupported type in uint64Metrics: %T (%v)", v, v))
		}
	}
	for name, dist := range snapshot.distributionTotalSamples {
		prev, ok := metricsAtLastEmit.distributionTotalSamples[name]
		for fieldKey, currentTotal := range dist {
			if currentTotal == 0 {
				continue
			}
			if ok {
				if prevTotal := prev[fieldKey]; prevTotal == currentTotal {
					continue
				}
			}
			oldSamples := metricsAtLastEmit.distributionMetrics[name]
			var newSamples []uint64
			if oldSamples != nil && oldSamples[fieldKey] != nil {
				currentSamples := snapshot.distributionMetrics[name][fieldKey]
				numBuckets := len(currentSamples)
				newSamples = make([]uint64, numBuckets)
				for i := 0; i < numBuckets; i++ {
					newSamples[i] = currentSamples[i] - oldSamples[fieldKey][i]
				}
			} else {
				// oldSamples == nil means that the previous snapshot has no samples.
				// This means the delta is the current number of samples, no need for
				// a copy.
				newSamples = snapshot.distributionMetrics[name][fieldKey]
			}
			m.Metrics = append(m.Metrics, &pb.MetricValue{
				Name:        name,
				FieldValues: allMetrics.distributionMetrics[name].fieldsToKey.keyToMultiField(fieldKey),
				Value: &pb.MetricValue_DistributionValue{
					DistributionValue: &pb.Samples{
						NewSamples: newSamples,
					},
				},
			})
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
			return m.Metrics[i].GetName() < m.Metrics[j].GetName()
		})
		log.Debugf("Emitting metrics:")
		for _, metric := range m.Metrics {
			var valueStr string
			switch metric.GetValue().(type) {
			case *pb.MetricValue_Uint64Value:
				valueStr = fmt.Sprintf("%d", metric.GetUint64Value())
			case *pb.MetricValue_DistributionValue:
				valueStr = fmt.Sprintf("new distribution samples: %+v", metric.GetDistributionValue())
			default:
				valueStr = "unsupported type"
			}
			if len(metric.GetFieldValues()) > 0 {
				var foundMetadata *pb.MetricMetadata
				if metricObj, found := allMetrics.uint64Metrics[metric.GetName()]; found {
					foundMetadata = metricObj.metadata
				} else if metricObj, found := allMetrics.distributionMetrics[metric.GetName()]; found {
					foundMetadata = metricObj.metadata
				}
				if foundMetadata == nil || len(foundMetadata.GetFields()) != len(metric.GetFieldValues()) {
					// This should never happen, but if it somehow does, we don't want to crash here, as
					// this is debug output that may already be printed in the context of panic.
					log.Debugf("%s%v (cannot find metric definition!): %s", metric.GetName(), metric.GetFieldValues(), valueStr)
					continue
				}
				var sb strings.Builder
				for i, fieldValue := range metric.GetFieldValues() {
					if i > 0 {
						sb.WriteRune(',')
					}
					sb.WriteString(foundMetadata.GetFields()[i].GetFieldName())
					sb.WriteRune('=')
					sb.WriteString(fieldValue)
				}
				log.Debugf("  Metric %s[%s]: %s", metric.GetName(), sb.String(), valueStr)
			} else {
				log.Debugf("  Metric %s: %s", metric.GetName(), valueStr)
			}
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

// SnapshotOptions controls how snapshots are exported in GetSnapshot.
type SnapshotOptions struct {
	// Filter, if set, should return true for metrics that should be written to
	// the snapshot. If unset, all metrics are written to the snapshot.
	Filter func(*prometheus.Metric) bool
}

// GetSnapshot returns a Prometheus snapshot of the metric data.
// Returns ErrNotYetInitialized if metrics have not yet been initialized.
func GetSnapshot(options SnapshotOptions) (*prometheus.Snapshot, error) {
	if !initialized.Load() {
		return nil, ErrNotYetInitialized
	}
	values := allMetrics.Values()
	snapshot := prometheus.NewSnapshot()
	for k, v := range values.uint64Metrics {
		m := allMetrics.uint64Metrics[k]
		if options.Filter != nil && !options.Filter(m.prometheusMetric) {
			continue
		}
		switch t := v.(type) {
		case uint64:
			if m.metadata.GetCumulative() && t == 0 {
				// Zero-valued counter, ignore.
				continue
			}
			snapshot.Add(prometheus.NewIntData(m.prometheusMetric, int64(t)))
		case map[*FieldValue]uint64:
			for fieldValue, metricValue := range t {
				if m.metadata.GetCumulative() && metricValue == 0 {
					// Zero-valued counter, ignore.
					continue
				}
				snapshot.Add(prometheus.LabeledIntData(m.prometheusMetric, map[string]string{
					// uint64 metrics currently only support at most one field name.
					m.metadata.Fields[0].GetFieldName(): fieldValue.Value,
				}, int64(metricValue)))
			}
		default:
			panic(fmt.Sprintf("unsupported type in uint64Metrics: %T (%v)", v, v))
		}
	}
	for k, dists := range values.distributionTotalSamples {
		m := allMetrics.distributionMetrics[k]
		if options.Filter != nil && !options.Filter(m.prometheusMetric) {
			continue
		}
		distributionSamples := values.distributionMetrics[k]
		numFiniteBuckets := m.exponentialBucketer.NumFiniteBuckets()
		statistics := values.distributionStatistics[k]
		for fieldKey := range dists {
			var labels map[string]string
			if numFields := m.fieldsToKey.numKeys(); numFields > 0 {
				labels = make(map[string]string, numFields)
				for fieldIndex, field := range m.fieldsToKey.keyToMultiField(fieldKey) {
					labels[m.metadata.Fields[fieldIndex].GetFieldName()] = field
				}
			}
			currentSamples := distributionSamples[fieldKey]
			buckets := make([]prometheus.Bucket, numFiniteBuckets+2)
			samplesForFieldKey := uint64(0)
			for b := 0; b < numFiniteBuckets+2; b++ {
				var upperBound prometheus.Number
				if b == numFiniteBuckets+1 {
					upperBound = prometheus.Number{Float: math.Inf(1)} // Overflow bucket.
				} else {
					upperBound = prometheus.Number{Int: m.exponentialBucketer.LowerBound(b)}
				}
				samples := uint64(0)
				if currentSamples != nil {
					samples = currentSamples[b]
					samplesForFieldKey += samples
				}
				buckets[b] = prometheus.Bucket{
					Samples:    samples,
					UpperBound: upperBound,
				}
			}
			if samplesForFieldKey == 0 {
				// Zero-valued distribution (no samples in any bucket for this field
				// combination). Ignore.
				continue
			}
			snapshot.Add(&prometheus.Data{
				Metric: m.prometheusMetric,
				Labels: labels,
				HistogramValue: &prometheus.Histogram{
					Total:                  prometheus.Number{Int: statistics[fieldKey].sampleSum},
					SumOfSquaredDeviations: prometheus.Number{Float: statistics[fieldKey].sumOfSquaredDeviations},
					Min:                    prometheus.Number{Int: statistics[fieldKey].min},
					Max:                    prometheus.Number{Int: statistics[fieldKey].max},
					Buckets:                buckets,
				},
			})
		}
	}
	return snapshot, nil
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
