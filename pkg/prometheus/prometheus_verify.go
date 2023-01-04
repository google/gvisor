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

package prometheus

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
	"unicode"

	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

const (
	// maxExportStaleness is the maximum allowed age of a snapshot when it is verified.
	// Used to avoid exporting snapshots from bogus times from ages past.
	maxExportStaleness = 10 * time.Second
)

// verifiableMetric verifies a single metric within a Verifier.
type verifiableMetric struct {
	metadata              *pb.MetricMetadata
	wantMetric            Metric
	numFields             int
	allowedFieldValues    map[string]map[string]struct{}
	wantBucketUpperBounds []Number

	// The following fields are used to verify that values are actually increasing monotonically.
	// They are only read and modified when the parent Verifier.mu is held.
	// They are mapped by their combination of field values.

	// lastCounterValue is used for counter metrics.
	lastCounterValue map[string]Number

	// lastBucketSamples is used for distribution ("histogram") metrics.
	lastBucketSamples map[string][]uint64
}

// newVerifiableMetric creates a new verifiableMetric that can verify the
// values of a metric with the given metadata.
func newVerifiableMetric(metadata *pb.MetricMetadata) (*verifiableMetric, error) {
	if metadata.GetName() == "" || metadata.GetPrometheusName() == "" {
		return nil, errors.New("metric has no name")
	}
	if !unicode.IsLower(rune(metadata.GetPrometheusName()[0])) {
		return nil, fmt.Errorf("invalid initial character in prometheus metric name: %q", metadata.GetPrometheusName())
	}
	for _, r := range metadata.GetPrometheusName() {
		if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '_' {
			return nil, fmt.Errorf("invalid character %c in prometheus metric name %q", r, metadata.GetPrometheusName())
		}
	}
	numFields := len(metadata.GetFields())
	var allowedFieldValues map[string]map[string]struct{}
	if numFields > 0 {
		seenFields := make(map[string]struct{}, numFields)
		allowedFieldValues = make(map[string]map[string]struct{}, numFields)
		for _, field := range metadata.GetFields() {
			fieldName := field.GetFieldName()
			if _, alreadyExists := seenFields[fieldName]; alreadyExists {
				return nil, fmt.Errorf("field %s is defined twice", fieldName)
			}
			seenFields[fieldName] = struct{}{}
			if len(field.GetAllowedValues()) == 0 {
				return nil, fmt.Errorf("field %s has no allowed values", fieldName)
			}
			fieldValues := make(map[string]struct{}, len(field.GetAllowedValues()))
			for _, value := range field.GetAllowedValues() {
				if _, alreadyExists := fieldValues[value]; alreadyExists {
					return nil, fmt.Errorf("field %s has duplicate allowed value %q", fieldName, value)
				}
				fieldValues[value] = struct{}{}
			}
			allowedFieldValues[fieldName] = fieldValues
		}
	}
	v := &verifiableMetric{
		metadata: metadata,
		wantMetric: Metric{
			Name: metadata.GetPrometheusName(),
			Help: metadata.GetDescription(),
		},
		numFields:          numFields,
		allowedFieldValues: allowedFieldValues,
	}
	numFieldCombinations := len(allowedFieldValues)
	switch metadata.GetType() {
	case pb.MetricMetadata_TYPE_UINT64:
		v.wantMetric.Type = TypeGauge
		if metadata.GetCumulative() {
			v.wantMetric.Type = TypeCounter
			v.lastCounterValue = make(map[string]Number, numFieldCombinations)
		}
	case pb.MetricMetadata_TYPE_DISTRIBUTION:
		v.wantMetric.Type = TypeHistogram
		numBuckets := len(metadata.GetDistributionBucketLowerBounds()) + 1
		if numBuckets <= 1 || numBuckets > 256 {
			return nil, fmt.Errorf("unsupported number of buckets: %d", numBuckets)
		}
		v.wantBucketUpperBounds = make([]Number, numBuckets)
		for i, boundary := range metadata.GetDistributionBucketLowerBounds() {
			v.wantBucketUpperBounds[i] = Number{Int: boundary}
		}
		v.wantBucketUpperBounds[numBuckets-1] = Number{Float: math.Inf(1)}
		v.lastBucketSamples = make(map[string][]uint64, numFieldCombinations)
	default:
		return nil, fmt.Errorf("invalid type: %v", metadata.GetType())
	}
	return v, nil
}

func (v *verifiableMetric) numFieldCombinations() int {
	return len(v.allowedFieldValues)
}

// verify does read-only checks on `data`.
// `metricFieldsSeen` is passed across calls to `verify`. It is used to track the set of metric
// field values that have already been seen. `verify` should populate this.
// `dataToFieldsSeen` is passed across calls to `verify` and other methods of `verifiableMetric`.
// It is used to store the canonical representation of the field values seen for each *Data.
func (v *verifiableMetric) verify(data *Data, metricFieldsSeen map[string]struct{}, dataToFieldsSeen map[*Data]string) error {
	if *data.Metric != v.wantMetric {
		return fmt.Errorf("invalid metric definition: got %+v want %+v", data.Metric, v.wantMetric)
	}

	// Verify fields.
	if len(data.Labels) != v.numFields {
		return fmt.Errorf("invalid number of fields: got %d want %d", len(data.Labels), v.numFields)
	}
	var fieldValues strings.Builder
	firstField := true
	for _, field := range v.metadata.GetFields() {
		fieldName := field.GetFieldName()
		value, found := data.Labels[fieldName]
		if !found {
			return fmt.Errorf("did not specify field %q", fieldName)
		}
		if _, allowed := v.allowedFieldValues[fieldName][value]; !allowed {
			return fmt.Errorf("value %q is not allowed for field %s", value, fieldName)
		}
		if !firstField {
			fieldValues.WriteRune(',')
		}
		fieldValues.WriteString(value)
		firstField = false
	}
	fieldValuesStr := fieldValues.String()
	if _, alreadySeen := metricFieldsSeen[fieldValuesStr]; alreadySeen {
		return fmt.Errorf("combination of field values %q was already seen", fieldValuesStr)
	}

	// Verify value.
	gotNumber := data.Number != nil
	gotHistogram := data.HistogramValue != nil
	numSpecified := 0
	if gotNumber {
		numSpecified++
	}
	if gotHistogram {
		numSpecified++
	}
	if numSpecified != 1 {
		return fmt.Errorf("invalid number of value fields specified: %d", numSpecified)
	}
	switch v.metadata.GetType() {
	case pb.MetricMetadata_TYPE_UINT64:
		if !gotNumber {
			return errors.New("expected number value for gauge or counter")
		}
		if !data.Number.IsInteger() {
			return fmt.Errorf("integer metric got non-integer value: %v", data.Number)
		}
	case pb.MetricMetadata_TYPE_DISTRIBUTION:
		if !gotHistogram {
			return errors.New("expected histogram value for histogram")
		}
		if len(data.HistogramValue.Buckets) != len(v.wantBucketUpperBounds) {
			return fmt.Errorf("invalid number of buckets: got %d want %d", len(data.HistogramValue.Buckets), len(v.wantBucketUpperBounds))
		}
		for i, b := range data.HistogramValue.Buckets {
			if want := v.wantBucketUpperBounds[i]; b.UpperBound != want {
				return fmt.Errorf("invalid upper bound for bucket %d (0-based): got %v want %v", i, b.UpperBound, want)
			}
		}
	default:
		return fmt.Errorf("invalid metric type: %v", v.wantMetric.Type)
	}

	// All passed. Update the maps that are shared across calls.
	dataToFieldsSeen[data] = fieldValuesStr
	metricFieldsSeen[fieldValuesStr] = struct{}{}
	return nil
}

// verifyIncrement verifies that incremental metrics are monotonically increasing.
// Preconditions: `verify` has succeeded on the given `data`, and `Verifier.mu` is held.
func (v *verifiableMetric) verifyIncrement(data *Data, fieldValues string) error {
	switch v.wantMetric.Type {
	case TypeCounter:
		last := v.lastCounterValue[fieldValues]
		if !last.SameType(data.Number) {
			return fmt.Errorf("counter number type changed: %v vs %v", last, data.Number)
		}
		if last.GreaterThan(data.Number) {
			return fmt.Errorf("counter value decreased from %v to %v", last, data.Number)
		}
	case TypeHistogram:
		lastBucketSamples := v.lastBucketSamples[fieldValues]
		if lastBucketSamples == nil {
			lastBucketSamples = make([]uint64, len(v.wantBucketUpperBounds))
			v.lastBucketSamples[fieldValues] = lastBucketSamples
		}
		for i, b := range data.HistogramValue.Buckets {
			if lastBucketSamples[i] > b.Samples {
				return fmt.Errorf("number of samples in bucket %d (0-based) decreased from %d to %d", i, lastBucketSamples[i], b.Samples)
			}
		}
	}
	return nil
}

// update updates incremental metrics' "last seen" data.
// Preconditions: `verifyIncrement` has succeeded on the given `data`, and `Verifier.mu` is held.
func (v *verifiableMetric) update(data *Data, fieldValues string) {
	switch v.wantMetric.Type {
	case TypeCounter:
		v.lastCounterValue[fieldValues] = *data.Number
	case TypeHistogram:
		lastBucketSamples := v.lastBucketSamples[fieldValues]
		for i, b := range data.HistogramValue.Buckets {
			lastBucketSamples[i] = b.Samples
		}
	}
}

// Verifier allows verifying metric snapshot against metric registration data.
// The aim is to prevent a compromised Sentry from emitting bogus data or DoS'ing metric ingestion.
// A single Verifier should be used per sandbox. It is expected to be reused across exports such
// that it can enforce the export snapshot timestamp is strictly monotonically increasing.
type Verifier struct {
	knownMetrics  map[string]*verifiableMetric
	mu            sync.Mutex
	lastTimestamp time.Time
}

// NewVerifier returns a new metric verifier that can verify the integrity of snapshots against
// the given metric registration data.
func NewVerifier(registration *pb.MetricRegistration) (*Verifier, error) {
	knownMetrics := make(map[string]*verifiableMetric)
	for _, metric := range registration.GetMetrics() {
		metricName := metric.GetPrometheusName()
		if _, alreadyExists := knownMetrics[metricName]; alreadyExists {
			return nil, fmt.Errorf("metric %q registered twice", metricName)
		}
		verifiableM, err := newVerifiableMetric(metric)
		if err != nil {
			return nil, fmt.Errorf("metric %q: %v", metricName, err)
		}
		knownMetrics[metricName] = verifiableM
	}
	return &Verifier{
		knownMetrics: knownMetrics,
	}, nil
}

// Verify verifies the integrity of a snapshot against the metric registration data of the Verifier.
// It assumes that it will be called on snapshots obtained chronologically over time.
func (v *Verifier) Verify(snapshot *Snapshot) error {
	var err error

	// Basic timestamp checks.
	now := timeNow()
	if snapshot.When.After(now) {
		return errors.New("snapshot is from the future")
	}
	if snapshot.When.Before(now.Add(-maxExportStaleness)) {
		return fmt.Errorf("snapshot is too old; it is from %v, expected at least %v (%v from now)", snapshot.When, now.Add(-maxExportStaleness), maxExportStaleness)
	}

	// Metrics checks.
	fieldsSeen := make(map[string]map[string]struct{}, len(v.knownMetrics))
	dataToFieldsSeen := make(map[*Data]string, len(snapshot.Data))
	for _, data := range snapshot.Data {
		metricName := data.Metric.Name
		verifiableM, found := v.knownMetrics[metricName]
		if !found {
			return fmt.Errorf("snapshot contains unknown metric %q", metricName)
		}
		metricFieldsSeen, found := fieldsSeen[metricName]
		if !found {
			metricFieldsSeen = make(map[string]struct{}, verifiableM.numFieldCombinations())
			fieldsSeen[metricName] = metricFieldsSeen
		}
		if err = verifiableM.verify(data, metricFieldsSeen, dataToFieldsSeen); err != nil {
			return fmt.Errorf("metric %q: %v", metricName, err)
		}
	}

	// Start the critical section.
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.lastTimestamp.After(snapshot.When) {
		return fmt.Errorf("consecutive snapshots are not chronologically ordered: last verified snapshot was exported at %v, this one is from %v", v.lastTimestamp, snapshot.When)
	}
	for _, data := range snapshot.Data {
		if err = v.knownMetrics[data.Metric.Name].verifyIncrement(data, dataToFieldsSeen[data]); err != nil {
			return fmt.Errorf("metric %q: %v", data.Metric.Name, err)
		}
	}

	// All checks succeeded, update last-seen data.
	v.lastTimestamp = snapshot.When
	for _, data := range snapshot.Data {
		v.knownMetrics[data.Metric.Name].update(data, dataToFieldsSeen[data])
	}
	return nil
}
