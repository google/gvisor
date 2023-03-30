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
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	v1proto "github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

// timeNowMu is used to synchronize injection of time.Now.
var timeNowMu sync.Mutex

// at executes a function with the clock returning a given time.
func at(when time.Time, f func()) {
	timeNowMu.Lock()
	defer timeNowMu.Unlock()
	previousFunc := timeNow
	timeNow = func() time.Time { return when }
	defer func() { timeNow = previousFunc }()
	f()
}

// newSnapshotAt creates a new Snapshot with the given timestamp.
func newSnapshotAt(when time.Time) *Snapshot {
	var s *Snapshot
	at(when, func() {
		s = NewSnapshot()
	})
	return s
}

// Helper builder type for metric metadata.
type metricMetadata struct {
	PB     *pb.MetricMetadata
	Fields map[string]string
}

func (m *metricMetadata) clone() *metricMetadata {
	m2 := &metricMetadata{
		PB:     &pb.MetricMetadata{},
		Fields: make(map[string]string, len(m.Fields)),
	}
	proto.Merge(m2.PB, m.PB)
	for k, v := range m.Fields {
		m2.Fields[k] = v
	}
	return m2
}

// withField returns a copy of this *metricMetadata with the given field added
// to its metadata.
func (m *metricMetadata) withField(fields ...*pb.MetricMetadata_Field) *metricMetadata {
	m2 := m.clone()
	m2.PB.Fields = make([]*pb.MetricMetadata_Field, 0, len(m.Fields)+len(fields))
	copy(m2.PB.Fields, m.PB.Fields)
	m2.PB.Fields = append(m2.PB.Fields, fields...)
	return m2
}

// metric returns the Metric metadata struct for this metric metadata.
func (m *metricMetadata) metric() *Metric {
	var metricType Type
	switch m.PB.GetType() {
	case pb.MetricMetadata_TYPE_UINT64:
		if m.PB.GetCumulative() {
			metricType = TypeCounter
		} else {
			metricType = TypeGauge
		}
	case pb.MetricMetadata_TYPE_DISTRIBUTION:
		metricType = TypeHistogram
	default:
		panic(fmt.Sprintf("invalid type %v", m.PB.GetType()))
	}
	return &Metric{
		Name: m.PB.GetPrometheusName(),
		Type: metricType,
		Help: m.PB.GetDescription(),
	}
}

// Convenient metric field metadata definitions.
var (
	field1 = &pb.MetricMetadata_Field{
		FieldName:     "field1",
		AllowedValues: []string{"val1a", "val1b"},
	}
	field2 = &pb.MetricMetadata_Field{
		FieldName:     "field2",
		AllowedValues: []string{"val2a", "val2b"},
	}
)

// fieldVal returns a copy of this *metricMetadata with the given field-value
// stored on the side of the metadata. Meant to be used during snapshot data
// construction, where methods like int() make it easy to construct *Data
// structs with field values.
func (m *metricMetadata) fieldVal(field *pb.MetricMetadata_Field, val string) *metricMetadata {
	return m.fieldVals(map[*pb.MetricMetadata_Field]string{field: val})
}

// fieldVals acts like fieldVal but for multiple fields, at the expense of
// having a less convenient function signature.
func (m *metricMetadata) fieldVals(fieldToVal map[*pb.MetricMetadata_Field]string) *metricMetadata {
	m2 := m.clone()
	for field, val := range fieldToVal {
		m2.Fields[field.GetFieldName()] = val
	}
	return m2
}

// labels returns a label key-value map associated with the metricMetadata.
func (m *metricMetadata) labels() map[string]string {
	if len(m.Fields) == 0 {
		return nil
	}
	return m.Fields
}

// int returns a new Data struct with the given value for the current metric.
// If the current metric has fields, all of its fields must accept exactly one
// value, and this value will be used as the value for that field.
// If a field accepts multiple values, the function will panic.
func (m *metricMetadata) int(val int64) *Data {
	data := NewIntData(m.metric(), val)
	data.Labels = m.labels()
	return data
}

// float returns a new Data struct with the given value for the current metric.
// If the current metric has fields, all of its fields must accept exactly one
// value, and this value will be used as the value for that field.
// If a field accepts multiple values, the function will panic.
func (m *metricMetadata) float(val float64) *Data {
	data := NewFloatData(m.metric(), val)
	data.Labels = m.labels()
	return data
}

// float returns a new Data struct with the given value for the current metric.
// If the current metric has fields, all of its fields must accept exactly one
// value, and this value will be used as the value for that field.
// If a field accepts multiple values, the function will panic.
func (m *metricMetadata) dist(samples ...int64) *Data {
	var total int64
	buckets := make([]Bucket, len(m.PB.GetDistributionBucketLowerBounds())+1)
	var bucket *Bucket
	for i, lowerBound := range m.PB.GetDistributionBucketLowerBounds() {
		(&buckets[i]).UpperBound = Number{Int: lowerBound}
	}
	(&buckets[len(buckets)-1]).UpperBound = Number{Float: math.Inf(1)}
	for _, sample := range samples {
		total += sample
		bucket = &buckets[0]
		for i, lowerBound := range m.PB.GetDistributionBucketLowerBounds() {
			if sample >= lowerBound {
				bucket = &buckets[i+1]
			} else {
				break
			}
		}
		bucket.Samples++
	}
	return &Data{
		Metric: m.metric(),
		Labels: m.labels(),
		HistogramValue: &Histogram{
			Total:   Number{Int: total},
			Buckets: buckets,
		},
	}
}

// Convenient metric metadata definitions.
var (
	fooInt = &metricMetadata{
		PB: &pb.MetricMetadata{
			Name:           "fooInt",
			PrometheusName: "foo_int",
			Description:    "An integer about foo",
			Cumulative:     false,
			Units:          pb.MetricMetadata_UNITS_NONE,
			Sync:           true,
			Type:           pb.MetricMetadata_TYPE_UINT64,
		},
	}
	fooCounter = &metricMetadata{
		PB: &pb.MetricMetadata{
			Name:           "fooCounter",
			PrometheusName: "foo_counter",
			Description:    "A counter of foos",
			Cumulative:     true,
			Units:          pb.MetricMetadata_UNITS_NONE,
			Sync:           true,
			Type:           pb.MetricMetadata_TYPE_UINT64,
		},
	}
	fooDist = &metricMetadata{
		PB: &pb.MetricMetadata{
			Name:                          "fooDist",
			PrometheusName:                "foo_dist",
			Description:                   "A distribution about foo",
			Cumulative:                    false,
			Units:                         pb.MetricMetadata_UNITS_NONE,
			Sync:                          true,
			Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
			DistributionBucketLowerBounds: []int64{0, 1, 2, 4, 8},
		},
	}
)

// newMetricRegistration returns a new *metricRegistration.
func newMetricRegistration(metricMetadata ...*metricMetadata) *pb.MetricRegistration {
	metadatas := make([]*pb.MetricMetadata, len(metricMetadata))
	for i, mm := range metricMetadata {
		metadatas[i] = mm.PB
	}
	return &pb.MetricRegistration{
		Metrics: metadatas,
	}
}

func TestVerifier(t *testing.T) {
	testStart := time.Now()
	epsilon := func(n int) time.Time {
		return testStart.Add(time.Duration(n) * time.Millisecond)
	}
	for _, test := range []struct {
		Name string
		// At is the time at which the test executes.
		// If unset, `testStart` is assumed.
		At time.Time
		// Registration is the metric registration data.
		Registration *pb.MetricRegistration
		// WantVerifierCreationErr is true if the test expects the
		// creation of the Verifier to fail. All the fields below it
		// are ignored in this case.
		WantVerifierCreationErr bool
		// WantSuccess is a sequence of Snapshots to present to
		// the verifier. The test expects all of them to pass verification.
		// If unset, the test simply presents the WantFail Snapshot.
		// If both WantSuccess and WantFail are unset, the test presents
		// an empty snapshot and expects it to succeed.
		WantSuccess []*Snapshot
		// WantFail is a Snapshot to present to the verifier after all
		// snapshots in WantSuccess have been presented.
		// The test expects this Snapshot to fail verification.
		// If unset, the test does not present any snapshot after
		// having presented the WantSuccess Snapshots.
		WantFail *Snapshot
	}{
		{
			Name: "no metrics, empty snapshot",
		},
		{
			Name:                    "duplicate metric",
			Registration:            newMetricRegistration(fooInt, fooInt),
			WantVerifierCreationErr: true,
		},
		{
			Name:                    "duplicate metric with different field set",
			Registration:            newMetricRegistration(fooInt, fooInt.withField(field1)),
			WantVerifierCreationErr: true,
		},
		{
			Name:                    "duplicate field in metric",
			Registration:            newMetricRegistration(fooInt.withField(field1, field1)),
			WantVerifierCreationErr: true,
		},
		{
			Name: "no field allowed value",
			Registration: newMetricRegistration(fooInt.withField(&pb.MetricMetadata_Field{
				FieldName: "field1",
			})),
			WantVerifierCreationErr: true,
		},
		{
			Name: "duplicate field allowed value",
			Registration: newMetricRegistration(fooInt.withField(&pb.MetricMetadata_Field{
				FieldName:     "field1",
				AllowedValues: []string{"val1", "val1"},
			})),
			WantVerifierCreationErr: true,
		},
		{
			Name: "invalid metric type",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "fooBar",
					PrometheusName: "foo_bar",
					Type:           pb.MetricMetadata_Type(1337),
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "empty metric name",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					PrometheusName: "foo_bar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "empty Prometheus metric name",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name: "fooBar",
					Type: pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "bad Prometheus metric name",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "fooBar",
					PrometheusName: "fooBar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "bad first Prometheus metric name character",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "fooBar",
					PrometheusName: "_foo_bar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "Prometheus metric name starts with reserved prefix",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "metaFooBar",
					PrometheusName: "meta_foo_bar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "Prometheus metric name does not starts with reserved prefix but non-Prometheus metric name does",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "metaFooBar",
					PrometheusName: "not_meta_foo_bar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: false,
		},
		{
			Name: "Prometheus metric name matches reserved one",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "doesNotMatter",
					PrometheusName: ProcessStartTimeSeconds.Name,
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "no buckets",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:                          "fooBar",
					PrometheusName:                "foo_bar",
					Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
					DistributionBucketLowerBounds: []int64{},
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "too many buckets",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:                          "fooBar",
					PrometheusName:                "foo_bar",
					Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
					DistributionBucketLowerBounds: make([]int64, 999),
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "successful registration of complex set of metrics",
			Registration: newMetricRegistration(
				fooInt,
				fooCounter.withField(field1, field2),
				fooDist.withField(field2),
			),
		},
		{
			Name: "snapshot time ordering",
			At:   epsilon(0),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)),
				newSnapshotAt(epsilon(-2)),
				newSnapshotAt(epsilon(-1)),
			},
			WantFail: newSnapshotAt(epsilon(-2)),
		},
		{
			Name: "same snapshot time is ok",
			At:   epsilon(0),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)),
				newSnapshotAt(epsilon(-2)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(0)),
				newSnapshotAt(epsilon(0)),
				newSnapshotAt(epsilon(0)),
				newSnapshotAt(epsilon(0)),
			},
		},
		{
			Name:     "snapshot from the future",
			At:       epsilon(0),
			WantFail: newSnapshotAt(epsilon(1)),
		},
		{
			Name:     "snapshot from the long past",
			At:       testStart,
			WantFail: newSnapshotAt(testStart.Add(-25 * time.Hour)),
		},
		{
			Name:         "simple metric update",
			Registration: newMetricRegistration(fooInt),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooInt.int(2),
				),
			},
		},
		{
			Name:         "simple metric update multiple times",
			Registration: newMetricRegistration(fooInt),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooInt.int(2)),
				newSnapshotAt(epsilon(-2)).Add(fooInt.int(-1)),
				newSnapshotAt(epsilon(-1)).Add(fooInt.int(4)),
			},
		},
		{
			Name:         "counter can go forwards",
			Registration: newMetricRegistration(fooCounter),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooCounter.int(1)),
				newSnapshotAt(epsilon(-2)).Add(fooCounter.int(3)),
				newSnapshotAt(epsilon(-1)).Add(fooCounter.int(3)),
			},
		},
		{
			Name:         "counter cannot go backwards",
			Registration: newMetricRegistration(fooCounter),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooCounter.int(1)),
				newSnapshotAt(epsilon(-2)).Add(fooCounter.int(3)),
			},
			WantFail: newSnapshotAt(epsilon(-1)).Add(fooCounter.int(2)),
		},
		{
			Name:         "counter cannot change type",
			Registration: newMetricRegistration(fooCounter),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooCounter.int(1)),
				newSnapshotAt(epsilon(-2)).Add(fooCounter.int(3)),
			},
			WantFail: newSnapshotAt(epsilon(-1)).Add(fooCounter.float(4)),
		},
		{
			Name:         "update for unknown metric",
			Registration: newMetricRegistration(fooInt),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(fooCounter.int(2)),
		},
		{
			Name:         "update for mismatching metric definition: type",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				(&metricMetadata{PB: &pb.MetricMetadata{
					PrometheusName: fooInt.PB.GetPrometheusName(),
					Type:           pb.MetricMetadata_TYPE_DISTRIBUTION,
					Description:    fooInt.PB.GetDescription(),
				}}).int(2),
			),
		},
		{
			Name:         "update for mismatching metric definition: name",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				(&metricMetadata{PB: &pb.MetricMetadata{
					PrometheusName: "not_foo_int",
					Type:           fooInt.PB.GetType(),
					Description:    fooInt.PB.GetDescription(),
				}}).int(2),
			),
		},
		{
			Name:         "update for mismatching metric definition: description",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				(&metricMetadata{PB: &pb.MetricMetadata{
					PrometheusName: fooInt.PB.GetPrometheusName(),
					Type:           fooInt.PB.GetType(),
					Description:    "not fooInt's description",
				}}).int(2),
			),
		},
		{
			Name:         "update with no fields for metric with fields",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(fooInt.int(2)),
		},
		{
			Name:         "update with fields for metric without fields",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field1, "val1a").int(2),
			),
		},
		{
			Name:         "update with invalid field value",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field1, "not_val1a").int(2),
			),
		},
		{
			Name:         "update with valid field value for wrong field",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field2, "val1a").int(2),
			),
		},
		{
			Name:         "update with valid field values provided twice",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field1, "val1a").int(2),
				fooInt.fieldVal(field1, "val1a").int(2),
			),
		},
		{
			Name:         "update with valid field value",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooInt.fieldVal(field1, "val1a").int(7),
					fooInt.fieldVal(field1, "val1b").int(2),
				),
			},
		},
		{
			Name:         "update with multiple valid field value",
			Registration: newMetricRegistration(fooCounter.withField(field1, field2)),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(3),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(2),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2b",
					}).int(1),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2b",
					}).int(4),
				),
			},
		},
		{
			Name:         "update with multiple valid field values but duplicated",
			Registration: newMetricRegistration(fooCounter.withField(field1, field2)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
					field1: "val1b",
					field2: "val2b",
				}).int(4),
				fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
					field1: "val1b",
					field2: "val2b",
				}).int(4),
			),
		},
		{
			Name: "update with same valid field values across two metrics",
			Registration: newMetricRegistration(
				fooInt.withField(field1, field2),
				fooCounter.withField(field1, field2),
			),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooInt.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(3),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(3),
				),
			},
		},
		{
			Name:         "update with multiple value types",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooInt.metric(),
					Number: &Number{Int: 2},
					HistogramValue: &Histogram{
						Total: Number{Int: 5},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 1},
							{UpperBound: Number{Int: 1}, Samples: 1},
						},
					},
				},
			),
		},
		{
			Name:         "integer metric gets float value",
			Registration: newMetricRegistration(fooInt),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(fooInt.float(2.5)),
		},
		{
			Name:         "metric gets no value",
			Registration: newMetricRegistration(fooInt),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(&Data{Metric: fooInt.metric()}),
		},
		{
			Name:         "distribution gets integer value",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooDist.int(2),
			),
		},
		{
			Name:         "successful distribution",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooDist.dist(1, 2, 3, 4, 5, 6),
				),
			},
		},
		{
			Name:         "distribution updates",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-2)).Add(
					fooDist.dist(1, 2, 3, 4, 5, 6),
				),
				newSnapshotAt(epsilon(-1)).Add(
					fooDist.dist(0, 1, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 25),
				),
			},
		},
		{
			Name:         "distribution updates with fields",
			Registration: newMetricRegistration(fooDist.withField(field1)),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-2)).Add(
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6),
				),
				newSnapshotAt(epsilon(-1)).Add(
					fooDist.fieldVal(field1, "val1a").dist(0, 1, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 25),
				),
			},
		},
		{
			Name:         "distribution cannot have number of samples regress",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(
					fooDist.dist(1, 2, 3, 4, 5, 6),
				),
				newSnapshotAt(epsilon(-2)).Add(
					fooDist.dist(0, 1, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 25),
				),
			},
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooDist.dist(0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9),
			),
		},
		{
			Name:         "distribution with zero samples",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 0},
							{UpperBound: Number{Int: 1}, Samples: 0},
							{UpperBound: Number{Int: 2}, Samples: 0},
							{UpperBound: Number{Int: 4}, Samples: 0},
							{UpperBound: Number{Int: 8}, Samples: 0},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 0},
						},
					},
				},
			)},
		},
		{
			Name:         "distribution with manual samples",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 2}, Samples: 3},
							{UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 1},
						},
					},
				},
			)},
		},
		{
			Name:         "distribution gets bad number of buckets",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 2}, Samples: 3},
							// Missing: {UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 1},
						},
					},
				},
			),
		},
		{
			Name:         "distribution gets unexpected bucket boundary",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 3 /* Should be 2 */}, Samples: 3},
							{UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 1},
						},
					},
				},
			),
		},
		{
			Name:         "distribution gets unexpected last bucket boundary",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 2}, Samples: 3},
							{UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{
								UpperBound: Number{Float: math.Inf(-1) /* Should be +inf */},
								Samples:    1,
							},
						},
					},
				},
			),
		},
		{
			Name: "worked example",
			Registration: newMetricRegistration(
				fooInt,
				fooDist.withField(field1),
				fooCounter.withField(field1, field2),
			),
			WantSuccess: []*Snapshot{
				// Empty snapshot.
				newSnapshotAt(epsilon(-6)),
				// Simple snapshot.
				newSnapshotAt(epsilon(-5)).Add(
					fooInt.int(3),
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6),
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(3),
				),
				// And another.
				newSnapshotAt(epsilon(-4)).Add(
					fooInt.int(1),
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6, 7),
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100, 42),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(4),
				),
				// And another one, partial this time.
				newSnapshotAt(epsilon(-3)).Add(
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100, 42, 1337),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
				),
				// An empty one.
				newSnapshotAt(epsilon(-2)),
				// Another empty one at the same timestamp.
				newSnapshotAt(epsilon(-1)),
				// Another full one which doesn't change any value.
				newSnapshotAt(epsilon(0)).Add(
					fooInt.int(1),
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6, 7),
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100, 42, 1337),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(4),
				),
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			testTime := test.At
			if testTime.IsZero() {
				testTime = testStart
			}
			at(testTime, func() {
				t.Logf("Test is running with simulated time: %v", testTime)
				verifier, cleanup, err := NewVerifier(test.Registration)
				defer cleanup()
				if err != nil && !test.WantVerifierCreationErr {
					t.Fatalf("unexpected verifier creation error: %v", err)
				}
				if err == nil && test.WantVerifierCreationErr {
					t.Fatal("verifier creation unexpectedly succeeded")
				}
				if err != nil {
					t.Logf("Verifier creation failed (as expected by this test): %v", err)
					return
				}

				if len(test.WantSuccess) == 0 && test.WantFail == nil {
					if err = verifier.Verify(NewSnapshot()); err != nil {
						t.Errorf("empty snapshot failed verification: %v", err)
					}
				} else {
					for i, snapshot := range test.WantSuccess {
						if err = verifier.Verify(snapshot); err != nil {
							t.Fatalf("snapshot WantSuccess[%d] failed verification: %v", i, err)
						}
					}
					if test.WantFail != nil {
						if err = verifier.Verify(test.WantFail); err == nil {
							t.Error("WantFail snapshot unexpectedly succeeded verification")
						} else {
							t.Logf("WantFail snapshot failed verification (as expected by this test): %v", err)
						}
					}
				}
			})
		})
	}
}

// shortWriter implements io.Writer but fails after a given number of bytes.
type shortWriter struct {
	buf     bytes.Buffer
	size    int
	maxSize int
}

// Reset erases buffer data and resets the shortWriter to the given size.
func (s *shortWriter) Reset(size int) {
	s.buf.Reset()
	s.size = 0
	s.maxSize = size
}

// String returns the buffered data as a string.
func (s *shortWriter) String() string {
	return s.buf.String()
}

// Write implements io.Writer.Write.
func (s *shortWriter) Write(b []byte) (n int, err error) {
	toWrite := len(b)
	leftToWrite := s.maxSize - s.size
	if leftToWrite < toWrite {
		toWrite = leftToWrite
	}
	if toWrite == 0 {
		return 0, errors.New("writer out of capacity")
	}
	written, err := s.buf.Write(b[:toWrite])
	s.size += written
	if written == len(b) {
		return written, err
	}
	return written, errors.New("short write")
}

// reflectProto converts a v1 or v2 proto message to a proto message with
// reflection enabled.
func reflectProto(m any) protoreflect.ProtoMessage {
	if msg, hasReflection := m.(proto.Message); hasReflection {
		return msg
	}
	// Convert v1 proto to introspectable view, if possible and necessary.
	if v1pb, ok := m.(v1proto.Message); ok {
		return v1proto.MessageReflect(v1pb).Interface()
	}
	panic(fmt.Sprintf("Proto message %v isn't of a supported protobuf type", m))
}

// TestSnapshotToPrometheus verifies that the contents of a Snapshot can be
// converted into text that can be parsed by the Prometheus parsing libraries,
// and produces the data we expect them to.
func TestSnapshotToPrometheus(t *testing.T) {
	singleLineFormatter := &prototext.MarshalOptions{Multiline: false, EmitUnknown: true}
	multiLineFormatter := &prototext.MarshalOptions{Multiline: true, Indent: "  ", EmitUnknown: true}
	testStart := time.Now()
	newSnapshot := func() *Snapshot {
		return newSnapshotAt(testStart)
	}
	for _, test := range []struct {
		Name string

		// Snapshot will be rendered as Prometheus and compared against WantData.
		Snapshot *Snapshot

		// ExportOptions dictates the options used during overall rendering.
		ExportOptions ExportOptions

		// SnapshotExportOptions dictates the options used during Snapshot rendering.
		SnapshotExportOptions SnapshotExportOptions

		// WantFail, if true, indicates that the test is expected to fail when
		// rendering or parsing the snapshot data.
		WantFail bool

		// WantData is Prometheus text format that matches the data in Snapshot.
		// The substring "{TIMESTAMP}" will be replaced with the value of
		// `testStart` in milliseconds.
		WantData string
	}{
		{
			Name:     "empty snapshot",
			Snapshot: newSnapshot(),
		},
		{
			Name:     "simple integer",
			Snapshot: newSnapshot().Add(fooInt.int(3)),
			WantData: `
				# HELP foo_int An integer about foo
				# TYPE foo_int gauge
				foo_int 3 {TIMESTAMP}
			`,
		},
		{
			Name:     "simple float",
			Snapshot: newSnapshot().Add(fooInt.float(2.5)),
			WantData: `
				# HELP foo_int An integer about foo
				# TYPE foo_int gauge
				foo_int 2.5 {TIMESTAMP}
			`,
		},
		{
			Name:     "simple counter",
			Snapshot: newSnapshot().Add(fooCounter.int(4)),
			WantData: `
				# HELP foo_counter A counter of foos
				# TYPE foo_counter counter
				foo_counter 4 {TIMESTAMP}
			`,
		},
		{
			Name: "two metrics",
			Snapshot: newSnapshot().Add(
				// Note the different order here than in WantData,
				// to test ordering independence.
				fooCounter.int(4),
				fooInt.int(3),
			),
			WantData: `
				# HELP foo_int An integer about foo
				# TYPE foo_int gauge
				foo_int 3 {TIMESTAMP}
				# HELP foo_counter A counter of foos
				# TYPE foo_counter counter
				foo_counter 4 {TIMESTAMP}
			`,
		},
		{
			Name: "metric with 1 field",
			Snapshot: newSnapshot().Add(
				fooInt.fieldVal(field1, "val1a").int(3),
				fooInt.fieldVal(field1, "val1b").int(7),
			),
			WantData: `
				# HELP foo_int An integer about foo
				# TYPE foo_int gauge
				foo_int{field1="val1a"} 3 {TIMESTAMP}
				foo_int{field1="val1b"} 7 {TIMESTAMP}
			`,
		},
		{
			Name: "metric with 2 fields",
			Snapshot: newSnapshot().Add(
				fooInt.fieldVal(field1, "val1a").fieldVal(field2, "val2a").int(3),
				fooInt.fieldVal(field2, "val2b").fieldVal(field1, "val1b").int(7),
			),
			WantData: `
				# HELP foo_int An integer about foo
				# TYPE foo_int gauge
				foo_int{field1="val1a",field2="val2a"} 3 {TIMESTAMP}
				foo_int{field1="val1b",field2="val2b"} 7 {TIMESTAMP}
			`,
		},
		{
			Name:     "simple integer with export options",
			Snapshot: newSnapshot().Add(fooInt.int(3)),
			ExportOptions: ExportOptions{
				CommentHeader: "Some header",
			},
			SnapshotExportOptions: SnapshotExportOptions{
				ExporterPrefix: "some_prefix_",
				ExtraLabels: map[string]string{
					"field3": "val3a",
				},
			},
			WantData: `
				# HELP some_prefix_foo_int An integer about foo
				# TYPE some_prefix_foo_int gauge
				some_prefix_foo_int{field3="val3a"} 3 {TIMESTAMP}
			`,
		},
		{
			Name: "integer with fields mixing with export options",
			Snapshot: newSnapshot().Add(
				fooInt.fieldVal(field1, "val1a").fieldVal(field2, "val2a").int(3),
				fooInt.fieldVal(field2, "val2b").fieldVal(field1, "val1b").int(7),
			),
			SnapshotExportOptions: SnapshotExportOptions{
				ExtraLabels: map[string]string{
					"field3": "val3a",
				},
			},
			WantData: `
				# HELP foo_int An integer about foo
				# TYPE foo_int gauge
				foo_int{field1="val1a",field2="val2a",field3="val3a"} 3 {TIMESTAMP}
				foo_int{field1="val1b",field2="val2b",field3="val3a"} 7 {TIMESTAMP}
			`,
		},
		{
			Name: "integer with fields conflicting with export options",
			Snapshot: newSnapshot().Add(
				fooInt.fieldVal(field1, "val1a").fieldVal(field2, "val2a").int(3),
				fooInt.fieldVal(field2, "val2b").fieldVal(field1, "val1b").int(7),
			),
			SnapshotExportOptions: SnapshotExportOptions{
				ExtraLabels: map[string]string{
					"field2": "val2c",
					"field3": "val3a",
				},
			},
			WantFail: true,
		},
		{
			Name: "simple distribution",
			Snapshot: newSnapshot().Add(
				// -1 + 3 + 3 + 3 + 5 + 7 + 7 + 99 = 126
				fooDist.dist(-1, 3, 3, 3, 5, 7, 7, 99),
			),
			WantData: `
				# HELP foo_dist A distribution about foo
				# TYPE foo_dist histogram
				foo_dist_bucket{le="0"} 1 {TIMESTAMP}
				foo_dist_bucket{le="1"} 1 {TIMESTAMP}
				foo_dist_bucket{le="2"} 1 {TIMESTAMP}
				foo_dist_bucket{le="4"} 4 {TIMESTAMP}
				foo_dist_bucket{le="8"} 7 {TIMESTAMP}
				foo_dist_bucket{le="+inf"} 8 {TIMESTAMP}
				foo_dist_sum 126 {TIMESTAMP}
				foo_dist_count 8 {TIMESTAMP}
			`,
		},
		{
			Name: "distribution with 'le' label",
			Snapshot: newSnapshot().Add(
				fooDist.fieldVal(&pb.MetricMetadata_Field{
					FieldName:     "le",
					AllowedValues: []string{"foo"},
				}, "foo").dist(-1, 3, 3, 3, 5, 7, 7, 99),
			),
			WantFail: true,
		},
		{
			Name: "distribution with no samples",
			Snapshot: newSnapshot().Add(
				fooDist.dist(),
			),
			WantData: `
				# HELP foo_dist A distribution about foo
				# TYPE foo_dist histogram
				foo_dist_bucket{le="0"} 0 {TIMESTAMP}
				foo_dist_bucket{le="1"} 0 {TIMESTAMP}
				foo_dist_bucket{le="2"} 0 {TIMESTAMP}
				foo_dist_bucket{le="4"} 0 {TIMESTAMP}
				foo_dist_bucket{le="8"} 0 {TIMESTAMP}
				foo_dist_bucket{le="+inf"} 0 {TIMESTAMP}
				foo_dist_sum 0 {TIMESTAMP}
				foo_dist_count 0 {TIMESTAMP}
			`,
		},
		{
			Name: "distribution with 1 field",
			Snapshot: newSnapshot().Add(
				// -1 + 3 + 3 + 3 + 5 + 7 + 7 + 99 = 126
				fooDist.fieldVal(field1, "val1a").dist(-1, 3, 3, 3, 5, 7, 7, 99),
				// 3 + 5 + 3 = 11
				fooDist.fieldVal(field1, "val1b").dist(3, 5, 3),
			),
			WantData: `
				# HELP foo_dist A distribution about foo
				# TYPE foo_dist histogram
				foo_dist_bucket{field1="val1a",le="0"} 1 {TIMESTAMP}
				foo_dist_bucket{field1="val1a",le="1"} 1 {TIMESTAMP}
				foo_dist_bucket{field1="val1a",le="2"} 1 {TIMESTAMP}
				foo_dist_bucket{field1="val1a",le="4"} 4 {TIMESTAMP}
				foo_dist_bucket{field1="val1a",le="8"} 7 {TIMESTAMP}
				foo_dist_bucket{field1="val1a",le="+inf"} 8 {TIMESTAMP}
				foo_dist_sum{field1="val1a"} 126 {TIMESTAMP}
				foo_dist_count{field1="val1a"} 8 {TIMESTAMP}
				foo_dist_bucket{field1="val1b",le="0"} 0 {TIMESTAMP}
				foo_dist_bucket{field1="val1b",le="1"} 0 {TIMESTAMP}
				foo_dist_bucket{field1="val1b",le="2"} 0 {TIMESTAMP}
				foo_dist_bucket{field1="val1b",le="4"} 2 {TIMESTAMP}
				foo_dist_bucket{field1="val1b",le="8"} 3 {TIMESTAMP}
				foo_dist_bucket{field1="val1b",le="+inf"} 3 {TIMESTAMP}
				foo_dist_sum{field1="val1b"} 11 {TIMESTAMP}
				foo_dist_count{field1="val1b"} 3 {TIMESTAMP}
			`,
		},
		{
			Name: "distribution with 2 fields, one from ExportOptions",
			Snapshot: newSnapshot().Add(
				// -1 + 3 + 3 + 3 + 5 + 7 + 7 + 99 = 126
				fooDist.fieldVal(field1, "val1a").dist(-1, 3, 3, 3, 5, 7, 7, 99),
				// 3 + 5 + 3 = 11
				fooDist.fieldVal(field1, "val1b").dist(3, 5, 3),
			),
			ExportOptions: ExportOptions{
				CommentHeader: "Some header",
			},
			SnapshotExportOptions: SnapshotExportOptions{
				ExporterPrefix: "some_prefix_",
				ExtraLabels:    map[string]string{"field2": "val2a"},
			},
			WantData: `
				# HELP some_prefix_foo_dist A distribution about foo
				# TYPE some_prefix_foo_dist histogram
				some_prefix_foo_dist_bucket{field1="val1a",field2="val2a",le="0"} 1 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1a",field2="val2a",le="1"} 1 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1a",field2="val2a",le="2"} 1 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1a",field2="val2a",le="4"} 4 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1a",field2="val2a",le="8"} 7 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1a",field2="val2a",le="+inf"} 8 {TIMESTAMP}
				some_prefix_foo_dist_sum{field1="val1a",field2="val2a"} 126 {TIMESTAMP}
				some_prefix_foo_dist_count{field1="val1a",field2="val2a"} 8 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1b",field2="val2a",le="0"} 0 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1b",field2="val2a",le="1"} 0 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1b",field2="val2a",le="2"} 0 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1b",field2="val2a",le="4"} 2 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1b",field2="val2a",le="8"} 3 {TIMESTAMP}
				some_prefix_foo_dist_bucket{field1="val1b",field2="val2a",le="+inf"} 3 {TIMESTAMP}
				some_prefix_foo_dist_sum{field1="val1b",field2="val2a"} 11 {TIMESTAMP}
				some_prefix_foo_dist_count{field1="val1b",field2="val2a"} 3 {TIMESTAMP}
			`,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			// Render and parse snapshot data.
			var buf bytes.Buffer
			snapshotToOptions := map[*Snapshot]SnapshotExportOptions{test.Snapshot: test.SnapshotExportOptions}
			if _, err := Write(&buf, test.ExportOptions, snapshotToOptions); err != nil {
				if test.WantFail {
					return
				}
				t.Fatalf("cannot write snapshot: %v", err)
			}
			gotMetricsRaw := buf.String()
			gotMetrics, err := (&expfmt.TextParser{}).TextToMetricFamilies(&buf)
			if err != nil {
				if test.WantFail {
					return
				}
				t.Fatalf("cannot parse data written from snapshot: %v", err)
			}
			if test.WantFail {
				t.Fatalf("Test unexpectedly succeeded to render and parse snapshot data")
			}

			// Verify that the data is consistent (i.e. verify that it's not based on random map ordering)
			var buf2 bytes.Buffer
			if _, err := Write(&buf2, test.ExportOptions, snapshotToOptions); err != nil {
				if test.WantFail {
					return
				}
				t.Fatalf("cannot write snapshot: %v", err)
			}
			gotMetricsRaw2 := buf2.String()
			if gotMetricsRaw != gotMetricsRaw2 {
				t.Errorf("inconsistent snapshot rendering:\n\n%s\n\n---- VS ----\n\n%s\n\n", gotMetricsRaw, gotMetricsRaw2)
			}

			// Verify that error propagation works by having the writer fail at each possible spot.
			// This exercises all the write error propagation branches.
			var shortWriter shortWriter
			for writeLength := 0; writeLength < len(gotMetricsRaw); writeLength++ {
				shortWriter.Reset(writeLength)
				if _, err := Write(&shortWriter, test.ExportOptions, snapshotToOptions); err == nil {
					t.Fatalf("snapshot data unexpectedly succeeded being written to short writer (length %d): %v", writeLength, shortWriter.String())
				}
				if shortWriter.size != writeLength {
					t.Fatalf("Short writer should have allowed %d bytes of snapshot data to be written, but actual number of bytes written is %d bytes", writeLength, shortWriter.size)
				}
			}

			// Parse reference data.
			wantData := strings.ReplaceAll(test.WantData, "{TIMESTAMP}", fmt.Sprintf("%d", testStart.UnixMilli()))
			wantMetrics, err := (&expfmt.TextParser{}).TextToMetricFamilies(strings.NewReader(wantData))
			if err != nil {
				t.Fatalf("cannot parse reference data: %v", err)
			}

			if len(test.Snapshot.Data) != 0 {
				// If the snapshot isn't empty, verify that the data we got from both `got` and `want`
				// is non-zero. Otherwise, this whole test could accidentally succeed by having all attempts
				// at  parsing the data result into an empty set.
				if len(wantMetrics) == 0 {
					t.Error("Snapshot is not empty, but parsing the reference data resulted in no data being produced")
				}
				if len(gotMetrics) == 0 {
					t.Error("Snapshot is not empty, but parsing the rendered snapshot resulted in no data being produced")
				}
			}

			// Verify that all of `wantMetrics` is in `gotMetrics`.
			for metric, want := range wantMetrics {
				if _, found := gotMetrics[metric]; !found {
					wantText, err := singleLineFormatter.Marshal(reflectProto(want))
					if err != nil {
						t.Fatalf("cannot marshal reference data: %v", err)
					}
					t.Errorf("metric %s is in reference data (%v) but not present in snapshot data", metric, string(wantText))
				}
			}

			// Verify that all of `gotMetrics` is in `wantMetrics`.
			for metric, got := range gotMetrics {
				if _, found := wantMetrics[metric]; !found {
					gotText, err := singleLineFormatter.Marshal(reflectProto(got))
					if err != nil {
						t.Fatalf("cannot marshal snapshot data: %v", err)
					}
					t.Errorf("metric %s found in snapshot data (%v) but not present in reference data", metric, string(gotText))
				}
			}

			// The rest of the test assumes the keys are the same.
			if t.Failed() {
				return
			}

			// Verify metric data matches.
			for metric := range wantMetrics {
				t.Run(metric, func(t *testing.T) {
					want := reflectProto(wantMetrics[metric])
					got := reflectProto(gotMetrics[metric])
					if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
						wantText, err := multiLineFormatter.Marshal(want)
						if err != nil {
							t.Fatalf("cannot marshal reference data: %v", err)
						}
						gotText, err := multiLineFormatter.Marshal(got)
						if err != nil {
							t.Fatalf("cannot marshal snapshot data: %v", err)
						}
						t.Errorf("Snapshot data did not produce the same data as the reference data.\n\nReference data:\n\n%v\n\nSnapshot data:\n\n%v\n\nDiff:\n\n%v\n\n", string(wantText), string(gotText), diff)
					}
				})
			}
		})
	}
}

func TestWriteMultipleSnapshots(t *testing.T) {
	testStart := time.Now()
	snapshot1 := newSnapshotAt(testStart).Add(fooInt.int(3))
	snapshot2 := newSnapshotAt(testStart.Add(3 * time.Minute)).Add(fooInt.int(5))
	var buf bytes.Buffer
	Write(&buf, ExportOptions{CommentHeader: "A header\non two lines"}, map[*Snapshot]SnapshotExportOptions{
		snapshot1: {ExporterPrefix: "export_"},
		snapshot2: {ExporterPrefix: "export_"},
	})
	gotData, err := (&expfmt.TextParser{}).TextToMetricFamilies(&buf)
	if err != nil {
		t.Fatalf("cannot parse data written from snapshots: %v", err)
	}
	if len(gotData) != 1 || gotData["export_"+fooInt.PB.GetPrometheusName()] == nil {
		t.Fatalf("unexpected data: %v", gotData)
	}
	got := reflectProto(gotData["export_"+fooInt.PB.GetPrometheusName()])
	var wantBuf bytes.Buffer
	io.WriteString(&wantBuf, fmt.Sprintf(`
		# HELP export_foo_int An integer about foo
		# TYPE export_foo_int gauge
		export_foo_int 3 %d
		export_foo_int 5 %d
	`, testStart.UnixMilli(), testStart.Add(3*time.Minute).UnixMilli()))
	wantData, err := (&expfmt.TextParser{}).TextToMetricFamilies(&wantBuf)
	if err != nil {
		t.Fatalf("cannot parse reference data: %v", err)
	}
	if len(wantData) != 1 || wantData["export_"+fooInt.PB.GetPrometheusName()] == nil {
		t.Fatalf("unexpected reference data: %v", gotData)
	}
	want := reflectProto(wantData["export_"+fooInt.PB.GetPrometheusName()])
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		multiLineFormatter := &prototext.MarshalOptions{Multiline: true, Indent: "  ", EmitUnknown: true}
		wantText, err := multiLineFormatter.Marshal(want)
		if err != nil {
			t.Fatalf("cannot marshal reference data: %v", err)
		}
		gotText, err := multiLineFormatter.Marshal(got)
		if err != nil {
			t.Fatalf("cannot marshal snapshot data: %v", err)
		}
		t.Errorf("Snapshot data did not produce the same data as the reference data.\n\nReference data:\n\n%v\n\nSnapshot data:\n\n%v\n\nDiff:\n\n%v\n\n", string(wantText), string(gotText), diff)
	}
}

func TestGroupSameNameMetrics(t *testing.T) {
	snapshot1 := NewSnapshot().Add(
		fooCounter.int(3),
		fooInt.int(3),
		fooDist.dist(0, 1),
	)
	snapshot2 := NewSnapshot().Add(
		fooDist.dist(1, 2),
		fooCounter.int(2),
	)
	snapshot3 := NewSnapshot().Add(
		fooDist.dist(1, 2),
		fooCounter.int(2),
	)
	var buf bytes.Buffer
	_, err := Write(&buf, ExportOptions{}, map[*Snapshot]SnapshotExportOptions{
		snapshot1: {ExporterPrefix: "my_little_prefix_", ExtraLabels: map[string]string{"snap": "1"}},
		snapshot2: {ExporterPrefix: "my_little_prefix_", ExtraLabels: map[string]string{"snap": "2"}},
		snapshot3: {ExporterPrefix: "not_the_same_prefix_", ExtraLabels: map[string]string{"snap": "1"}},
	})
	if err != nil {
		t.Fatalf("Cannot write snapshot data: %v", err)
	}
	rawData := buf.String() // Capture the data written.

	// Make sure the data written does parse.
	// We don't use this result here because the Prometheus library is more permissive than this test.
	if _, err := (&expfmt.TextParser{}).TextToMetricFamilies(&buf); err != nil {
		t.Fatalf("cannot parse data written from snapshots: %v", err)
	}

	// Verify that we see all metrics, and that each time we see a new one, it's one we haven't seen
	// before.
	seenMetrics := map[string]bool{}
	var lastMetric string
	for lineNumber, line := range strings.Split(rawData, "\n") {
		t.Logf("Line %d: %q", lineNumber+1, line)
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		strippedMetricName := strings.TrimLeftFunc(line, func(r rune) bool {
			return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
		})
		if len(strippedMetricName) == 0 {
			t.Fatalf("invalid line: %q", line)
		}
		if strippedMetricName[0] != '{' && strippedMetricName[0] != ' ' {
			t.Fatalf("invalid line: %q", line)
		}
		metricName := line[:len(line)-len(strippedMetricName)]
		for _, distribSuffix := range []string{"_sum", "_count", "_bucket"} {
			metricName = strings.TrimSuffix(metricName, distribSuffix)
		}
		if lastMetric != "" && lastMetric != metricName && seenMetrics[metricName] {
			t.Fatalf("line %q: got already-seen metric name %q yet it is not the last metric (%s)", line, metricName, lastMetric)
		}
		lastMetric = metricName
		seenMetrics[metricName] = true
	}
	wantSeenMetrics := map[string]bool{
		fmt.Sprintf("my_little_prefix_%s", fooCounter.PB.GetPrometheusName()):    true,
		fmt.Sprintf("my_little_prefix_%s", fooInt.PB.GetPrometheusName()):        true,
		fmt.Sprintf("my_little_prefix_%s", fooDist.PB.GetPrometheusName()):       true,
		fmt.Sprintf("not_the_same_prefix_%s", fooCounter.PB.GetPrometheusName()): true,
		fmt.Sprintf("not_the_same_prefix_%s", fooDist.PB.GetPrometheusName()):    true,
	}
	if !cmp.Equal(seenMetrics, wantSeenMetrics) {
		t.Errorf("Seen metrics: %v\nWant metrics: %v", seenMetrics, wantSeenMetrics)
	}
}

func TestNumberPacker(t *testing.T) {
	interestingIntegers := map[uint64]struct{}{
		uint64(0):                  struct{}{},
		uint64(0x5555555555555555): struct{}{},
		uint64(0xaaaaaaaaaaaaaaaa): struct{}{},
		uint64(0xffffffffffffffff): struct{}{},
	}
	for numBits := 0; numBits < 2; numBits++ {
		newIntegers := map[uint64]struct{}{}
		for interestingInt := range interestingIntegers {
			for i := 0; i < 64; i++ {
				newIntegers[interestingInt|(1<<i)] = struct{}{}
				newIntegers[interestingInt & ^(1<<i)] = struct{}{}
			}
		}
		for newInt := range newIntegers {
			interestingIntegers[newInt] = struct{}{}
		}
	}
	for _, i := range []int64{
		math.MinInt,
		math.MaxInt,
		math.MinInt8,
		math.MaxInt8,
		math.MaxUint8,
		math.MinInt16,
		math.MaxInt16,
		math.MaxUint16,
		math.MinInt32,
		math.MaxInt32,
		math.MaxUint32,
		math.MinInt64,
		math.MaxInt64,
	} {
		for d := int64(-3); d <= int64(3); d++ {
			interestingIntegers[uint64(i+d)] = struct{}{}
		}
	}
	interestingIntegers[0] = struct{}{}
	interestingIntegers[1] = struct{}{}
	interestingIntegers[2] = struct{}{}
	interestingIntegers[3] = struct{}{}
	interestingIntegers[math.MaxUint64-3] = struct{}{}
	interestingIntegers[math.MaxUint64-2] = struct{}{}
	interestingIntegers[math.MaxUint64-1] = struct{}{}
	interestingIntegers[math.MaxUint64] = struct{}{}

	p := &numberPacker{}
	t.Run("integers", func(t *testing.T) {
		seenDirectInteger := false
		seenIndirectInteger := false
		for interestingInt := range interestingIntegers {
			orig := NewInt(int64(interestingInt))
			packed, err := p.pack(orig)
			if err != nil {
				t.Fatalf("integer %v (bits=%x): cannot pack: %v", orig, interestingInt, err)
			}
			unpacked := p.unpack(packed)
			if !orig.SameType(unpacked) || orig.Int != unpacked.Int {
				t.Errorf("integer %v (bits=%x): got packed=%v => unpacked version %v (int: %d)", orig, interestingInt, uint32(packed), unpacked, unpacked.Int)
			}
			seenDirectInteger = seenDirectInteger || (uint32(packed)&storageField) == storageFieldDirect
			seenIndirectInteger = seenIndirectInteger || (uint32(packed)&storageField) == storageFieldIndirect
		}
		if !seenDirectInteger {
			t.Error("did not encounter any integer that could be packed directly")
		}
		if !seenIndirectInteger {
			t.Error("did not encounter any integer that was packed indirectly")
		}
	})
	t.Run("packing_efficiency", func(t *testing.T) {
		// Verify that we actually saved space by not packing every number in numberPacker itself.
		if len(p.data) >= len(interestingIntegers) {
			t.Errorf("packer had %d data points stored in its data, but we expected some of it to not be stored in it (tried to pack %d integers total)", len(p.data), len(interestingIntegers))
		}
	})
	t.Run("floats", func(t *testing.T) {
		interestingFloats := make(map[float64]struct{}, len(interestingIntegers)+21*21+17)
		for divExp := -10; divExp < 10; divExp++ {
			div := math.Pow(10, float64(divExp))
			for i := -10; i < 10; i++ {
				interestingFloats[float64(i)*div] = struct{}{}
			}
		}
		interestingFloats[0.0] = struct{}{}
		interestingFloats[math.NaN()] = struct{}{}
		interestingFloats[math.Inf(1)] = struct{}{}
		interestingFloats[math.Inf(-1)] = struct{}{}
		interestingFloats[math.Pi] = struct{}{}
		interestingFloats[math.Sqrt2] = struct{}{}
		interestingFloats[math.E] = struct{}{}
		interestingFloats[math.SqrtE] = struct{}{}
		interestingFloats[math.Ln2] = struct{}{}
		interestingFloats[math.MaxFloat32] = struct{}{}
		interestingFloats[-math.MaxFloat32] = struct{}{}
		interestingFloats[math.MaxFloat64] = struct{}{}
		interestingFloats[-math.MaxFloat64] = struct{}{}
		interestingFloats[math.SmallestNonzeroFloat32] = struct{}{}
		interestingFloats[-math.SmallestNonzeroFloat32] = struct{}{}
		interestingFloats[math.SmallestNonzeroFloat64] = struct{}{}
		interestingFloats[-math.SmallestNonzeroFloat64] = struct{}{}
		for interestingInt := range interestingIntegers {
			interestingFloats[math.Float64frombits(interestingInt)] = struct{}{}
		}
		seenDirectFloat := false
		seenIndirectFloat := false
		for interestingFloat := range interestingFloats {
			orig := NewFloat(interestingFloat)
			packed, err := p.pack(orig)
			if err != nil {
				t.Fatalf("float %v (64bits=%x, 32bits=%x. float32-encodable=%v): cannot pack: %v", orig, math.Float64bits(interestingFloat), math.Float32bits(float32(interestingFloat)), float64(float32(interestingFloat)) == interestingFloat, err)
			}
			unpacked := p.unpack(packed)
			switch {
			case interestingFloat == 0: // Zero-valued float becomes an integer.
				if !unpacked.IsInteger() {
					t.Errorf("Zero-valued float %v: got non-integer number: %v", orig, unpacked)
				} else if unpacked.Int != 0 {
					t.Errorf("Zero-valued float %v: got non-zero integer: %d", orig, unpacked.Int)
				}
			case math.IsNaN(orig.Float):
				if !math.IsNaN(unpacked.Float) {
					t.Errorf("NaN float %v: got non-NaN unpacked version %v", orig, unpacked)
				}
			default: // Not NaN, not integer
				if !orig.SameType(unpacked) || orig.Float != unpacked.Float {
					t.Errorf("float %v (64bits=%x, 32bits=%x, float32-encodable=%v): got packed=%x => unpacked version %v (float: %f)", orig, math.Float64bits(interestingFloat), math.Float32bits(float32(interestingFloat)), float64(float32(interestingFloat)) == interestingFloat, uint32(packed), unpacked, unpacked.Float)
				}
			}
			seenDirectFloat = seenDirectFloat || (uint32(packed)&storageField) == storageFieldDirect
			seenIndirectFloat = seenIndirectFloat || (uint32(packed)&storageField) == storageFieldIndirect
		}
		if !seenDirectFloat {
			t.Error("did not encounter any float that could be packed directly")
		}
		if !seenIndirectFloat {
			t.Error("did not encounter any float that was packed indirectly")
		}
	})
}
