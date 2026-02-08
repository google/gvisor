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

package metric

import (
	"bufio"
	"bytes"
	"fmt"
	"hash/adler32"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	fooDescription     = "Foo!"
	barDescription     = "Bar Baz"
	counterDescription = "Counter"
	distribDescription = "A distribution metric for testing"
)

var (
	fieldValFoo  = FieldValue{"foo"}
	fieldValBar  = FieldValue{"bar"}
	fieldValBaz  = FieldValue{"baz"}
	fieldValQuux = FieldValue{"quux"}
)

// Helper method that exercises Prometheus metric exporting.
// Ensures that current metric data, if it were to be exported and formatted as Prometheus format,
// would be successfully parsable by the reference Prometheus implementation.
// However, it does not verify that the data that was parsed actually matches the metric data.
func verifyPrometheusParsing(t *testing.T) {
	t.Helper()
	snapshot, err := GetSnapshot(SnapshotOptions{})
	if err != nil {
		t.Errorf("failed to get Prometheus snapshot: %v", err)
		return
	}
	var buf bytes.Buffer
	if _, err := prometheus.Write(&buf, prometheus.ExportOptions{}, map[*prometheus.Snapshot]prometheus.SnapshotExportOptions{
		snapshot: {},
	}); err != nil {
		t.Errorf("failed to get Prometheus snapshot: %v", err)
		return
	}
	if _, err := (&expfmt.TextParser{}).TextToMetricFamilies(&buf); err != nil {
		t.Errorf("failed to parse Prometheus output: %v", err)
	}
}

func TestVerifyName(t *testing.T) {
	for name, wantErr := range map[string]bool{
		"":              true,
		"/":             true,
		"/foo":          false,
		"/foo/bar":      false,
		"/foo/bar/baz":  false,
		"/foo/bar/bar":  false,
		"/foo//bar/baz": true,
		"//foo/bar":     true,
		"//":            true,
		"foo":           true,
		"foo/bar":       true,
		"/foo-bar":      true,
		"/foo bar":      true,
		"/foo_bar":      false,
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyName(name)
			if gotErr := (err != nil); gotErr != wantErr {
				t.Errorf("verifyName(%q) got err=%v wantErr=%v", name, err, wantErr)
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	defer resetTest()
	field1 := NewField("field1", &fieldValFoo, &fieldValBar)
	field2 := NewField("field2", &fieldValBaz, &fieldValQuux)

	_, err := NewUint64Metric("/foo", Uint64Metadata{
		Cumulative:  true,
		Description: fooDescription,
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", Uint64Metadata{
		Cumulative:  true,
		Sync:        true,
		Description: barDescription,
		Fields:      []Field{field1, field2},
		Unit:        pb.MetricMetadata_UNITS_NANOSECONDS,
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	bucketer := NewExponentialBucketer(3, 2, 0, 1)
	_, err = NewDistributionMetric("/distrib", true, bucketer, pb.MetricMetadata_UNITS_NANOSECONDS, distribDescription, field1, field2)
	if err != nil {
		t.Fatalf("NewDistributionMetric got err %v want nil", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}
	verifyPrometheusParsing(t)

	if len(emitter) != 1 {
		t.Fatalf("Initialize emitted %d events want 1", len(emitter))
	}

	mr, ok := emitter[0].(*pb.MetricRegistration)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricRegistration", emitter[0], emitter[0])
	}

	if len(mr.Metrics) != 3 {
		t.Errorf("MetricRegistration got %d metrics want %d", len(mr.Metrics), 3)
	}

	foundFoo := false
	foundBar := false
	foundDistrib := false
	for _, m := range mr.Metrics {
		switch m.Name {
		case "/foo":
			foundFoo = true
			if m.Type != pb.MetricMetadata_TYPE_UINT64 {
				t.Errorf("Metadata %+v Type got %v want pb.MetricMetadata_TYPE_UINT64", m, m.Type)
			}
			if !m.Cumulative {
				t.Errorf("Metadata %+v Cumulative got false want true", m)
			}
			if m.Description != fooDescription {
				t.Errorf("/foo %+v Description got %q want %q", m, m.Description, fooDescription)
			}
			if m.Sync {
				t.Errorf("/foo %+v Sync got true want false", m)
			}
			if m.Units != pb.MetricMetadata_UNITS_NONE {
				t.Errorf("/foo %+v Units got %v want %v", m, m.Units, pb.MetricMetadata_UNITS_NONE)
			}
		case "/bar":
			foundBar = true
			if m.Type != pb.MetricMetadata_TYPE_UINT64 {
				t.Errorf("Metadata %+v Type got %v want pb.MetricMetadata_TYPE_UINT64", m, m.Type)
			}
			if !m.Cumulative {
				t.Errorf("Metadata %+v Cumulative got false want true", m)
			}
			if m.Description != barDescription {
				t.Errorf("/bar %+v Description got %q want %q", m, m.Description, barDescription)
			}
			if !m.Sync {
				t.Errorf("/bar %+v Sync got false want true", m)
			}
			wantFields := []*pb.MetricMetadata_Field{
				{FieldName: "field1", AllowedValues: []string{"foo", "bar"}},
				{FieldName: "field2", AllowedValues: []string{"baz", "quux"}},
			}
			if diff := cmp.Diff(m.Fields, wantFields, protocmp.Transform()); diff != "" {
				t.Errorf("/bar %+v fields: got %v want %v\ndiff:\n%s", m, m.Fields, wantFields, diff)
			}
			if m.Units != pb.MetricMetadata_UNITS_NANOSECONDS {
				t.Errorf("/bar %+v Units got %v want %v", m, m.Units, pb.MetricMetadata_UNITS_NANOSECONDS)
			}
		case "/distrib":
			foundDistrib = true
			want := &pb.MetricMetadata{
				Name:           "/distrib",
				PrometheusName: "distrib",
				Type:           pb.MetricMetadata_TYPE_DISTRIBUTION,
				Units:          pb.MetricMetadata_UNITS_NANOSECONDS,
				Description:    distribDescription,
				Sync:           true,
				Fields: []*pb.MetricMetadata_Field{
					{FieldName: "field1", AllowedValues: []string{"foo", "bar"}},
					{FieldName: "field2", AllowedValues: []string{"baz", "quux"}},
				},
				DistributionBucketLowerBounds: []int64{0, 2, 4, 6},
			}
			if !proto.Equal(m, want) {
				t.Fatalf("got /distrib metadata:\n%v\nwant:\n%v", m, want)
			}
		}
	}

	if !foundFoo {
		t.Errorf("/foo not found: %+v", emitter)
	}
	if !foundBar {
		t.Errorf("/bar not found: %+v", emitter)
	}
	if !foundDistrib {
		t.Errorf("/distrib not found: %+v", emitter)
	}
	verifyPrometheusParsing(t)
}

func TestDisable(t *testing.T) {
	defer resetTest()

	_, err := NewUint64Metric("/foo", Uint64Metadata{
		Cumulative:  true,
		Description: fooDescription,
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", Uint64Metadata{
		Cumulative:  true,
		Description: barDescription,
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewDistributionMetric("/distrib", false, NewExponentialBucketer(2, 2, 0, 1), pb.MetricMetadata_UNITS_NONE, distribDescription)
	if err != nil {
		t.Fatalf("NewDistributionMetric got err %v want nil", err)
	}

	if err := Disable(); err != nil {
		t.Fatalf("Disable(): %s", err)
	}

	if len(emitter) != 1 {
		t.Fatalf("Initialize emitted %d events want 1", len(emitter))
	}

	mr, ok := emitter[0].(*pb.MetricRegistration)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricRegistration", emitter[0], emitter[0])
	}

	if len(mr.Metrics) != 0 {
		t.Errorf("MetricRegistration got %d metrics want 0", len(mr.Metrics))
	}
}

func TestEmitMetricUpdate(t *testing.T) {
	defer resetTest()
	field1 := NewField("field1", &fieldValFoo, &fieldValBar)
	field2 := NewField("field2", &fieldValBaz, &fieldValQuux)

	foo, err := NewUint64Metric("/foo", Uint64Metadata{
		Cumulative:  true,
		Description: fooDescription,
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	bar, err := NewUint64Metric("/bar", Uint64Metadata{
		Cumulative:  true,
		Description: barDescription,
		Fields:      []Field{field1, field2},
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	bucketer := NewExponentialBucketer(2, 2, 0, 1)
	distrib, err := NewDistributionMetric("/distrib", false, bucketer, pb.MetricMetadata_UNITS_NONE, distribDescription, field1, field2)
	if err != nil {
		t.Fatalf("NewDistributionMetric: %v", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}

	// Don't care about the registration metrics.
	emitter.Reset()
	EmitMetricUpdate()

	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	}

	update, ok := emitter[0].(*pb.MetricUpdate)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricUpdate", emitter[0], emitter[0])
	}

	// We only expect /foo, as /bar is initially omitted due to being all-zero.
	if len(update.Metrics) != 1 {
		t.Errorf("MetricUpdate got %d metrics want %d", len(update.Metrics), 1)
	}

	foundFoo := false
	foundBar := false
	foundDistrib := false
	for _, m := range update.Metrics {
		switch m.Name {
		case "/foo":
			foundFoo = true
		case "/bar":
			foundBar = true
		case "/distrib":
			foundDistrib = true
		}
		if m.Name != "/distrib" {
			uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
			if !ok {
				t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
				continue
			}
			if uv.Uint64Value != 0 {
				t.Errorf("%v: Value got %v want %d", m, uv.Uint64Value, 0)
			}
		}
	}

	if !foundFoo {
		t.Errorf("/foo not found: %+v", emitter)
	}
	if foundBar {
		t.Errorf("/bar unexpectedly found: %+v", emitter)
	}
	if foundDistrib {
		t.Errorf("/distrib unexpectedly found: %+v", emitter)
	}
	if t.Failed() {
		t.Fatal("Aborting test so far due to earlier errors.")
	}

	verifyPrometheusParsing(t)

	// Increment foo. Only it is included in the next update.
	foo.Increment()
	foo.Increment()
	foo.Increment()
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want 1", len(emitter))
	}
	update, ok = emitter[0].(*pb.MetricUpdate)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricUpdate", emitter[0], emitter[0])
	}
	if len(update.Metrics) != 1 {
		t.Fatalf("MetricUpdate got %d metrics want %d", len(update.Metrics), 1)
	}
	m := update.Metrics[0]
	if m.Name != "/foo" {
		t.Fatalf("Metric %+v name got %q want '/foo'", m, m.Name)
	}
	uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
	if !ok {
		t.Fatalf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
	}
	if uv.Uint64Value != 3 {
		t.Errorf("%v: Value got %v want %d", m, uv.Uint64Value, 3)
	}
	verifyPrometheusParsing(t)

	// Add a few samples to the distribution metric and increment two of the
	// /bar field combinations.
	distrib.AddSample(1, &fieldValFoo, &fieldValBaz)
	distrib.AddSample(1, &fieldValFoo, &fieldValBaz)
	distrib.AddSample(3, &fieldValFoo, &fieldValBaz)
	distrib.AddSample(-1, &fieldValFoo, &fieldValQuux)
	distrib.AddSample(1, &fieldValFoo, &fieldValQuux)
	distrib.AddSample(100, &fieldValFoo, &fieldValQuux)
	bar.Increment(&fieldValFoo, &fieldValBaz)
	bar.IncrementBy(1337, &fieldValFoo, &fieldValQuux)
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	}
	update, ok = emitter[0].(*pb.MetricUpdate)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricUpdate", emitter[0], emitter[0])
	}
	if len(update.Metrics) != 4 {
		t.Fatalf("MetricUpdate got %d metrics want %d", len(update.Metrics), 4)
	}
	for _, m := range update.Metrics {
		switch m.Name {
		case "/distrib":
			if len(m.FieldValues) != 2 {
				t.Fatalf("Metric %+v fields: got %v want %d fields", m, m.FieldValues, 2)
			}
			if m.FieldValues[0] != "foo" {
				t.Fatalf("Metric %+v field 0: got %v want %v", m, m.FieldValues[0], "foo")
			}
			dv, ok := m.Value.(*pb.MetricValue_DistributionValue)
			if !ok {
				t.Fatalf("%+v: value %v got %T want pb.MetricValue_DistributionValue", m, m.Value, m.Value)
			}
			samples := dv.DistributionValue.GetNewSamples()
			if len(samples) != 4 {
				t.Fatalf("%+v: got %d buckets, want %d", dv.DistributionValue, len(samples), 4)
			}
			var wantSamples []uint64
			switch m.FieldValues[1] {
			case "baz":
				wantSamples = []uint64{0, 2, 1, 0}
			case "quux":
				wantSamples = []uint64{1, 1, 0, 1}
			default:
				t.Fatalf("%+v: got unexpected field[1]: %q", m, m.FieldValues[1])
			}
			for i, s := range samples {
				if s != wantSamples[i] {
					t.Errorf("%+v [fields %v]: sample %d: got %d want %d", dv.DistributionValue, m.FieldValues, i, s, wantSamples[i])
				}
			}
		case "/bar":
			if len(m.FieldValues) != 2 {
				t.Fatalf("Metric %+v fields: got %v want %d fields", m, m.FieldValues, 2)
			}
			if m.FieldValues[0] != "foo" {
				t.Fatalf("Metric %+v field 0: got %v want %v", m, m.FieldValues[0], "foo")
			}
			var wantValue uint64
			switch m.FieldValues[1] {
			case "baz":
				wantValue = 1
			case "quux":
				wantValue = 1337
			default:
				t.Fatalf("%+v: got unexpected field[1]: %q", m, m.FieldValues[1])
			}
			if uv, ok := m.Value.(*pb.MetricValue_Uint64Value); !ok || uv.Uint64Value != wantValue {
				t.Errorf("%+v: value for fields %v: got %T value %v want uint64 value %d", m, m.FieldValues, m.Value, m.Value, wantValue)
			}
		default:
			t.Fatalf("Metric update %+v: Unexpected metric name got %q", m, m.Name)
		}
	}
	verifyPrometheusParsing(t)

	// Add more samples to the distribution metric, check that we get the delta.
	distrib.AddSample(3, &fieldValFoo, &fieldValBaz)
	distrib.AddSample(2, &fieldValFoo, &fieldValBaz)
	distrib.AddSample(1, &fieldValFoo, &fieldValBaz)
	distrib.AddSample(3, &fieldValFoo, &fieldValBaz)
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	}
	dv, ok := emitter[0].(*pb.MetricUpdate).Metrics[0].Value.(*pb.MetricValue_DistributionValue)
	if !ok {
		t.Fatalf("%+v: want pb.MetricValue_DistributionValue", emitter)
	}
	samples := dv.DistributionValue.GetNewSamples()
	if len(samples) != 4 {
		t.Fatalf("%+v: got %d buckets, want %d", dv.DistributionValue, len(samples), 4)
	}
	wantSamples := []uint64{0, 1, 3, 0}
	for i, s := range samples {
		if s != wantSamples[i] {
			t.Errorf("%+v: sample %d: got %d want %d", dv.DistributionValue, i, s, wantSamples[i])
		}
	}
	verifyPrometheusParsing(t)

	// Change nothing but still call EmitMetricUpdate. Verify that nothing gets sent.
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 0 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 0)
	}
	verifyPrometheusParsing(t)
}

func TestMetricUpdateStageTiming(t *testing.T) {
	defer resetTest()

	expectedTimings := map[InitStage]struct{ min, max time.Duration }{}
	measureStage := func(stage InitStage, body func()) {
		stageStarted := time.Now()
		endStage := StartStage(stage)
		bodyStarted := time.Now()
		body()
		bodyEnded := time.Now()
		endStage()
		stageEnded := time.Now()

		expectedTimings[stage] = struct{ min, max time.Duration }{
			min: bodyEnded.Sub(bodyStarted),
			max: stageEnded.Sub(stageStarted),
		}
	}
	checkStage := func(got *pb.StageTiming, want InitStage) {
		if InitStage(got.GetStage()) != want {
			t.Errorf("%v: got stage %q expected %q", got, got.GetStage(), want)
		}
		timingBounds, found := expectedTimings[want]
		if !found {
			t.Fatalf("invalid init stage name %q", want)
		}
		started := got.Started.AsTime()
		ended := got.Ended.AsTime()
		duration := ended.Sub(started)
		if duration < timingBounds.min {
			t.Errorf("stage %v: lasted %v, expected at least %v", want, duration, timingBounds.min)
		} else if duration > timingBounds.max {
			t.Errorf("stage %v: lasted %v, expected no more than %v", want, duration, timingBounds.max)
		}
	}

	// Test that it's legit to go through stages before metric registration.
	measureStage("before_first_update_1", func() {
		time.Sleep(100 * time.Millisecond)
	})
	measureStage("before_first_update_2", func() {
		time.Sleep(100 * time.Millisecond)
	})

	fooMetric, err := NewUint64Metric("/foo", Uint64Metadata{
		Cumulative:  true,
		Description: fooDescription,
	})
	if err != nil {
		t.Fatalf("Cannot register /foo: %v", err)
	}
	emitter.Reset()
	Initialize()
	EmitMetricUpdate()

	// We should have gotten the metric registration and the first MetricUpdate.
	if len(emitter) != 2 {
		t.Fatalf("emitter has %d messages (%v), expected %d", len(emitter), emitter, 2)
	}

	if registration, ok := emitter[0].(*pb.MetricRegistration); !ok {
		t.Errorf("first message is not MetricRegistration: %T / %v", emitter[0], emitter[0])
	} else if len(registration.Stages) != len(allStages) {
		t.Errorf("MetricRegistration has %d stages (%v), expected %d (%v)", len(registration.Stages), registration.Stages, len(allStages), allStages)
	} else {
		for i := 0; i < len(allStages); i++ {
			if InitStage(registration.Stages[i]) != allStages[i] {
				t.Errorf("MetricRegistration.Stages[%d]: got %q want %q", i, registration.Stages[i], allStages[i])
			}
		}
	}

	if firstUpdate, ok := emitter[1].(*pb.MetricUpdate); !ok {
		t.Errorf("second message is not MetricUpdate: %T / %v", emitter[1], emitter[1])
	} else if len(firstUpdate.StageTiming) != 2 {
		t.Errorf("MetricUpdate has %d stage timings (%v), expected %d", len(firstUpdate.StageTiming), firstUpdate.StageTiming, 2)
	} else {
		checkStage(firstUpdate.StageTiming[0], "before_first_update_1")
		checkStage(firstUpdate.StageTiming[1], "before_first_update_2")
	}
	verifyPrometheusParsing(t)

	// Ensure re-emitting doesn't cause another event to be sent.
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 0 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 0)
	}
	verifyPrometheusParsing(t)

	// Generate monitoring data, we should get an event with no stages.
	fooMetric.Increment()
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	} else if update, ok := emitter[0].(*pb.MetricUpdate); !ok {
		t.Errorf("message is not MetricUpdate: %T / %v", emitter[1], emitter[1])
	} else if len(update.StageTiming) != 0 {
		t.Errorf("unexpected stage timing information: %v", update.StageTiming)
	}
	verifyPrometheusParsing(t)

	// Now generate new stages.
	measureStage("foo_stage_1", func() {
		time.Sleep(100 * time.Millisecond)
	})
	measureStage("foo_stage_2", func() {
		time.Sleep(100 * time.Millisecond)
	})
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	} else if update, ok := emitter[0].(*pb.MetricUpdate); !ok {
		t.Errorf("message is not MetricUpdate: %T / %v", emitter[1], emitter[1])
	} else if len(update.Metrics) != 0 {
		t.Errorf("MetricUpdate has %d metric value changes (%v), expected %d", len(update.Metrics), update.Metrics, 0)
	} else if len(update.StageTiming) != 2 {
		t.Errorf("MetricUpdate has %d stages (%v), expected %d", len(update.StageTiming), update.StageTiming, 2)
	} else {
		checkStage(update.StageTiming[0], "foo_stage_1")
		checkStage(update.StageTiming[1], "foo_stage_2")
	}
	verifyPrometheusParsing(t)

	// Now try generating data for both metrics and stages.
	fooMetric.Increment()
	measureStage("last_stage_1", func() {
		time.Sleep(100 * time.Millisecond)
	})
	measureStage("last_stage_2", func() {
		time.Sleep(100 * time.Millisecond)
	})
	fooMetric.Increment()
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	} else if update, ok := emitter[0].(*pb.MetricUpdate); !ok {
		t.Errorf("message is not MetricUpdate: %T / %v", emitter[1], emitter[1])
	} else if len(update.Metrics) != 1 {
		t.Errorf("MetricUpdate has %d metric value changes (%v), expected %d", len(update.Metrics), update.Metrics, 1)
	} else if len(update.StageTiming) != 2 {
		t.Errorf("MetricUpdate has %d stages (%v), expected %d", len(update.StageTiming), update.StageTiming, 2)
	} else {
		checkStage(update.StageTiming[0], "last_stage_1")
		checkStage(update.StageTiming[1], "last_stage_2")
	}
	verifyPrometheusParsing(t)
}

func TestTimerMetric(t *testing.T) {
	defer resetTest()
	// This bucketer just has 2 finite buckets: [0, 500ms) and [500ms, 1s).
	bucketer := NewExponentialBucketer(2, uint64((500 * time.Millisecond).Nanoseconds()), 0, 1)
	field1 := NewField("field1", &fieldValFoo, &fieldValBar)
	field2 := NewField("field2", &fieldValBaz, &fieldValQuux)
	timer, err := NewTimerMetric("/timer", bucketer, "a timer metric", field1, field2)
	if err != nil {
		t.Fatalf("NewTimerMetric: %v", err)
	}
	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}
	// Don't care about the registration metrics.
	emitter.Reset()

	// Create timer data.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := timer.Start(&fieldValFoo)
			defer op.Finish(&fieldValQuux)
			time.Sleep(250 * time.Millisecond)
		}()
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := timer.Start()
			defer op.Finish(&fieldValFoo, &fieldValQuux)
			time.Sleep(750 * time.Millisecond)
		}()
	}
	wg.Wait()
	EmitMetricUpdate()
	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 1)
	}
	m := emitter[0].(*pb.MetricUpdate).Metrics[0]
	wantFields := []string{"foo", "quux"}
	if !slices.Equal(m.GetFieldValues(), wantFields) {
		t.Errorf("%+v: got fields %v want %v", m, m.GetFieldValues(), wantFields)
	}
	dv, ok := m.Value.(*pb.MetricValue_DistributionValue)
	if !ok {
		t.Fatalf("%+v: want pb.MetricValue_DistributionValue", m)
	}
	samples := dv.DistributionValue.GetNewSamples()
	if len(samples) != 4 {
		t.Fatalf("%+v: got %d buckets, want %d", dv.DistributionValue, len(samples), 4)
	}
	wantSamples := []uint64{0, 5, 3, 0}
	for i, s := range samples {
		if s != wantSamples[i] {
			t.Errorf("%+v: sample %d: got %d want %d", dv.DistributionValue, i, s, wantSamples[i])
		}
	}
	verifyPrometheusParsing(t)
}

func TestBucketer(t *testing.T) {
	for _, test := range []struct {
		name                    string
		bucketer                Bucketer
		minSample               int64
		maxSample               int64
		step                    int64
		firstFewLowerBounds     []int64
		successiveBucketSamples []int64
	}{
		{
			name:                "static-sized buckets",
			bucketer:            NewExponentialBucketer(10, 10, 0, 1),
			minSample:           -5,
			maxSample:           105,
			firstFewLowerBounds: []int64{0, 10, 20, 30, 40, 50},
		},
		{
			name:      "exponential buckets",
			bucketer:  NewExponentialBucketer(10, 10, 2, 1.5),
			minSample: -5,
			maxSample: int64(20 * math.Pow(1.5, 12)),
			firstFewLowerBounds: []int64{
				0,
				10 + 2,
				20 + int64(2*1.5),
				30 + int64(math.Floor(2*1.5*1.5)),
				40 + int64(math.Floor(2*1.5*1.5*1.5)),
				50 + int64(math.Floor(2*1.5*1.5*1.5*1.5)),
			},
		},
		{
			name:      "timer buckets",
			bucketer:  NewDurationBucketer(8, time.Second, time.Minute),
			minSample: 0,
			maxSample: (5 * time.Minute).Nanoseconds(),
			step:      (500 * time.Millisecond).Nanoseconds(),
			successiveBucketSamples: []int64{
				// Roughly exponential successive durations:
				(500 * time.Millisecond).Nanoseconds(),
				(1200 * time.Millisecond).Nanoseconds(),
				(2500 * time.Millisecond).Nanoseconds(),
				(5 * time.Second).Nanoseconds(),
				(15 * time.Second).Nanoseconds(),
				(35 * time.Second).Nanoseconds(),
				(75 * time.Second).Nanoseconds(),
				(3 * time.Minute).Nanoseconds(),
				(7 * time.Minute).Nanoseconds(),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			numFiniteBuckets := test.bucketer.NumFiniteBuckets()
			t.Logf("Underflow bucket has bounds (-inf, %d)", test.bucketer.LowerBound(0))
			for b := 0; b < numFiniteBuckets; b++ {
				t.Logf("Bucket %d has bounds [%d, %d)", b, test.bucketer.LowerBound(b), test.bucketer.LowerBound(b+1))
			}
			t.Logf("Overflow bucket has bounds [%d, +inf)", test.bucketer.LowerBound(numFiniteBuckets))
			testAround := func(bound int64, bucketIndex int) {
				for sample := bound - 2; sample <= bound+2; sample++ {
					gotIndex := test.bucketer.BucketIndex(sample)
					if sample < bound && gotIndex != bucketIndex-1 || sample >= bound && gotIndex != bucketIndex {
						t.Errorf("LowerBound(%d) = %d, yet BucketIndex(%d) = %d", bucketIndex, bound, sample, gotIndex)
					}
				}
			}
			step := test.step
			if step == 0 {
				step = 1
			}
			for sample := test.minSample; sample <= test.maxSample; sample += step {
				bucket := test.bucketer.BucketIndex(sample)
				if bucket == -1 {
					lowestBound := test.bucketer.LowerBound(0)
					if sample >= lowestBound {
						t.Errorf("sample %d: got bucket %d but lowest bound %d", sample, bucket, lowestBound)
					}
					testAround(lowestBound, 0)
				} else if bucket > numFiniteBuckets {
					t.Errorf("sample %d: got bucket with 0-based index %d but bucketer supposedly only has %d buckets", sample, bucket, numFiniteBuckets)
				} else if bucket == numFiniteBuckets {
					lastBucketBound := test.bucketer.LowerBound(bucket)
					if sample < lastBucketBound {
						t.Errorf("sample %d: got bucket %d but it has lower bound %d", sample, bucket, lastBucketBound)
					}
					testAround(lastBucketBound, bucket)
				} else {
					lowerBound := test.bucketer.LowerBound(bucket)
					upperBound := test.bucketer.LowerBound(bucket + 1)
					if upperBound <= lowerBound {
						t.Errorf("sample %d: got bucket %d, upperbound %d <= lowerbound %d", sample, bucket, upperBound, lowerBound)
					}
					if sample < lowerBound || sample >= upperBound {
						t.Errorf("sample %d: got bucket %d which has range [%d, %d)", sample, bucket, lowerBound, upperBound)
					}
					testAround(lowerBound, bucket)
					testAround(upperBound, bucket+1)
				}
			}
			for bi, want := range test.firstFewLowerBounds {
				if got := test.bucketer.LowerBound(bi); got != want {
					t.Errorf("bucket %d has lower bound %d, want %d", bi, got, want)
				}
			}
			previousBucket := -1
			for i, sample := range test.successiveBucketSamples {
				gotBucket := test.bucketer.BucketIndex(sample)
				if gotBucket != previousBucket+1 {
					t.Errorf("successive-bucket sample #%d (%d) fell in bucket %d whereas previous sample fell in bucket %d", i, sample, gotBucket, previousBucket)
				}
				previousBucket = gotBucket
			}
		})
	}
}

func TestBucketerPanics(t *testing.T) {
	for name, fn := range map[string]func(){
		"NewExponentialBucketer @ 0": func() {
			NewExponentialBucketer(0, 2, 0, 1)
		},
		"NewExponentialBucketer @ 120": func() {
			NewExponentialBucketer(120, 2, 0, 1)
		},
		"NewDurationBucketer @ 2": func() {
			NewDurationBucketer(2, time.Second, time.Minute)
		},
		"NewDurationBucketer @ 80": func() {
			NewDurationBucketer(80, time.Microsecond, 50*time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var recovered any
			func() {
				defer func() {
					recovered = recover()
				}()
				fn()
			}()
			if recovered == nil {
				t.Error("did not panic")
			}
		})
	}
}

func TestFieldMapperWithFields(t *testing.T) {
	generateFields := func(fieldSizes []int) []Field {
		fields := make([]Field, len(fieldSizes))
		for i, fieldSize := range fieldSizes {
			fieldName := fmt.Sprintf("%c", 'A'+i)
			allowedValues := make([]*FieldValue, fieldSize)
			for val := range allowedValues {
				allowedValues[val] = &FieldValue{fmt.Sprintf("%s%d", fieldName, val)}
			}
			fields[i] = NewField(fieldName, allowedValues...)
		}
		return fields
	}

	for _, test := range []struct {
		name          string
		fields        []Field
		errOnCreation error
	}{
		{
			name:          "FieldMapper8x10",
			fields:        generateFields([]int{8, 10}),
			errOnCreation: nil,
		},
		{
			name:          "FieldMapper3x4x5",
			fields:        generateFields([]int{3, 4, 5}),
			errOnCreation: nil,
		},
		{
			name:          "FieldMapper4x5x6x7",
			fields:        generateFields([]int{4, 5, 6, 7}),
			errOnCreation: nil,
		},
		{
			name:          "FieldMapperErrNoAllowedValues",
			fields:        []Field{NewField("TheNoValuesField")},
			errOnCreation: ErrFieldHasNoAllowedValues,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, err := newFieldMapper(test.fields...)
			if err != test.errOnCreation {
				t.Fatalf("newFieldMapper err: got %v wanted %v", err, test.errOnCreation)
			}

			// Test that every field value combination corresponds to just one entry.
			mapping := make([]int, m.numKeys())
			var visitCombinations func(curFields []*FieldValue, remFields []Field)
			visitCombinations = func(curFields []*FieldValue, remFields []Field) {
				depth := len(remFields)
				if depth == 0 {
					return
				}
				if depth == 1 {
					for _, val := range remFields[0].values {
						fields := append(curFields, val)
						key := m.lookup(fields...)
						mapping[key]++

						// Assert that the reverse operation is also correct.
						fields2 := m.keyToMultiField(key)
						for i, f1val := range fields {
							if f1val.Value != fields2[i] {
								t.Errorf("Field values put into the map are not the same as ones returned: got %v wanted %v", fields2, f1val)
							}
						}
					}
				} else {
					for _, val := range remFields[0].values {
						visitCombinations(append(curFields, val), remFields[1:])
					}
				}
			}
			visitCombinations(nil, test.fields)

			for i, numVisits := range mapping {
				if numVisits != 1 {
					t.Errorf("Index key %d incorrect number of mappings: got %d wanted 1", i, numVisits)
				}
			}
		})
	}
}

func TestFieldMapperNoFields(t *testing.T) {
	m, err := newFieldMapper()
	if err != nil {
		t.Fatalf("newFieldMapper err: got %v wanted nil", err)
	}

	if n := m.numKeys(); n > 1 {
		t.Fatalf("m.numKeys() err: got %d wanted 1", n)
	}

	key := m.lookup()
	if len(m.keyToMultiField(key)) != 0 {
		t.Errorf("keyToMultiField using key %v (corresponding to no field values): expected no values, got some", key)
	}
}

func TestFieldValueUniqueness(t *testing.T) {
	panicked := false
	func() {
		defer func() {
			recover()
			panicked = true
		}()
		NewField("field1", &FieldValue{"foo"}, &FieldValue{"foo"})
	}()
	if !panicked {
		t.Error("did not panic")
	}
}

func TestFieldMapperMustUseSameValuePointer(t *testing.T) {
	const fooString = "foo"
	var constFoo = FieldValue{fooString}
	var heapBar = &FieldValue{fmt.Sprintf("%sr", "ba")}
	n, err := newFieldMapper(NewField("field1", &constFoo, heapBar))
	if err != nil {
		t.Fatalf("newFieldMapper err: got %v wanted nil", err)
	}
	n.lookup(&constFoo)
	n.lookup(heapBar)
	newFoo := &FieldValue{fmt.Sprintf("%so", "fo")}
	panicked := false
	func() {
		defer func() {
			recover()
			panicked = true
		}()
		n.lookup(newFoo)
	}()
	if !panicked {
		t.Error("did not panic")
	}
}

func TestMetricProfiling(t *testing.T) {
	fieldVal1 := &FieldValue{"val1"}
	fieldVal2 := &FieldValue{"val2"}
	fieldVal3 := &FieldValue{"val3"}
	fieldVal4 := &FieldValue{"val4"}
	fieldVal5 := &FieldValue{"val5"}
	fieldVal6 := &FieldValue{"val6"}
	fieldVal7 := &FieldValue{"val7"}
	fieldVal8 := &FieldValue{"val8"}
	fieldVal9 := &FieldValue{"val9"}

	for _, test := range []struct {
		name                 string
		profilingMetricsFlag string
		metricNames          []string
		firstMetricFields    []Field
		expectedHeader       string // If unspecified, computed automatically for non-field metrics.
		lossy                bool
		incrementMetricBy    []uint64
		numIterations        uint64
		errOnStartProfiling  bool
	}{
		{
			name:                 "simple single metric",
			profilingMetricsFlag: "/foo",
			metricNames:          []string{"/foo"},
			incrementMetricBy:    []uint64{50},
			numIterations:        100,
			errOnStartProfiling:  false,
		},
		{
			name:                 "simple single metric, lossy writer",
			profilingMetricsFlag: "/foo",
			metricNames:          []string{"/foo"},
			lossy:                true,
			incrementMetricBy:    []uint64{50},
			numIterations:        100,
			errOnStartProfiling:  false,
		},
		{
			name:                 "single metric exceeds snapshot buffer",
			profilingMetricsFlag: "/foo",
			metricNames:          []string{"/foo"},
			incrementMetricBy:    []uint64{1},
			numIterations:        3500,
			errOnStartProfiling:  false,
		},
		{
			name:                 "multiple metrics",
			profilingMetricsFlag: "/foo,/bar,/big/test/baz,/metric",
			metricNames:          []string{"/foo", "/bar", "/big/test/baz", "/metric"},
			incrementMetricBy:    []uint64{1, 29, 73, 991},
			numIterations:        100,
			errOnStartProfiling:  false,
		},
		{
			name:                 "single metric with 1 field",
			profilingMetricsFlag: "/foo",
			metricNames:          []string{"/foo"},
			firstMetricFields: []Field{
				NewField("field1", fieldVal1, fieldVal2, fieldVal3),
			},
			expectedHeader:      TimeColumn + "\t/foo[val1]\t/foo[val2]\t/foo[val3]",
			incrementMetricBy:   []uint64{1337},
			numIterations:       100,
			errOnStartProfiling: false,
		},
		{
			name:                 "single metric with multiple fields",
			profilingMetricsFlag: "/foo",
			metricNames:          []string{"/foo"},
			firstMetricFields: []Field{
				NewField("field1", fieldVal1, fieldVal2, fieldVal3),
				NewField("field2", fieldVal4, fieldVal5, fieldVal6),
				NewField("field3", fieldVal7, fieldVal8, fieldVal9),
			},
			expectedHeader: TimeColumn + "\t" + strings.Join([]string{
				"/foo[val1,val4,val7]",
				"/foo[val1,val4,val8]",
				"/foo[val1,val4,val9]",
				"/foo[val1,val5,val7]",
				"/foo[val1,val5,val8]",
				"/foo[val1,val5,val9]",
				"/foo[val1,val6,val7]",
				"/foo[val1,val6,val8]",
				"/foo[val1,val6,val9]",
				"/foo[val2,val4,val7]",
				"/foo[val2,val4,val8]",
				"/foo[val2,val4,val9]",
				"/foo[val2,val5,val7]",
				"/foo[val2,val5,val8]",
				"/foo[val2,val5,val9]",
				"/foo[val2,val6,val7]",
				"/foo[val2,val6,val8]",
				"/foo[val2,val6,val9]",
				"/foo[val3,val4,val7]",
				"/foo[val3,val4,val8]",
				"/foo[val3,val4,val9]",
				"/foo[val3,val5,val7]",
				"/foo[val3,val5,val8]",
				"/foo[val3,val5,val9]",
				"/foo[val3,val6,val7]",
				"/foo[val3,val6,val8]",
				"/foo[val3,val6,val9]",
			}, "\t"),
			incrementMetricBy:   []uint64{1337},
			numIterations:       100,
			errOnStartProfiling: false,
		},
		{
			name:                 "multiple metrics and one has fields",
			profilingMetricsFlag: "/foo,/bar",
			metricNames:          []string{"/foo", "/bar"},
			firstMetricFields: []Field{
				NewField("field1", fieldVal1, fieldVal2, fieldVal3),
			},
			expectedHeader:      TimeColumn + "\t/foo[val1]\t/foo[val2]\t/foo[val3]\t/bar",
			incrementMetricBy:   []uint64{42, 27},
			numIterations:       100,
			errOnStartProfiling: false,
		},
		{
			name:                 "mismatched names",
			profilingMetricsFlag: "/foo,/fighter,/big/test/baz,/metric",
			metricNames:          []string{"/foo", "/bar", "/big/test/baz", "/metric"},
			incrementMetricBy:    []uint64{},
			numIterations:        0,
			errOnStartProfiling:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer resetTest()
			const profilingRate = 1000 * time.Microsecond
			numEntries := 0
			for i := range test.metricNames {
				if i == 0 {
					fm, err := newFieldMapper(test.firstMetricFields...)
					if err != nil {
						t.Fatalf("newFieldMapper err: got %v wanted nil", err)
					}
					numEntries += fm.numKeys()
				} else {
					numEntries++
				}
			}

			metrics := make([]*Uint64Metric, len(test.metricNames))
			for i, m := range test.metricNames {
				var fields []Field
				if i == 0 {
					fields = append(fields, test.firstMetricFields...)
				}
				newMetric, err := NewUint64Metric(m, Uint64Metadata{
					Cumulative:  true,
					Sync:        true,
					Description: fooDescription,
					Fields:      fields,
				})
				metrics[i] = newMetric
				if err != nil {
					t.Fatalf("NewUint64Metric got err '%v' want nil", err)
				}
			}
			firstMetricFieldMapper, err := newFieldMapper(test.firstMetricFields...)
			if err != nil {
				t.Fatalf("newFieldMapper err: got %v wanted nil", err)
			}

			f, err := os.CreateTemp(t.TempDir(), "profiling-metrics")
			if err != nil {
				t.Fatalf("failed to create file: '%v'", err)
			}
			fName := f.Name()

			if err := Initialize(); err != nil {
				t.Fatalf("Initialize error: got '%v' want nil", err)
			}
			if err := StartProfilingMetrics(ProfilingMetricsOptions[*os.File]{
				Sink:    f,
				Lossy:   test.lossy,
				Metrics: test.profilingMetricsFlag,
				Rate:    profilingRate,
			}); err != nil {
				if test.errOnStartProfiling {
					return
				}
				t.Fatalf("StartProfilingMetrics error: got '%v' want '%v'", err, test.errOnStartProfiling)
			}
			if test.errOnStartProfiling {
				t.Fatal("did not error out on StartProflingMetrics as expected")
			}

			// Generate some test data
			for i := 0; i < int(test.numIterations); i++ {
				for metricIdx, m := range metrics {
					if metricIdx == 0 {
						for fieldKey := 0; fieldKey < firstMetricFieldMapper.numKeys(); fieldKey++ {
							fieldValues := make([]*FieldValue, len(test.firstMetricFields))
							firstMetricFieldMapper.keyToMultiFieldInPlace(fieldKey, fieldValues)
							m.IncrementBy(test.incrementMetricBy[metricIdx], fieldValues...)
						}
					} else {
						m.IncrementBy(test.incrementMetricBy[metricIdx])
					}
				}
				// Give time to the collector to record it.
				time.Sleep(profilingRate)
			}

			StopProfilingMetrics()

			f, err = os.Open(fName)
			if err != nil {
				t.Fatalf("failed to open file a second time: %v", err)
			}

			// Check that the log looks sane:
			// - Header should match what we expect.
			// - We should have one metadata line per metric.
			// - We should have one start time line.
			// - If in lossy mode, we should have a hash line.
			// - If we have a hash, it should match the one computed by this test.
			// - Each timestamp should always be bigger.
			// - Each metric value should be at least as big as the previous.
			h := adler32.New()
			lines := bufio.NewScanner(f)
			expectedHeader := test.expectedHeader
			if expectedHeader == "" {
				expectedHeader = TimeColumn + "\t" + strings.Join(test.metricNames, "\t")
			}
			if test.lossy {
				expectedHeader += "\tChecksum"
			}
			prevTS := uint64(0)
			prevValues := make([]uint64, numEntries)
			numDatapoints := 0
			var hashLine string
			gotMetadataFor := make(map[string]struct{}, len(test.metricNames))
			gotHeader := false
			gotStartTime := false
			gotStats := false
			for lines.Scan() {
				line := lines.Text()
				if line == "" {
					continue
				}
				if test.lossy {
					if !strings.HasPrefix(line, MetricsPrefix) {
						t.Fatalf("lossy writer output does not have expected prefix: got %q want %q", line, MetricsPrefix)
					}
					line = strings.TrimPrefix(line, MetricsPrefix)
				}
				if strings.HasPrefix(line, MetricsHashIndicator) {
					if hashLine != "" {
						t.Fatalf("got multiple hash lines")
					}
					hashLine = line
					continue
				}
				h.Write([]byte(line + "\n"))
				// Check line checksum
				if test.lossy {
					tabSplit := strings.Split(line, "\t")
					gotLineChecksum := tabSplit[len(tabSplit)-1]
					wantLineChecksum := fmt.Sprintf("0x%x", adler32.Checksum([]byte(strings.Join(tabSplit[:len(tabSplit)-1], "\t"))))
					if gotLineChecksum != wantLineChecksum {
						t.Errorf("got line checksum %q, want %q", gotLineChecksum, wantLineChecksum)
						continue
					}
					line = strings.TrimSuffix(line, "\t"+gotLineChecksum)
				}
				if strings.HasPrefix(line, MetricsMetaIndicator) {
					line = strings.TrimPrefix(line, MetricsMetaIndicator)
					components := strings.Split(line, "\t")
					if len(components) != 2 {
						t.Fatalf("got %d components in metadata line %q, want 2", len(components), line)
					}
					// We only verify that the metadata is present, not its contents.
					if components[0] == "" || components[1] == "" {
						t.Fatalf("got empty metadata line: %q", line)
					}
					gotMetadataFor[components[0]] = struct{}{}
					continue
				}
				if strings.HasPrefix(line, MetricsStartTimeIndicator) {
					if gotStartTime {
						t.Fatalf("got multiple start time lines")
					}
					gotStartTime = true
					continue
				}
				if strings.HasPrefix(line, MetricsStatsIndicator) {
					if gotStats {
						t.Fatalf("got multiple stats lines")
					}
					gotStats = true
					_, err := ParseCollectionStats(line)
					if err != nil {
						t.Fatalf("failed to parse collection stats: %v", err)
					}
					continue
				}
				if !gotHeader {
					// This line must be the header.
					if line != expectedHeader {
						t.Fatalf("got header %q, want %q", line, expectedHeader)
					}
					gotHeader = true
					continue
				}
				numDatapoints++
				items := strings.Split(line, "\t")
				if len(items) != (numEntries + 1) {
					t.Fatalf("incorrect number of items on line '%s': got %d, want %d", line, len(items), numEntries+1)
				}
				// Check timestamp
				ts, err := strconv.ParseUint(items[0], 10, 64)
				if err != nil {
					t.Errorf("ts ParseUint error on line '%s': got '%v' want nil", line, err)
				}
				if ts <= prevTS && numDatapoints > 1 {
					t.Errorf("expecting timestamp to always increase on line '%s': got %d, previous was %d", line, ts, prevTS)
				}
				prevTS = ts

				// Check metric values
				for i := 1; i <= numEntries; i++ {
					m, err := strconv.ParseUint(items[i], 10, 64)
					if err != nil {
						t.Errorf("m ParseUint error on line '%s': got '%v' want nil", line, err)
					}
					if m < prevValues[i-1] {
						t.Errorf("expecting metric value to always increase on line '%s': got %d, previous was %d", line, m, prevValues[i-1])
					}
					prevValues[i-1] = m
				}
			}
			expectedMinNumDatapoints := int(0.7 * float32(test.numIterations))
			if numDatapoints < expectedMinNumDatapoints {
				t.Errorf("numDatapoints: got %d, want at least %d", numDatapoints, expectedMinNumDatapoints)
			}
			// Check that the final total for each metric is correct
			for metricIdx := range metrics {
				expected := test.numIterations * test.incrementMetricBy[metricIdx]
				if metricIdx == 0 {
					for fieldKey := 0; fieldKey < firstMetricFieldMapper.numKeys(); fieldKey++ {
						if prevValues[fieldKey] != expected {
							t.Errorf("incorrect final metric value: got %d, want %d", prevValues[fieldKey], expected)
						}
					}
				} else {
					if itemIdx := firstMetricFieldMapper.numKeys() + metricIdx - 1; prevValues[itemIdx] != expected {
						t.Errorf("incorrect final metric value: got %d, want %d", prevValues[itemIdx], expected)
					}
				}
			}
			if len(gotMetadataFor) != len(test.metricNames) {
				t.Errorf("got metadata for %d metrics, want %d", len(gotMetadataFor), len(test.metricNames))
			}
			for _, metricName := range test.metricNames {
				if _, ok := gotMetadataFor[metricName]; !ok {
					t.Errorf("did not get metadata for metric %q", metricName)
				}
			}
			if !gotStartTime {
				t.Error("did not get start time metadata")
			}
			if !gotStats {
				t.Error("did not get collection stats")
			}
			if !gotHeader {
				t.Error("did not get header")
			}
			if test.lossy {
				if hashLine == "" {
					t.Fatal("lossy writer output does not have expected hash line")
				}
				wantHash := fmt.Sprintf("0x%x", h.Sum32())
				gotHash := strings.TrimPrefix(hashLine, MetricsHashIndicator)
				if gotHash != wantHash {
					t.Fatalf("lossy writer output does not have expected hash line: got %q want %q", gotHash, wantHash)
				}
			} else {
				if hashLine != "" {
					t.Fatalf("unexpectedly found hash line in non-lossy output: %q", hashLine)
				}
			}
			f.Close()
		})
	}
}
