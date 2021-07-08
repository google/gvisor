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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/eventchannel"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

// sliceEmitter implements eventchannel.Emitter by appending all messages to a
// slice.
type sliceEmitter []proto.Message

// Emit implements eventchannel.Emitter.Emit.
func (s *sliceEmitter) Emit(msg proto.Message) (bool, error) {
	*s = append(*s, msg)
	return false, nil
}

// Emit implements eventchannel.Emitter.Close.
func (s *sliceEmitter) Close() error {
	return nil
}

// Reset clears all events in s.
func (s *sliceEmitter) Reset() {
	*s = nil
}

// emitter is the eventchannel.Emitter used for all tests. Package eventchannel
// doesn't allow removing Emitters, so we must use one global emitter for all
// test cases.
var emitter sliceEmitter

func init() {
	reset()

	eventchannel.AddEmitter(&emitter)
}

// reset clears all global state in the metric package.
func reset() {
	initialized = false
	allMetrics = makeMetricSet()
	emitter.Reset()
}

const (
	fooDescription     = "Foo!"
	barDescription     = "Bar Baz"
	counterDescription = "Counter"
)

func TestInitialize(t *testing.T) {
	defer reset()

	_, err := NewUint64Metric("/foo", false, pb.MetricMetadata_UNITS_NONE, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", true, pb.MetricMetadata_UNITS_NANOSECONDS, barDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}

	if len(emitter) != 1 {
		t.Fatalf("Initialize emitted %d events want 1", len(emitter))
	}

	mr, ok := emitter[0].(*pb.MetricRegistration)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricRegistration", emitter[0], emitter[0])
	}

	if len(mr.Metrics) != 2 {
		t.Errorf("MetricRegistration got %d metrics want 2", len(mr.Metrics))
	}

	foundFoo := false
	foundBar := false
	for _, m := range mr.Metrics {
		if m.Type != pb.MetricMetadata_TYPE_UINT64 {
			t.Errorf("Metadata %+v Type got %v want pb.MetricMetadata_TYPE_UINT64", m, m.Type)
		}
		if !m.Cumulative {
			t.Errorf("Metadata %+v Cumulative got false want true", m)
		}

		switch m.Name {
		case "/foo":
			foundFoo = true
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
			if m.Description != barDescription {
				t.Errorf("/bar %+v Description got %q want %q", m, m.Description, barDescription)
			}
			if !m.Sync {
				t.Errorf("/bar %+v Sync got true want false", m)
			}
			if m.Units != pb.MetricMetadata_UNITS_NANOSECONDS {
				t.Errorf("/bar %+v Units got %v want %v", m, m.Units, pb.MetricMetadata_UNITS_NANOSECONDS)
			}
		}
	}

	if !foundFoo {
		t.Errorf("/foo not found: %+v", emitter)
	}
	if !foundBar {
		t.Errorf("/bar not found: %+v", emitter)
	}
}

func TestDisable(t *testing.T) {
	defer reset()

	_, err := NewUint64Metric("/foo", false, pb.MetricMetadata_UNITS_NONE, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", true, pb.MetricMetadata_UNITS_NONE, barDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
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
	defer reset()

	foo, err := NewUint64Metric("/foo", false, pb.MetricMetadata_UNITS_NONE, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", true, pb.MetricMetadata_UNITS_NONE, barDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}

	// Don't care about the registration metrics.
	emitter.Reset()
	EmitMetricUpdate()

	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want 1", len(emitter))
	}

	update, ok := emitter[0].(*pb.MetricUpdate)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricUpdate", emitter[0], emitter[0])
	}

	if len(update.Metrics) != 2 {
		t.Errorf("MetricUpdate got %d metrics want 2", len(update.Metrics))
	}

	// Both are included for their initial values.
	foundFoo := false
	foundBar := false
	for _, m := range update.Metrics {
		switch m.Name {
		case "/foo":
			foundFoo = true
		case "/bar":
			foundBar = true
		}
		uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
		if !ok {
			t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
			continue
		}
		if uv.Uint64Value != 0 {
			t.Errorf("%v: Value got %v want 0", m, uv.Uint64Value)
		}
	}

	if !foundFoo {
		t.Errorf("/foo not found: %+v", emitter)
	}
	if !foundBar {
		t.Errorf("/bar not found: %+v", emitter)
	}

	// Increment foo. Only it is included in the next update.
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
		t.Errorf("MetricUpdate got %d metrics want 1", len(update.Metrics))
	}

	m := update.Metrics[0]

	if m.Name != "/foo" {
		t.Errorf("Metric %+v name got %q want '/foo'", m, m.Name)
	}

	uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
	if !ok {
		t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
	}
	if uv.Uint64Value != 1 {
		t.Errorf("%v: Value got %v want 1", m, uv.Uint64Value)
	}
}

func TestEmitMetricUpdateWithFields(t *testing.T) {
	defer reset()

	field := Field{
		name:          "weirdness_type",
		allowedValues: []string{"weird1", "weird2"}}

	counter, err := NewUint64Metric("/weirdness", false, pb.MetricMetadata_UNITS_NONE, counterDescription, field)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}

	// Don't care about the registration metrics.
	emitter.Reset()
	EmitMetricUpdate()

	// For metrics with fields, we do not emit data unless the value is
	// incremented.
	if len(emitter) != 0 {
		t.Fatalf("EmitMetricUpdate emitted %d events want 0", len(emitter))
	}

	counter.IncrementBy(4, "weird1")
	counter.Increment("weird2")

	emitter.Reset()
	EmitMetricUpdate()

	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want 1", len(emitter))
	}

	update, ok := emitter[0].(*pb.MetricUpdate)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricUpdate", emitter[0], emitter[0])
	}

	if len(update.Metrics) != 2 {
		t.Errorf("MetricUpdate got %d metrics want 2", len(update.Metrics))
	}

	foundWeird1 := false
	foundWeird2 := false
	for i := 0; i < len(update.Metrics); i++ {
		m := update.Metrics[i]

		if m.Name != "/weirdness" {
			t.Errorf("Metric %+v name got %q want '/weirdness'", m, m.Name)
		}
		if len(m.FieldValues) != 1 {
			t.Errorf("MetricUpdate got %d fields want 1", len(m.FieldValues))
		}

		switch m.FieldValues[0] {
		case "weird1":
			uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
			if !ok {
				t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
			}
			if uv.Uint64Value != 4 {
				t.Errorf("%v: Value got %v want 4", m, uv.Uint64Value)
			}
			foundWeird1 = true
		case "weird2":
			uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
			if !ok {
				t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
			}
			if uv.Uint64Value != 1 {
				t.Errorf("%v: Value got %v want 1", m, uv.Uint64Value)
			}
			foundWeird2 = true
		}
	}

	if !foundWeird1 {
		t.Errorf("Field value weird1 not found: %+v", emitter)
	}
	if !foundWeird2 {
		t.Errorf("Field value weird2 not found: %+v", emitter)
	}
}

func TestMetricUpdateStageTiming(t *testing.T) {
	defer reset()

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

	fooMetric, err := NewUint64Metric("/foo", false, pb.MetricMetadata_UNITS_NONE, fooDescription)
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

	// Ensure re-emitting doesn't cause another event to be sent.
	emitter.Reset()
	EmitMetricUpdate()
	if len(emitter) != 0 {
		t.Fatalf("EmitMetricUpdate emitted %d events want %d", len(emitter), 0)
	}

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
}

func TestEmitMetricUpdateWithMicroseconds(t *testing.T) {
	defer reset()

	foo, err := NewUint64Metric("/fooDuration", false, pb.MetricMetadata_UNITS_MICROSECONDS, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}

	// Don't care about the registration metrics.
	emitter.Reset()
	EmitMetricUpdate()

	if len(emitter) != 1 {
		t.Fatalf("EmitMetricUpdate emitted %d events want 1", len(emitter))
	}

	update, ok := emitter[0].(*pb.MetricUpdate)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricUpdate", emitter[0], emitter[0])
	}

	if len(update.Metrics) != 1 {
		t.Errorf("MetricUpdate got %d metrics want 2", len(update.Metrics))
	}

	// Both are included for their initial values.
	m := update.Metrics[0]
	if m.Name != "/fooDuration" {
		t.Errorf("/fooDuration not found: %+v", emitter)
	}

	uv, ok := m.Value.(*pb.MetricValue_Uint64Value)
	if !ok {
		t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
	}
	if uv.Uint64Value != 0 {
		t.Errorf("%v: Value got %v want 0", m, uv.Uint64Value)
	}

	// Increment fooDuration. Only it is included in the next update.
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
		t.Errorf("MetricUpdate got %d metrics want 1", len(update.Metrics))
	}

	m = update.Metrics[0]
	if m.Name != "/fooDuration" {
		t.Errorf("Metric %+v name got %q want '/fooDuration'", m, m.Name)
	}

	uv, ok = m.Value.(*pb.MetricValue_Uint64Value)
	if !ok {
		t.Errorf("%+v: value %v got %T want pb.MetricValue_Uint64Value", m, m.Value, m.Value)
	}
	if uv.Uint64Value != 1 {
		t.Errorf("%v: Value got %v want 1", m, uv.Uint64Value)
	}
}
