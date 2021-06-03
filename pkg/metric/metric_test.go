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
