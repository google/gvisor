// Copyright 2018 Google LLC
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

	"github.com/golang/protobuf/proto"
	"gvisor.googlesource.com/gvisor/pkg/eventchannel"
	pb "gvisor.googlesource.com/gvisor/pkg/metric/metric_go_proto"
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
	eventchannel.AddEmitter(&emitter)
}

// reset clears all global state in the metric package.
func reset() {
	initialized = false
	allMetrics = makeMetricSet()
	emitter.Reset()
}

const (
	fooDescription = "Foo!"
	barDescription = "Bar Baz"
)

func TestInitialize(t *testing.T) {
	defer reset()

	_, err := NewUint64Metric("/foo", false, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", true, barDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	Initialize()

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
		if m.Type != pb.MetricMetadata_UINT64 {
			t.Errorf("Metadata %+v Type got %v want %v", m, m.Type, pb.MetricMetadata_UINT64)
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
		case "/bar":
			foundBar = true
			if m.Description != barDescription {
				t.Errorf("/bar %+v Description got %q want %q", m, m.Description, barDescription)
			}
			if !m.Sync {
				t.Errorf("/bar %+v Sync got true want false", m)
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

	_, err := NewUint64Metric("/foo", false, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", true, barDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	Disable()

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

	foo, err := NewUint64Metric("/foo", false, fooDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	_, err = NewUint64Metric("/bar", true, barDescription)
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	Initialize()

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
