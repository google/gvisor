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

package seccheck

import (
	"runtime"
	"testing"
)

func TestSinkRegistration(t *testing.T) {
	sink := SinkDesc{Name: "test"}
	RegisterSink(sink)
	if _, ok := Sinks["test"]; !ok {
		t.Errorf("sink registration failed")
	}

	defer func() {
		recover()
	}()
	RegisterSink(sink)
	t.Errorf("Registering the same sink twice should panic")
}

func TestPointRegistration(t *testing.T) {
	point := PointDesc{Name: "test"}
	registerPoint(point)
	if _, ok := Points["test"]; !ok {
		t.Errorf("point registration failed")
	}

	defer func() {
		recover()
	}()
	registerPoint(point)
	t.Errorf("Registering the same point twice should panic")
}

func TestPointRegistrationFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		point PointDesc
	}{
		{
			name: "optional_name",
			point: PointDesc{
				OptionalFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 456, Name: "field1"},
				},
			},
		},
		{
			name: "optional_id",
			point: PointDesc{
				OptionalFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 123, Name: "field2"},
				},
			},
		},
		{
			name: "context_name",
			point: PointDesc{
				ContextFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 456, Name: "field1"},
				},
			},
		},
		{
			name: "context_id",
			point: PointDesc{
				ContextFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 123, Name: "field2"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Use a unique point name, so that only the repeated field can cause
			// the registration to panic.
			pt := tc.point
			pt.Name = "test_fields/" + tc.name
			defer func() {
				recover()
			}()
			registerPoint(pt)
			t.Errorf("Registering a point with repeated fields should panic")
		})
	}
}

// BenchmarkInitialize measures the cost of Initialize from scratch, and
// reports the heap size that Points retains.
func BenchmarkInitialize(b *testing.B) {
	saved := Points
	defer func() { Points = saved }()
	initialize := func() {
		Points = map[string]PointDesc{}
		genericInit()
		archInit()
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		initialize()
	}
	b.StopTimer()
	b.ReportMetric(float64(retainedBytes(func() { Points = nil }, initialize)), "retained-B")
}

// retainedBytes returns how much the live heap grows when build runs, after
// reset drops the result of previous runs.
func retainedBytes(reset, build func()) int64 {
	reset()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	build()
	runtime.GC()
	runtime.ReadMemStats(&after)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}
