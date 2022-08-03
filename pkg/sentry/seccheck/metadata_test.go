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
				Name: "test",
				OptionalFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 456, Name: "field1"},
				},
			},
		},
		{
			name: "optional_id",
			point: PointDesc{
				Name: "test",
				OptionalFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 123, Name: "field2"},
				},
			},
		},
		{
			name: "context_name",
			point: PointDesc{
				Name: "test",
				ContextFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 456, Name: "field1"},
				},
			},
		},
		{
			name: "context_id",
			point: PointDesc{
				Name: "test",
				ContextFields: []FieldDesc{
					{ID: 123, Name: "field1"},
					{ID: 123, Name: "field2"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				recover()
			}()
			registerPoint(tc.point)
			t.Errorf("Registering the same point twice should panic")

		})
	}
}
