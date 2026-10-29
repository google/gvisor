// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state/wire"
)

func init() {
	registerBinary((*binaryFailure)(nil))
}

var errBinary = errors.New("binary codec failed")

type binaryFailure struct {
	failAppend bool
}

func (b *binaryFailure) AppendBinary(data []byte) ([]byte, error) {
	if b.failAppend {
		return nil, errBinary
	}
	return data, nil
}

func (*binaryFailure) UnmarshalBinary([]byte) error { return errBinary }

func TestBinaryErrors(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Save(t.Context(), &buf, &binaryFailure{failAppend: true}); !errors.Is(err, errBinary) {
		t.Fatalf("Save = %v, want %v", err, errBinary)
	}
	buf.Reset()
	if _, err := Save(t.Context(), &buf, &binaryFailure{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(t.Context(), &buf, &binaryFailure{}); !errors.Is(err, errBinary) {
		t.Fatalf("Load = %v, want %v", err, errBinary)
	}
}

// lazyType counts StateFields calls.
type lazyType struct{}

var lazyTypeFieldsCalls int

func (*lazyType) StateTypeName() string { return "state.lazyType" }

func (*lazyType) StateFields() []string {
	lazyTypeFieldsCalls++
	return nil
}

func (*lazyType) StateSave(Sink) {}

func (*lazyType) StateLoad(context.Context, Source) {}

// duplicateFieldType is never registered: race builds would reject it at init.
type duplicateFieldType struct {
	v int64
}

func (*duplicateFieldType) StateTypeName() string { return "state.duplicateFieldType" }

func (*duplicateFieldType) StateFields() []string { return []string{"v", "v"} }

func (d *duplicateFieldType) StateSave(s Sink) { s.Save(0, &d.v) }

func (d *duplicateFieldType) StateLoad(_ context.Context, s Source) { s.Load(0, &d.v) }

// TestRegisterIsLazy checks that Register does not collect type metadata when
// it is deferred.
func TestRegisterIsLazy(t *testing.T) {
	if eagerTypeInfo {
		t.Skip("type metadata is collected eagerly")
	}
	before := lazyTypeFieldsCalls
	Register((*lazyType)(nil))
	if calls := lazyTypeFieldsCalls - before; calls != 0 {
		t.Errorf("Register called StateFields %d times, want 0", calls)
	}
}

// TestLazyValidation checks that types skipped by Register are validated on use.
func TestLazyValidation(t *testing.T) {
	if eagerTypeInfo {
		t.Skip("type metadata is validated eagerly")
	}
	var buf bytes.Buffer
	_, err := Save(t.Context(), &buf, &duplicateFieldType{})
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("Save = %v, want duplicate field error", err)
	}
}

func TestArrayPartialStores(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []wire.Object
		target any
		want   any
	}{
		{"signed", []wire.Object{wire.Int(7), wire.Int(128), wire.Int(9)}, &[3]int8{99, 99, 99}, [3]int8{7, -128, 99}},
		{"unsigned", []wire.Object{wire.Uint(7), wire.Uint(256), wire.Uint(9)}, &[3]uint8{99, 99, 99}, [3]uint8{7, 0, 99}},
		{"float", []wire.Object{wire.Float64(7), wire.Float64(1 + 1e-10), wire.Float64(9)}, &[3]float32{99, 99, 99}, [3]float32{7, 1, 99}},
		{"complex", []wire.Object{new(wire.Complex128(7)), new(wire.Complex128(complex(1, 1+1e-10))), new(wire.Complex128(9))}, &[3]complex64{99, 99, 99}, [3]complex64{7, 1 + 1i, 99}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var saved bytes.Buffer
			writer := wire.Writer{Writer: &saved}
			if err := WriteHeader(&writer, 1, true); err != nil {
				t.Fatal(err)
			}
			wire.Save(&writer, wire.Uint(1))
			wire.Save(&writer, &wire.ObjectArray{Contents: test.values})
			if _, err := Load(t.Context(), &saved, test.target); err == nil || !strings.Contains(err.Error(), "truncated") {
				t.Fatalf("Load = %v, want truncation error", err)
			}
			if got, want := reflect.ValueOf(test.target).Elem().Interface(), test.want; !reflect.DeepEqual(got, want) {
				t.Errorf("partial destination = %v, want %v", got, want)
			}
		})
	}
}

func TestArrayDestinationFlags(t *testing.T) {
	private := struct{ values [2]int64 }{values: [2]int64{17, 29}}
	slice := []int64{17, 29}
	for _, test := range []struct {
		name    string
		target  reflect.Value
		wantErr string
	}{
		{"read_only", reflect.ValueOf(&private).Elem().Field(0), "array element of type int64 is not settable"},
		{"unaddressable_array", reflect.ValueOf([2]int64{17, 29}), "array element of type int64 is not settable"},
		{"unaddressable_slice", reflect.ValueOf(slice), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Use the public parser so this exercises its actual typed payload.
			var saved bytes.Buffer
			wire.Save(&wire.Writer{Writer: &saved}, &wire.ObjectArray{Contents: []wire.Object{wire.Int(7), wire.Int(11)}})
			encoded := wire.Load(&wire.Reader{Reader: &saved})
			var ds decodeState
			err := safely(func() { ds.decodeObject(nil, test.target, encoded) })
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("restore error = %v, want %q", err, test.wantErr)
			}
		})
	}
	if got, want := private.values, [2]int64{17, 29}; got != want {
		t.Errorf("read-only destination = %v, want %v", got, want)
	}
	if got, want := slice, []int64{7, 11}; !reflect.DeepEqual(got, want) {
		t.Errorf("slice destination = %v, want %v", got, want)
	}
}
