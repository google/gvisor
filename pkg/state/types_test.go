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
type lazyType struct {
	v int64
}

var lazyTypeFieldsCalls int

func (*lazyType) StateTypeName() string { return "state.lazyType" }

func (*lazyType) StateFields() []string {
	lazyTypeFieldsCalls++
	return []string{"v"}
}

func (l *lazyType) StateSave(s Sink) { s.Save(0, &l.v) }

func (l *lazyType) StateLoad(_ context.Context, s Source) { s.Load(0, &l.v) }

// duplicateFieldType is never registered: race builds would reject it at init.
type duplicateFieldType struct {
	v int64
}

func (*duplicateFieldType) StateTypeName() string { return "state.duplicateFieldType" }

func (*duplicateFieldType) StateFields() []string { return []string{"v", "v"} }

func (d *duplicateFieldType) StateSave(s Sink) { s.Save(0, &d.v) }

func (d *duplicateFieldType) StateLoad(_ context.Context, s Source) { s.Load(0, &d.v) }

// TestRegisterIsLazy checks that Register stays cheap in non-race builds,
// since it runs in the init functions of every binary on every start.
func TestRegisterIsLazy(t *testing.T) {
	if raceEnabled {
		t.Skip("race builds validate types eagerly")
	}
	Register((*lazyType)(nil))
	if lazyTypeFieldsCalls != 0 {
		t.Errorf("Register called StateFields %d times, want 0", lazyTypeFieldsCalls)
	}
	typ := reflect.TypeFor[lazyType]()
	if _, ok := reverseTypeDatabase[typ]; ok {
		t.Errorf("Register populated reverseTypeDatabase")
	}
	if got := globalTypeDatabase["state.lazyType"]; got != typ {
		t.Errorf("globalTypeDatabase[%q] = %v, want %v", "state.lazyType", got, typ)
	}

	var buf bytes.Buffer
	if _, err := Save(t.Context(), &buf, &lazyType{v: 42}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var got lazyType
	if _, err := Load(t.Context(), &buf, &got); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.v != 42 {
		t.Errorf("Load: v = %d, want 42", got.v)
	}
}

// TestLazyValidation checks that types skipped by Register are validated on use.
func TestLazyValidation(t *testing.T) {
	if raceEnabled {
		t.Skip("race builds validate types eagerly")
	}
	var buf bytes.Buffer
	_, err := Save(t.Context(), &buf, &duplicateFieldType{})
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("Save = %v, want duplicate field error", err)
	}
}
