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
	"fmt"
	"reflect"
	"strings"
	"structs"
	"testing"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state/wire"
)

type directTestStruct struct {
	p *int
}

type testIface interface {
	testVal() int
}

type testImpl int

func (t testImpl) testVal() int           { return int(t) }
func (t *testImpl) StateTypeName() string { return "state.testImpl" }
func (t *testImpl) StateFields() []string { return nil }

type testPrintHolder struct {
	v any
}

func (*testPrintHolder) StateTypeName() string { return "state.testPrintHolder" }
func (*testPrintHolder) StateFields() []string { return []string{"v"} }
func (h *testPrintHolder) StateSave(s Sink)    { s.graph.save(0, &h.v) }
func (h *testPrintHolder) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &h.v)
}

func init() {
	Register((*testImpl)(nil))
	RegisterStruct((*testPrintHolder)(nil))
}

func TestIsDirect(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[int](),
		reflect.TypeFor[string](),
		reflect.TypeFor[*int](),
		reflect.TypeFor[map[int]int](),
		reflect.TypeFor[chan int](),
		reflect.TypeFor[func()](),
		reflect.TypeFor[[]*int](),
		reflect.TypeFor[[0]*int](),
		reflect.TypeFor[[1]*int](),
		reflect.TypeFor[[2]*int](),
		reflect.TypeFor[[1][1]*int](),
		reflect.TypeFor[[1]int](),
		reflect.TypeFor[struct{}](),
		reflect.TypeFor[directTestStruct](),
		reflect.TypeFor[struct{ a [1]*int }](),
		reflect.TypeFor[[1]directTestStruct](),
		reflect.TypeFor[struct {
			p *int
			z struct{}
		}](),
		reflect.TypeFor[struct {
			z struct{}
			p *int
		}](),
		reflect.TypeFor[struct{ i int }](),
	} {
		// Values stored indirectly are pointed to by a non-nil data word,
		// even for zero values. The data word holds zero values of direct
		// types.
		v := reflect.Zero(typ).Interface()
		want := efaceOf(&v).data == nil
		if got := isDirect(typ); got != want {
			t.Errorf("isDirect(%v) = %t, want %t", typ, got, want)
		}
	}
}

func TestMakeAny(t *testing.T) {
	var nilAny any
	if got := makeAny(typeInfoOf(reflect.TypeFor[any]()), unsafe.Pointer(&nilAny)); got != nil {
		t.Fatalf("makeAny(nil any) = %#v, want nil", got)
	}
	nonNilAny := any(testImpl(7))
	if got := makeAny(typeInfoOf(reflect.TypeFor[any]()), unsafe.Pointer(&nonNilAny)); got != testImpl(7) {
		t.Fatalf("makeAny(testImpl(7) any) = %#v, want 7", got)
	}
	var nilIface testIface
	if got := makeAny(typeInfoOf(reflect.TypeFor[testIface]()), unsafe.Pointer(&nilIface)); got != nil {
		t.Fatalf("makeAny(nil testIface) = %#v, want nil", got)
	}
	nonNilIface := testIface(testImpl(9))
	got := makeAny(typeInfoOf(reflect.TypeFor[testIface]()), unsafe.Pointer(&nonNilIface))
	if ti, ok := got.(testIface); !ok || ti.testVal() != 9 {
		t.Fatalf("makeAny(testImpl(9) testIface) = %#v, want 9", got)
	}
}

func TestPlainFields(t *testing.T) {
	typeInfosMu.Lock()
	defer typeInfosMu.Unlock()
	var b typeInfoBuilder
	if b.plainFields(reflect.TypeFor[struct {
		A byte
		B int64
	}]()) || b.plainFields(reflect.TypeFor[struct {
		_ int64
		A int64
	}]()) || b.plainFields(reflect.TypeFor[struct{ A bool }]()) {
		t.Errorf("plainFields accepted struct with padding, non-zero blank, or bool")
	}
	if !b.plainFields(reflect.TypeFor[struct {
		_    structs.HostLayout
		A, B uint32
	}]()) {
		t.Errorf("plainFields rejected packed structs.HostLayout struct")
	}
}

func TestGraphRootMismatchAndPrintTime(t *testing.T) {
	var src *uint64
	u := uint64(0xdeadbeef)
	src = &u
	var buf bytes.Buffer
	if _, err := saveGraph(context.Background(), &buf, &src); err != nil {
		t.Fatalf("saveGraph failed: %v", err)
	}
	var wrong **int64
	r := wire.Reader{Reader: bytes.NewReader(buf.Bytes())}
	hdr, err := ReadHeaderMode(&r)
	if err != nil {
		t.Fatalf("ReadHeaderMode failed: %v", err)
	}
	if _, err := loadGraph(context.Background(), r.Reader, &wrong, hdr.Length, 0); err == nil {
		t.Fatalf("loadGraph(*uint64 -> **int64) succeeded, want error")
	}

	ts := time.Date(2026, time.October, 28, 1, 2, 3, 0, time.UTC)
	holder := testPrintHolder{v: ts}
	buf.Reset()
	if _, err := saveGraph(context.Background(), &buf, &holder); err != nil {
		t.Fatalf("saveGraph(holder) failed: %v", err)
	}
	r = wire.Reader{Reader: bytes.NewReader(buf.Bytes())}
	hdr, err = ReadHeaderMode(&r)
	if err != nil {
		t.Fatalf("ReadHeaderMode failed: %v", err)
	}
	raw := make([]byte, hdr.Length)
	if _, err := r.Read(raw); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	var out strings.Builder
	if err := PrintGraph(&out, raw, 0, false); err != nil {
		t.Fatalf("PrintGraph failed: %v", err)
	}
	if !strings.Contains(out.String(), fmt.Sprint(ts.Year())) {
		t.Errorf("PrintGraph output %q missing timestamp %v", out.String(), ts)
	}
}
