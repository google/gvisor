// Copyright 2026 The gVisor Authors.
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

package tests

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/pretty"
)

func TestZeroSizedCrossEngineRoundTrip(t *testing.T) {
	prev := state.GraphEngineEnabled()
	defer state.EnableGraphEngine(prev)

	saveWith := func(graph bool, root *zeroCrossRoot) []byte {
		t.Helper()
		state.EnableGraphEngine(graph)
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save(graph=%v): %v", graph, err)
		}
		return buf.Bytes()
	}
	load := func(data []byte) *zeroCrossRoot {
		t.Helper()
		var out zeroCrossRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(data), &out); err != nil {
			t.Fatalf("Load: %v", err)
		}
		return &out
	}
	verify := func(step string, got *zeroCrossRoot) {
		t.Helper()
		if got.emptyA == nil || got.emptyB == nil || got.nested == nil || got.anon == nil {
			t.Fatalf("%s: nil zero-sized pointer in %+v", step, got)
		}
		if p, ok := got.ifaceA.(*savableEmptyStruct); !ok || p == nil {
			t.Fatalf("%s: ifaceA = %#v (%T), want non-nil *savableEmptyStruct", step, got.ifaceA, got.ifaceA)
		}
		if p, ok := got.ifaceB.(*zeroSizedOther); !ok || p == nil {
			t.Fatalf("%s: ifaceB = %#v (%T), want non-nil *zeroSizedOther", step, got.ifaceB, got.ifaceB)
		}
		if got.emptyInts == nil || len(got.emptyInts) != 0 || cap(got.emptyInts) != 0 {
			t.Fatalf("%s: emptyInts = %#v (len=%d cap=%d), want non-nil empty cap 0", step, got.emptyInts, len(got.emptyInts), cap(got.emptyInts))
		}
		if got.emptyStrs == nil || len(got.emptyStrs) != 0 || cap(got.emptyStrs) != 0 {
			t.Fatalf("%s: emptyStrs = %#v (len=%d cap=%d), want non-nil empty cap 0", step, got.emptyStrs, len(got.emptyStrs), cap(got.emptyStrs))
		}
		if got.zeroElems == nil || len(got.zeroElems) != 3 || cap(got.zeroElems) != 5 {
			t.Fatalf("%s: zeroElems len=%d cap=%d, want 3/5", step, len(got.zeroElems), cap(got.zeroElems))
		}
		if got.anonElems == nil || len(got.anonElems) != 4 || cap(got.anonElems) != 4 {
			t.Fatalf("%s: anonElems len=%d cap=%d, want 4/4", step, len(got.anonElems), cap(got.anonElems))
		}
		if got.checkValue != 42 {
			t.Fatalf("%s: checkValue = %d, want 42", step, got.checkValue)
		}
	}

	orig := &zeroCrossRoot{
		emptyA:     new(savableEmptyStruct),
		emptyB:     new(zeroSizedOther),
		nested:     new(zeroSizedNested),
		anon:       new(struct{}),
		ifaceA:     new(savableEmptyStruct),
		ifaceB:     new(zeroSizedOther),
		emptyInts:  []int64{},
		emptyStrs:  []string{},
		zeroElems:  make([]savableEmptyStruct, 3, 5),
		anonElems:  make([]struct{}, 4),
		checkValue: 42,
	}

	// Chained graph -> wire -> graph (exercises saving a graph-decoded state
	// containing multiple distinct zero-sized pointer types with the wire engine).
	g1 := saveWith(true, orig)
	var textOut, htmlOut bytes.Buffer
	if err := pretty.PrintText(&textOut, bytes.NewReader(g1)); err != nil {
		t.Fatalf("PrintText: %v", err)
	}
	if err := pretty.PrintHTML(&htmlOut, bytes.NewReader(g1)); err != nil {
		t.Fatalf("PrintHTML: %v", err)
	}
	r1 := load(g1)
	verify("graph_1", r1)
	w2 := saveWith(false, r1)
	r2 := load(w2)
	verify("wire_2", r2)
	g3 := saveWith(true, r2)
	r3 := load(g3)
	verify("graph_3", r3)

	// Chained wire -> graph -> wire.
	cw1 := saveWith(false, orig)
	cr1 := load(cw1)
	verify("wire_1", cr1)
	cg2 := saveWith(true, cr1)
	cr2 := load(cg2)
	verify("graph_2", cr2)
	cw3 := saveWith(false, cr2)
	cr3 := load(cw3)
	verify("wire_3", cr3)
}

func TestZeroSizedStandaloneWithHooks(t *testing.T) {
	if sz := reflect.TypeFor[zeroHookTarget]().Size(); sz != 0 {
		t.Fatalf("zeroHookTarget size = %d, want 0", sz)
	}
	prev := state.GraphEngineEnabled()
	defer state.EnableGraphEngine(prev)

	for _, graph := range []bool{false, true} {
		name := "wire"
		if graph {
			name = "graph"
		}
		t.Run(name, func(t *testing.T) {
			state.EnableGraphEngine(graph)

			var localTarget zeroHookTarget
			orig := &zeroHookWaiter{
				dep:   &localTarget,
				iface: &localTarget,
				id:    99,
			}
			var buf bytes.Buffer
			if _, err := state.Save(t.Context(), &buf, orig); err != nil {
				t.Fatalf("Save: %v", err)
			}
			data := buf.Bytes()

			if graph {
				var textOut, htmlOut bytes.Buffer
				if err := pretty.PrintText(&textOut, bytes.NewReader(data)); err != nil {
					t.Fatalf("PrintText: %v", err)
				}
				if !strings.Contains(textOut.String(), "zeroHookTarget") {
					t.Errorf("PrintText missing standalone zeroHookTarget object:\n%s", textOut.String())
				}
				if err := pretty.PrintHTML(&htmlOut, bytes.NewReader(data)); err != nil {
					t.Fatalf("PrintHTML: %v", err)
				}
			}

			rec := &zeroHookRecorder{}
			ctx := context.WithValue(t.Context(), zeroHookRecorderKey{}, rec)
			var got zeroHookWaiter
			if _, err := state.Load(ctx, bytes.NewReader(data), &got); err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got.id != 99 || got.dep == nil {
				t.Fatalf("got = %+v, want id=99 and non-nil dep", got)
			}
			if p, ok := got.iface.(*zeroHookTarget); !ok || p == nil || p != got.dep {
				t.Fatalf("got.iface = %#v (%T), want %p (*zeroHookTarget)", got.iface, got.iface, got.dep)
			}
			if rec.gotVal != 777 || !rec.targetDone {
				t.Fatalf("zeroHookRecorder = %+v, want gotVal=777 and targetDone=true", rec)
			}
			targetIdx := slices.Index(rec.events, "target:afterLoad")
			waiterIdx := slices.Index(rec.events, "waiter:afterLoad")
			if targetIdx < 0 || waiterIdx < 0 || targetIdx >= waiterIdx {
				t.Fatalf("unexpected callback order %v; want target:afterLoad before waiter:afterLoad", rec.events)
			}

			// Also test saving and loading zeroHookTarget directly as the root object.
			buf.Reset()
			if _, err := state.Save(t.Context(), &buf, new(zeroHookTarget)); err != nil {
				t.Fatalf("Save(root=zeroHookTarget): %v", err)
			}
			rootRec := &zeroHookRecorder{}
			rootCtx := context.WithValue(t.Context(), zeroHookRecorderKey{}, rootRec)
			var gotRoot zeroHookTarget
			if _, err := state.Load(rootCtx, bytes.NewReader(buf.Bytes()), &gotRoot); err != nil {
				t.Fatalf("Load(root=zeroHookTarget): %v", err)
			}
			if rootRec.gotVal != 777 || !rootRec.targetDone {
				t.Fatalf("root zeroHookRecorder = %+v, want gotVal=777 and targetDone=true", rootRec)
			}
		})
	}
}
