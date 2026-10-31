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

package state

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/state/wire"
)

type cycleTestNode struct {
	waitFor *cycleTestNode
}

func (*cycleTestNode) StateTypeName() string { return "state.cycleTestNode" }
func (*cycleTestNode) StateFields() []string { return []string{"waitFor"} }
func (n *cycleTestNode) StateSave(s Sink)    { s.graph.save(0, &n.waitFor) }
func (n *cycleTestNode) StateLoad(_ context.Context, s Source) {
	s.graph.loadWait(0, &n.waitFor)
	s.graph.afterLoad(func() {})
}

type cycleStemNode struct {
	waitFor *cycleTestNode
}

func (*cycleStemNode) StateTypeName() string { return "state.cycleStemNode" }
func (*cycleStemNode) StateFields() []string { return []string{"waitFor"} }
func (n *cycleStemNode) StateSave(s Sink)    { s.graph.save(0, &n.waitFor) }
func (n *cycleStemNode) StateLoad(_ context.Context, s Source) {
	s.graph.loadWait(0, &n.waitFor)
	s.graph.afterLoad(func() {})
}

type cycleCollectionNode struct {
	s []*cycleCollectionNode
	m map[int]*cycleCollectionNode
}

func (*cycleCollectionNode) StateTypeName() string { return "state.cycleCollectionNode" }
func (*cycleCollectionNode) StateFields() []string { return []string{"s", "m"} }
func (n *cycleCollectionNode) StateSave(s Sink) {
	s.graph.save(0, &n.s)
	s.graph.save(1, &n.m)
}
func (n *cycleCollectionNode) StateLoad(_ context.Context, s Source) {
	s.graph.loadWait(0, &n.s)
	s.graph.loadWait(1, &n.m)
	s.graph.afterLoad(func() {})
}

var registerCycleTestTypes = sync.OnceFunc(func() {
	Register((*cycleTestNode)(nil))
	Register((*cycleStemNode)(nil))
	Register((*cycleCollectionNode)(nil))
	Register((*cbOrderNode)(nil))
	fingerprint.Store(0)
})

func roundTripGraphErr[T any](t *testing.T, root T) error {
	t.Helper()
	registerCycleTestTypes()
	var buf bytes.Buffer
	// Wrap root below object 0, which Load allows other objects to reference
	// without waiting.
	savedRoot := root
	if _, err := saveGraph(t.Context(), &buf, &savedRoot); err != nil {
		t.Fatalf("saveGraph: %v", err)
	}
	wr := wire.Reader{Reader: &buf}
	hdr, err := ReadHeaderMode(&wr)
	if err != nil {
		t.Fatalf("ReadHeaderMode: %v", err)
	}
	if !hdr.Object || !hdr.Graph {
		t.Fatalf("ReadHeaderMode = %+v, want Object=true Graph=true", hdr)
	}
	var loadedRoot T
	_, err = loadGraph(t.Context(), &buf, &loadedRoot, hdr.Length, 0)
	return err
}

func TestGraphDependencyCycle(t *testing.T) {
	t.Run("direct_two_node_cycle", func(t *testing.T) {
		a := &cycleTestNode{}
		b := &cycleTestNode{waitFor: a}
		a.waitFor = b

		err := roundTripGraphErr(t, a)
		const want = `incomplete graph: dependency cycle: {"state.cycleTestNode" => "state.cycleTestNode" => "state.cycleTestNode"}`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("loadGraph = %v, want substring %s", err, want)
		}
	})

	t.Run("stem_outside_cycle_is_trimmed", func(t *testing.T) {
		a := &cycleTestNode{}
		b := &cycleTestNode{waitFor: a}
		a.waitFor = b
		stem := &cycleStemNode{waitFor: a}

		err := roundTripGraphErr(t, stem)
		const want = `incomplete graph: dependency cycle: {"state.cycleTestNode" => "state.cycleTestNode" => "state.cycleTestNode"}`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("loadGraph = %v, want substring %s", err, want)
		}
		if strings.Contains(err.Error(), "cycleStemNode") {
			t.Fatalf("cycle diagnostic included non-cycle stem node: %v", err)
		}
	})

	t.Run("array_cycle_formats_array_kind", func(t *testing.T) {
		n := &cycleCollectionNode{}
		n.s = []*cycleCollectionNode{n}

		err := roundTripGraphErr(t, n)
		if err == nil || !strings.Contains(err.Error(), "incomplete graph: dependency cycle:") || !strings.Contains(err.Error(), `"[1]*state.cycleCollectionNode"`) {
			t.Fatalf("loadGraph = %v, want dependency cycle naming [1]*state.cycleCollectionNode", err)
		}
	})

	t.Run("map_cycle_formats_map_kind", func(t *testing.T) {
		n := &cycleCollectionNode{}
		n.m = map[int]*cycleCollectionNode{0: n}

		err := roundTripGraphErr(t, n)
		if err == nil || !strings.Contains(err.Error(), "incomplete graph: dependency cycle:") || !strings.Contains(err.Error(), `"map[int]*state.cycleCollectionNode"`) {
			t.Fatalf("loadGraph = %v, want dependency cycle naming map[int]*state.cycleCollectionNode", err)
		}
	})
}

type cbOrderLogKey struct{}

type cbOrderNode struct {
	name      string
	early     []*cbOrderNode
	waitFor   []*cbOrderNode
	valueRef  *cbOrderNode
	scalarVal int64

	// Non-saved fields populated during Load callbacks.
	scalarDone    bool
	valueRefDone  bool
	afterStep1    bool
	afterLoadDone bool
	computed      int64
}

func (*cbOrderNode) StateTypeName() string { return "state.cbOrderNode" }
func (*cbOrderNode) StateFields() []string {
	return []string{"name", "early", "waitFor", "scalarVal", "valueRef"}
}

func (n *cbOrderNode) StateSave(s Sink) {
	s.graph.save(0, &n.name)
	s.graph.save(1, &n.early)
	s.graph.save(2, &n.waitFor)
	s.graph.saveValue(3, n.scalarVal)
	s.graph.saveValue(4, n.valueRef)
}

func (n *cbOrderNode) StateLoad(ctx context.Context, s Source) {
	record := func(step string) {
		if logPtr, ok := ctx.Value(cbOrderLogKey{}).(*[]string); ok {
			*logPtr = append(*logPtr, fmt.Sprintf("%s:%s", n.name, step))
		}
	}
	s.graph.load(0, &n.name)
	s.graph.load(1, &n.early)
	s.graph.loadWait(2, &n.waitFor)
	s.graph.loadValue(3, new(int64), func(v any) {
		if n.valueRefDone || n.afterStep1 || n.afterLoadDone {
			Failf("%s: scalar loadValue ran out of order", n.name)
		}
		n.scalarVal = v.(int64)
		n.scalarDone = true
		record("scalar")
	})
	s.graph.loadValueTo(4, (**cbOrderNode)(nil), n)
	s.graph.afterLoad(func() {
		if !n.scalarDone || !n.valueRefDone || n.afterLoadDone {
			Failf("%s: first afterLoad ran out of order (scalar=%v valueRef=%v after=%v)", n.name, n.scalarDone, n.valueRefDone, n.afterLoadDone)
		}
		n.afterStep1 = true
		record("after1")
	})
	s.graph.afterLoadTo(n)
}

func (n *cbOrderNode) StateLoadValue(ctx context.Context, slot int, v any) {
	if slot != 4 {
		Failf("%s: unexpected slot %d", n.name, slot)
	}
	if !n.scalarDone || n.afterStep1 || n.afterLoadDone {
		Failf("%s: StateLoadValue ran out of order", n.name)
	}
	ref := v.(*cbOrderNode)
	if ref != nil && !ref.afterLoadDone {
		Failf("%s: valueRef %s had not completed AfterLoad", n.name, ref.name)
	}
	n.valueRef = ref
	n.valueRefDone = true
	if logPtr, ok := ctx.Value(cbOrderLogKey{}).(*[]string); ok {
		*logPtr = append(*logPtr, fmt.Sprintf("%s:valueRef", n.name))
	}
}

func (n *cbOrderNode) StateAfterLoad(ctx context.Context) {
	if !n.scalarDone || !n.valueRefDone || !n.afterStep1 || n.afterLoadDone {
		Failf("%s: AfterLoad ran out of order", n.name)
	}
	sum := n.scalarVal
	for _, dep := range n.waitFor {
		if !dep.afterLoadDone {
			Failf("%s: wait dependency %s had not completed AfterLoad", n.name, dep.name)
		}
		sum += dep.computed
	}
	if n.valueRef != nil {
		sum += n.valueRef.computed * 10
	}
	n.computed = sum
	n.afterLoadDone = true
	if logPtr, ok := ctx.Value(cbOrderLogKey{}).(*[]string); ok {
		*logPtr = append(*logPtr, fmt.Sprintf("%s:after2", n.name))
	}
}

func TestGraphCallbackOrder(t *testing.T) {
	registerCycleTestTypes()

	// Build a diamond + valueRef dependency graph while forcing discovery in
	// reverse topological order (A discovered first, leaf D discovered last):
	//   A waits on B and C, and has a valueRef to E;
	//   B and C both wait on D;
	//   E waits on C.
	d := &cbOrderNode{name: "D", scalarVal: 1}
	b := &cbOrderNode{name: "B", waitFor: []*cbOrderNode{d}, scalarVal: 2}
	c := &cbOrderNode{name: "C", waitFor: []*cbOrderNode{d}, scalarVal: 4}
	e := &cbOrderNode{name: "E", waitFor: []*cbOrderNode{c}, scalarVal: 8}
	a := &cbOrderNode{
		name:      "A",
		early:     []*cbOrderNode{b, c, e, d},
		waitFor:   []*cbOrderNode{b, c},
		valueRef:  e,
		scalarVal: 16,
	}

	var buf bytes.Buffer
	if _, err := saveGraph(t.Context(), &buf, &a); err != nil {
		t.Fatalf("saveGraph: %v", err)
	}
	wr := wire.Reader{Reader: &buf}
	hdr, err := ReadHeaderMode(&wr)
	if err != nil {
		t.Fatalf("ReadHeaderMode: %v", err)
	}

	var events []string
	ctx := context.WithValue(t.Context(), cbOrderLogKey{}, &events)
	var loaded *cbOrderNode
	if _, err := loadGraph(ctx, &buf, &loaded, hdr.Length, 0); err != nil {
		t.Fatalf("loadGraph: %v", err)
	}

	// Verify exact computed state propagation:
	// D = 1; B = 2 + 1 = 3; C = 4 + 1 = 5; E = 8 + 5 = 13;
	// A = 16 + B(3) + C(5) + 10*E(13) = 154.
	if got, want := loaded.computed, int64(154); got != want {
		t.Fatalf("loaded.computed = %d, want %d (events=%v)", got, want, events)
	}

	pos := func(ev string) int {
		idx := slices.Index(events, ev)
		if idx < 0 {
			t.Fatalf("missing callback event %q in %v", ev, events)
		}
		return idx
	}
	if len(events) != 5*4 {
		t.Fatalf("got %d callback events %v, want 20 (4 per node)", len(events), events)
	}

	// Per-node intra-object FIFO order: scalar -> valueRef -> after1 -> after2.
	for _, name := range []string{"A", "B", "C", "D", "E"} {
		s, vr, a1, a2 := pos(name+":scalar"), pos(name+":valueRef"), pos(name+":after1"), pos(name+":after2")
		if !(s < vr && vr < a1 && a1 < a2) {
			t.Errorf("node %s intra-object order violated: scalar=%d valueRef=%d after1=%d after2=%d (%v)", name, s, vr, a1, a2, events)
		}
	}

	// Cross-object topological dependency constraints.
	for _, edge := range [][2]string{
		{"D:after2", "B:after1"},
		{"D:after2", "C:after1"},
		{"C:after2", "E:after1"},
		{"E:after2", "A:valueRef"},
		{"B:after2", "A:after1"},
		{"C:after2", "A:after1"},
	} {
		if pos(edge[0]) >= pos(edge[1]) {
			t.Errorf("dependency order violated: %s (%d) did not run before %s (%d); events=%v", edge[0], pos(edge[0]), edge[1], pos(edge[1]), events)
		}
	}
}

type defIface interface {
	defTag() int
}

type defImpl struct {
	v         int
	afterRuns int
}

func (*defImpl) defTag() int           { return 1 }
func (*defImpl) StateTypeName() string { return "state.defImpl" }
func (*defImpl) StateFields() []string { return []string{"v"} }
func (x *defImpl) StateSave(s Sink)    { s.graph.save(0, &x.v) }
func (x *defImpl) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.v)
	s.graph.afterLoad(func() { x.afterRuns++ })
}

type defInner struct {
	subMaps    []map[string]defIface
	fullMaps   []map[string]defIface
	ifacePtr   *defIface
	ifaceSlice []defIface
}

func (*defInner) StateTypeName() string { return "state.defInner" }
func (*defInner) StateFields() []string {
	return []string{"subMaps", "fullMaps", "ifacePtr", "ifaceSlice"}
}
func (x *defInner) StateSave(s Sink) {
	s.graph.save(0, &x.subMaps)
	s.graph.save(1, &x.fullMaps)
	s.graph.save(2, &x.ifacePtr)
	s.graph.save(3, &x.ifaceSlice)
}
func (x *defInner) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.subMaps)
	s.graph.load(1, &x.fullMaps)
	s.graph.load(2, &x.ifacePtr)
	s.graph.load(3, &x.ifaceSlice)
}

type defOuter struct {
	subIn     defInner
	in        defInner
	pad       int
	afterRuns int
}

func (*defOuter) StateTypeName() string { return "state.defOuter" }
func (*defOuter) StateFields() []string { return []string{"subIn", "in", "pad"} }
func (x *defOuter) StateSave(s Sink) {
	s.graph.save(0, &x.subIn)
	s.graph.save(1, &x.in)
	s.graph.save(2, &x.pad)
}
func (x *defOuter) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.subIn)
	s.graph.load(1, &x.in)
	s.graph.load(2, &x.pad)
	s.graph.afterLoad(func() { x.afterRuns++ })
}

type defHolder struct {
	in    *defInner
	next  *defHolder
	outer *defOuter
}

func (*defHolder) StateTypeName() string { return "state.defHolder" }
func (*defHolder) StateFields() []string { return []string{"in", "next", "outer"} }
func (x *defHolder) StateSave(s Sink) {
	s.graph.save(0, &x.in)
	s.graph.save(1, &x.next)
	s.graph.save(2, &x.outer)
}
func (x *defHolder) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.in)
	s.graph.load(1, &x.next)
	s.graph.load(2, &x.outer)
}

type defRoot struct {
	early1      *defInner
	directSlice []defIface
	holder      *defHolder
}

func (*defRoot) StateTypeName() string { return "state.defRoot" }
func (*defRoot) StateFields() []string { return []string{"early1", "directSlice", "holder"} }
func (x *defRoot) StateSave(s Sink) {
	s.graph.save(0, &x.early1)
	s.graph.save(1, &x.directSlice)
	s.graph.save(2, &x.holder)
}
func (x *defRoot) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.early1)
	s.graph.load(1, &x.directSlice)
	s.graph.load(2, &x.holder)
}

type defMapHolder struct {
	m map[int]int
}

func (*defMapHolder) StateTypeName() string { return "state.defMapHolder" }
func (*defMapHolder) StateFields() []string { return []string{"m"} }
func (x *defMapHolder) StateSave(s Sink)    { s.graph.save(0, &x.m) }
func (x *defMapHolder) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.m)
}

type defTrailingRoot struct {
	h *defMapHolder
}

func (*defTrailingRoot) StateTypeName() string { return "state.defTrailingRoot" }
func (*defTrailingRoot) StateFields() []string { return []string{"h"} }
func (x *defTrailingRoot) StateSave(s Sink)    { s.graph.save(0, &x.h) }
func (x *defTrailingRoot) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.h)
}

var registerDeferredTestTypes = sync.OnceFunc(func() {
	Register((*defImpl)(nil))
	Register((*defInner)(nil))
	Register((*defOuter)(nil))
	Register((*defHolder)(nil))
	Register((*defRoot)(nil))
	Register((*defMapHolder)(nil))
	Register((*defTrailingRoot)(nil))
	fingerprint.Store(0)
})

func TestGraphDeferredObjectDecode(t *testing.T) {
	registerDeferredTestTypes()

	t.Run("multi_pass_round_trip", func(t *testing.T) {
		var ifaceVal defIface = &defImpl{v: 42}
		nestedMap := map[string]defIface{"nested": &defImpl{v: 99}}
		// Place subMaps (mapArr[0:1:1]) on outer.subIn at BFS depth 1 so its
		// 1-element array encodes nestedMap before holder.in (outer.in)
		// discovers fullMaps (mapArr[0:2:2]) and absorbs the backing array,
		// while holder.next.outer reparents outer after both. On load:
		//   - Pass 0 defers nestedMap (map), mapArr (inexact array),
		//     ifaceVal (inexact value), and ifaceSlice (inexact array), then
		//     decodes outer at the end of Pass 0, revealing mapArr, ifaceVal,
		//     and ifaceSlice.
		//   - Deferred Pass 1 keeps nestedMap in remaining, then decodes
		//     mapArr, revealing nestedMap's mapType.
		//   - Deferred Pass 2 decodes nestedMap.
		mapArr := &[2]map[string]defIface{
			nestedMap,
			{"other": &defImpl{v: 5}},
		}
		outer := &defOuter{
			subIn: defInner{subMaps: mapArr[0:1:1]},
			in: defInner{
				subMaps:    mapArr[0:1:1],
				fullMaps:   mapArr[0:2:2],
				ifacePtr:   &ifaceVal,
				ifaceSlice: []defIface{&defImpl{v: 10}, &defImpl{v: 20}},
			},
			pad: 13,
		}
		saved := defRoot{
			early1:      &outer.subIn,
			directSlice: []defIface{&defImpl{v: 7}},
			holder:      &defHolder{in: &outer.in, next: &defHolder{outer: outer}},
		}

		var buf bytes.Buffer
		if _, err := saveGraph(t.Context(), &buf, &saved); err != nil {
			t.Fatalf("saveGraph: %v", err)
		}
		allBytes := buf.Bytes()
		wr := wire.Reader{Reader: bytes.NewReader(allBytes)}
		hdr, err := ReadHeaderMode(&wr)
		if err != nil {
			t.Fatalf("ReadHeaderMode: %v", err)
		}
		raw := allBytes[len(allBytes)-int(hdr.Length):]
		var printed strings.Builder
		if err := PrintGraph(&printed, raw, 0, false); err != nil {
			t.Fatalf("PrintGraph: %v", err)
		}
		out := printed.String()
		nestedIdx := strings.Index(out, `"nested"`)
		mapArrIdx := strings.Index(out, "= [g0r")
		outerIdx := strings.Index(out, "state.defOuter{")
		if nestedIdx < 0 || mapArrIdx < 0 || outerIdx < 0 || !(nestedIdx < mapArrIdx && mapArrIdx < outerIdx) {
			t.Fatalf("stream object order does not exercise 2 deferred passes (nested=%d, mapArr=%d, outer=%d):\n%s", nestedIdx, mapArrIdx, outerIdx, out)
		}

		var loaded defRoot
		if _, err := loadGraph(t.Context(), bytes.NewReader(raw), &loaded, hdr.Length, 0); err != nil {
			t.Fatalf("loadGraph: %v", err)
		}

		gotOuter := loaded.holder.next.outer
		if loaded.early1 != &gotOuter.subIn {
			t.Errorf("early1 %p does not alias &holder.next.outer.subIn %p", loaded.early1, &gotOuter.subIn)
		}
		if loaded.holder.in != &gotOuter.in {
			t.Errorf("holder.in %p does not alias &holder.next.outer.in %p", loaded.holder.in, &gotOuter.in)
		}
		if len(loaded.early1.subMaps) != 1 || len(gotOuter.in.subMaps) != 1 || len(gotOuter.in.fullMaps) != 2 {
			t.Fatalf("subIn.subMaps/in.subMaps/in.fullMaps lengths = %d/%d/%d, want 1/1/2", len(loaded.early1.subMaps), len(gotOuter.in.subMaps), len(gotOuter.in.fullMaps))
		}
		if &loaded.early1.subMaps[0] != &gotOuter.in.fullMaps[0] || &gotOuter.in.subMaps[0] != &gotOuter.in.fullMaps[0] {
			t.Errorf("subMaps[0] does not share backing array with fullMaps[0]")
		}
		gotNested, ok := gotOuter.in.fullMaps[0]["nested"].(*defImpl)
		if !ok || gotNested.v != 99 || gotNested.afterRuns != 1 {
			t.Errorf("nested map entry = %+v, want v=99 afterRuns=1", gotNested)
		}
		gotOther, ok := gotOuter.in.fullMaps[1]["other"].(*defImpl)
		if !ok || gotOther.v != 5 || gotOther.afterRuns != 1 {
			t.Errorf("other map entry = %+v, want v=5 afterRuns=1", gotOther)
		}
		if got := (*gotOuter.in.ifacePtr).(*defImpl); got.v != 42 || got.afterRuns != 1 {
			t.Errorf("ifacePtr = %+v, want v=42 afterRuns=1", got)
		}
		if len(gotOuter.in.ifaceSlice) != 2 {
			t.Fatalf("len(ifaceSlice) = %d, want 2", len(gotOuter.in.ifaceSlice))
		}
		for i, wantV := range []int{10, 20} {
			got := gotOuter.in.ifaceSlice[i].(*defImpl)
			if got.v != wantV || got.afterRuns != 1 {
				t.Errorf("ifaceSlice[%d] = %+v, want v=%d afterRuns=1", i, got, wantV)
			}
		}
		if len(loaded.directSlice) != 1 {
			t.Fatalf("len(directSlice) = %d, want 1", len(loaded.directSlice))
		}
		if got := loaded.directSlice[0].(*defImpl); got.v != 7 || got.afterRuns != 1 {
			t.Errorf("directSlice[0] = %+v, want v=7 afterRuns=1", got)
		}
		if gotOuter.afterRuns != 1 {
			t.Errorf("outer.afterRuns = %d, want 1", gotOuter.afterRuns)
		}
	})

	t.Run("unknown_deferred_type_error", func(t *testing.T) {
		var tt typeTable
		intIdx := tt.rootIndex(typeInfoOf(reflect.TypeFor[int]()))
		var raw encBuf
		raw.uint32(streamMagic)
		raw.uint64(schemaFingerprint())
		raw.uvarint(uint64(len(tt.types)))
		raw.bytes(tt.buf.b)
		// 2 objects: root int + unreferenced empty map.
		raw.uvarint(2)
		raw.byte(objKindValue)
		raw.uvarint(uint64(intIdx))
		raw.byte(objKindMap)
		raw.uvarint(0)
		// 0 targets.
		raw.uvarint(0)
		// Object 0 data (0) + Object 1 byteLength (0).
		raw.uvarint(0)
		raw.uvarint(0)

		var root int
		_, err := loadGraph(t.Context(), bytes.NewReader(raw.b), &root, uint64(len(raw.b)), 0)
		const want = "the type of object 1 (map (0 entries)) is not known from references to it"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("loadGraph = %v, want substring %q", err, want)
		}
	})

	t.Run("deferred_trailing_data_error", func(t *testing.T) {
		var tt typeTable
		rootIdx := tt.rootIndex(typeInfoOf(reflect.TypeFor[defTrailingRoot]()))
		holderIdx := tt.exactIndex(typeInfoOf(reflect.TypeFor[defMapHolder]()))
		var raw encBuf
		raw.uint32(streamMagic)
		raw.uint64(schemaFingerprint())
		raw.uvarint(uint64(len(tt.types)))
		raw.bytes(tt.buf.b)
		// 3 objects: 0 = defTrailingRoot, 1 = deferred empty map, 2 = defMapHolder.
		raw.uvarint(3)
		raw.byte(objKindValue)
		raw.uvarint(uint64(rootIdx))
		raw.byte(objKindMap)
		raw.uvarint(0)
		raw.byte(objKindValue)
		raw.uvarint(uint64(holderIdx))
		// 2 targets: target 0 -> object 1 (map), target 1 -> object 2 (defMapHolder).
		raw.uvarint(2)
		raw.uvarint((1 + 1) << 1)
		raw.uvarint((2 + 1) << 1)
		// Object 0: h -> target 1 (encoded as targetIndex+1 = 2).
		raw.uvarint(2)
		// Object 1: deferred 0-entry map with 1 trailing byte.
		raw.uvarint(1)
		raw.byte(0xff)
		// Object 2: m -> target 0 (encoded as targetIndex+1 = 1).
		raw.uvarint(1)

		var root defTrailingRoot
		_, err := loadGraph(t.Context(), bytes.NewReader(raw.b), &root, uint64(len(raw.b)), 0)
		const want = "object 1 has 1 bytes of trailing data"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("loadGraph = %v, want substring %q", err, want)
		}
	})
}

// TestGraphLoadNilRoot checks that Load rejects a nil root cleanly.
func TestGraphLoadNilRoot(t *testing.T) {
	saved := 7
	var buf bytes.Buffer
	if _, err := saveGraph(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("saveGraph: %v", err)
	}
	hdr, err := ReadHeaderMode(&wire.Reader{Reader: &buf})
	if err != nil {
		t.Fatalf("ReadHeaderMode: %v", err)
	}
	for _, root := range []any{nil, (*int)(nil)} {
		data := bytes.NewReader(buf.Bytes())
		_, err := loadGraph(t.Context(), data, root, hdr.Length, 0)
		const want = "Load requires a non-nil pointer"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("loadGraph(%T(nil)) = %v, want substring %q", root, err, want)
		}
	}
}

// TestGraphDecodeValueIntegerOverflow checks that out-of-range integers for
// narrow integer types are rejected rather than truncated, matching the wire
// engine and the typed loaders.
func TestGraphDecodeValueIntegerOverflow(t *testing.T) {
	stream := func(rootType reflect.Type, enc func(*encBuf)) []byte {
		var tt typeTable
		idx := tt.rootIndex(typeInfoOf(rootType))
		var raw encBuf
		raw.uint32(streamMagic)
		raw.uint64(schemaFingerprint())
		raw.uvarint(uint64(len(tt.types)))
		raw.bytes(tt.buf.b)
		raw.uvarint(1)
		raw.byte(objKindValue)
		raw.uvarint(uint64(idx))
		raw.uvarint(0)
		enc(&raw)
		return raw.b
	}
	signed := func(v int64) func(*encBuf) { return func(b *encBuf) { b.varint(v) } }
	unsigned := func(v uint64) func(*encBuf) { return func(b *encBuf) { b.uvarint(v) } }

	for _, tc := range []struct {
		name string
		root any
		enc  func(*encBuf)
	}{
		{"int16", new(int16), signed(1 << 16)},
		{"int16_negative", new(int16), signed(-1<<15 - 1)},
		{"int32", new(int32), signed(1 << 32)},
		{"uint16", new(uint16), unsigned(1 << 16)},
		{"uint32", new(uint32), unsigned(1 << 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rv := reflect.ValueOf(tc.root)
			rv.Elem().SetZero()
			raw := stream(rv.Type().Elem(), tc.enc)
			if _, err := loadGraph(t.Context(), bytes.NewReader(raw), tc.root, uint64(len(raw)), 0); err == nil || !strings.Contains(err.Error(), "overflows") {
				t.Errorf("loadGraph(%s) = %v (root=%v), want overflow error", tc.name, err, rv.Elem())
			}
		})
	}

	// In-range boundary values still load.
	for _, tc := range []struct {
		root any
		want any
		enc  func(*encBuf)
	}{
		{new(int16), int16(-1 << 15), signed(-1 << 15)},
		{new(int32), int32(1<<31 - 1), signed(1<<31 - 1)},
		{new(uint16), uint16(1<<16 - 1), unsigned(1<<16 - 1)},
		{new(uint32), uint32(1<<32 - 1), unsigned(1<<32 - 1)},
	} {
		rv := reflect.ValueOf(tc.root)
		raw := stream(rv.Type().Elem(), tc.enc)
		if _, err := loadGraph(t.Context(), bytes.NewReader(raw), tc.root, uint64(len(raw)), 0); err != nil {
			t.Errorf("loadGraph(%v) = %v, want nil", tc.want, err)
		} else if got := rv.Elem().Interface(); got != tc.want {
			t.Errorf("loadGraph(%T) = %v, want %v", tc.want, got, tc.want)
		}
	}
}

// mapDirectHookVal is a 1-pointer struct (ti.direct == true) whose single
// pointer word is populated and mutated via LoadValue and AfterLoad hooks.
type mapDirectHookVal struct {
	p *int
}

func (*mapDirectHookVal) StateTypeName() string { return "state.mapDirectHookVal" }
func (*mapDirectHookVal) StateFields() []string { return []string{"p"} }
func (x *mapDirectHookVal) StateSave(s Sink) {
	s.SaveValue(0, x.p)
}
func (x *mapDirectHookVal) StateLoad(_ context.Context, s Source) {
	s.LoadValue(0, new(*int), func(y any) {
		x.p = y.(*int)
	})
	s.AfterLoad(func() {
		v := *x.p + 100
		x.p = &v
	})
}

type mapDirectHookNode struct {
	anyVal any
	arrVal [1]any
	toAny  any
	toArr  [1]any
}

func (*mapDirectHookNode) StateTypeName() string { return "state.mapDirectHookNode" }
func (*mapDirectHookNode) StateFields() []string {
	return []string{"anyVal", "arrVal", "toAny", "toArr"}
}
func (x *mapDirectHookNode) StateSave(s Sink) {
	s.Save(0, &x.anyVal)
	s.SaveValue(1, x.arrVal)
	s.Save(2, &x.toAny)
	s.SaveValue(3, x.toArr)
}
func (x *mapDirectHookNode) StateLoad(_ context.Context, s Source) {
	s.LoadValue(0, new(any), func(y any) { x.anyVal = y })
	s.LoadValue(1, new([1]any), func(y any) { x.arrVal = y.([1]any) })
	s.LoadValueTo(2, new(any), x)
	s.LoadValueTo(3, new([1]any), x)
}
func (x *mapDirectHookNode) StateLoadValue(_ context.Context, slot int, v any) {
	switch slot {
	case 2:
		x.toAny = v
	case 3:
		x.toArr = v.([1]any)
	}
}

type mapDirectHookRoot struct {
	shared int
	dep    *int
	valA   map[uint8]any
	valB   map[uint8]any
	keyMap map[any]int
	rootLV mapDirectHookNode
	child  *mapDirectHookNode
}

func (*mapDirectHookRoot) StateTypeName() string { return "state.mapDirectHookRoot" }
func (*mapDirectHookRoot) StateFields() []string {
	return []string{"shared", "dep", "valA", "valB", "keyMap", "rootLV", "child"}
}
func (x *mapDirectHookRoot) StateSave(s Sink) {
	s.Save(0, &x.shared)
	s.Save(1, &x.dep)
	s.Save(2, &x.valA)
	s.Save(3, &x.valB)
	s.Save(4, &x.keyMap)
	s.Save(5, &x.rootLV)
	s.Save(6, &x.child)
}
func (x *mapDirectHookRoot) StateLoad(_ context.Context, s Source) {
	s.Load(0, &x.shared)
	s.Load(1, &x.dep)
	s.Load(2, &x.valA)
	s.Load(3, &x.valB)
	s.Load(4, &x.keyMap)
	s.Load(5, &x.rootLV)
	s.Load(6, &x.child)
}

var registerMapDirectHookTypes = sync.OnceFunc(func() {
	Register((*mapDirectHookVal)(nil))
	Register((*mapDirectHookNode)(nil))
	Register((*mapDirectHookRoot)(nil))
	fingerprint.Store(0)
})

func TestGraphDecodeMapAndLoadValueDirectStructWithHooks(t *testing.T) {
	registerMapDirectHookTypes()
	if !typeInfoOf(reflect.TypeFor[mapDirectHookVal]()).direct {
		t.Fatalf("mapDirectHookVal must be a direct-interface 1-pointer struct")
	}

	dep := 7
	saved := mapDirectHookRoot{
		shared: 3,
	}
	saved.dep = &dep
	saved.valA = map[uint8]any{
		1: mapDirectHookVal{p: &dep},
		2: mapDirectHookVal{p: &saved.shared},
	}
	saved.valB = map[uint8]any{
		9: mapDirectHookVal{p: &dep},
	}
	saved.keyMap = map[any]int{
		mapDirectHookVal{p: &dep}: 55,
	}
	saved.rootLV = mapDirectHookNode{
		anyVal: mapDirectHookVal{p: &saved.shared},
		arrVal: [1]any{mapDirectHookVal{p: &dep}},
		toAny:  mapDirectHookVal{p: &dep},
		toArr:  [1]any{mapDirectHookVal{p: &saved.shared}},
	}
	saved.child = &mapDirectHookNode{
		anyVal: mapDirectHookVal{p: &dep},
		arrVal: [1]any{mapDirectHookVal{p: &dep}},
		toAny:  mapDirectHookVal{p: &saved.shared},
		toArr:  [1]any{mapDirectHookVal{p: &dep}},
	}

	var buf bytes.Buffer
	if _, err := saveGraph(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("saveGraph: %v", err)
	}
	allBytes := buf.Bytes()
	wr := wire.Reader{Reader: bytes.NewReader(allBytes)}
	hdr, err := ReadHeaderMode(&wr)
	if err != nil {
		t.Fatalf("ReadHeaderMode: %v", err)
	}
	raw := allBytes[len(allBytes)-int(hdr.Length):]

	// PrintGraph sets noCallbacks=true and must still print all map entries cleanly.
	var printed strings.Builder
	if err := PrintGraph(&printed, raw, 0, false); err != nil {
		t.Fatalf("PrintGraph: %v", err)
	}
	if out := printed.String(); !strings.Contains(out, "state.mapDirectHookVal") || !strings.Contains(out, "55") {
		t.Fatalf("PrintGraph missing expected entries:\n%s", out)
	}

	var loaded mapDirectHookRoot
	if _, err := loadGraph(t.Context(), bytes.NewReader(raw), &loaded, hdr.Length, 0); err != nil {
		t.Fatalf("loadGraph: %v", err)
	}

	checkVal := func(desc string, v any, want int) {
		t.Helper()
		hv, ok := v.(mapDirectHookVal)
		if !ok || hv.p == nil || *hv.p != want {
			var got any = hv
			if ok && hv.p != nil {
				got = *hv.p
			}
			t.Errorf("%s = %#v (%v), want *p == %d", desc, v, got, want)
		}
	}
	checkVal("valA[1]", loaded.valA[1], 107)
	checkVal("valA[2]", loaded.valA[2], 103)
	checkVal("valB[9]", loaded.valB[9], 107)
	if len(loaded.keyMap) != 1 {
		t.Fatalf("len(keyMap) = %d, want 1", len(loaded.keyMap))
	}
	for k, v := range loaded.keyMap {
		checkVal("keyMap key", k, 107)
		if v != 55 {
			t.Errorf("keyMap value = %d, want 55", v)
		}
	}
	checkVal("rootLV.anyVal", loaded.rootLV.anyVal, 103)
	checkVal("rootLV.arrVal[0]", loaded.rootLV.arrVal[0], 107)
	checkVal("rootLV.toAny", loaded.rootLV.toAny, 107)
	checkVal("rootLV.toArr[0]", loaded.rootLV.toArr[0], 103)
	checkVal("child.anyVal", loaded.child.anyVal, 107)
	checkVal("child.arrVal[0]", loaded.child.arrVal[0], 107)
	checkVal("child.toAny", loaded.child.toAny, 103)
	checkVal("child.toArr[0]", loaded.child.toArr[0], 107)
}

// mapSyncHookKey is registered via RegisterStruct (ti.hooks == true) while
// StateLoad schedules no deferred callbacks.
type mapSyncHookKey struct {
	id int
}

func (*mapSyncHookKey) StateTypeName() string { return "state.mapSyncHookKey" }
func (*mapSyncHookKey) StateFields() []string { return []string{"id"} }
func (k *mapSyncHookKey) StateSave(s Sink)    { s.Save(0, &k.id) }
func (k *mapSyncHookKey) StateLoad(_ context.Context, s Source) {
	s.Load(0, &k.id)
}

// mapScalarLoadVal loads a scalar value via StateLoadValue synchronously during
// decodeValue without queuing deferred callbacks.
type mapScalarLoadVal struct {
	v int
}

func (*mapScalarLoadVal) StateTypeName() string { return "state.mapScalarLoadVal" }
func (*mapScalarLoadVal) StateFields() []string { return []string{"v"} }
func (x *mapScalarLoadVal) StateSave(s Sink)    { s.SaveValue(0, int64(x.v)) }
func (x *mapScalarLoadVal) StateLoad(_ context.Context, s Source) {
	s.LoadValueTo(0, new(int64), x)
}
func (x *mapScalarLoadVal) StateLoadValue(_ context.Context, _ int, v any) {
	x.v = int(v.(int64))
}

type mapSyncHookChild struct {
	parent        *mapSyncHookOwner
	sawParentKeys int
}

func (*mapSyncHookChild) StateTypeName() string { return "state.mapSyncHookChild" }
func (*mapSyncHookChild) StateFields() []string { return []string{"parent"} }
func (c *mapSyncHookChild) StateSave(s Sink)    { s.Save(0, &c.parent) }
func (c *mapSyncHookChild) StateLoad(_ context.Context, s Source) {
	s.LoadWait(0, &c.parent)
	s.AfterLoad(func() {
		c.sawParentKeys = len(c.parent.byBeforeSave)
	})
}

type mapSyncHookOwner struct {
	byTime       map[string]time.Time
	byBeforeSave map[mapSyncHookKey]*mapSyncHookChild
	byScalarLV   map[int]mapScalarLoadVal

	afterTimeLen   int
	afterBeforeLen int
	afterScalarVal int
}

func (*mapSyncHookOwner) StateTypeName() string { return "state.mapSyncHookOwner" }
func (*mapSyncHookOwner) StateFields() []string {
	return []string{"byTime", "byBeforeSave", "byScalarLV"}
}
func (o *mapSyncHookOwner) StateSave(s Sink) {
	s.Save(0, &o.byTime)
	s.Save(1, &o.byBeforeSave)
	s.Save(2, &o.byScalarLV)
}
func (o *mapSyncHookOwner) StateLoad(_ context.Context, s Source) {
	s.Load(0, &o.byTime)
	s.Load(1, &o.byBeforeSave)
	s.Load(2, &o.byScalarLV)
	s.AfterLoad(func() {
		o.afterTimeLen = len(o.byTime)
		o.afterBeforeLen = len(o.byBeforeSave)
		o.afterScalarVal = o.byScalarLV[1].v
	})
}

type mapSyncHookRoot struct {
	owner *mapSyncHookOwner
}

func (*mapSyncHookRoot) StateTypeName() string { return "state.mapSyncHookRoot" }
func (*mapSyncHookRoot) StateFields() []string { return []string{"owner"} }
func (r *mapSyncHookRoot) StateSave(s Sink)    { s.Save(0, &r.owner) }
func (r *mapSyncHookRoot) StateLoad(_ context.Context, s Source) {
	s.Load(0, &r.owner)
}

var registerMapSyncHookTypes = sync.OnceFunc(func() {
	RegisterStruct((*mapSyncHookKey)(nil))
	RegisterStruct((*mapScalarLoadVal)(nil))
	RegisterStruct((*mapSyncHookChild)(nil))
	RegisterStruct((*mapSyncHookOwner)(nil))
	RegisterNoHooks((*mapSyncHookRoot)(nil))
	fingerprint.Store(0)
})

func TestGraphDecodeMapPopulatedBeforeCallbacks(t *testing.T) {
	registerMapSyncHookTypes()

	ts := time.Date(2026, time.March, 15, 12, 30, 0, 0, time.UTC)
	prev := GraphEngineEnabled()
	defer EnableGraphEngine(prev)

	for _, tc := range []struct {
		name  string
		graph bool
	}{
		{name: "wire", graph: false},
		{name: "graph", graph: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			EnableGraphEngine(tc.graph)
			owner := &mapSyncHookOwner{
				byTime: map[string]time.Time{
					"a": ts,
					"b": ts.Add(time.Hour),
				},
				byBeforeSave: make(map[mapSyncHookKey]*mapSyncHookChild),
				byScalarLV: map[int]mapScalarLoadVal{
					1: {v: 77},
					2: {v: 88},
				},
			}
			c1 := &mapSyncHookChild{parent: owner}
			c2 := &mapSyncHookChild{parent: owner}
			owner.byBeforeSave[mapSyncHookKey{id: 10}] = c1
			owner.byBeforeSave[mapSyncHookKey{id: 20}] = c2
			saved := mapSyncHookRoot{owner: owner}

			var buf bytes.Buffer
			if _, err := Save(t.Context(), &buf, &saved); err != nil {
				t.Fatalf("Save: %v", err)
			}

			var loaded mapSyncHookRoot
			if _, err := Load(t.Context(), &buf, &loaded); err != nil {
				t.Fatalf("Load: %v", err)
			}

			got := loaded.owner
			if got.afterTimeLen != 2 {
				t.Errorf("owner.AfterLoad len(byTime) = %d, want 2", got.afterTimeLen)
			}
			if got.afterBeforeLen != 2 {
				t.Errorf("owner.AfterLoad len(byBeforeSave) = %d, want 2", got.afterBeforeLen)
			}
			if got.afterScalarVal != 77 {
				t.Errorf("owner.AfterLoad byScalarLV[1].v = %d, want 77", got.afterScalarVal)
			}
			for k, child := range got.byBeforeSave {
				if child.sawParentKeys != 2 {
					t.Errorf("child(%v).AfterLoad sawParentKeys = %d, want 2", k, child.sawParentKeys)
				}
			}
			if !got.byTime["a"].Equal(ts) || !got.byTime["b"].Equal(ts.Add(time.Hour)) {
				t.Errorf("byTime = %v, want a=%v b=%v", got.byTime, ts, ts.Add(time.Hour))
			}
			if got.byScalarLV[1].v != 77 || got.byScalarLV[2].v != 88 {
				t.Errorf("byScalarLV = %v, want 1:77 2:88", got.byScalarLV)
			}
		})
	}
}

type refSnapshotVal struct {
	p *int
	n int64
}

func (*refSnapshotVal) StateTypeName() string { return "state.refSnapshotVal" }
func (*refSnapshotVal) StateFields() []string { return []string{"p", "n"} }
func (x *refSnapshotVal) StateSave(s Sink) {
	s.Save(0, &x.p)
	s.Save(1, &x.n)
}
func (x *refSnapshotVal) StateLoad(_ context.Context, s Source) {
	s.Load(0, &x.p)
	s.Load(1, &x.n)
}

type deferredSnapshotVal struct {
	a, b int64
}

func (*deferredSnapshotVal) StateTypeName() string { return "state.deferredSnapshotVal" }
func (*deferredSnapshotVal) StateFields() []string { return []string{"a", "b"} }
func (x *deferredSnapshotVal) StateSave(s Sink) {
	s.Save(0, &x.a)
	s.Save(1, &x.b)
}
func (x *deferredSnapshotVal) StateLoad(_ context.Context, s Source) {
	s.Load(0, &x.a)
	s.Load(1, &x.b)
	s.AfterLoad(func() {})
}

type loadValueSnapshotNode struct {
	scalar      int64
	pair        [2]int64
	waitPair    [2]*int
	refVal      refSnapshotVal
	deferredVal deferredSnapshotVal

	retainedScalar   any
	retainedPair     any
	retainedWait     any
	retainedRef      any
	retainedDeferred any
}

func (*loadValueSnapshotNode) StateTypeName() string { return "state.loadValueSnapshotNode" }
func (*loadValueSnapshotNode) StateFields() []string {
	return []string{"scalar", "pair", "waitPair", "refVal", "deferredVal"}
}
func (n *loadValueSnapshotNode) StateSave(s Sink) {
	s.SaveValue(0, n.scalar)
	s.SaveValue(1, n.pair)
	s.SaveValue(2, n.waitPair)
	s.SaveValue(3, n.refVal)
	s.SaveValue(4, n.deferredVal)
}
func (n *loadValueSnapshotNode) StateLoad(_ context.Context, s Source) {
	s.LoadValue(0, &n.scalar, func(v any) {
		n.retainedScalar = v
		n.scalar = -1
	})
	s.LoadValue(1, &n.pair, func(v any) {
		n.retainedPair = v
		n.pair = [2]int64{-1, -2}
	})
	s.LoadValue(2, &n.waitPair, func(v any) {
		n.retainedWait = v
	})
	s.LoadValue(3, &n.refVal, func(v any) {
		n.retainedRef = v
	})
	s.LoadValue(4, &n.deferredVal, func(v any) {
		n.retainedDeferred = v
	})
	s.AfterLoad(func() {
		other := 999
		n.waitPair = [2]*int{&other, &other}
		n.refVal = refSnapshotVal{p: &other, n: -1}
		n.deferredVal = deferredSnapshotVal{a: -1, b: -2}
	})
}

type loadValueSnapshotRoot struct {
	dep  *int
	node *loadValueSnapshotNode
}

func (*loadValueSnapshotRoot) StateTypeName() string { return "state.loadValueSnapshotRoot" }
func (*loadValueSnapshotRoot) StateFields() []string { return []string{"dep", "node"} }
func (r *loadValueSnapshotRoot) StateSave(s Sink) {
	s.Save(0, &r.dep)
	s.Save(1, &r.node)
}
func (r *loadValueSnapshotRoot) StateLoad(_ context.Context, s Source) {
	s.Load(0, &r.dep)
	s.Load(1, &r.node)
}

var registerLoadValueSnapshotTypes = sync.OnceFunc(func() {
	Register((*refSnapshotVal)(nil))
	Register((*deferredSnapshotVal)(nil))
	Register((*loadValueSnapshotNode)(nil))
	Register((*loadValueSnapshotRoot)(nil))
	fingerprint.Store(0)
})

func TestLoadValueSnapshot(t *testing.T) {
	registerLoadValueSnapshotTypes()

	prev := GraphEngineEnabled()
	defer EnableGraphEngine(prev)

	for _, tc := range []struct {
		name  string
		graph bool
	}{
		{name: "wire", graph: false},
		{name: "graph", graph: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			EnableGraphEngine(tc.graph)
			dep := 42
			saved := loadValueSnapshotRoot{
				dep: &dep,
				node: &loadValueSnapshotNode{
					scalar:      17,
					pair:        [2]int64{11, 22},
					waitPair:    [2]*int{&dep, &dep},
					refVal:      refSnapshotVal{p: &dep, n: 9},
					deferredVal: deferredSnapshotVal{a: 5, b: 8},
				},
			}

			var buf bytes.Buffer
			if _, err := Save(t.Context(), &buf, &saved); err != nil {
				t.Fatalf("Save: %v", err)
			}
			var loaded loadValueSnapshotRoot
			if _, err := Load(t.Context(), &buf, &loaded); err != nil {
				t.Fatalf("Load: %v", err)
			}

			got := loaded.node
			if got.retainedScalar != int64(17) {
				t.Errorf("retainedScalar = %#v, want int64(17)", got.retainedScalar)
			}
			if got.retainedPair != ([2]int64{11, 22}) {
				t.Errorf("retainedPair = %#v, want [2]int64{11, 22}", got.retainedPair)
			}
			wp, ok := got.retainedWait.([2]*int)
			if !ok || wp[0] == nil || *wp[0] != 42 || wp[1] != wp[0] {
				t.Errorf("retainedWait = %#v, want [2]*int pointing to 42", got.retainedWait)
			}
			rv, ok := got.retainedRef.(refSnapshotVal)
			if !ok || rv.p == nil || *rv.p != 42 || rv.n != 9 {
				t.Errorf("retainedRef = %#v, want refSnapshotVal{*p=42, n=9}", got.retainedRef)
			}
			wantDeferred := deferredSnapshotVal{a: 5, b: 8}
			if got.retainedDeferred != wantDeferred {
				t.Errorf("retainedDeferred = %#v, want %#v", got.retainedDeferred, wantDeferred)
			}
		})
	}
}

func TestZeroSizedSliceLargeCapacity(t *testing.T) {
	prev := GraphEngineEnabled()
	EnableGraphEngine(true)
	defer EnableGraphEngine(prev)

	for _, c := range []int{7, 1 << 40, (1 << 40) + 1, math.MaxInt} {
		saved := make([]struct{}, 0, c)
		var buf bytes.Buffer
		if _, err := Save(t.Context(), &buf, &saved); err != nil {
			t.Fatalf("Save(cap=%d): %v", c, err)
		}
		allBytes := buf.Bytes()
		wr := wire.Reader{Reader: bytes.NewReader(allBytes)}
		hdr, err := ReadHeaderMode(&wr)
		if err != nil {
			t.Fatalf("ReadHeaderMode(cap=%d): %v", c, err)
		}
		raw := allBytes[len(allBytes)-int(hdr.Length):]
		var printed strings.Builder
		if err := PrintGraph(&printed, raw, 0, false); err != nil {
			t.Fatalf("PrintGraph(cap=%d): %v", c, err)
		}
		wantSub := fmt.Sprintf("[:0:%d]", c)
		if !strings.Contains(printed.String(), wantSub) {
			t.Errorf("PrintGraph(cap=%d) = %q, want substring %q", c, printed.String(), wantSub)
		}
		var loaded []struct{}
		if _, err := Load(t.Context(), &buf, &loaded); err != nil {
			t.Fatalf("Load(cap=%d): %v", c, err)
		}
		if loaded == nil || len(loaded) != 0 || cap(loaded) != c {
			t.Errorf("Load(cap=%d): nil=%v len=%d cap=%d", c, loaded == nil, len(loaded), cap(loaded))
		}
	}

	// Capacities exceeding math.MaxInt must be rejected cleanly.
	var tt typeTable
	idx := tt.rootIndex(typeInfoOf(reflect.TypeFor[[]struct{}]()))
	var raw encBuf
	raw.uint32(streamMagic)
	raw.uint64(schemaFingerprint())
	raw.uvarint(uint64(len(tt.types)))
	raw.bytes(tt.buf.b)
	raw.uvarint(1)
	raw.byte(objKindValue)
	raw.uvarint(uint64(idx))
	raw.uvarint(0)
	raw.uvarint(1) // length + 1 => length = 0
	raw.uvarint(uint64(math.MaxInt) + 1)
	var out []struct{}
	if _, err := loadGraph(t.Context(), bytes.NewReader(raw.b), &out, uint64(len(raw.b)), 0); err == nil || !strings.Contains(err.Error(), "invalid slice capacity") {
		t.Fatalf("loadGraph(MaxInt+1) = %v, want invalid slice capacity error", err)
	}
}

type scratchAliasVal struct {
	payload   *[4096]byte
	aliasSelf bool
}

func (*scratchAliasVal) StateTypeName() string { return "state.scratchAliasVal" }
func (*scratchAliasVal) StateFields() []string { return []string{"payload", "aliasSelf", "selfPtr"} }
func (v *scratchAliasVal) StateSave(s Sink) {
	s.Save(0, &v.payload)
	s.Save(1, &v.aliasSelf)
	var selfPtr *bool
	if v.aliasSelf {
		selfPtr = &v.aliasSelf
	}
	s.SaveValue(2, selfPtr)
}
func (v *scratchAliasVal) StateLoad(_ context.Context, s Source) {
	s.Load(0, &v.payload)
	s.Load(1, &v.aliasSelf)
	s.LoadValue(2, new(*bool), func(any) {})
}

var registerScratchAliasTypes = sync.OnceFunc(func() {
	Register((*scratchAliasVal)(nil))
	fingerprint.Store(0)
})

func TestPooledEncoderScratchReleasesPointers(t *testing.T) {
	registerScratchAliasTypes()
	ti := typeInfoOf(reflect.TypeFor[scratchAliasVal]())
	if !ti.inlineStruct || ti.direct {
		t.Fatalf("scratchAliasVal must have inlineStruct=true and direct=false (got inlineStruct=%v direct=%v)", ti.inlineStruct, ti.direct)
	}

	collected := make(chan struct{}, 1)
	func() {
		userAlloc := new([4096]byte)
		userAlloc[0] = 42
		runtime.AddCleanup(userAlloc, func(ch chan struct{}) {
			ch <- struct{}{}
		}, collected)

		// Element 0 populates es.copies[ti]; element 1 pops that copy slot,
		// copies userAlloc into it, and aliases the copy so it is not returned
		// to es.copies[ti].
		saved := [2]any{
			scratchAliasVal{aliasSelf: false},
			scratchAliasVal{payload: userAlloc, aliasSelf: true},
		}
		var buf bytes.Buffer
		if _, err := saveGraph(t.Context(), &buf, &saved); err != nil {
			t.Fatalf("saveGraph: %v", err)
		}
	}()

	// Hold all currently pooled encoders alive across GC so sync.Pool eviction
	// cannot mask any pointer retained inside a pooled graphEncodeState.
	var held []any
	for {
		v := graphEncodeStatePool.Get()
		if v == nil {
			break
		}
		held = append(held, v)
	}
	defer func() {
		for _, v := range held {
			graphEncodeStatePool.Put(v)
		}
		runtime.KeepAlive(held)
	}()

	for i := 0; i < 4; i++ {
		runtime.GC()
		select {
		case <-collected:
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
	t.Fatal("pooled graphEncodeState retained user allocation across GC")
}
