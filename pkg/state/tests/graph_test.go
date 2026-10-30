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
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/pretty"
)

// saveBytes saves the graph rooted at root.
func saveBytes(t testing.TB, root any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, root); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	return buf.Bytes()
}

// loadBytes loads a graph saved by saveBytes into a new T.
func loadBytes[T any](t testing.TB, data []byte) *T {
	t.Helper()
	root := new(T)
	if _, err := state.Load(context.Background(), bytes.NewReader(data), root); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	return root
}

// reachable calls fn for each addressable value of type T that is reachable
// from root through saved fields, once per distinct address.
func reachable[T any](root any, fn func(*T)) {
	target := reflect.TypeFor[T]()
	seen := make(map[addrKey]bool)
	seenMaps := make(map[uintptr]bool)
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		if v.CanAddr() && v.Type().Size() != 0 {
			k := addrKey{v.UnsafeAddr(), v.Type()}
			if seen[k] {
				return
			}
			seen[k] = true
			if v.Type() == target {
				fn((*T)(v.Addr().UnsafePointer()))
			}
		}
		switch v.Kind() {
		case reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
			reflect.Float32, reflect.Float64,
			reflect.Complex64, reflect.Complex128,
			reflect.String:
			// Scalar values do not reference other objects.
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		case reflect.Map:
			if v.IsNil() || seenMaps[v.Pointer()] {
				return
			}
			seenMaps[v.Pointer()] = true
			for it := v.MapRange(); it.Next(); {
				walk(it.Key())
				walk(it.Value())
			}
		case reflect.Struct:
			typ := v.Type()
			if typ.PkgPath() == "sync/atomic" {
				if p := v.FieldByName("v"); p.IsValid() && p.Kind() == reflect.UnsafePointer && !unRO(p).IsNil() {
					walk(reflect.NewAt(typ.Field(0).Type.Elem().Elem(), unRO(p).UnsafePointer()).Elem())
				}
				return
			}
			for i := 0; i < typ.NumField(); i++ {
				if savedField(typ.Field(i)) {
					walk(v.Field(i))
				}
			}
		default:
			panic(fmt.Sprintf("unexpected reflect.Kind: %v (%v)", v.Kind(), v.Type()))
		}
	}
	walk(reflect.ValueOf(root))
}

// sliceWindowsSupported indicates whether the state package supports saving
// slices that share a backing array at different offsets, or with elements of
// one slice beyond the length of another. The legacy encoder clears elements
// beyond a slice's length in the saved graph, and can't express a slice that
// starts within another slice's array.
const sliceWindowsSupported = false

func skipUnlessSliceWindows(t *testing.T) {
	t.Helper()
	if !sliceWindowsSupported {
		t.Skip("slice windows are not supported")
	}
}

var graphConfigs = []graphOptions{
	{nodes: 1},
	{nodes: 2, all: true},
	{nodes: 10},
	{nodes: 10, all: true, windows: true},
	{nodes: 50, windows: true},
	{nodes: 50, all: true},
	{nodes: 200, all: true, windows: true},
}

// TestRandomGraphs tests graph save/load.
func TestRandomGraphs(t *testing.T) {
	seeds := int64(25)
	if testing.Short() {
		seeds = 5
	}
	for _, opts := range graphConfigs {
		for seed := int64(0); seed < seeds; seed++ {
			t.Run(fmt.Sprintf("nodes=%d,all=%v,windows=%v/seed=%d", opts.nodes, opts.all, opts.windows, seed), func(t *testing.T) {
				if opts.windows {
					skipUnlessSliceWindows(t)
				}
				original := randomGraph(seed, opts)
				saved := randomGraph(seed, opts)
				data := saveBytes(t, saved)

				// Save must not modify the saved graph.
				if err := isomorphic(original, saved); err != nil {
					t.Fatalf("Save modified the graph: %v", err)
				}
				// beforeSave must be called exactly once per object.
				reachable(saved, func(n *gNode) {
					if n.saveCalls != 1 {
						t.Errorf("node %d: beforeSave called %d times, want 1", n.id, n.saveCalls)
					}
				})

				loaded := loadBytes[gRoot](t, data)
				checkIsomorphic(t, original, loaded)
				reachable(loaded, func(n *gNode) {
					if !n.loaded || n.skipped != 0 {
						t.Errorf("node %d: loaded=%v skipped=%d, want true/0", n.id, n.loaded, n.skipped)
					}
				})

				// Saving the loaded graph must produce an equivalent graph.
				reloaded := loadBytes[gRoot](t, saveBytes(t, loaded))
				checkIsomorphic(t, original, reloaded)
			})
		}
	}
}

// TestSharedSliceWindows tests graph save/load.
func TestSharedSliceWindows(t *testing.T) {
	newBacking := func() []gInner {
		b := make([]gInner, 4, 6)
		for i := range b {
			b[i] = gInner{x: int64(100 + i), s: fmt.Sprintf("e%d", i)}
		}
		return b
	}
	for _, test := range []struct {
		name   string
		window func(b []gInner) []gInner
	}{
		{"prefix", func(b []gInner) []gInner { return b[:1] }},
		{"middle", func(b []gInner) []gInner { return b[1:2] }},
		{"empty", func(b []gInner) []gInner { return b[2:2] }},
		{"suffix", func(b []gInner) []gInner { return b[3:] }},
		{"beyond_len", func(b []gInner) []gInner { return b[2:6] }},
		{"full", func(b []gInner) []gInner { return b[:] }},
	} {
		for _, windowFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/window_first=%v", test.name, windowFirst), func(t *testing.T) {
				if test.name != "full" {
					skipUnlessSliceWindows(t)
				}
				build := func() *gRoot {
					full, part := &gNode{id: 1}, &gNode{id: 2}
					full.vals = newBacking()
					part.window = test.window(full.vals)
					if windowFirst {
						return &gRoot{entries: []*gNode{part, full}}
					}
					return &gRoot{entries: []*gNode{full, part}}
				}
				original, saved := build(), build()
				data := saveBytes(t, saved)
				if err := isomorphic(original, saved); err != nil {
					t.Fatalf("Save modified the graph: %v", err)
				}
				checkIsomorphic(t, original, loadBytes[gRoot](t, data))
			})
		}
	}
}

// TestInteriorPointersIntoSlices tests graph save/load.
func TestInteriorPointersIntoSlices(t *testing.T) {
	for _, ptrFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("ptr_first=%v", ptrFirst), func(t *testing.T) {
			build := func() *gRoot {
				owner := &gNode{id: 1, vals: []gInner{{x: 1}, {x: 2}, {x: 3}}, blob: []byte("hello")}
				ptrs := &gNode{id: 2}
				ptrs.innerPtr = &owner.vals[1]
				ptrs.intPtr = &owner.vals[2].x
				ptrs.bytePtr = &owner.blob[4]
				ptrs.iface = &owner.vals[0]
				if ptrFirst {
					return &gRoot{entries: []*gNode{ptrs, owner}}
				}
				return &gRoot{entries: []*gNode{owner, ptrs}}
			}
			original := build()
			loaded := loadBytes[gRoot](t, saveBytes(t, build()))
			checkIsomorphic(t, original, loaded)
		})
	}
}

// TestMapIdentity tests graph save/load.
func TestMapIdentity(t *testing.T) {
	build := func() *gRoot {
		a, b := &gNode{id: 1}, &gNode{id: 2}
		a.shared = map[string]int64{"x": 1, "y": 2}
		b.shared = a.shared
		b.sharedPtr = &a.shared
		b.iface = a.shared
		return &gRoot{entries: []*gNode{b, a}, any: a.shared}
	}
	original := build()
	loaded := loadBytes[gRoot](t, saveBytes(t, build()))
	checkIsomorphic(t, original, loaded)
	a, b := loaded.entries[1], loaded.entries[0]
	b.shared["z"] = 3
	if a.shared["z"] != 3 || loaded.any.(map[string]int64)["z"] != 3 || (*b.sharedPtr)["z"] != 3 {
		t.Errorf("maps are not shared after loading")
	}
	if b.sharedPtr != &a.shared {
		t.Errorf("sharedPtr does not point to a.shared")
	}
}

// TestNilAndEmpty tests graph save/load.
func TestNilAndEmpty(t *testing.T) {
	build := func() *gRoot {
		nilNode := &gNode{id: 1}
		emptyNode := &gNode{id: 2, nodes: []*gNode{}, vals: make([]gInner, 0, 3), blob: []byte{}, byID: map[int64]*gNode{}, shared: map[string]int64{}, ifaces: []any{}}
		return &gRoot{entries: []*gNode{nilNode, emptyNode}}
	}
	original := build()
	loaded := loadBytes[gRoot](t, saveBytes(t, build()))
	checkIsomorphic(t, original, loaded)
}

// TestWaitOrdering tests graph save/load.
func TestWaitOrdering(t *testing.T) {
	for _, field := range []string{"wait", "array"} {
		t.Run(field, func(t *testing.T) {
			build := func() *gRoot {
				nodes := make([]*gNode, 100)
				for i := range nodes {
					nodes[i] = &gNode{id: int64(i)}
				}
				for i := 0; i+1 < len(nodes); i++ {
					if field == "wait" {
						nodes[i].waitFor = nodes[i+1]
					} else {
						nodes[i].later[1] = nodes[i+1]
					}
					// Also point backwards, without waiting.
					nodes[i+1].next = nodes[i]
				}
				return &gRoot{first: nodes[0]}
			}
			loaded := loadBytes[gRoot](t, saveBytes(t, build()))
			checkIsomorphic(t, build(), loaded)
		})
	}
}

// TestValueFields tests graph save/load.
func TestValueFields(t *testing.T) {
	build := func() *gRoot {
		a, b := &gNode{id: 1, saved: 42}, &gNode{id: 2, saved: -7}
		a.savedNode = b
		b.savedNode = b
		a.alias.Store(b)
		b.next = a
		return &gRoot{first: a}
	}
	loaded := loadBytes[gRoot](t, saveBytes(t, build()))
	checkIsomorphic(t, build(), loaded)
	if got := loaded.first.alias.Load().next; got != loaded.first {
		t.Errorf("alias cycle broken: got %p, want %p", got, loaded.first)
	}
}

// TestTruncatedStreams tests graph save/load.
func TestTruncatedStreams(t *testing.T) {
	data := saveBytes(t, randomGraph(1, graphOptions{nodes: 20, all: true, windows: sliceWindowsSupported}))
	step := 1
	if testing.Short() {
		step = 7
	}
	for l := 0; l < len(data); l += step {
		root := new(gRoot)
		if _, err := state.Load(context.Background(), bytes.NewReader(data[:l]), root); err == nil {
			t.Fatalf("Load of %d/%d bytes succeeded", l, len(data))
		}
	}
}

// TestWrongRootType checks that loading into a root of another type fails.
func TestWrongRootType(t *testing.T) {
	data := saveBytes(t, randomGraph(1, graphOptions{nodes: 5}))
	var wrong gNode
	if _, err := state.Load(context.Background(), bytes.NewReader(data), &wrong); err == nil {
		t.Fatalf("Load into the wrong root type succeeded")
	}
}

// gIDs is an unregistered named slice type.
type gIDs []gID

// TestUnregisteredInterfaceValues tests graph save/load.
func TestUnregisteredInterfaceValues(t *testing.T) {
	for _, v := range []any{gID(1), gIDs{1, 2}, &gIDs{3}} {
		var buf bytes.Buffer
		if _, err := state.Save(context.Background(), &buf, &gRoot{any: v}); err == nil {
			t.Errorf("Save of %T in an interface succeeded", v)
		}
	}
}

// TestIsomorphismChecker tests graph save/load.
func TestIsomorphismChecker(t *testing.T) {
	shared := &gNode{id: 3}
	aliased := &gRoot{entries: []*gNode{shared, shared}}
	distinct := &gRoot{entries: []*gNode{{id: 3}, {id: 3}}}
	if err := isomorphic(aliased, distinct); err == nil {
		t.Errorf("checker did not detect lost aliasing")
	}
	if err := isomorphic(distinct, aliased); err == nil {
		t.Errorf("checker did not detect added aliasing")
	}
	owner := &gNode{id: 1}
	interior := &gRoot{first: owner, any: &owner.inner}
	copied := &gRoot{first: &gNode{id: 1}, any: &gInner{}}
	if err := isomorphic(interior, copied); err == nil {
		t.Errorf("checker did not detect lost interior pointer")
	}
	backing := []gInner{{x: 1}, {x: 2}}
	windowed := &gRoot{first: &gNode{vals: backing, window: backing[1:]}}
	unwindowed := &gRoot{first: &gNode{vals: []gInner{{x: 1}, {x: 2}}, window: []gInner{{x: 2}}}}
	if err := isomorphic(windowed, unwindowed); err == nil {
		t.Errorf("checker did not detect lost slice window")
	}
	b4 := make([]gInner, 4, 6)
	if isomorphic(&gRoot{entries: []*gNode{{vals: b4}, {window: b4[2:2]}}}, &gRoot{entries: []*gNode{{vals: make([]gInner, 4, 6)}, {window: make([]gInner, 0, 4)}}}) == nil {
		t.Errorf("checker did not detect detached empty slice window")
	}
	m := map[string]int64{"a": 1}
	sharedMap := &gRoot{entries: []*gNode{{shared: m}, {shared: m}}}
	copiedMap := &gRoot{entries: []*gNode{{shared: map[string]int64{"a": 1}}, {shared: map[string]int64{"a": 1}}}}
	if err := isomorphic(sharedMap, copiedMap); err == nil {
		t.Errorf("checker did not detect lost map aliasing")
	}
	if err := isomorphic(sharedMap, sharedMap); err != nil {
		t.Errorf("checker rejected identical graphs: %v", err)
	}
}

// TestScatteredArrayElements tests graph save/load.
func TestScatteredArrayElements(t *testing.T) {
	skipUnlessSliceWindows(t)
	for _, order := range [][]int{
		{8, 2, 5, 0, 9},
		{0, 9, 5, 2, 8},
		{5, 4, 6, 3, 7},
		{9, 7, 5, 3, 1},
	} {
		for _, sliceFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/slice_first=%v", order, sliceFirst), func(t *testing.T) {
				build := func() *gRoot {
					backing := make([]gInner, 10, 12)
					for i := range backing {
						backing[i] = gInner{x: int64(i + 1)}
					}
					var entries []*gNode
					for _, i := range order {
						entries = append(entries, &gNode{innerPtr: &backing[i], intPtr: &backing[i].x})
					}
					entries = append(entries, &gNode{window: backing[3:4]}, &gNode{window: backing[6:8:9]})
					owner := &gNode{vals: backing[:2]}
					if sliceFirst {
						entries = append([]*gNode{owner}, entries...)
					} else {
						entries = append(entries, owner)
					}
					return &gRoot{entries: entries}
				}
				original := build()
				loaded := loadBytes[gRoot](t, saveBytes(t, build()))
				checkIsomorphic(t, original, loaded)
			})
		}
	}
}

// TestRootZeroFields checks that zero fields do not overwrite the root on Load.
func TestRootZeroFields(t *testing.T) {
	if !sliceWindowsSupported {
		t.Skip("wire engine overwrites zero root arrays")
	}
	data := saveBytes(t, &gBytesRoot{})
	want := gBytesRoot{b: [1]byte{7}, arr: [3]byte{1, 2, 3}, n: 5, s: "x"}
	got := want
	if _, err := state.Load(context.Background(), bytes.NewReader(data), &got); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got != want {
		t.Errorf("Load of zero fields changed the root: got %+v, want %+v", got, want)
	}
	data = saveBytes(t, &gBytesRoot{b: [1]byte{9}, n: 3})
	if _, err := state.Load(context.Background(), bytes.NewReader(data), &got); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	want.b, want.n = [1]byte{9}, 3
	if got != want {
		t.Errorf("Load of non-zero fields: got %+v, want %+v", got, want)
	}
}

func TestSliceOfArraysRoundTrip(t *testing.T) {
	prev := state.GraphEngineEnabled()
	state.EnableGraphEngine(true)
	defer state.EnableGraphEngine(prev)

	s1 := [][2]int64{{1, 2}, {3, 4}, {5, 6}}
	s2 := [][2]int64{{10, 20}, {30, 40}, {50, 60}}
	saved := &gSliceOfArraysRoot{
		sliceFirst: s1,
		ptrSecond:  (*[2][2]int64)(s1[0:2]),
		ptrFirst:   (*[2][2]int64)(s2[1:3]),
		sliceNext:  s2,
	}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, saved); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data := buf.Bytes()
	var out bytes.Buffer
	if err := pretty.PrintText(&out, bytes.NewReader(data)); err != nil {
		t.Fatalf("PrintText: %v", err)
	}
	var got gSliceOfArraysRoot
	if _, err := state.Load(t.Context(), bytes.NewReader(data), &got); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got.ptrSecond[1][0] = 99
	if got.sliceFirst[1][0] != 99 {
		t.Errorf("ptrSecond does not alias sliceFirst[0:2]: sliceFirst=%v", got.sliceFirst)
	}
	got.ptrFirst[0][1] = 88
	if got.sliceNext[1][1] != 88 {
		t.Errorf("ptrFirst does not alias sliceNext[1:3]: sliceNext=%v", got.sliceNext)
	}

	// Slice of arrays of non-pod structs (inlineStruct) where a multi-element
	// array pointer is encoded (reaching objDone) before the enclosing slice
	// is discovered in a deeper object.
	ks := [][2]gKey{
		{{a: 1, b: "one"}, {a: 2, b: "two"}},
		{{a: 3, b: "three"}, {a: 4, b: "four"}},
		{{a: 5, b: "five"}, {a: 6, b: "six"}},
	}
	kRoot := &gRoot{
		any: (*[2][2]gKey)(ks[1:3]),
		all: []*gNode{{iface: ks}},
	}
	buf.Reset()
	if _, err := state.Save(t.Context(), &buf, kRoot); err != nil {
		t.Fatalf("Save struct slice-of-arrays: %v", err)
	}
	var gotKRoot gRoot
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &gotKRoot); err != nil {
		t.Fatalf("Load struct slice-of-arrays: %v", err)
	}
	gotPtr := gotKRoot.any.(*[2][2]gKey)
	gotSlice := gotKRoot.all[0].iface.([][2]gKey)
	gotPtr[0][1] = gKey{a: 42, b: "mutated"}
	if gotSlice[1][1] != (gKey{a: 42, b: "mutated"}) {
		t.Errorf("gotPtr does not alias gotSlice[1:3]: gotSlice=%v", gotSlice)
	}

	// Partially overlapping slices of non-power-of-2-sized [2]gKey elements
	// where the lower-addressed slice is encoded first.
	overlapRoot := &gRoot{
		any: ks[0:2:2],
		all: []*gNode{{iface: ks[1:3:3]}},
	}
	buf.Reset()
	if _, err := state.Save(t.Context(), &buf, overlapRoot); err != nil {
		t.Fatalf("Save overlapping slice-of-arrays: %v", err)
	}
	var gotOverlap gRoot
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &gotOverlap); err != nil {
		t.Fatalf("Load overlapping slice-of-arrays: %v", err)
	}
	gotLo := gotOverlap.any.([][2]gKey)
	gotHi := gotOverlap.all[0].iface.([][2]gKey)
	gotLo[1][0] = gKey{a: 77, b: "shared"}
	if gotHi[0][0] != (gKey{a: 77, b: "shared"}) {
		t.Errorf("gotLo[1][0] does not alias gotHi[0][0]: gotHi=%v", gotHi)
	}

	// Unaligned sub-slice of arrays spanning an outer element boundary,
	// absorbed by an enclosing slice of the same array element type.
	flat := [6]gKey{
		{a: 10, b: "a"}, {a: 20, b: "b"},
		{a: 30, b: "c"}, {a: 40, b: "d"},
		{a: 50, b: "e"}, {a: 60, b: "f"},
	}
	sInner := unsafe.Slice((*[2]gKey)(unsafe.Pointer(&flat[1])), 1)
	sOuter := unsafe.Slice((*[2]gKey)(unsafe.Pointer(&flat[0])), 3)
	uRoot := &gRoot{
		any: sInner,
		all: []*gNode{{iface: sOuter}},
	}
	buf.Reset()
	if _, err := state.Save(t.Context(), &buf, uRoot); err != nil {
		t.Fatalf("Save unaligned slice-of-arrays: %v", err)
	}
	var gotURoot gRoot
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &gotURoot); err != nil {
		t.Fatalf("Load unaligned slice-of-arrays: %v", err)
	}
	gotInner := gotURoot.any.([][2]gKey)
	gotOuter := gotURoot.all[0].iface.([][2]gKey)
	gotInner[0][0] = gKey{a: 98, b: "aliased-lo"}
	gotInner[0][1] = gKey{a: 99, b: "aliased-hi"}
	if gotOuter[0][1] != (gKey{a: 98, b: "aliased-lo"}) || gotOuter[1][0] != (gKey{a: 99, b: "aliased-hi"}) {
		t.Errorf("gotInner does not alias gotOuter across boundary: gotOuter=%v", gotOuter)
	}
}

type gReverseOrderStruct struct {
	lo gSpliceChild
	hi gSpliceChild
}

func (*gReverseOrderStruct) StateTypeName() string {
	return "pkg/state/tests.gReverseOrderStruct"
}

func (*gReverseOrderStruct) StateFields() []string {
	return []string{"hi", "lo"}
}

func (r *gReverseOrderStruct) StateSave(s state.Sink) {
	s.Save(0, &r.hi)
	s.Save(1, &r.lo)
}

func (r *gReverseOrderStruct) StateLoad(_ context.Context, s state.Source) {
	s.Load(0, &r.hi)
	s.Load(1, &r.lo)
}

func init() {
	state.RegisterStruct((*gReverseOrderStruct)(nil))
}

func forEachEngine(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	for _, tc := range []struct {
		name  string
		graph bool
	}{
		{name: "wire", graph: false},
		{name: "graph", graph: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := state.GraphEngineEnabled()
			state.EnableGraphEngine(tc.graph)
			defer state.EnableGraphEngine(prev)
			fn(t)
		})
	}
}

func TestAbsorbedInlineStructSplices(t *testing.T) {
	t.Run("SkippedConvertedAndManualFields", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T) {
			container := &gSpliceContainer{
				converted: gSpliceChild{val: 7, tag: "orig-conv"},
				manual:    gSpliceChild{val: 50, tag: "orig-manual"},
				normal:    gSpliceChild{val: 99, tag: "kept"},
				mid:       gSpliceMid{child: gSpliceChild{val: 12, tag: "orig-mid"}, extra: 5},
				seed:      5,
			}
			// Discover and encode interior inlineStruct pointers (&converted,
			// &manual, &normal) before container itself is discovered via deeper
			// node all[0].
			root := &gRoot{
				any: [3]*gSpliceChild{&container.converted, &container.manual, &container.normal},
				all: []*gNode{{iface: container}},
			}
			var buf bytes.Buffer
			if _, err := state.Save(t.Context(), &buf, root); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if state.GraphEngineEnabled() && container.normal.beforeSaveCalls != 1 {
				t.Errorf("normal.beforeSaveCalls = %d, want 1", container.normal.beforeSaveCalls)
			}
			var out bytes.Buffer
			if err := pretty.PrintText(&out, bytes.NewReader(buf.Bytes())); err != nil {
				t.Fatalf("PrintText: %v", err)
			}
			var got gRoot
			if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
				t.Fatalf("Load: %v", err)
			}
			ptrs := got.any.([3]*gSpliceChild)
			gotContainer := got.all[0].iface.(*gSpliceContainer)
			if ptrs[0] != &gotContainer.converted || ptrs[1] != &gotContainer.manual || ptrs[2] != &gotContainer.normal {
				t.Fatalf("interior pointers did not alias container fields")
			}
			if gotContainer.converted.val != 7 || gotContainer.manual.val != 50 || gotContainer.normal.val != 99 || gotContainer.normal.tag != "kept" {
				t.Errorf("unexpected restored fields: %+v", gotContainer)
			}
		})
	})

	t.Run("ReverseAddressOrderSaverLoader", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T) {
			rev := &gReverseOrderStruct{
				lo: gSpliceChild{val: 11, tag: "lo"},
				hi: gSpliceChild{val: 22, tag: "hi"},
			}
			root := &gRoot{
				any: [2]*gSpliceChild{&rev.lo, &rev.hi},
				all: []*gNode{{iface: rev}},
			}
			var buf bytes.Buffer
			if _, err := state.Save(t.Context(), &buf, root); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if state.GraphEngineEnabled() {
				if rev.lo.beforeSaveCalls != 1 || rev.hi.beforeSaveCalls != 1 {
					t.Errorf("beforeSaveCalls = (%d, %d), want (1, 1)", rev.lo.beforeSaveCalls, rev.hi.beforeSaveCalls)
				}
			}
			var got gRoot
			if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
				t.Fatalf("Load: %v", err)
			}
			ptrs := got.any.([2]*gSpliceChild)
			gotRev := got.all[0].iface.(*gReverseOrderStruct)
			if ptrs[0] != &gotRev.lo || ptrs[1] != &gotRev.hi {
				t.Fatalf("interior pointers did not alias reverse-order struct fields")
			}
			if gotRev.lo.val != 11 || gotRev.hi.val != 22 {
				t.Errorf("got (%+v, %+v), want (11, 22)", gotRev.lo, gotRev.hi)
			}
		})
	})
}

func TestAbsorbedSupersededReferencesPruned(t *testing.T) {
	prev := state.GraphEngineEnabled()
	state.EnableGraphEngine(true)
	defer state.EnableGraphEngine(prev)

	t.Run("BeforeSaveFlushesMap", func(t *testing.T) {
		holder := &gCacheFlushHolder{
			cachedMap: map[string]int64{"stale": 123},
			saved:     42,
		}
		root := &gCacheFlushRoot{
			mp:   &holder.cachedMap,
			node: &gNode{iface: holder},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var out bytes.Buffer
		if err := pretty.PrintText(&out, bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("PrintText: %v", err)
		}
		var got gCacheFlushRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotHolder := got.node.iface.(*gCacheFlushHolder)
		if got.mp != &gotHolder.cachedMap || gotHolder.cachedMap != nil || gotHolder.saved != 42 {
			t.Errorf("unexpected restored state: mp=%p &cachedMap=%p holder=%+v", got.mp, &gotHolder.cachedMap, gotHolder)
		}
	})

	t.Run("BeforeSaveFlushesInexactSlice", func(t *testing.T) {
		holder := &gCacheFlushHolder{
			cachedIfaces: []gIface{&gNode{id: 77}},
			saved:        42,
		}
		root := &gCacheFlushRoot{
			ip:   &holder.cachedIfaces,
			node: &gNode{iface: holder},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var out bytes.Buffer
		if err := pretty.PrintText(&out, bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("PrintText: %v", err)
		}
		var got gCacheFlushRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotHolder := got.node.iface.(*gCacheFlushHolder)
		if got.ip != &gotHolder.cachedIfaces || gotHolder.cachedIfaces != nil || gotHolder.saved != 42 {
			t.Errorf("unexpected restored state: ip=%p &cachedIfaces=%p holder=%+v", got.ip, &gotHolder.cachedIfaces, gotHolder)
		}
	})

	t.Run("BeforeSaveFlushesDeadObjectAfterLoad", func(t *testing.T) {
		holder := &gCacheFlushHolder{
			cachedDead: &gDeadLeaf{val: 999},
			saved:      42,
		}
		root := &gCacheFlushRoot{
			dp:   &holder.cachedDead,
			node: &gNode{iface: holder},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		deadLoads := 0
		ctx := context.WithValue(t.Context(), gDeadAfterLoadKey{}, &deadLoads)
		var got gCacheFlushRoot
		if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if deadLoads != 0 {
			t.Errorf("unreachable dead leaf ran afterLoad %d times, want 0", deadLoads)
		}
		gotHolder := got.node.iface.(*gCacheFlushHolder)
		if got.dp != &gotHolder.cachedDead || gotHolder.cachedDead != nil || gotHolder.saved != 42 {
			t.Errorf("unexpected restored state: dp=%p &cachedDead=%p holder=%+v", got.dp, &gotHolder.cachedDead, gotHolder)
		}
	})

	t.Run("ValueSavedMapFieldAbsorbed", func(t *testing.T) {
		holder := &gValueMapHolder{m: map[string]int64{"k": 55}}
		root := &gRoot{
			any: &holder.m,
			all: []*gNode{{iface: holder}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var out bytes.Buffer
		if err := pretty.PrintText(&out, bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("PrintText: %v", err)
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotMPtr := got.any.(*map[string]int64)
		gotHolder := got.all[0].iface.(*gValueMapHolder)
		if gotMPtr != &gotHolder.m || gotHolder.m["k"] != 55 {
			t.Errorf("gotMPtr=%p &holder.m=%p m=%v", gotMPtr, &gotHolder.m, gotHolder.m)
		}
	})

	t.Run("SplicedThenDiscardedMapRef", func(t *testing.T) {
		container := &gSpliceContainer{
			normal: gSpliceChild{val: 9},
			mid: gSpliceMid{
				child: gSpliceChild{
					val: 20,
					m:   map[string]int64{"orphan": 1},
				},
				extra: 3,
			},
			seed: 3,
		}
		root := &gRoot{
			any: &container.mid.child,
			all: []*gNode{{
				iface: &container.mid,
				next:  &gNode{iface: container},
			}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var out bytes.Buffer
		if err := pretty.PrintText(&out, bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("PrintText: %v", err)
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotChildPtr := got.any.(*gSpliceChild)
		gotMidPtr := got.all[0].iface.(*gSpliceMid)
		gotContainer := got.all[0].next.iface.(*gSpliceContainer)
		if gotChildPtr != &gotContainer.mid.child || gotMidPtr != &gotContainer.mid {
			t.Fatalf("interior pointers did not alias container.mid")
		}
		if gotContainer.mid.child.val != 20 || gotContainer.mid.extra != 3 {
			t.Errorf("unexpected mid: %+v", gotContainer.mid)
		}
	})
}

func TestOverlappingArrayPointersAndSlicesGraph(t *testing.T) {
	prev := state.GraphEngineEnabled()
	state.EnableGraphEngine(true)
	defer state.EnableGraphEngine(prev)

	t.Run("ArrayPtrBeforeOverlappingSlice", func(t *testing.T) {
		ks := [][2]gKey{
			{{a: 1, b: "one"}, {a: 2, b: "two"}},
			{{a: 3, b: "three"}, {a: 4, b: "four"}},
			{{a: 5, b: "five"}, {a: 6, b: "six"}},
		}
		root := &gRoot{
			any: (*[2][2]gKey)(ks[0:2]),
			all: []*gNode{{iface: ks[1:3:3]}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotPtr := got.any.(*[2][2]gKey)
		gotSlice := got.all[0].iface.([][2]gKey)
		gotPtr[1][1] = gKey{a: 99, b: "shared"}
		if gotSlice[0][1] != (gKey{a: 99, b: "shared"}) {
			t.Errorf("gotPtr[1][1] does not alias gotSlice[0][1]: gotSlice=%v", gotSlice)
		}
	})

	t.Run("SliceBeforeOverlappingArrayPtr", func(t *testing.T) {
		ks := [][2]gKey{
			{{a: 1, b: "one"}, {a: 2, b: "two"}},
			{{a: 3, b: "three"}, {a: 4, b: "four"}},
			{{a: 5, b: "five"}, {a: 6, b: "six"}},
		}
		root := &gRoot{
			any: ks[1:3:3],
			all: []*gNode{{iface: (*[2][2]gKey)(ks[0:2])}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotSlice := got.any.([][2]gKey)
		gotPtr := got.all[0].iface.(*[2][2]gKey)
		gotSlice[0][0] = gKey{a: 88, b: "shared2"}
		if gotPtr[1][0] != (gKey{a: 88, b: "shared2"}) {
			t.Errorf("gotSlice[0][0] does not alias gotPtr[1][0]: gotPtr=%v", gotPtr)
		}
	})

	t.Run("TwoOverlappingArrayPointers", func(t *testing.T) {
		backing := []gSpliceChild{
			{val: 10, tag: "a"},
			{val: 20, tag: "b"},
			{val: 30, tag: "c"},
		}
		p1 := (*[2]gSpliceChild)(backing[0:2])
		p2 := (*[2]gSpliceChild)(backing[1:3])
		root := &gRoot{
			any: p1,
			all: []*gNode{{iface: p2}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		for i := range backing {
			if backing[i].beforeSaveCalls != 1 {
				t.Errorf("backing[%d].beforeSaveCalls = %d, want 1", i, backing[i].beforeSaveCalls)
			}
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotP1 := got.any.(*[2]gSpliceChild)
		gotP2 := got.all[0].iface.(*[2]gSpliceChild)
		if &gotP1[1] != &gotP2[0] {
			t.Fatalf("&gotP1[1] (%p) != &gotP2[0] (%p)", &gotP1[1], &gotP2[0])
		}
		if gotP1[0].val != 10 || gotP1[1].val != 20 || gotP2[1].val != 30 {
			t.Errorf("unexpected values: p1=%+v p2=%+v", gotP1, gotP2)
		}
	})

	t.Run("TwoOverlappingInexactInterfaceArrayPointers", func(t *testing.T) {
		backing := []gIface{
			&gNode{id: 1},
			&gNode{id: 2},
			&gNode{id: 3},
		}
		p1 := (*[2]gIface)(backing[0:2])
		p2 := (*[2]gIface)(backing[1:3])
		root := &gOverlapIfaceArrayRoot{
			p1:     p1,
			holder: &gOverlapIfaceArrayHolder{p2: p2},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var got gOverlapIfaceArrayRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got.p1 == nil || got.holder == nil || got.holder.p2 == nil {
			t.Fatalf("unexpected nil pointers in restored root: %+v", got)
		}
		if &got.p1[1] != &got.holder.p2[0] || got.p1[1].gID() != 2 || got.holder.p2[1].gID() != 3 {
			t.Errorf("unexpected restored interface array pointers: p1=%v p2=%v", got.p1, got.holder.p2)
		}
	})

	t.Run("MisalignedNestedArrayPointers", func(t *testing.T) {
		flat := []gKey{
			{a: 1, b: "one"},
			{a: 2, b: "two"},
			{a: 3, b: "three"},
			{a: 4, b: "four"},
			{a: 5, b: "five"},
		}
		p1 := (*[2][2]gKey)(unsafe.Slice((*[2]gKey)(unsafe.Pointer(&flat[0])), 2))
		p2 := (*[2][2]gKey)(unsafe.Slice((*[2]gKey)(unsafe.Pointer(&flat[1])), 2))
		root := &gRoot{
			any: p1,
			all: []*gNode{{iface: p2}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotP1 := got.any.(*[2][2]gKey)
		gotP2 := got.all[0].iface.(*[2][2]gKey)
		if &gotP1[0][1] != &gotP2[0][0] || &gotP1[1][1] != &gotP2[1][0] {
			t.Fatalf("misaligned nested array pointers lost aliasing")
		}
		if gotP1[0][0].a != 1 || gotP2[1][1].a != 5 {
			t.Errorf("unexpected values: p1=%v p2=%v", gotP1, gotP2)
		}
	})

	t.Run("CoarseSliceUnusedCapOverlappingFinerArrayPtr", func(t *testing.T) {
		backing := make([][2]gSpliceChild, 3)
		backing[0] = [2]gSpliceChild{{val: 10}, {val: 20}}
		backing[1] = [2]gSpliceChild{{val: 30}, {val: 40}}
		backing[2] = [2]gSpliceChild{{val: 50}, {val: 60}}
		s1 := backing[0:1:2] // len=1, cap=2 ([0..4)): flat[2..3] is unused capacity
		flat := unsafe.Slice(&backing[0][0], 6)
		p2 := (*[2]gSpliceChild)(flat[3:5]) // [3..5) partially overlaps s1's capacity [0..4), leaving flat[2] uncovered
		root := &gRoot{
			any: s1,
			all: []*gNode{{iface: p2}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if flat[2].beforeSaveCalls != 0 || flat[5].beforeSaveCalls != 0 {
			t.Errorf("unused capacity elements ran beforeSave: flat[2]=%d flat[5]=%d, want 0", flat[2].beforeSaveCalls, flat[5].beforeSaveCalls)
		}
		for _, idx := range []int{0, 1, 3, 4} {
			if flat[idx].beforeSaveCalls != 1 {
				t.Errorf("flat[%d].beforeSaveCalls = %d, want 1", idx, flat[idx].beforeSaveCalls)
			}
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotS1 := got.any.([][2]gSpliceChild)
		gotP2 := got.all[0].iface.(*[2]gSpliceChild)
		gotS1 = gotS1[:2]
		if &gotS1[1][1] != &gotP2[0] || gotP2[0].val != 40 || gotP2[1].val != 50 {
			t.Errorf("unexpected restored aliasing: s1=%+v p2=%+v", gotS1, gotP2)
		}
	})

	t.Run("CoarseSliceUnusedCapInsideFinerMergedArray", func(t *testing.T) {
		backing := make([][2]gSpliceChild, 3)
		backing[0] = [2]gSpliceChild{{val: 10}, {val: 20}}
		backing[1] = [2]gSpliceChild{{val: 30}, {val: 40}}
		backing[2] = [2]gSpliceChild{{val: 50}, {val: 60}}
		flat := unsafe.Slice(&backing[0][0], 6)
		// Discover finer array [0..6) first via flat[0:1:6], then visit
		// coarser slice backing[0:1:3] whose unused capacity spans flat[2..5].
		finer := flat[0:1:6]
		coarser := backing[0:1:3]
		root := &gRoot{
			any: finer,
			all: []*gNode{{iface: coarser}},
		}
		var buf bytes.Buffer
		if _, err := state.Save(t.Context(), &buf, root); err != nil {
			t.Fatalf("Save: %v", err)
		}
		for _, idx := range []int{2, 3, 4, 5} {
			if flat[idx].beforeSaveCalls != 0 {
				t.Errorf("unused capacity flat[%d].beforeSaveCalls = %d, want 0", idx, flat[idx].beforeSaveCalls)
			}
		}
		for _, idx := range []int{0, 1} {
			if flat[idx].beforeSaveCalls != 1 {
				t.Errorf("live flat[%d].beforeSaveCalls = %d, want 1", idx, flat[idx].beforeSaveCalls)
			}
		}
		var got gRoot
		if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &got); err != nil {
			t.Fatalf("Load: %v", err)
		}
		gotFiner := got.any.([]gSpliceChild)
		gotCoarser := got.all[0].iface.([][2]gSpliceChild)
		if &gotFiner[0] != &gotCoarser[0][0] || gotCoarser[0][1].val != 20 {
			t.Errorf("unexpected restored aliasing: finer=%+v coarser=%+v", gotFiner, gotCoarser)
		}
	})
}

func TestMapAliasedThroughNamedType(t *testing.T) {
	prev := state.GraphEngineEnabled()
	state.EnableGraphEngine(true)
	defer state.EnableGraphEngine(prev)

	m := map[string]int64{"x": 1}
	saved := &gAliasMapRoot{m: m, nm: m}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, saved); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data := buf.Bytes()
	var out bytes.Buffer
	if err := pretty.PrintText(&out, bytes.NewReader(data)); err != nil {
		t.Fatalf("PrintText: %v", err)
	}
	var got gAliasMapRoot
	if _, err := state.Load(t.Context(), bytes.NewReader(data), &got); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got.m["y"] = 2
	if got.nm["x"] != 1 || got.nm["y"] != 2 {
		t.Errorf("map not shared after load: m=%v nm=%v", got.m, got.nm)
	}
}
