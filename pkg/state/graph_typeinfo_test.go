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
	"sync"
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

type unregMapVal int

type testNestedExactHolder struct {
	ifaceMatrix [][]testIface
	ifacePtrs   []*testIface
	ifacePtrPtr **testIface
	slicePtr    *[]testIface
	mapMatrix   [][]map[string]testIface
	mapPtrs     []*map[string]testIface
	nestedAlias [][]map[string]unregMapVal
	directAlias map[string]unregMapVal
}

func (*testNestedExactHolder) StateTypeName() string { return "state.testNestedExactHolder" }
func (*testNestedExactHolder) StateFields() []string {
	return []string{
		"ifaceMatrix", "ifacePtrs", "ifacePtrPtr", "slicePtr",
		"mapMatrix", "mapPtrs", "nestedAlias", "directAlias",
	}
}
func (h *testNestedExactHolder) StateSave(s Sink) {
	s.Save(0, &h.ifaceMatrix)
	s.Save(1, &h.ifacePtrs)
	s.Save(2, &h.ifacePtrPtr)
	s.Save(3, &h.slicePtr)
	s.Save(4, &h.mapMatrix)
	s.Save(5, &h.mapPtrs)
	s.Save(6, &h.nestedAlias)
	s.Save(7, &h.directAlias)
}
func (h *testNestedExactHolder) StateLoad(_ context.Context, s Source) {
	s.Load(0, &h.ifaceMatrix)
	s.Load(1, &h.ifacePtrs)
	s.Load(2, &h.ifacePtrPtr)
	s.Load(3, &h.slicePtr)
	s.Load(4, &h.mapMatrix)
	s.Load(5, &h.mapPtrs)
	s.Load(6, &h.nestedAlias)
	s.Load(7, &h.directAlias)
}

type cycExactA *cycExactB
type cycExactB []map[int]cycExactA

type unregRecSlice []unregRecSlice
type unregRecPtr *unregRecPtr
type unregRecMap map[string]unregRecMap
type unregMutA []unregMutB
type unregMutB []unregMutA

type unregZeroSL struct{}

func (*unregZeroSL) StateTypeName() string { return "state.unregZeroSL" }
func (*unregZeroSL) StateFields() []string { return []string{"v"} }
func (*unregZeroSL) StateSave(s Sink)      { s.SaveValue(0, int64(77)) }
func (*unregZeroSL) StateLoad(_ context.Context, s Source) {
	s.LoadValue(0, new(int64), func(any) {})
}

type fpRecFunc func(fpRecFunc, fpRecFunc)
type fpRecMap map[*fpRecMap]fpRecFunc

var fpManualSwapOrder bool

type fpManual struct{ raw uint64 }

func (*fpManual) StateTypeName() string { return "state.fpManual" }
func (*fpManual) StateFields() []string {
	if fpManualSwapOrder {
		return []string{"beta", "alpha"}
	}
	return []string{"alpha", "beta"}
}
func (x *fpManual) StateSave(s Sink) {
	if fpManualSwapOrder {
		s.SaveValue(0, uint64(0))
		s.SaveValue(1, x.raw)
		return
	}
	s.SaveValue(0, x.raw)
	s.SaveValue(1, uint64(0))
}
func (x *fpManual) StateLoad(_ context.Context, s Source) {
	if fpManualSwapOrder {
		s.LoadValue(0, new(uint64), func(any) {})
		s.LoadValue(1, new(uint64), func(v any) { x.raw = v.(uint64) })
		return
	}
	s.LoadValue(0, new(uint64), func(v any) { x.raw = v.(uint64) })
	s.LoadValue(1, new(uint64), func(any) {})
}

func init() {
	Register((*testImpl)(nil))
	RegisterStruct((*testPrintHolder)(nil))
	RegisterStruct((*testNestedExactHolder)(nil))
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

func TestNestedNeedsExact(t *testing.T) {
	t.Run("nested_slice_and_ptr_to_nonempty_iface", func(t *testing.T) {
		var iv1 testIface = testImpl(33)
		var iv2 testIface = testImpl(34)
		iv2Ptr := &iv2
		sl := []testIface{testImpl(44)}
		mp := map[string]testIface{"p": testImpl(66)}
		orig := testNestedExactHolder{
			ifaceMatrix: [][]testIface{{testImpl(11), testImpl(22)}},
			ifacePtrs:   []*testIface{&iv1},
			ifacePtrPtr: &iv2Ptr,
			slicePtr:    &sl,
			mapMatrix:   [][]map[string]testIface{{{"k": testImpl(55)}}},
			mapPtrs:     []*map[string]testIface{&mp},
		}
		var buf bytes.Buffer
		if _, err := saveGraph(context.Background(), &buf, &orig); err != nil {
			t.Fatalf("saveGraph failed: %v", err)
		}
		r := wire.Reader{Reader: bytes.NewReader(buf.Bytes())}
		hdr, err := ReadHeaderMode(&r)
		if err != nil {
			t.Fatalf("ReadHeaderMode failed: %v", err)
		}
		raw := make([]byte, hdr.Length)
		if _, err := r.Read(raw); err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		var printed strings.Builder
		if err := PrintGraph(&printed, raw, 0, false); err != nil {
			t.Fatalf("PrintGraph failed: %v", err)
		}
		var got testNestedExactHolder
		if _, err := loadGraph(context.Background(), bytes.NewReader(raw), &got, hdr.Length, 0); err != nil {
			t.Fatalf("loadGraph failed: %v", err)
		}
		if v := got.ifaceMatrix[0][0].testVal(); v != 11 {
			t.Fatalf("ifaceMatrix[0][0] = %d, want 11", v)
		}
		if v := got.ifaceMatrix[0][1].testVal(); v != 22 {
			t.Fatalf("ifaceMatrix[0][1] = %d, want 22", v)
		}
		if v := (*got.ifacePtrs[0]).testVal(); v != 33 {
			t.Fatalf("ifacePtrs[0] = %d, want 33", v)
		}
		if v := (**got.ifacePtrPtr).testVal(); v != 34 {
			t.Fatalf("ifacePtrPtr = %d, want 34", v)
		}
		if v := (*got.slicePtr)[0].testVal(); v != 44 {
			t.Fatalf("slicePtr[0] = %d, want 44", v)
		}
		if v := got.mapMatrix[0][0]["k"].testVal(); v != 55 {
			t.Fatalf("mapMatrix[0][0][\"k\"] = %d, want 55", v)
		}
		if v := (*got.mapPtrs[0])["p"].testVal(); v != 66 {
			t.Fatalf("mapPtrs[0][\"p\"] = %d, want 66", v)
		}
	})

	t.Run("aliased_map_with_unregistered_typedef", func(t *testing.T) {
		shared := map[string]unregMapVal{"a": 7}
		orig := testNestedExactHolder{
			nestedAlias: [][]map[string]unregMapVal{{shared}},
			directAlias: shared,
		}
		var buf bytes.Buffer
		if _, err := saveGraph(context.Background(), &buf, &orig); err != nil {
			t.Fatalf("saveGraph failed: %v", err)
		}
		r := wire.Reader{Reader: bytes.NewReader(buf.Bytes())}
		hdr, err := ReadHeaderMode(&r)
		if err != nil {
			t.Fatalf("ReadHeaderMode failed: %v", err)
		}
		var got testNestedExactHolder
		if _, err := loadGraph(context.Background(), r.Reader, &got, hdr.Length, 0); err != nil {
			t.Fatalf("loadGraph failed: %v", err)
		}
		if got.directAlias["a"] != 7 || got.nestedAlias[0][0]["a"] != 7 {
			t.Fatalf("loaded maps = %v / %v, want 7", got.directAlias, got.nestedAlias)
		}
		got.directAlias["b"] = 9
		if got.nestedAlias[0][0]["b"] != 9 {
			t.Fatalf("map aliasing lost across nested and direct references")
		}
	})

	t.Run("cyclic_type_needs_exact", func(t *testing.T) {
		// Enter at the map node so cycExactA and cycExactB hit b.pending
		// while the map's needsExact is being computed.
		_ = typeInfoOf(reflect.TypeFor[map[int]cycExactA]())
		if !typeInfoOf(reflect.TypeFor[cycExactA]()).needsExact {
			t.Errorf("cycExactA.needsExact = false, want true")
		}
		if !typeInfoOf(reflect.TypeFor[cycExactB]()).needsExact {
			t.Errorf("cycExactB.needsExact = false, want true")
		}
	})
}

func TestNilTypeAndRoot(t *testing.T) {
	// Prepare a valid graph stream so loadGraph runs before checking rootPtr.
	x := 1
	var valid bytes.Buffer
	if _, err := saveGraph(context.Background(), &valid, &x); err != nil {
		t.Fatalf("saveGraph(&x) failed: %v", err)
	}

	typeInfosMu.RLock()
	beforeCount := typeInfoCount
	typeInfosMu.RUnlock()

	var out bytes.Buffer
	_, saveErr := saveGraph(context.Background(), &out, nil)
	if saveErr == nil {
		t.Fatalf("saveGraph(nil) succeeded, want error")
	}
	if strings.Contains(saveErr.Error(), "nil pointer dereference") {
		t.Errorf("saveGraph(nil) panicked with nil dereference: %v", saveErr)
	}

	r := wire.Reader{Reader: bytes.NewReader(valid.Bytes())}
	hdr, err := ReadHeaderMode(&r)
	if err != nil {
		t.Fatalf("ReadHeaderMode failed: %v", err)
	}
	_, loadErr := loadGraph(context.Background(), r.Reader, nil, hdr.Length, 0)
	if loadErr == nil {
		t.Fatalf("loadGraph(nil) succeeded, want error")
	}
	if strings.Contains(loadErr.Error(), "nil pointer dereference") {
		t.Errorf("loadGraph(nil) panicked with nil dereference: %v", loadErr)
	}

	if err := safely(func() { _ = typeInfoForRtype(nil) }); err == nil || strings.Contains(err.Error(), "nil pointer dereference") {
		t.Errorf("typeInfoForRtype(nil) = %v, want clean Failf error", err)
	}
	if err := safely(func() { _ = typeInfoOf(nil) }); err == nil || strings.Contains(err.Error(), "nil pointer dereference") {
		t.Errorf("typeInfoOf(nil) = %v, want clean Failf error", err)
	}

	typeInfosMu.RLock()
	afterCount := typeInfoCount
	nilEntry := typeInfos[nil]
	typeInfosMu.RUnlock()
	if afterCount != beforeCount {
		t.Errorf("typeInfoCount changed from %d to %d on nil type", beforeCount, afterCount)
	}
	if nilEntry != nil {
		t.Errorf("typeInfos[nil] = %+v, want nil", nilEntry)
	}
}

func TestUnregisteredRecursiveType(t *testing.T) {
	s := make(unregRecSlice, 1)
	ps := &s

	var p unregRecPtr
	p = &p
	pp := &p

	m := unregRecMap{"self": nil}
	pm := &m

	a := make(unregMutA, 1)
	pa := &a

	var iface any = unregRecSlice(nil)

	for name, root := range map[string]any{
		"rec_slice":     &ps,
		"rec_ptr":       &pp,
		"rec_map":       &pm,
		"mutual_slices": &pa,
		"iface_exact":   &iface,
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := saveGraph(context.Background(), &buf, root); err == nil {
				t.Fatalf("saveGraph(%s) succeeded for unregistered recursive type, want error", name)
			}
		})
	}
}

func TestUnregisteredZeroFieldSaverLoader(t *testing.T) {
	s := []unregZeroSL{{}}
	ps := &s
	var buf bytes.Buffer
	if _, err := saveGraph(context.Background(), &buf, &ps); err == nil {
		t.Fatalf("saveGraph(*[]unregZeroSL) succeeded for unregistered SaverLoader, want error")
	}
}

func TestSchemaFingerprintCompleteness(t *testing.T) {
	withTempReg := func(name string, typ reflect.Type, noHooks bool, fn func()) {
		prev, hadPrev := globalTypeDatabase[name]
		prevNH := noHooksTypes[typ]
		globalTypeDatabase[name] = typ
		if noHooks {
			noHooksTypes[typ] = true
		}
		fingerprint.Store(0)
		defer func() {
			if hadPrev {
				globalTypeDatabase[name] = prev
			} else {
				delete(globalTypeDatabase, name)
			}
			if !prevNH {
				delete(noHooksTypes, typ)
			}
			fingerprint.Store(0)
		}()
		fn()
	}

	t.Run("manual_state_fields_change", func(t *testing.T) {
		defer func() { fpManualSwapOrder = false }()
		var buf bytes.Buffer
		var fp1, fp2 uint64
		withTempReg("state.fpManual", reflect.TypeFor[fpManual](), false, func() {
			fpManualSwapOrder = false
			fingerprint.Store(0)
			fp1 = schemaFingerprint()
			v1 := &fpManual{raw: 42}
			if _, err := saveGraph(context.Background(), &buf, &v1); err != nil {
				t.Fatalf("saveGraph(v1) failed: %v", err)
			}

			fpManualSwapOrder = true
			fingerprint.Store(0)
			fp2 = schemaFingerprint()
			r := wire.Reader{Reader: bytes.NewReader(buf.Bytes())}
			hdr, err := ReadHeaderMode(&r)
			if err != nil {
				t.Fatalf("ReadHeaderMode failed: %v", err)
			}
			var v2 *fpManual
			if _, err := loadGraph(context.Background(), r.Reader, &v2, hdr.Length, 0); err == nil {
				t.Fatalf("loadGraph(v1 -> v2) succeeded with raw=%d, want fingerprint mismatch error", v2.raw)
			}
		})
		if fp1 == fp2 {
			t.Fatalf("schemaFingerprint unchanged (%#x) when StateFields() changed", fp1)
		}
	})

	t.Run("deep_composite_leaf_change", func(t *testing.T) {
		t1 := reflect.StructOf([]reflect.StructField{{
			Name: "X",
			Type: reflect.TypeFor[[1][1][1][1]uint64](),
		}})
		t2 := reflect.StructOf([]reflect.StructField{{
			Name: "X",
			Type: reflect.TypeFor[[1][1][1][1]float64](),
		}})
		var fp1, fp2 uint64
		withTempReg("state.fpDeepPod", t1, true, func() {
			fp1 = schemaFingerprint()
		})
		withTempReg("state.fpDeepPod", t2, true, func() {
			fp2 = schemaFingerprint()
		})
		if fp1 == fp2 {
			t.Fatalf("schemaFingerprint unchanged (%#x) when depth-4 leaf changed from uint64 to float64", fp1)
		}
	})

	t.Run("anonymous_interface_methods_change", func(t *testing.T) {
		t1 := reflect.StructOf([]reflect.StructField{{
			Name: "Fn",
			Type: reflect.TypeFor[any](),
		}})
		t2 := reflect.StructOf([]reflect.StructField{{
			Name: "Fn",
			Type: reflect.TypeFor[interface{ Foo() }](),
		}})
		var fp1, fp2 uint64
		withTempReg("state.fpAnonIface", t1, false, func() {
			fp1 = schemaFingerprint()
		})
		withTempReg("state.fpAnonIface", t2, false, func() {
			fp2 = schemaFingerprint()
		})
		if fp1 == fp2 {
			t.Fatalf("schemaFingerprint unchanged (%#x) when field changed from any to interface{ Foo() }", fp1)
		}
	})

	t.Run("recursive_func_and_map_types", func(t *testing.T) {
		t1 := reflect.StructOf([]reflect.StructField{{
			Name: "M",
			Type: reflect.TypeFor[fpRecMap](),
		}})
		withTempReg("state.fpRecTypes", t1, false, func() {
			if fp := schemaFingerprint(); fp == 0 {
				t.Fatalf("schemaFingerprint() = 0, want non-zero")
			}
		})
	})
}

func TestStatsNilAndZeroString(t *testing.T) {
	t.Run("nil_receiver", func(t *testing.T) {
		var nilStats *Stats
		if got := nilStats.String(); got != "" {
			t.Errorf("(*Stats)(nil).String() = %q, want empty string", got)
		}
	})
	t.Run("zero_value", func(t *testing.T) {
		var zeroStats Stats
		_ = zeroStats.String()
	})
}

// defIndirectRoot holds non-empty interfaces and maps of them behind unnamed
// pointer, slice, and array objects.
type defIndirectRoot struct {
	pp            **defIface
	ptrSlice      []*defIface
	slicePtr      *[]defIface
	nestedSlice   [][]defIface
	mapPtrPtr     **map[string]defIface
	zeroArrPtrPtr **[0]defIface
}

func (*defIndirectRoot) StateTypeName() string { return "state.defIndirectRoot" }
func (*defIndirectRoot) StateFields() []string {
	return []string{"pp", "ptrSlice", "slicePtr", "nestedSlice", "mapPtrPtr", "zeroArrPtrPtr"}
}
func (x *defIndirectRoot) StateSave(s Sink) {
	s.graph.save(0, &x.pp)
	s.graph.save(1, &x.ptrSlice)
	s.graph.save(2, &x.slicePtr)
	s.graph.save(3, &x.nestedSlice)
	s.graph.save(4, &x.mapPtrPtr)
	s.graph.save(5, &x.zeroArrPtrPtr)
}
func (x *defIndirectRoot) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.pp)
	s.graph.load(1, &x.ptrSlice)
	s.graph.load(2, &x.slicePtr)
	s.graph.load(3, &x.nestedSlice)
	s.graph.load(4, &x.mapPtrPtr)
	s.graph.load(5, &x.zeroArrPtrPtr)
}

var registerIndirectTestTypes = sync.OnceFunc(func() {
	registerDeferredTestTypes()
	Register((*defIndirectRoot)(nil))
	fingerprint.Store(0)
})

// graphRoundTrip saves saved with the graph engine and loads it into loaded.
func graphRoundTrip(t *testing.T, saved, loaded any) {
	t.Helper()
	var buf bytes.Buffer
	if _, err := saveGraph(t.Context(), &buf, saved); err != nil {
		t.Fatalf("saveGraph: %v", err)
	}
	hdr, err := ReadHeaderMode(&wire.Reader{Reader: &buf})
	if err != nil {
		t.Fatalf("ReadHeaderMode: %v", err)
	}
	if _, err := loadGraph(t.Context(), &buf, loaded, hdr.Length, 0); err != nil {
		t.Fatalf("loadGraph: %v", err)
	}
}

// TestGraphIndirectInexactTypesRoundTrip checks that non-empty interfaces
// reached only through unnamed pointer, slice, and map objects keep their
// itab-based representation across save and load.
func TestGraphIndirectInexactTypesRoundTrip(t *testing.T) {
	registerIndirectTestTypes()

	var i1 defIface = &defImpl{v: 11}
	p1 := &i1
	var i2 defIface = &defImpl{v: 22}
	s := []defIface{&defImpl{v: 33}, &defImpl{v: 44}}
	m := map[string]defIface{"k": &defImpl{v: 55}}
	mp := &m
	var za [0]defIface
	zap := &za

	saved := defIndirectRoot{
		pp:            &p1,
		ptrSlice:      []*defIface{&i2},
		slicePtr:      &s,
		nestedSlice:   [][]defIface{{&defImpl{v: 66}}},
		mapPtrPtr:     &mp,
		zeroArrPtrPtr: &zap,
	}
	var loaded defIndirectRoot
	graphRoundTrip(t, &saved, &loaded)

	if got := (**loaded.pp).defTag(); got != 1 {
		t.Errorf("(**loaded.pp).defTag() = %d, want 1", got)
	}
	if impl := (**loaded.pp).(*defImpl); impl.v != 11 {
		t.Errorf("**loaded.pp = %+v, want v=11", impl)
	}
	if got := (*loaded.ptrSlice[0]).defTag(); got != 1 {
		t.Errorf("(*loaded.ptrSlice[0]).defTag() = %d, want 1", got)
	}
	if got := (*loaded.ptrSlice[0]).(*defImpl).v; got != 22 {
		t.Errorf("(*loaded.ptrSlice[0]).v = %d, want 22", got)
	}
	if len(*loaded.slicePtr) != 2 || (*loaded.slicePtr)[0].defTag() != 1 || (*loaded.slicePtr)[1].(*defImpl).v != 44 {
		t.Errorf("*loaded.slicePtr = %v, want [33 44]", *loaded.slicePtr)
	}
	if got := loaded.nestedSlice[0][0].(*defImpl).v; got != 66 {
		t.Errorf("loaded.nestedSlice[0][0].v = %d, want 66", got)
	}
	if got := (**loaded.mapPtrPtr)["k"]; got == nil || got.defTag() != 1 || got.(*defImpl).v != 55 {
		t.Errorf("(**loaded.mapPtrPtr)[k] = %v, want v=55", got)
	}
	if loaded.zeroArrPtrPtr == nil || *loaded.zeroArrPtrPtr == nil {
		t.Errorf("loaded.zeroArrPtrPtr = %v, want non-nil", loaded.zeroArrPtrPtr)
	}
}
