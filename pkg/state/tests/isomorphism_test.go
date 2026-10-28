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
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// addrKey identifies a value in memory. The type is part of the key because a
// struct and its first field (or an array and its first element) share an
// address.
type addrKey struct {
	addr uintptr
	typ  reflect.Type
}

// isoChecker checks that two object graphs are isomorphic: they have equal
// saved scalar values, and there is a bijection between the memory locations
// of the two graphs that preserves pointers. Unlike reflect.DeepEqual, this
// detects lost or added aliasing: two pointers to the same object (or to the
// same field of an object, or to overlapping slice windows) in one graph must
// point to the same location in the other graph.
type isoChecker struct {
	// fwd maps locations of the first graph to locations of the second.
	fwd map[addrKey]uintptr
	// rev maps locations of the second graph to locations of the first.
	rev map[addrKey]uintptr
	// fwdMaps and revMaps map map identities.
	fwdMaps map[unsafe.Pointer]unsafe.Pointer
	revMaps map[unsafe.Pointer]unsafe.Pointer
	// shallow are locations that were recorded, but whose values were not
	// compared.
	shallow map[addrKey]bool
	// deferredMaps are maps with keys containing pointers. They are matched
	// after the rest of the graph, so that pointer keys can be translated.
	deferredMaps []deferredMap
	errs         []string
}

type deferredMap struct {
	path string
	a, b reflect.Value
}

var timeType = reflect.TypeFor[time.Time]()

func init() {
	isomorphicCheck = isomorphic
}

// unRO clears the read-only flags of v, which are set for values obtained
// through unexported fields. This allows calling Interface on them. Test use
// only: reflect.Value's layout is {typ, ptr, flag}, and the read-only flags
// are flagStickyRO (1<<5) and flagEmbedRO (1<<6).
func unRO(v reflect.Value) reflect.Value {
	type value struct {
		typ  unsafe.Pointer
		ptr  unsafe.Pointer
		flag uintptr
	}
	(*value)(unsafe.Pointer(&v)).flag &^= 1<<5 | 1<<6
	return v
}

// checkIsomorphic fails the test if a and b are not isomorphic. a and b must
// be pointers to the roots of the graphs.
func checkIsomorphic(t testing.TB, a, b any) {
	t.Helper()
	if err := isomorphic(a, b); err != nil {
		t.Fatalf("Graphs are not isomorphic: %v", err)
	}
}

// isomorphic returns an error if a and b are not isomorphic. a and b must be
// pointers to the roots of the graphs.
func isomorphic(a, b any) error {
	c := &isoChecker{
		fwd:     make(map[addrKey]uintptr),
		rev:     make(map[addrKey]uintptr),
		fwdMaps: make(map[unsafe.Pointer]unsafe.Pointer),
		revMaps: make(map[unsafe.Pointer]unsafe.Pointer),
		shallow: make(map[addrKey]bool),
	}
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if av.Kind() != reflect.Pointer || bv.Kind() != reflect.Pointer {
		return fmt.Errorf("roots must be pointers, got %T and %T", a, b)
	}
	c.visit("root", av, bv)
	// Deferred maps may discover new parts of the graph, which may in turn
	// defer more maps. Re-defer maps with unresolved pointer keys until a
	// pass makes no progress, then report any remaining unresolved keys.
	for len(c.deferredMaps) > 0 {
		fwdBefore, mapsBefore := len(c.fwd), len(c.fwdMaps)
		pending := c.deferredMaps
		c.deferredMaps = nil
		for _, dm := range pending {
			if !c.matchPointerKeyedMap(dm.path, dm.a, dm.b, true) {
				c.deferredMaps = append(c.deferredMaps, dm)
			}
		}
		if len(c.deferredMaps) == len(pending) && len(c.fwd) == fwdBefore && len(c.fwdMaps) == mapsBefore {
			remaining := c.deferredMaps
			c.deferredMaps = nil
			for _, dm := range remaining {
				c.matchPointerKeyedMap(dm.path, dm.a, dm.b, false)
			}
		}
	}
	if len(c.errs) > 0 {
		if len(c.errs) > 10 {
			c.errs = append(c.errs[:10], fmt.Sprintf("... and %d more", len(c.errs)-10))
		}
		return fmt.Errorf("%s", strings.Join(c.errs, "\n"))
	}
	return nil
}

func (c *isoChecker) errorf(path, format string, args ...any) {
	c.errs = append(c.errs, path+": "+fmt.Sprintf(format, args...))
}

// record records that location a corresponds to location b. It returns false
// if this correspondence was already known, in which case the values need not
// be compared again.
func (c *isoChecker) record(path string, typ reflect.Type, a, b uintptr) bool {
	ka, kb := addrKey{a, typ}, addrKey{b, typ}
	fb, okF := c.fwd[ka]
	fa, okR := c.rev[kb]
	switch {
	case okF && fb != b:
		c.errorf(path, "%v at %#x corresponds to both %#x and %#x: aliasing differs", typ, a, fb, b)
		return false
	case okR && fa != a:
		c.errorf(path, "%v at %#x corresponds to both %#x and %#x: aliasing differs", typ, b, fa, a)
		return false
	case okF:
		if c.shallow[ka] {
			delete(c.shallow, ka)
			return true
		}
		return false
	}
	c.fwd[ka] = b
	c.rev[kb] = a
	return true
}

// visit compares a and b, which have the same type.
func (c *isoChecker) visit(path string, a, b reflect.Value) {
	if a.Type() != b.Type() {
		c.errorf(path, "types differ: %v vs %v", a.Type(), b.Type())
		return
	}
	typ := a.Type()
	if a.CanAddr() != b.CanAddr() {
		c.errorf(path, "addressability differs")
		return
	}
	if a.CanAddr() && typ.Size() != 0 {
		if !c.record(path, typ, a.UnsafeAddr(), b.UnsafeAddr()) {
			return
		}
	}
	switch typ.Kind() {
	case reflect.Bool:
		if a.Bool() != b.Bool() {
			c.errorf(path, "%v != %v", a.Bool(), b.Bool())
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if a.Int() != b.Int() {
			c.errorf(path, "%d != %d", a.Int(), b.Int())
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if a.Uint() != b.Uint() {
			c.errorf(path, "%d != %d", a.Uint(), b.Uint())
		}
	case reflect.Float32, reflect.Float64:
		if math.Float64bits(a.Float()) != math.Float64bits(b.Float()) {
			c.errorf(path, "%v != %v", a.Float(), b.Float())
		}
	case reflect.Complex64, reflect.Complex128:
		ca, cb := a.Complex(), b.Complex()
		if math.Float64bits(real(ca)) != math.Float64bits(real(cb)) || math.Float64bits(imag(ca)) != math.Float64bits(imag(cb)) {
			c.errorf(path, "%v != %v", ca, cb)
		}
	case reflect.String:
		if a.String() != b.String() {
			c.errorf(path, "%q != %q", a.String(), b.String())
		}
	case reflect.Pointer:
		if a.IsNil() != b.IsNil() {
			c.errorf(path, "nil pointer mismatch: %v vs %v", a.IsNil(), b.IsNil())
			return
		}
		if a.IsNil() {
			return
		}
		c.visit("(*"+path+")", a.Elem(), b.Elem())
	case reflect.Array:
		for i := 0; i < a.Len(); i++ {
			c.visit(fmt.Sprintf("%s[%d]", path, i), a.Index(i), b.Index(i))
		}
	case reflect.Slice:
		if a.IsNil() != b.IsNil() {
			c.errorf(path, "nil slice mismatch: %v vs %v", a.IsNil(), b.IsNil())
			return
		}
		if a.Len() != b.Len() || a.Cap() != b.Cap() {
			c.errorf(path, "len/cap mismatch: %d/%d vs %d/%d", a.Len(), a.Cap(), b.Len(), b.Cap())
			return
		}
		for i := 0; i < a.Len(); i++ {
			c.visit(fmt.Sprintf("%s[%d]", path, i), a.Index(i), b.Index(i))
		}
		// Elements beyond the length are only saved if they are within
		// other slices or pointed to, but must still correspond: windows
		// of the same array must share the same array after loading.
		if et := typ.Elem(); et.Size() != 0 {
			fa, fb := a.Slice3(0, a.Cap(), a.Cap()), b.Slice3(0, b.Cap(), b.Cap())
			for i := a.Len(); i < a.Cap(); i++ {
				ka := addrKey{fa.Index(i).UnsafeAddr(), et}
				_, existed := c.fwd[ka]
				wasShallow := c.shallow[ka]
				if c.record(fmt.Sprintf("%s[%d]", path, i), et, ka.addr, fb.Index(i).UnsafeAddr()) && (!existed || wasShallow) {
					c.shallow[ka] = true
				}
			}
		}
	case reflect.Interface:
		if a.IsNil() != b.IsNil() {
			c.errorf(path, "nil interface mismatch: %v vs %v", a.IsNil(), b.IsNil())
			return
		}
		if a.IsNil() {
			return
		}
		ae, be := a.Elem(), b.Elem()
		if ae.Type() != be.Type() {
			c.errorf(path, "dynamic types differ: %v vs %v", ae.Type(), be.Type())
			return
		}
		c.visit(fmt.Sprintf("%s.(%v)", path, ae.Type()), ae, be)
	case reflect.Map:
		c.visitMap(path, a, b)
	case reflect.Struct:
		if typ == timeType {
			ta := unRO(a).Interface().(time.Time)
			tb := unRO(b).Interface().(time.Time)
			_, oa := ta.Zone()
			_, ob := tb.Zone()
			if !ta.Equal(tb) || oa != ob {
				c.errorf(path, "%v != %v", ta, tb)
			}
			return
		}
		if typ.PkgPath() == "sync/atomic" && strings.HasPrefix(typ.Name(), "Pointer[") {
			// atomic.Pointer[T] is {_ [0]*T; _ noCopy; v unsafe.Pointer}.
			elemType := typ.Field(0).Type.Elem().Elem()
			pa := reflect.NewAt(elemType, unRO(a.FieldByName("v")).UnsafePointer())
			pb := reflect.NewAt(elemType, unRO(b.FieldByName("v")).UnsafePointer())
			c.visit(path+".Load()", pa, pb)
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !savedField(f) {
				continue
			}
			c.visit(path+"."+f.Name, a.Field(i), b.Field(i))
		}
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		c.errorf(path, "unsupported kind %v", typ.Kind())
	default:
		c.errorf(path, "unknown kind %v", typ.Kind())
	}
}

// savedField returns true if f is saved by the generated StateSave methods.
func savedField(f reflect.StructField) bool {
	if f.Name == "_" {
		return false
	}
	switch f.Tag.Get("state") {
	case "nosave", "manual", "ignore":
		return false
	}
	return true
}

func (c *isoChecker) visitMap(path string, a, b reflect.Value) {
	if a.IsNil() != b.IsNil() {
		c.errorf(path, "nil map mismatch: %v vs %v", a.IsNil(), b.IsNil())
		return
	}
	if a.IsNil() {
		return
	}
	pa, pb := a.UnsafePointer(), b.UnsafePointer()
	fb, okF := c.fwdMaps[pa]
	fa, okR := c.revMaps[pb]
	switch {
	case okF && fb != pb, okR && fa != pa:
		c.errorf(path, "map aliasing differs")
		return
	case okF:
		return
	}
	c.fwdMaps[pa] = pb
	c.revMaps[pb] = pa
	if a.Len() != b.Len() {
		c.errorf(path, "map length mismatch: %d vs %d", a.Len(), b.Len())
		return
	}
	if hasPointers(a.Type().Key()) {
		c.deferredMaps = append(c.deferredMaps, deferredMap{path, a, b})
		return
	}
	// Match keys by their bits: this handles NaN keys, which can't be
	// looked up.
	bEntries := make(map[string][]reflect.Value)
	for it := b.MapRange(); it.Next(); {
		k := fingerprint(nil, it.Key(), nil)
		bEntries[k] = append(bEntries[k], it.Value())
	}
	for it := a.MapRange(); it.Next(); {
		k := fingerprint(nil, it.Key(), nil)
		vs := bEntries[k]
		if len(vs) == 0 {
			c.errorf(path, "key %v missing", unRO(it.Key()))
			continue
		}
		bEntries[k] = vs[1:]
		c.visit(fmt.Sprintf("%s[%v]", path, unRO(it.Key())), it.Value(), vs[0])
	}
}

// matchPointerKeyedMap matches the entries of maps whose keys contain
// pointers. The pointers in the keys of a are translated to the second graph.
// When allowDefer is true, it returns false without modifying checker state if
// any key references an object that has not been visited yet.
func (c *isoChecker) matchPointerKeyedMap(path string, a, b reflect.Value, allowDefer bool) bool {
	if allowDefer {
		for it := a.MapRange(); it.Next(); {
			var untranslated bool
			fingerprint(nil, it.Key(), func(key addrKey) uintptr {
				bAddr, ok := c.fwd[key]
				if !ok {
					untranslated = true
				}
				return bAddr
			})
			if untranslated {
				return false
			}
		}
	}
	bEntries := make(map[string][]reflect.Value)
	for it := b.MapRange(); it.Next(); {
		k := fingerprint(nil, it.Key(), nil)
		bEntries[k] = append(bEntries[k], it.Value())
	}
	for it := a.MapRange(); it.Next(); {
		var untranslated bool
		k := fingerprint(nil, it.Key(), func(key addrKey) uintptr {
			bAddr, ok := c.fwd[key]
			if !ok {
				untranslated = true
			}
			return bAddr
		})
		if untranslated {
			c.errorf(path, "key %v points to an object reachable only from map keys; unsupported by the checker", unRO(it.Key()))
			continue
		}
		vs := bEntries[k]
		if len(vs) == 0 {
			c.errorf(path, "key %v missing", unRO(it.Key()))
			continue
		}
		bEntries[k] = vs[1:]
		c.visit(fmt.Sprintf("%s[%v]", path, unRO(it.Key())), it.Value(), vs[0])
	}
	return true
}

// hasPointers returns true if saved values of typ may contain pointers.
func hasPointers(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return true
	case reflect.Array:
		return hasPointers(typ.Elem())
	case reflect.Struct:
		if typ == timeType {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); savedField(f) && hasPointers(f.Type) {
				return true
			}
		}
	}
	return false
}

// fingerprint returns a string that is equal for map keys that are identical.
// If translate is non-nil, pointers are mapped through it.
func fingerprint(buf *bytes.Buffer, v reflect.Value, translate func(addrKey) uintptr) string {
	if buf == nil {
		buf = new(bytes.Buffer)
	}
	fmt.Fprintf(buf, "%v:", v.Type())
	switch v.Kind() {
	case reflect.Bool:
		fmt.Fprintf(buf, "%v", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(buf, "%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprintf(buf, "%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprintf(buf, "%x", math.Float64bits(v.Float()))
	case reflect.Complex64, reflect.Complex128:
		fmt.Fprintf(buf, "%x/%x", math.Float64bits(real(v.Complex())), math.Float64bits(imag(v.Complex())))
	case reflect.String:
		fmt.Fprintf(buf, "%q", v.String())
	case reflect.Pointer:
		p := v.Pointer()
		if translate != nil && p != 0 && v.Type().Elem().Size() != 0 {
			p = translate(addrKey{p, v.Type().Elem()})
		}
		fmt.Fprintf(buf, "%#x", p)
	case reflect.Interface:
		if v.IsNil() {
			buf.WriteString("nil")
		} else {
			fingerprint(buf, v.Elem(), translate)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fingerprint(buf, v.Index(i), translate)
			buf.WriteByte(',')
		}
	case reflect.Struct:
		if v.Type() == timeType {
			tv := unRO(v).Interface().(time.Time)
			_, off := tv.Zone()
			fmt.Fprintf(buf, "%d/%d", tv.UnixNano(), off)
			break
		}
		for i := 0; i < v.NumField(); i++ {
			if !savedField(v.Type().Field(i)) {
				continue
			}
			fingerprint(buf, v.Field(i), translate)
			buf.WriteByte(',')
		}
	default:
		panic(fmt.Sprintf("unsupported map key kind %v", v.Kind()))
	}
	buf.WriteByte(';')
	return buf.String()
}
