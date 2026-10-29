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
	"fmt"
	"reflect"
	"sync/atomic"
	"unsafe"
)

// typeCacheSize is the number of entries in direct-mapped per-stream caches.
// A power of two compiles modulo indexing to a bitmask; 256 covers the active
// dynamic interface types in a Sentry checkpoint (typed struct fields use
// per-slot caches instead) while keeping typeCache (4 KiB) and itabCache
// (6 KiB) small enough to fit in L1 cache and zero cheaply per stream.
const typeCacheSize = 256

type typeCacheEntry struct {
	key unsafe.Pointer
	ti  *typeInfo
}

// typeCache caches typeInfos for runtime type descriptors and itabs.
type typeCache [typeCacheSize]typeCacheEntry

func (c *typeCache) entry(key unsafe.Pointer) *typeCacheEntry {
	h := uintptr(key) >> 3
	h ^= h >> 8
	return &c[h%typeCacheSize]
}

func (c *typeCache) rtype(rt unsafe.Pointer) *typeInfo {
	e := c.entry(rt)
	if e.key != rt {
		e.key, e.ti = rt, typeInfoForRtype(rt)
	}
	return e.ti
}

// itab returns the dynamic type of the non-nil, non-empty interface at p.
func (c *typeCache) itab(p unsafe.Pointer) *typeInfo {
	tab := (*iface)(p).tab
	e := c.entry(tab)
	if e.key != tab {
		e.key, e.ti = tab, typeInfoForRtype(itabType(tab))
	}
	return e.ti
}

// itabCache caches itabs by interface and dynamic type.
type itabCache [typeCacheSize]struct {
	iface, dyn *typeInfo
	tab        unsafe.Pointer
}

func (c *itabCache) get(ifaceType, dyn *typeInfo) unsafe.Pointer {
	e := &c[uint32(ifaceType.id*31+dyn.id)%typeCacheSize]
	if e.iface != ifaceType || e.dyn != dyn {
		e.iface, e.dyn, e.tab = ifaceType, dyn, itabFor(ifaceType, dyn)
	}
	return e.tab
}

type itabKey struct {
	iface, dyn *typeInfo
}

var itabs map[itabKey]unsafe.Pointer // +checklocks:typeInfosMu

// itabFor returns the itab for values of type dyn in interfaces of type
// ifaceType.
func itabFor(ifaceType, dyn *typeInfo) unsafe.Pointer {
	k := itabKey{ifaceType, dyn}
	typeInfosMu.RLock()
	tab, ok := itabs[k]
	typeInfosMu.RUnlock()
	if ok {
		return tab
	}
	// Set panics if dyn does not implement the interface.
	v := reflect.New(ifaceType.typ).Elem()
	v.Set(reflect.Zero(dyn.typ))
	tab = (*iface)(v.Addr().UnsafePointer()).tab
	typeInfosMu.Lock()
	if itabs == nil {
		itabs = make(map[itabKey]unsafe.Pointer)
	}
	itabs[k] = tab
	typeInfosMu.Unlock()
	return tab
}

// builtinTypes are the predeclared types, by kind.
var builtinTypes = [...]reflect.Type{
	reflect.Bool:       reflect.TypeFor[bool](),
	reflect.Int:        reflect.TypeFor[int](),
	reflect.Int8:       reflect.TypeFor[int8](),
	reflect.Int16:      reflect.TypeFor[int16](),
	reflect.Int32:      reflect.TypeFor[int32](),
	reflect.Int64:      reflect.TypeFor[int64](),
	reflect.Uint:       reflect.TypeFor[uint](),
	reflect.Uint8:      reflect.TypeFor[uint8](),
	reflect.Uint16:     reflect.TypeFor[uint16](),
	reflect.Uint32:     reflect.TypeFor[uint32](),
	reflect.Uint64:     reflect.TypeFor[uint64](),
	reflect.Uintptr:    reflect.TypeFor[uintptr](),
	reflect.Float32:    reflect.TypeFor[float32](),
	reflect.Float64:    reflect.TypeFor[float64](),
	reflect.Complex64:  reflect.TypeFor[complex64](),
	reflect.Complex128: reflect.TypeFor[complex128](),
	reflect.String:     reflect.TypeFor[string](),
}

var (
	anyType         = reflect.TypeFor[any]()
	emptyStructType = reflect.TypeFor[struct{}]()
)

// fingerprint is the cached schemaFingerprint, or zero.
var fingerprint atomic.Uint64

// Inline 64-bit FNV-1a constants. Inline helpers hash length-prefixed strings
// and uint64s directly in registers without hash.Hash64 interface dispatch,
// string-to-[]byte conversions, or scratch slice allocations.
const (
	fnvOffset = 14695981039346656037
	fnvPrime  = 1099511628211
)

func hashStr(h uint64, s string) uint64 {
	h = (h ^ uint64(len(s))) * fnvPrime
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * fnvPrime
	}
	return h
}

func hashUint(h, v uint64) uint64 {
	h = (h ^ v) * fnvPrime
	return (h ^ (v >> 32)) * fnvPrime
}

// schemaFingerprint returns a hash of the schemas of all registered types.
// Streams can only be loaded by binaries with the same fingerprint.
func schemaFingerprint() uint64 {
	if f := fingerprint.Load(); f != 0 {
		return f
	}
	var f uint64
	for name, t := range globalTypeDatabase {
		h := hashStr(fnvOffset, name)
		var flags byte
		if noHooksTypes[t] {
			flags |= 1
		}
		if binaryTypes[t] != "" {
			flags |= 2
		}
		f += hashTypeSig(hashUint(h, uint64(flags)), t, 0) // Order-independent across map entries.
	}
	f |= 1 // Never zero.
	fingerprint.Store(f)
	return f
}

func hashTypeSig(h uint64, t reflect.Type, depth int) uint64 {
	h = hashUint(h, uint64(t.Kind()))
	h = hashUint(h, uint64(t.Size()))
	h = hashStr(h, t.PkgPath())
	h = hashStr(h, t.Name())
	if depth >= 4 {
		return h
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice:
		return hashTypeSig(h, t.Elem(), depth+1)
	case reflect.Array:
		return hashTypeSig(hashUint(h, uint64(t.Len())), t.Elem(), depth+1)
	case reflect.Map:
		return hashTypeSig(hashTypeSig(h, t.Key(), depth+1), t.Elem(), depth+1)
	case reflect.Struct:
		if depth > 0 && t.Name() != "" {
			return h
		}
		n := t.NumField()
		h = hashUint(h, uint64(n))
		for i := 0; i < n; i++ {
			f := t.Field(i)
			h = hashStr(h, f.Name)
			h = hashUint(h, uint64(f.Offset))
			h = hashStr(h, string(f.Tag))
			h = hashTypeSig(h, f.Type, depth+1)
		}
		return h
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.String, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return h
	default:
		panic(fmt.Sprintf("unexpected reflect.Kind: %v (%v)", t.Kind(), t))
	}
}

// typeTable assigns stream indices to types.
type typeTable struct {
	// exact and shape map typeInfo ids to indices plus one.
	exact, shape []int32
	types        []*typeInfo
	buf          encBuf
}

// Type descriptor tags.
const (
	typeNamed = iota
	typeBuiltin
	typePointer
	typeSlice
	typeArray
	typeMap
	typeAny
	typeEmptyStruct
)

// reset clears the table.
func (tt *typeTable) reset() {
	clear(tt.exact)
	clear(tt.shape)
	clear(tt.types)
	tt.types = tt.types[:0]
	tt.buf.b = tt.buf.b[:0]
}

func lookupIndex(m []int32, ti *typeInfo) (int, bool) {
	if int(ti.id) < len(m) {
		if v := m[ti.id]; v != 0 {
			return int(v - 1), true
		}
	}
	return 0, false
}

// Object kinds in the object table.
const (
	objKindValue = iota
	objKindArray
	objKindMap

	// objInexact is set on the kinds of objects whose types are described
	// only by their layout.
	objInexact = 0x80
)

func setIndex(m *[]int32, ti *typeInfo, idx int) {
	if int(ti.id) >= len(*m) {
		grown := make([]int32, max(2*len(*m), int(ti.id)+256))
		copy(grown, *m)
		*m = grown
	}
	(*m)[ti.id] = int32(idx + 1)
}

// exactIndex returns the index of a type, which the decoder must be able to
// identify: named types must be registered.
func (tt *typeTable) exactIndex(ti *typeInfo) int {
	if idx, ok := lookupIndex(tt.exact, ti); ok {
		return idx
	}
	return tt.add(ti, true)
}

// shapeIndex returns the index of a type with the same memory layout as ti.
func (tt *typeTable) shapeIndex(ti *typeInfo) int {
	if idx, ok := lookupIndex(tt.shape, ti); ok {
		return idx
	}
	return tt.add(ti, false)
}

// add appends a wire descriptor for ti to tt.buf, recursively adding any
// unrecorded element or key types first so their indices precede ti's, and
// records and returns ti's new index in tt.types. If exact is true, ti must be
// reconstructible with its exact Go type on decode rather than only a
// layout-compatible shape.
func (tt *typeTable) add(ti *typeInfo, exact bool) int {
	// Descriptors of composite types refer to the descriptors of their
	// elements, which must come first.
	registered := ti.registered
	var key, elem int
	if !registered {
		switch ti.kind {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			elem = tt.index(ti.elem, exact)
		case reflect.Map:
			key = tt.index(ti.key, exact)
			elem = tt.index(ti.elem, exact)
		}
	}
	b := &tt.buf
	switch {
	case registered:
		b.byte(typeNamed)
		b.string(ti.name)
	case int(ti.kind) < len(builtinTypes) && builtinTypes[ti.kind] != nil:
		if exact && ti.typ != builtinTypes[ti.kind] {
			Failf("type %q is not known", ti.typ)
		}
		b.byte(typeBuiltin)
		b.byte(byte(ti.kind))
	case exact && ti.typ.Name() != "":
		Failf("type %q is not registered", ti.typ)
	case ti.kind == reflect.Pointer:
		b.byte(typePointer)
		b.uvarint(uint64(elem))
	case ti.kind == reflect.Slice:
		b.byte(typeSlice)
		b.uvarint(uint64(elem))
	case ti.kind == reflect.Array:
		b.byte(typeArray)
		b.uvarint(uint64(ti.length))
		b.uvarint(uint64(elem))
	case ti.kind == reflect.Map:
		b.byte(typeMap)
		b.uvarint(uint64(key))
		b.uvarint(uint64(elem))
	case ti.kind == reflect.Interface && (!exact || ti.typ == anyType):
		b.byte(typeAny)
	case ti.kind == reflect.Struct && ti.typ.NumField() == 0 && (!exact || ti.typ == emptyStructType):
		b.byte(typeEmptyStruct)
	default:
		Failf("type %q is not known", ti.typ)
	}
	idx := len(tt.types)
	tt.types = append(tt.types, ti)
	if exact || registered {
		setIndex(&tt.exact, ti, idx)
	}
	setIndex(&tt.shape, ti, idx)
	return idx
}

// canExact returns true if ti can be described exactly.
func (tt *typeTable) canExact(ti *typeInfo, depth int) bool {
	if depth > 32 {
		return false
	}
	switch {
	case ti.name != "":
		return ti.registered
	case int(ti.kind) < len(builtinTypes) && builtinTypes[ti.kind] != nil:
		return ti.typ == builtinTypes[ti.kind]
	case ti.typ.Name() != "":
		// Other named types must be registered.
		return false
	case ti.kind == reflect.Pointer, ti.kind == reflect.Slice, ti.kind == reflect.Array:
		return tt.canExact(ti.elem, depth+1)
	case ti.kind == reflect.Map:
		return tt.canExact(ti.key, depth+1) && tt.canExact(ti.elem, depth+1)
	case ti.kind == reflect.Interface:
		return ti.typ == anyType
	case ti.kind == reflect.Struct:
		return ti.typ == emptyStructType
	}
	return false
}

// isInexact returns true if objects of type ti are described inexactly, and
// must be decoded with their exact type.
func (tt *typeTable) isInexact(ti *typeInfo) bool {
	return ti.needsExact && !tt.canExact(ti, 0)
}

// objectIndex returns the index of the type of an object, and objInexact if
// the decoder must learn its exact type from references.
func (tt *typeTable) objectIndex(ti *typeInfo) (int, byte) {
	if tt.isInexact(ti) {
		return tt.shapeIndex(ti), objInexact
	}
	if ti.needsExact {
		return tt.exactIndex(ti), 0
	}
	return tt.shapeIndex(ti), 0
}

// rootIndex returns the type table index of a root value.
func (tt *typeTable) rootIndex(ti *typeInfo) int {
	if !ti.registered && ti.structKind == structSaverLoader {
		tt.buf.byte(typeNamed)
		tt.buf.string(ti.name)
		idx := len(tt.types)
		tt.types = append(tt.types, ti)
		return idx
	}
	idx, _ := tt.objectIndex(ti)
	return idx
}

func (tt *typeTable) index(ti *typeInfo, exact bool) int {
	if exact {
		return tt.exactIndex(ti)
	}
	return tt.shapeIndex(ti)
}
