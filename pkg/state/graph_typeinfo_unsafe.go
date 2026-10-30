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
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// structKind classifies struct types.
type structKind uint8

const (
	// structUnsupported structs can't be saved.
	structUnsupported structKind = iota
	// structEmpty structs have no saved state.
	structEmpty
	// structSaverLoader structs implement SaverLoader.
	structSaverLoader
	// structBinary structs implement binaryObject and are registered with
	// registerBinary.
	structBinary
)

// typeInfo describes a Go type. It is built once per type, using reflection,
// so that values can be saved and loaded without reflection.
//
// typeInfos are immutable once published, except for slots.
type typeInfo struct {
	id           int32 // unique small integer for per-stream tables
	typ          reflect.Type
	rtype        unsafe.Pointer
	kind         reflect.Kind
	size         uintptr
	alignMask    uintptr
	elem         *typeInfo // element type of pointers, slices, arrays, and maps
	key          *typeInfo // key type of maps
	length       uintptr   // length of arrays
	direct       bool      // stored directly in interface data word
	pod          bool      // saved as raw memory representation
	inlineStruct bool      // contains inline structs with StateSave methods
	emptyIface   bool      // interface with no methods
	needsExact   bool      // contains or points to non-empty interfaces or maps
	partial      bool      // decode may leave unsaved memory untouched
	hooks        bool      // StateLoad may run non-generated code
	structKind   structKind
	methodItab   unsafe.Pointer // itab of StructType or binaryObject for *typ
	name         string
	registered   bool
	sliceType    atomic.Pointer[reflect.Type]
	// hintBytes and hintTargets record the size of the last graph with this root type.
	hintBytes, hintTargets atomic.Int32
	valSlot, ptrSlot       slotEntry
	// slots caches field types saved/loaded by SaverLoader methods, by slot.
	slots []atomic.Pointer[slotEntry]
}

// slotEntry is the cached type of a struct field slot.
type slotEntry struct {
	rtype unsafe.Pointer
	ti    *typeInfo
	ptr   bool
}

const itabTypeOffset = unsafe.Sizeof(unsafe.Pointer(nil)) // +checkoffset internal/abi ITab.Type

// itabType returns the concrete runtime type descriptor in a non-nil itab.
func itabType(itab unsafe.Pointer) unsafe.Pointer {
	return *(*unsafe.Pointer)(add(itab, itabTypeOffset))
}

var (
	typeInfosMu   sync.RWMutex
	typeInfos     map[unsafe.Pointer]*typeInfo // +checklocks:typeInfosMu
	typeInfoCount int32                        // +checklocks:typeInfosMu
	typeInfoSlab  []typeInfo                   // +checklocks:typeInfosMu
	slotsSlab     []atomic.Pointer[slotEntry]  // +checklocks:typeInfosMu
)

// typeInfoSlabSize is the number of typeInfos per allocation.
const typeInfoSlabSize = 64

// findTypeInfo returns the typeInfo for a runtime type descriptor, or nil.
func findTypeInfo(rt unsafe.Pointer) *typeInfo {
	typeInfosMu.RLock()
	ti := typeInfos[rt]
	typeInfosMu.RUnlock()
	return ti
}

// typeInfoForRtype returns the typeInfo for a runtime type descriptor.
func typeInfoForRtype(rt unsafe.Pointer) *typeInfo {
	if rt == nil {
		Failf("nil type")
	}
	if ti := findTypeInfo(rt); ti != nil {
		return ti
	}
	return buildTypeInfo(typeOfRtype(rt))
}

// typeInfoOf returns the typeInfo for t.
func typeInfoOf(t reflect.Type) *typeInfo {
	if t == nil {
		Failf("nil type")
	}
	if ti := findTypeInfo(rtypeOf(t)); ti != nil {
		return ti
	}
	return buildTypeInfo(t)
}

// newSlots returns n slot cache entries.
//
// +checklocks:typeInfosMu
func newSlots(n int) []atomic.Pointer[slotEntry] {
	if n > typeInfoSlabSize {
		return make([]atomic.Pointer[slotEntry], n)
	}
	if len(slotsSlab) < n {
		slotsSlab = make([]atomic.Pointer[slotEntry], 4*typeInfoSlabSize)
	}
	slots := slotsSlab[:n:n]
	slotsSlab = slotsSlab[n:]
	return slots
}

// sliceTypeOf returns the type of slices of st.
func (st *typeInfo) sliceTypeOf() reflect.Type {
	if t := st.sliceType.Load(); t != nil {
		return *t
	}
	t := reflect.SliceOf(st.typ)
	st.sliceType.Store(&t)
	return t
}

// typeInfoBuilder builds typeInfos, which are published once complete.
//
// Preconditions: typeInfosMu is locked.
type typeInfoBuilder struct {
	// pending are the typeInfos being built.
	pending []*typeInfo
}

func buildTypeInfo(t reflect.Type) *typeInfo {
	typeInfosMu.Lock()
	defer typeInfosMu.Unlock()
	// Stack-allocate space for the common case (a type and its immediate
	// element/key types); deeply nested types or structs with many plain
	// composite fields may spill to the heap.
	var pending [8]*typeInfo
	b := typeInfoBuilder{pending: pending[:0]}
	ti := b.get(t)
	if len(b.pending) > 1 {
		for {
			changed := false
			for _, p := range b.pending {
				if !p.needsExact && (p.kind == reflect.Pointer || p.kind == reflect.Slice || p.kind == reflect.Array) && p.elem.needsExact {
					p.needsExact = true
					changed = true
				}
			}
			if !changed {
				break
			}
		}
	}
	if typeInfos == nil {
		typeInfos = make(map[unsafe.Pointer]*typeInfo)
	}
	for _, p := range b.pending {
		typeInfos[p.rtype] = p
	}
	return ti
}

// isDirect returns true if values of t are stored directly in interfaces.
func isDirect(t reflect.Type) bool {
	if t.Kind() == reflect.Interface || t.Size() != unsafe.Sizeof(uintptr(0)) {
		// Only pointer-shaped values are direct. This avoids allocating
		// large values below.
		return false
	}
	v := reflect.Zero(t).Interface()
	// Values stored indirectly are pointed to by a non-nil data word, even
	// for zero values. The data word holds zero values of direct types.
	return efaceOf(&v).data == nil
}

// +checklocks:typeInfosMu
func (b *typeInfoBuilder) get(t reflect.Type) *typeInfo {
	rtype := rtypeOf(t)
	if ti := typeInfos[rtype]; ti != nil {
		return ti
	}
	for _, ti := range b.pending {
		if ti.rtype == rtype {
			return ti
		}
	}
	if len(typeInfoSlab) == 0 {
		typeInfoSlab = make([]typeInfo, typeInfoSlabSize)
	}
	ti := &typeInfoSlab[0]
	typeInfoSlab = typeInfoSlab[1:]
	ti.id = typeInfoCount
	ti.typ = t
	ti.rtype = rtype
	ti.kind = t.Kind()
	ti.size = t.Size()
	ti.alignMask = uintptr(t.Align() - 1)
	ti.valSlot = slotEntry{rtype: rtype, ti: ti}
	typeInfoCount++
	b.pending = append(b.pending, ti)
	ti.direct = isDirect(t)
	// Only defined types and structs (with embedded fields) have methods.
	// The itabs of StructType for registered structs, and of Type for other
	// registered types, are static (see RegisterStruct), so these type
	// assertions do not build itabs.
	var (
		pt     reflect.Type
		st     StructType
		isType bool
	)
	if ti.kind == reflect.Struct {
		pt = reflect.PointerTo(t)
		st, _ = reflect.Zero(pt).Interface().(StructType)
	}
	if st != nil {
		ti.name = st.StateTypeName()
		isType = true
	} else if t.Name() != "" || ti.kind == reflect.Struct {
		pt = reflect.PointerTo(t)
		if tt, ok := reflect.Zero(pt).Interface().(Type); ok {
			ti.name = tt.StateTypeName()
			isType = true
		}
	}
	if info, ok := binaryTypes[t]; ok {
		ti.name = info
	}
	rt := globalTypeDatabase[ti.name]
	ti.registered = ti.name != "" && rt == t
	switch ti.kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		ti.pod = true
	case reflect.Pointer:
		ti.elem = b.get(t.Elem())
		ti.needsExact = ti.elem.needsExact
		ti.ptrSlot = slotEntry{rtype: rtype, ti: ti.elem, ptr: true}
	case reflect.Slice:
		ti.elem = b.get(t.Elem())
		ti.needsExact = ti.elem.needsExact
	case reflect.Array:
		ti.elem = b.get(t.Elem())
		ti.length = uintptr(t.Len())
		ti.pod = ti.elem.pod
		ti.inlineStruct = ti.length > 0 && ti.elem.inlineStruct
		ti.needsExact = ti.elem.needsExact
		ti.partial = ti.elem.partial
	case reflect.Map:
		ti.needsExact = true
		ti.key = b.get(t.Key())
		ti.elem = b.get(t.Elem())
	case reflect.Interface:
		ti.emptyIface = t.NumMethod() == 0
		ti.needsExact = !ti.emptyIface
	case reflect.Struct:
		switch {
		case st != nil:
			ti.structKind = structSaverLoader
			ti.inlineStruct = true
			ti.methodItab = (*iface)(unsafe.Pointer(&st)).tab
			fields := st.StateFields()
			if !eagerTypeInfo {
				// Register did not validate the type.
				validateTypeInfo(wire.Type{Name: ti.name, Fields: fields})
			}
			ti.slots = newSlots(len(fields))
			ti.hooks = !ti.registered || !isNoHooks(t)
			if !ti.hooks && b.plainFields(t) {
				// The StateSave and StateLoad methods only save and load
				// the fields, which are all plain data.
				ti.pod = true
				ti.inlineStruct = false
			}
		case binaryTypes[t] != "":
			ti.structKind = structBinary
			bo := reflect.Zero(pt).Interface().(binaryObject)
			ti.methodItab = (*iface)(unsafe.Pointer(&bo)).tab
		case t.NumField() == 0 || isType:
			// Unregistered empty structs, and structs that implement only
			// Type, have no saved state.
			ti.structKind = structEmpty
			ti.pod = t.Size() == 0 && b.plainFields(t)
		}
		ti.partial = !ti.pod
	case reflect.Bool, reflect.String:
		// Non-pod scalar types.
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		// Unsupported types; encodeValue and decodeValue fail if
		// values of these kinds are saved or loaded directly.
	default:
		Failf("unexpected reflect.Kind: %v (%v)", ti.kind, t)
	}
	return ti
}

// plainFields returns true if all fields of the struct t are saved plain data
// with no padding, so that the memory representation of t can be saved.
//
// +checklocks:typeInfosMu
func (b *typeInfoBuilder) plainFields(t reflect.Type) bool {
	var off uintptr
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Offset != off {
			return false
		}
		if f.Name == "_" {
			if f.Type.Size() != 0 {
				return false
			}
			continue
		}
		tag := f.Tag.Get("state")
		if tag != "" && tag != "wait" {
			return false
		}
		if f.Type.Kind() == reflect.Struct && f.Type.Name() == "" && tag == "" {
			if !b.plainFields(f.Type) {
				return false
			}
			off += f.Type.Size()
			continue
		}
		switch f.Type.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
			reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		case reflect.Array, reflect.Struct:
			if !b.get(f.Type).pod {
				return false
			}
		default:
			return false
		}
		off += f.Type.Size()
	}
	return off == t.Size()
}

// slotType returns the type of the field in the given slot of st, given the
// runtime type passed to a Sink or Source method. If ptr is true, rt is a
// pointer to the field.
func (st *typeInfo) slotType(slot int, rt unsafe.Pointer, ptr bool) *typeInfo {
	if uint(slot) < uint(len(st.slots)) {
		if e := st.slots[slot].Load(); e != nil && e.rtype == rt && e.ptr == ptr {
			return e.ti
		}
	}
	if rt == nil {
		Failf("nil value saved in slot %d of %v", slot, st.typ)
	}
	ti := typeInfoForRtype(rt)
	e := &ti.valSlot
	if ptr {
		if ti.kind != reflect.Pointer {
			Failf("non-pointer %v passed for slot %d of %v", ti.typ, slot, st.typ)
		}
		e = &ti.ptrSlot
	}
	if uint(slot) < uint(len(st.slots)) {
		st.slots[slot].Store(e)
	}
	return e.ti
}

// makeAny returns an interface holding the value of type ti at p.
//
// Preconditions: The value at p must not be modified while the returned
// interface is in use, unless ti is direct.
func makeAny(ti *typeInfo, p unsafe.Pointer) any {
	if ti.kind == reflect.Interface {
		if ti.emptyIface {
			return *(*any)(p)
		}
		it := (*iface)(p)
		if it.tab == nil {
			return nil
		}
		var v any
		*efaceOf(&v) = eface{typ: itabType(it.tab), data: it.data}
		return v
	}
	var v any
	e := efaceOf(&v)
	e.typ = ti.rtype
	if ti.direct {
		e.data = *(*unsafe.Pointer)(p)
	} else {
		e.data = p
	}
	return v
}
