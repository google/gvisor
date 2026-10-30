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
	"encoding/binary"
	"reflect"
	"unsafe"
)

// decodeValue decodes a value of type ti to p.
func (ds *graphDecodeState) decodeValue(ti *typeInfo, p unsafe.Pointer) {
	d := &ds.in
	switch ti.kind {
	case reflect.Bool:
		v := d.byte()
		if v > 1 {
			Failf("invalid bool %d", v)
		}
		if v != 0 || !ds.keepZero {
			*(*bool)(p) = v != 0
		}
	case reflect.Int8, reflect.Uint8:
		if v := d.byte(); v != 0 || !ds.keepZero {
			*(*uint8)(p) = v
		}
	case reflect.Int:
		v := d.varint()
		if int64(int(v)) != v {
			Failf("signed integer %d overflows int", v)
		}
		if v != 0 || !ds.keepZero {
			*(*int)(p) = int(v)
		}
	case reflect.Int16:
		v := d.varint()
		if int64(int16(v)) != v {
			Failf("signed integer %d overflows int16", v)
		}
		if v != 0 || !ds.keepZero {
			*(*int16)(p) = int16(v)
		}
	case reflect.Int32:
		v := d.varint()
		if int64(int32(v)) != v {
			Failf("signed integer %d overflows int32", v)
		}
		if v != 0 || !ds.keepZero {
			*(*int32)(p) = int32(v)
		}
	case reflect.Int64:
		if v := d.varint(); v != 0 || !ds.keepZero {
			*(*int64)(p) = v
		}
	case reflect.Uint:
		v := d.uvarint()
		if uint64(uint(v)) != v {
			Failf("unsigned integer %d overflows uint", v)
		}
		if v != 0 || !ds.keepZero {
			*(*uint)(p) = uint(v)
		}
	case reflect.Uintptr:
		v := d.uvarint()
		if uint64(uintptr(v)) != v {
			Failf("unsigned integer %d overflows uintptr", v)
		}
		if v != 0 || !ds.keepZero {
			*(*uintptr)(p) = uintptr(v)
		}
	case reflect.Uint16:
		v := d.uvarint()
		if uint64(uint16(v)) != v {
			Failf("unsigned integer %d overflows uint16", v)
		}
		if v != 0 || !ds.keepZero {
			*(*uint16)(p) = uint16(v)
		}
	case reflect.Uint32:
		v := d.uvarint()
		if uint64(uint32(v)) != v {
			Failf("unsigned integer %d overflows uint32", v)
		}
		if v != 0 || !ds.keepZero {
			*(*uint32)(p) = uint32(v)
		}
	case reflect.Uint64:
		if v := d.uvarint(); v != 0 || !ds.keepZero {
			*(*uint64)(p) = v
		}
	case reflect.Float32:
		if v := d.uint32(); v != 0 || !ds.keepZero {
			*(*uint32)(p) = v
		}
	case reflect.Float64:
		if v := d.uint64(); v != 0 || !ds.keepZero {
			*(*uint64)(p) = v
		}
	case reflect.Complex64, reflect.Complex128:
		b := d.next(int(ti.size))
		if !ds.keepZero || !isZero(b) {
			copy(unsafe.Slice((*byte)(p), ti.size), b)
		}
	case reflect.String:
		if n := d.byteLength(); n != 0 {
			*(*string)(p) = ds.makeString(d.next(n))
		} else if !ds.keepZero {
			*(*string)(p) = ""
		}
	case reflect.Pointer:
		v := d.uvarint()
		if v == 0 {
			if !ds.keepZero {
				*(*unsafe.Pointer)(p) = nil
			}
			return
		}
		*(*unsafe.Pointer)(p) = ds.ptrRef(ti, v)
	case reflect.Slice:
		ds.decodeSlice(ti, (*sliceHeader)(p))
	case reflect.Array:
		ds.decodeArray(ti, p)
	case reflect.Map:
		v := d.uvarint()
		if v == 0 {
			if !ds.keepZero {
				*(*unsafe.Pointer)(p) = nil
			}
			return
		}
		*(*unsafe.Pointer)(p) = ds.mapRef(ti, v)
	case reflect.Interface:
		ds.decodeInterface(ti, p)
	case reflect.Struct:
		if ti.pod {
			if ds.keepZero {
				decodePodKeepZero(ti.typ, p, d.next(int(ti.size)))
			} else {
				d.raw(p, ti.size)
			}
			return
		}
		ds.decodeStruct(ti, p)
		ds.lastRef = -1
	default:
		Failf("unsupported type %v", ti.typ)
	}
}

func decodePodKeepZero(t reflect.Type, p unsafe.Pointer, b []byte) {
	switch t.Kind() {
	case reflect.Struct:
		if isZero(b) {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			if f := t.Field(i); f.Name != "_" && f.Type.Size() != 0 {
				decodePodKeepZero(f.Type, add(p, f.Offset), b[f.Offset:f.Offset+f.Type.Size()])
			}
		}
	case reflect.Array:
		if isZero(b) {
			return
		}
		if esz := t.Elem().Size(); esz != 0 {
			for i := 0; i < t.Len(); i++ {
				decodePodKeepZero(t.Elem(), add(p, uintptr(i)*esz), b[uintptr(i)*esz:uintptr(i+1)*esz])
			}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		if !isZero(b) {
			copy(unsafe.Slice((*byte)(p), len(b)), b)
		}
	default:
		Failf("unexpected non-pod reflect.Kind: %v (%v)", t.Kind(), t)
	}
}

func (ds *graphDecodeState) hasShape(root, target *typeInfo, off, count uintptr) bool {
	// Distinct odd prime multipliers spread small sequential typeInfo IDs across
	// the direct-mapped shapeCache slots (for example, distinguishing
	// (root, target) from (target, root)); collisions only cause cache misses,
	// as full traversalKey equality is checked below.
	const (
		rootIDPrime   = 31
		targetIDPrime = 17
	)
	k := traversalKey{root, target, off, count}
	idx := (uint64(root.id)*rootIDPrime + uint64(target.id)*targetIDPrime + uint64(off)) % uint64(len(ds.shapeCache))
	e := &ds.shapeCache[idx]
	if *e == k {
		return true
	}
	if !containsType(root, target, off, count, compatibleShape) {
		return false
	}
	*e = k
	return true
}

func (ds *graphDecodeState) checkTarget(o *decObject, off uintptr, elem *typeInfo, count uintptr) {
	if o.kind == objKindValue {
		if !ds.hasShape(o.ti, elem, off, count) {
			Failf("target %v at offset %d is incompatible with %v", elem.typ, off, o.ti.typ)
		}
		return
	}
	esz := o.ti.size
	if o.ti == elem && off%esz == 0 {
		return
	}
	rElem, rLen := leafArray(o.ti, o.size/esz)
	tElem, tCount := leafArray(elem, count)
	if off%rElem.size == 0 && compatibleShape(rElem, tElem) && off/rElem.size+tCount <= rLen {
		return
	}
	if off/esz >= o.size/esz || !ds.hasShape(o.ti, elem, off%esz, count) {
		Failf("target %v at offset %d is incompatible with array of %v", elem.typ, off, o.ti.typ)
	}
}

func (ds *graphDecodeState) ptrRef(ti *typeInfo, v uint64) unsafe.Pointer {
	t, obj := ds.target(v)
	elem := ti.elem
	if obj < 0 {
		if elem.size != 0 {
			Failf("zero-sized target for %v", ti.typ)
		}
		return t
	}
	if t == nil {
		Failf("pointer %v to map", ti.typ)
	}
	o := &ds.objs[obj]
	if t != o.base || o.kind != objKindValue || o.ti != elem {
		off := uintptr(t) - uintptr(o.base)
		if elem.size > o.size-off || uintptr(t)&elem.alignMask != 0 {
			Failf("invalid pointer %v at offset %d in %v", ti.typ, off, o.ti.typ)
		}
		ds.checkTarget(o, off, elem, 1)
	}
	ds.lastRef, ds.refs = obj, ds.refs+1
	if o.inexact {
		ds.noteRef(obj, t, elem)
	}
	return t
}

func isZero(b []byte) bool {
	// Width-matched loads avoid loop overhead on scalar pod leaves (1..16
	// bytes); the 8-byte loop handles composite pod slices.
	// binary.LittleEndian loads compile to single instructions on
	// unaligned-capable architectures while remaining valid under checkptr
	// when b starts at an unaligned offset in the input stream.
	switch len(b) {
	case 1:
		return b[0] == 0
	case 2:
		return binary.LittleEndian.Uint16(b) == 0
	case 4:
		return binary.LittleEndian.Uint32(b) == 0
	case 8:
		return binary.LittleEndian.Uint64(b) == 0
	case 16:
		return (binary.LittleEndian.Uint64(b) | binary.LittleEndian.Uint64(b[8:])) == 0
	}
	for len(b) >= 8 {
		if binary.LittleEndian.Uint64(b) != 0 {
			return false
		}
		b = b[8:]
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// makeString returns a string with the contents of b.
func (ds *graphDecodeState) makeString(b []byte) string {
	// Bump-allocate small strings out of 16 KiB (two 8 KiB Go runtime pages)
	// byte slabs to amortize per-string heap allocations across typical
	// checkpoint strings (paths, names, env vars). Strings larger than a quarter
	// of a slab (4 KiB) allocate directly so a single large string neither
	// wastes >25% of the remaining slab nor pins a 16 KiB slab alive.
	const chunkSize = 16 << 10
	if len(b) > chunkSize/4 {
		return string(b)
	}
	if len(ds.strings) < len(b) {
		ds.strings = make([]byte, chunkSize)
	}
	s := ds.strings[:len(b):len(b)]
	ds.strings = ds.strings[len(b):]
	copy(s, b)
	return unsafe.String(unsafe.SliceData(s), len(s))
}

// mapRef returns the map with the given target index plus one, allocating it
// if needed.
func (ds *graphDecodeState) mapRef(ti *typeInfo, v uint64) unsafe.Pointer {
	_, obj := ds.target(v)
	if obj < 0 || ds.objs[obj].kind != objKindMap {
		Failf("map %v is not a map object", ti.typ)
	}
	o := &ds.objs[obj]
	if o.mapType == nil {
		o.mapType = ti
		// Limit the size hint of invalid streams by their length.
		hint := min(int(o.size), len(ds.in.b))
		o.base = reflect.MakeMapWithSize(ti.typ, hint).UnsafePointer()
	} else if o.mapType != ti && (o.mapType.key != ti.key || o.mapType.elem != ti.elem) {
		Failf("map is both %v and %v", o.mapType.typ, ti.typ)
	}
	ds.lastRef, ds.refs = obj, ds.refs+1
	return o.base
}

func (ds *graphDecodeState) decodeSlice(ti *typeInfo, h *sliceHeader) {
	d := &ds.in
	v := d.uvarint()
	if v == 0 {
		if !ds.keepZero {
			*h = sliceHeader{}
		}
		return
	}
	length := v - 1
	capacity := length + d.uvarint()
	if capacity < length || capacity > 1<<40 {
		Failf("invalid slice capacity %d", capacity)
	}
	esz := ti.elem.size
	if esz == 0 {
		z := zeroSizedPtr()
		*h = sliceHeader{data: z, len: int(length), cap: int(capacity)}
		if !ti.elem.pod && length > 0 {
			keepZero := ds.keepZero
			ds.keepZero = false
			ds.decodeElems(ti.elem, z, uintptr(length))
			ds.keepZero = keepZero
		}
		return
	}
	if capacity == 0 {
		*h = sliceHeader{data: zeroSizedPtr(), len: int(length), cap: 0}
		return
	}
	t, obj := ds.target(d.uvarint() + 1)
	if obj < 0 || t == nil {
		Failf("invalid slice target")
	}
	o := &ds.objs[obj]
	if t != o.base || o.kind != objKindArray || o.ti != ti.elem || esz >= 1<<20 || capacity*uint64(esz) > uint64(o.size) {
		off := uintptr(t) - uintptr(o.base)
		if capacity > uint64((o.size-off)/esz) || uintptr(t)&ti.elem.alignMask != 0 {
			Failf("slice of %d %v exceeds object", capacity, ti.elem.typ)
		}
		ds.checkTarget(o, off, ti.elem, uintptr(capacity))
	}
	*h = sliceHeader{data: t, len: int(length), cap: int(capacity)}
	ds.lastRef, ds.refs = obj, ds.refs+1
	if o.inexact {
		ds.noteRef(obj, t, ti.elem)
	}
}

// decodeArray decodes an array value.
func (ds *graphDecodeState) decodeArray(ti *typeInfo, p unsafe.Pointer) {
	if ti.elem.pod && ds.keepZero {
		decodePodKeepZero(ti.typ, p, ds.in.next(int(ti.size)))
		return
	}
	ds.decodeElems(ti.elem, p, ti.length)
}

// decodeElems decodes n elements of type elem to p. The current object waits
// for the objects referred to by the elements.
func (ds *graphDecodeState) decodeElems(elem *typeInfo, p unsafe.Pointer, n uintptr) {
	if elem.pod {
		ds.in.raw(p, elem.size*n)
		return
	}
	esz := elem.size
	for i := uintptr(0); i < n; i++ {
		ds.lastRef = -1
		ds.decodeValue(elem, add(p, i*esz))
		if ds.lastRef >= 0 {
			ds.wait(ds.cur, ds.lastRef, decodeCallback{waiter: -1})
		}
	}
	ds.lastRef = -1
}

// decodeInterface decodes an interface value.
func (ds *graphDecodeState) decodeInterface(ti *typeInfo, p unsafe.Pointer) {
	v := ds.in.uvarint()
	if v == 0 {
		if !ds.keepZero {
			*(*iface)(p) = iface{}
		}
		return
	}
	dyn := ds.typeAt(v - 1)
	if dyn.kind == reflect.Interface {
		Failf("interface dynamic type %v is an interface", dyn.typ)
	}
	keepZero := ds.keepZero
	ds.keepZero = false
	data, deferred := ds.decodeDynamic(dyn)
	ds.keepZero = keepZero
	if ti.emptyIface {
		*(*eface)(p) = eface{typ: dyn.rtype, data: data}
		if deferred != nil {
			ds.addCallback(ds.cur, decodeCallback{fn: func() { (*eface)(p).data = *deferred }, waiter: -1})
		}
	} else {
		*(*iface)(p) = iface{tab: ds.itabCache.get(ti, dyn), data: data}
		if deferred != nil {
			ds.addCallback(ds.cur, decodeCallback{fn: func() { (*iface)(p).data = *deferred }, waiter: -1})
		}
	}
}

// decodeDynamic decodes a value of type ti, and returns the data word of
// interfaces holding it (plus deferred word storage if decoding a direct
// non-pointer value queued callbacks).
func (ds *graphDecodeState) decodeDynamic(ti *typeInfo) (unsafe.Pointer, *unsafe.Pointer) {
	if !ti.direct {
		q := reflect.New(ti.typ).UnsafePointer()
		ds.decodeValue(ti, q)
		return q, nil
	}
	switch ti.kind {
	case reflect.Pointer:
		if v := ds.in.uvarint(); v != 0 {
			return ds.ptrRef(ti, v), nil
		}
		return nil, nil
	case reflect.Map:
		if v := ds.in.uvarint(); v != 0 {
			return ds.mapRef(ti, v), nil
		}
		return nil, nil
	default:
		deferred := ds.deferred
		w := new(unsafe.Pointer)
		ds.decodeValue(ti, unsafe.Pointer(w))
		if ds.noCallbacks || ds.deferred == deferred {
			return *w, nil
		}
		return *w, w
	}
}

func (ds *graphDecodeState) decodeStruct(ti *typeInfo, p unsafe.Pointer) {
	switch ti.structKind {
	case structSaverLoader:
		if ti.hooks {
			ds.hooks++
		}
		var sl StructType
		*(*iface)(unsafe.Pointer(&sl)) = iface{tab: ti.methodItab, data: p}
		if ds.stats.enabled {
			ds.stats.start(ti)
			defer ds.stats.done()
		}
		sl.StateLoad(ds.ctx, Source{graph: graphStructDecoder{ds: ds, st: ti}})
	case structBinary:
		ds.hooks++
		data := ds.in.next(ds.in.byteLength())
		var bo binaryObject
		*(*iface)(unsafe.Pointer(&bo)) = iface{tab: ti.methodItab, data: p}
		if err := bo.UnmarshalBinary(data); err != nil {
			Failf("decoding %s: %w", ti.name, err)
		}
	case structEmpty:
	default:
		Failf("struct %v does not implement SaverLoader", ti.typ)
	}
}

// decodeMap decodes the n entries of a map. The map waits for the objects
// referred to by its entries.
func (ds *graphDecodeState) decodeMap(ti *typeInfo, m unsafe.Pointer, n int) {
	if n == 0 {
		return
	}
	ds.mapPtr = m
	mv := reflect.NewAt(ti.typ, unsafe.Pointer(&ds.mapPtr)).Elem()
	kt, et := ti.key, ti.elem
	var (
		k, e   reflect.Value
		kp, ep unsafe.Pointer
	)
	// Callbacks and the StateLoad methods of structs with hooks may retain
	// the addresses of keys and values. Entries get fresh storage after
	// those run; other entries reuse the storage of the previous entry.
	fresh := true
	for i := 0; i < n; i++ {
		if fresh {
			k = reflect.New(kt.typ).Elem()
			e = reflect.New(et.typ).Elem()
			kp, ep = k.Addr().UnsafePointer(), e.Addr().UnsafePointer()
		} else {
			// Decoding does not write fields that are not saved.
			if kt.partial {
				k.SetZero()
			}
			if et.partial {
				e.SetZero()
			}
		}
		hooks, deferred := ds.hooks, ds.deferred
		ds.lastRef = -1
		ds.decodeValue(kt, kp)
		if ds.lastRef >= 0 {
			ds.wait(ds.cur, ds.lastRef, decodeCallback{waiter: -1})
		}
		ds.lastRef = -1
		ds.decodeValue(et, ep)
		if ds.lastRef >= 0 {
			ds.wait(ds.cur, ds.lastRef, decodeCallback{waiter: -1})
		}
		if !ds.noCallbacks && ds.deferred != deferred {
			ds.deferMapSetIndex(ti.typ, m, k, e)
		} else {
			mv.SetMapIndex(k, e)
		}
		fresh = ds.hooks != hooks
	}
	ds.lastRef = -1
}

// deferMapSetIndex inserts (k, e) into m once queued callbacks on ds.cur have
// finalized k and e.
func (ds *graphDecodeState) deferMapSetIndex(mapTyp reflect.Type, m unsafe.Pointer, k, e reflect.Value) {
	mv := reflect.NewAt(mapTyp, unsafe.Pointer(&m)).Elem()
	ds.addCallback(ds.cur, decodeCallback{
		fn:     func() { mv.SetMapIndex(k, e) },
		waiter: -1,
	})
}

// graphStructDecoder decodes the fields of a struct.
type graphStructDecoder struct {
	ds *graphDecodeState
	st *typeInfo
}
