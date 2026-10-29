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
	"context"
	"reflect"
	"slices"
	"sync"
	"unsafe"
)

// decObject is an object being decoded.
type decObject struct {
	base unsafe.Pointer
	ti   *typeInfo
	// size is the size of the object in bytes.
	size uintptr
	kind uint8
	// mapType is the type of map objects, known once they are referred to.
	mapType *typeInfo
	// inexact is true for objects whose type is only known to have the
	// layout of ti. exact is their type, once known from a reference.
	inexact bool
	exact   *typeInfo
}

// decodeCallback is a post-decode callback run once an object has been decoded
// and all objects it depends on have completed decoding (see
// graphObjectDecodeState).
type decodeCallback struct {
	// fn is a user callback.
	fn func()
	// valueFn is called with value.
	valueFn func(any)
	value   any
	// afterLoader is a generated AfterLoad callback.
	afterLoader AfterLoader
	// valueLoader is called with slot and value.
	valueLoader ValueLoader
	slot        int
	// waiter is an object that waits for the object, or -1.
	waiter int32
	// next is the next callback of the same object, or -1.
	next int32
}

// graphObjectDecodeState tracks the decoding completion of an object.
//
// After all objects' data has been decoded from the stream, an object becomes
// complete once every object it waits on (via LoadWait, LoadValue, slice/array
// elements, or map entries) is complete, at which point its own post-decode
// callbacks (such as AfterLoad) run and unblock any objects waiting on it.
type graphObjectDecodeState struct {
	blockedBy int32
	// cbHead..cbTail delimit this object's own callbacks; waitHead..waitTail
	// delimit callbacks waiting for this object to complete, or are -1.
	cbHead, cbTail     int32
	waitHead, waitTail int32
	complete           bool
}

// graphDecodeState is the state of Load.
type graphDecodeState struct {
	ctx context.Context
	in  decBuf

	types []*typeInfo
	// typeNames are the names of named types, which may not be registered.
	typeNames []string
	objs      []decObject
	ods       []graphObjectDecodeState
	cbs       []decodeCallback
	targets   []unsafe.Pointer
	// targetObjs are the objects of targets, or -1.
	targetObjs []int32

	// cur is the object being decoded.
	cur int32
	// lastRef is the object referred to by the last decoded pointer, slice,
	// map or interface, or -1.
	lastRef int32
	// keepZero is true while decoding the root object: like the zero values
	// of fields, which are not encoded, zero values do not overwrite the
	// root's existing state.
	keepZero bool

	// mapPtr holds the map being decoded.
	mapPtr unsafe.Pointer

	// noCallbacks disables user callbacks.
	noCallbacks bool

	// hooks counts the runs of code that may retain the addresses of
	// decoded values: callbacks, and the methods of structs with hooks.
	hooks uint64
	// refs counts object references resolved so far.
	refs uint64

	// leaves is the queue of objects whose callbacks can run.
	leaves []int32

	// strings is the current allocation for string data.
	strings []byte

	itabCache  itabCache
	shapeCache [128]traversalKey

	// valueScratch holds storage for values loaded by Source.LoadValueTo,
	// by type.
	valueScratch map[*typeInfo]unsafe.Pointer

	stats graphStats
}

// graphDecodeStatePool holds decodeStates for reuse.
var graphDecodeStatePool sync.Pool

func newGraphDecodeState(ctx context.Context) *graphDecodeState {
	if ds, ok := graphDecodeStatePool.Get().(*graphDecodeState); ok {
		ds.ctx = ctx
		return ds
	}
	return &graphDecodeState{ctx: ctx}
}

const (
	maxDecodeObjectBytes = 1 << 30 // 1 GiB per single allocated object
	maxDecodeTotalBytes  = 4 << 30 // 4 GiB total allocated object bytes per Load
)

// release returns ds to graphDecodeStatePool. Tables are cleared, so that they do
// not keep loaded objects alive.
func (ds *graphDecodeState) release() {
	if cap(ds.objs) > maxPooledBytes/64 || cap(ds.targets) > maxPooledBytes/8 || cap(ds.cbs) > maxPooledBytes/64 {
		return
	}
	clear(ds.types[:cap(ds.types)])
	clear(ds.typeNames[:cap(ds.typeNames)])
	clear(ds.objs[:cap(ds.objs)])
	clear(ds.cbs[:cap(ds.cbs)])
	clear(ds.targets[:cap(ds.targets)])
	*ds = graphDecodeState{
		types:      ds.types[:0],
		typeNames:  ds.typeNames[:0],
		objs:       ds.objs[:0],
		ods:        ds.ods[:0],
		cbs:        ds.cbs[:0],
		targets:    ds.targets[:0],
		targetObjs: ds.targetObjs[:0],
		leaves:     ds.leaves[:0],
		itabCache:  ds.itabCache,
		shapeCache: ds.shapeCache,
	}
	graphDecodeStatePool.Put(ds)
}

// readTypes reads the type table.
func (ds *graphDecodeState) readTypes() {
	d := &ds.in
	n := d.count(1)
	ds.types = slices.Grow(ds.types[:0], n)[:n]
	ds.typeNames = slices.Grow(ds.typeNames[:0], n)[:n]
	elem := func() reflect.Type {
		i := d.uvarint()
		if i >= uint64(len(ds.types)) || ds.types[i] == nil {
			Failf("invalid type reference %d", i)
		}
		return ds.types[i].typ
	}
	for i := range ds.types {
		var t reflect.Type
		switch tag := d.byte(); tag {
		case typeNamed:
			// The name refers to the input, which outlives typeNames.
			nb := d.next(d.byteLength())
			name := unsafe.String(unsafe.SliceData(nb), len(nb))
			ds.typeNames[i] = name
			var ok bool
			if t = globalTypeDatabase[name]; t == nil {
				if t, ok = primitiveTypeDatabase[name]; !ok {
					// The type may be the root's, which need not be
					// registered.
					continue
				}
			}
		case typeBuiltin:
			k := d.byte()
			if int(k) >= len(builtinTypes) || builtinTypes[k] == nil {
				Failf("invalid builtin kind %d", k)
			}
			t = builtinTypes[k]
		case typePointer:
			t = reflect.PointerTo(elem())
		case typeSlice:
			t = reflect.SliceOf(elem())
		case typeArray:
			n := d.uvarint()
			el := elem()
			if n > maxDecodeObjectBytes || (el.Size() > 0 && n > maxDecodeObjectBytes/uint64(el.Size())) {
				Failf("invalid array length %d of %v", n, el)
			}
			t = reflect.ArrayOf(int(n), el)
		case typeMap:
			k := elem()
			t = reflect.MapOf(k, elem())
		case typeAny:
			t = anyType
		case typeEmptyStruct:
			t = emptyStructType
		default:
			Failf("invalid type tag %d", tag)
		}
		ds.types[i] = typeInfoOf(t)
	}
}

func (ds *graphDecodeState) typeAt(i uint64) *typeInfo {
	if i >= uint64(len(ds.types)) {
		Failf("invalid type index %d", i)
	}
	if ds.types[i] == nil {
		Failf("type name %q is not available", ds.typeNames[i])
	}
	return ds.types[i]
}

// compatibleShape returns true if unnamed stream type a is structurally
// compatible with unnamed destination type b.
func compatibleShape(a, b *typeInfo) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil || a.registered || b.registered || a.kind != b.kind || a.size != b.size {
		return false
	}
	switch a.kind {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.String, reflect.Interface:
		return true
	case reflect.Pointer, reflect.Slice:
		return compatibleShape(a.elem, b.elem)
	case reflect.Array:
		return a.length == b.length && compatibleShape(a.elem, b.elem)
	case reflect.Map:
		return compatibleShape(a.key, b.key) && compatibleShape(a.elem, b.elem)
	case reflect.Struct:
		return a.structKind == structEmpty && b.structKind == structEmpty && a.size == 0
	default:
		return false
	}
}

// readObjects reads the object table, and allocates objects.
func (ds *graphDecodeState) readObjects(root unsafe.Pointer, rootType *typeInfo) {
	d := &ds.in
	n := d.count(1)
	if n == 0 {
		Failf("no objects")
	}
	ds.objs = slices.Grow(ds.objs[:0], n)[:n]
	ds.ods = slices.Grow(ds.ods[:0], n)[:n]
	var totalBytes uint64
	for i := range ds.objs {
		o := &ds.objs[i]
		ds.ods[i] = graphObjectDecodeState{cbHead: -1, cbTail: -1, waitHead: -1, waitTail: -1}
		o.kind = d.byte()
		o.inexact = o.kind&objInexact != 0
		o.kind &^= objInexact
		switch o.kind {
		case objKindValue:
			if i == 0 {
				// The root's type is described by its shape, and its name
				// if it has one.
				idx := d.uvarint()
				if idx >= uint64(len(ds.types)) {
					Failf("invalid type index %d", idx)
				}
				t := ds.types[idx]
				if name := ds.typeNames[idx]; name != "" {
					if name != rootType.name {
						Failf("root has type %q, want %v", name, rootType.typ)
					}
				} else if !compatibleShape(t, rootType) {
					var got any = "<unknown>"
					if t != nil {
						got = t.typ
					}
					Failf("root has type %v, want %v", got, rootType.typ)
				}
				o.ti = rootType
				o.size = o.ti.size
				o.base = root
				continue
			}
			o.ti = ds.typeAt(d.uvarint())
			o.size = o.ti.size
			if uint64(o.size) > maxDecodeObjectBytes || totalBytes+uint64(o.size) > maxDecodeTotalBytes {
				Failf("object allocation %v (%d bytes) exceeds limit", o.ti.typ, o.size)
			}
			if (o.ti.kind == reflect.Struct || o.ti.kind == reflect.Array) && o.ti.pod && !o.inexact && o.size > uintptr(len(d.b)-d.pos) {
				Failf("truncated pod object %v", o.ti.typ)
			}
			totalBytes += uint64(o.size)
			o.base = reflect.New(o.ti.typ).UnsafePointer()
		case objKindArray:
			o.ti = ds.typeAt(d.uvarint())
			count := d.uvarint()
			if o.ti.size == 0 || count > maxDecodeObjectBytes/uint64(o.ti.size) {
				Failf("invalid array of %d %v", count, o.ti.typ)
			}
			o.size = uintptr(count) * o.ti.size
			if totalBytes+uint64(o.size) > maxDecodeTotalBytes {
				Failf("array allocation %d*%v exceeds limit", count, o.ti.typ)
			}
			totalBytes += uint64(o.size)
			o.base = reflect.MakeSlice(o.ti.sliceTypeOf(), int(count), int(count)).UnsafePointer()
		case objKindMap:
			if i == 0 {
				Failf("root is a map")
			}
			// size is the number of entries.
			count := d.uvarint()
			if count > maxDecodeObjectBytes {
				Failf("invalid map of %d entries", count)
			}
			o.size = uintptr(count)
		default:
			Failf("invalid object kind %d", o.kind)
		}
	}
}

// readTargets reads the target table.
func (ds *graphDecodeState) readTargets() {
	d := &ds.in
	n := d.count(1)
	ds.targets = slices.Grow(ds.targets[:0], n)[:n]
	ds.targetObjs = slices.Grow(ds.targetObjs[:0], n)[:n]
	for i := range ds.targets {
		v := d.uvarint()
		if v == 0 {
			ds.targets[i] = zeroSizedPtr()
			ds.targetObjs[i] = -1
			continue
		}
		obj := v>>1 - 1
		if obj >= uint64(len(ds.objs)) {
			Failf("invalid target object %d", obj)
		}
		var off uint64
		if v&1 != 0 {
			off = d.uvarint()
		}
		o := &ds.objs[obj]
		if o.kind == objKindMap {
			if off != 0 {
				Failf("invalid map target")
			}
		} else if (o.size == 0 && off != 0) || (o.size > 0 && off >= uint64(o.size)) {
			Failf("invalid target offset %d in %v", off, o.ti.typ)
		} else {
			ds.targets[i] = add(o.base, uintptr(off))
		}
		ds.targetObjs[i] = int32(obj)
	}
}

// target returns the target with the given index plus one, which must be
// non-zero.
func (ds *graphDecodeState) target(v uint64) (unsafe.Pointer, int32) {
	if v == 0 || v > uint64(len(ds.targets)) {
		Failf("invalid target %d", v)
	}
	return ds.targets[v-1], ds.targetObjs[v-1]
}

// noteRef notes a reference to a value of type ti at t in the object obj,
// which tells the exact type of inexact objects.
func (ds *graphDecodeState) noteRef(obj int32, t unsafe.Pointer, ti *typeInfo) {
	o := &ds.objs[obj]
	if !o.inexact || o.exact != nil {
		return
	}
	for o.kind == objKindArray && ti.kind == reflect.Array && ti.size > o.ti.size {
		ti = ti.elem
	}
	if ti.size != o.ti.size || ti.kind != o.ti.kind {
		return
	}
	off := uintptr(t) - uintptr(o.base)
	if off == 0 || (o.kind == objKindArray && ti.size > 0 && off%ti.size == 0) {
		o.exact = ti
	}
}

// user returns true if cb runs user code.
func (cb *decodeCallback) user() bool {
	return cb.fn != nil || cb.valueFn != nil || cb.afterLoader != nil || cb.valueLoader != nil
}

func (ds *graphDecodeState) appendCallback(head, tail *int32, cb decodeCallback) {
	if cb.waiter < 0 {
		ds.hooks++
	}
	cb.next = -1
	ds.cbs = append(ds.cbs, cb)
	i := int32(len(ds.cbs) - 1)
	if *tail < 0 {
		*head = i
	} else {
		ds.cbs[*tail].next = i
	}
	*tail = i
}

// addCallback adds a callback to obj's own callbacks.
func (ds *graphDecodeState) addCallback(obj int32, cb decodeCallback) {
	o := &ds.ods[obj]
	ds.appendCallback(&o.cbHead, &o.cbTail, cb)
}

// runCallback runs cb if it is a user callback.
func (ds *graphDecodeState) runCallback(cb *decodeCallback) {
	if ds.noCallbacks {
		return
	}
	switch {
	case cb.fn != nil:
		ds.hooks++
		cb.fn()
	case cb.valueFn != nil:
		ds.hooks++
		cb.valueFn(cb.value)
	case cb.afterLoader != nil:
		ds.hooks++
		cb.afterLoader.StateAfterLoad(ds.ctx)
	case cb.valueLoader != nil:
		ds.hooks++
		cb.valueLoader.StateLoadValue(ds.ctx, cb.slot, cb.value)
	}
}

// wait makes waiter wait for obj, and runs cb (if it is a user callback) once
// obj is complete.
//
// As special cases, objects may refer to themselves and to the root object
// without waiting, since the root object may have fields that are already
// decoded.
func (ds *graphDecodeState) wait(waiter, obj int32, cb decodeCallback) {
	if obj == waiter || obj == 0 {
		ds.runCallback(&cb)
		return
	}
	ds.ods[waiter].blockedBy++
	o := &ds.ods[obj]
	if cb.user() {
		ds.appendCallback(&o.waitHead, &o.waitTail, cb)
	}
	ds.appendCallback(&o.waitHead, &o.waitTail, decodeCallback{waiter: waiter})
}
