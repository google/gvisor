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
	"io"
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// load decodes the stream in data into the value of type ti at root.
func (ds *graphDecodeState) load(root unsafe.Pointer, ti *typeInfo) {
	d := &ds.in
	if magic := d.uint32(); magic != streamMagic {
		Failf("invalid stream: bad magic %#x", magic)
	}
	if f := d.uint64(); f != schemaFingerprint() {
		Failf("the state was saved by a binary with different types (fingerprint %#x, want %#x)", f, schemaFingerprint())
	}
	ds.readTypes()
	ds.readObjects(root, ti)
	ds.readTargets()
	ds.decodeObjects()
	setHints(ti, len(d.b), len(ds.targets))
	if d.pos != len(d.b) {
		Failf("%d bytes of trailing data", len(d.b)-d.pos)
	}
	ds.runCallbacks()
}

// decodeObjects decodes the data of all objects.
func (ds *graphDecodeState) decodeObjects() {
	d := &ds.in
	var deferred []deferredObject
	for i := range ds.objs {
		ds.cur = int32(i)
		o := &ds.objs[i]
		if o.kind == objKindMap || (o.inexact && o.kind == objKindValue) {
			n := d.byteLength()
			if !ds.decodable(o) {
				// Decode the object once it has been referred to.
				deferred = append(deferred, deferredObject{obj: int32(i), pos: d.pos, end: d.pos + n})
				d.pos += n
				continue
			}
		} else if o.inexact && !ds.decodable(o) {
			n := d.byteLength()
			deferred = append(deferred, deferredObject{obj: int32(i), pos: d.pos, end: d.pos + n})
			d.pos += n
			continue
		} else if o.inexact {
			d.byteLength()
		}
		ds.decodeObject(int32(i))
	}
	for len(deferred) > 0 {
		remaining := deferred[:0]
		for _, do := range deferred {
			if !ds.decodable(&ds.objs[do.obj]) {
				remaining = append(remaining, do)
				continue
			}
			pos := d.pos
			d.pos = do.pos
			ds.cur = do.obj
			ds.decodeObject(do.obj)
			if d.pos != do.end {
				Failf("object %d has %d bytes of trailing data", do.obj, do.end-d.pos)
			}
			d.pos = pos
		}
		if len(remaining) == len(deferred) {
			Failf("the type of object %d (%s) is not known from references to it", remaining[0].obj, ds.objTypeName(remaining[0].obj))
		}
		deferred = remaining
	}
}

// decodable returns true if the type needed to decode o is known.
func (ds *graphDecodeState) decodable(o *decObject) bool {
	if o.kind == objKindMap {
		return o.mapType != nil
	}
	return !o.inexact || o.exact != nil
}

// decodeObject decodes the data of the object obj.
func (ds *graphDecodeState) decodeObject(obj int32) {
	d := &ds.in
	o := &ds.objs[obj]
	ti := o.ti
	if o.exact != nil {
		ti = o.exact
	}
	switch o.kind {
	case objKindValue:
		ds.keepZero = obj == 0
		ds.decodeValue(ti, o.base)
		ds.keepZero = false
	case objKindArray:
		n := d.count(1)
		esz := ti.size
		var pos uint64
		for j := 0; j < n; j++ {
			pos += d.uvarint()
			count := d.uvarint()
			if pos+count > uint64(o.size/esz) || pos+count < pos {
				Failf("invalid chunk %d+%d of %d %v", pos, count, o.size/esz, ti.typ)
			}
			ds.decodeElems(ti, add(o.base, uintptr(pos)*esz), uintptr(count))
			pos += count
		}
	case objKindMap:
		ds.decodeMap(o.mapType, o.base, int(o.size))
	default:
		Failf("unexpected object kind %d", o.kind)
	}
}

// deferredObject is the data of an object that is decoded after other
// objects.
type deferredObject struct {
	obj      int32
	pos, end int
}

// loadValue decodes a value of type ti for Source.LoadValueTo, and calls
// l.StateLoadValue with it once the objects it refers to are complete.
func (ds *graphDecodeState) loadValue(ti *typeInfo, slot int, l ValueLoader) {
	// Values are decoded to storage that is reused while the values are
	// only passed to l immediately: generated StateLoadValue methods copy
	// them. Values passed later, or whose decoding ran code that may keep
	// their address, keep their storage.
	p := ds.valueScratch[ti]
	if p == nil {
		p = reflect.New(ti.typ).UnsafePointer()
	} else {
		delete(ds.valueScratch, ti)
		if ti.partial {
			reflect.NewAt(ti.typ, p).Elem().SetZero()
		}
	}
	hooks, deferred, refs := ds.hooks, ds.deferred, ds.refs
	ds.lastRef = -1
	keepZero := ds.keepZero
	ds.keepZero = false
	ds.decodeValue(ti, p)
	ds.keepZero = keepZero
	if ds.deferred != deferred {
		if ds.lastRef >= 0 && ds.lastRef != ds.cur && ds.lastRef != 0 {
			ds.wait(ds.cur, ds.lastRef, decodeCallback{waiter: -1})
		}
		if !ds.noCallbacks {
			valPtr := p
			ds.addCallback(ds.cur, decodeCallback{fn: func() { l.StateLoadValue(ds.ctx, slot, makeAny(ti, valPtr)) }, waiter: -1})
		}
		return
	}
	cb := decodeCallback{valueLoader: l, slot: slot, value: makeAny(ti, p), waiter: -1}
	if ds.lastRef >= 0 {
		if ds.lastRef != ds.cur && ds.lastRef != 0 {
			ds.wait(ds.cur, ds.lastRef, cb)
			return
		}
	} else if ds.refs != refs {
		if !ds.noCallbacks {
			ds.addCallback(ds.cur, cb)
		}
		return
	}
	reusable := ds.hooks == hooks
	ds.runCallback(&cb)
	if reusable {
		if ds.valueScratch == nil {
			ds.valueScratch = make(map[*typeInfo]unsafe.Pointer)
		}
		ds.valueScratch[ti] = p
	}
}

// runCallbacks runs the callbacks of objects as they become complete.
func (ds *graphDecodeState) runCallbacks() {
	leaves := ds.leaves[:0]
	defer func() { ds.leaves = leaves }()
	for i := range ds.ods {
		o := &ds.ods[i]
		if o.waitHead >= 0 {
			if o.cbTail < 0 {
				o.cbHead = o.waitHead
			} else {
				ds.cbs[o.cbTail].next = o.waitHead
			}
			o.cbTail = o.waitTail
		}
		if o.blockedBy == 0 {
			leaves = append(leaves, int32(i))
		}
	}
	pending := len(ds.ods)
	var cur int32
	if err := safely(func() {
		for i := 0; i < len(leaves); i++ {
			cur = leaves[i]
			o := &ds.ods[cur]
			if o.blockedBy != 0 || o.complete {
				continue
			}
			if ds.stats.enabled && o.cbHead >= 0 && ds.objs[cur].ti != nil {
				ds.stats.start(ds.objs[cur].ti)
			}
			for c := o.cbHead; c >= 0; c = ds.cbs[c].next {
				cb := &ds.cbs[c]
				if cb.waiter >= 0 {
					w := &ds.ods[cb.waiter]
					w.blockedBy--
					if w.blockedBy == 0 {
						leaves = append(leaves, cb.waiter)
					} else if w.blockedBy < 0 {
						Failf("object %d has negative blockedBy: %d", cb.waiter, w.blockedBy)
					}
					continue
				}
				ds.runCallback(cb)
			}
			if ds.stats.enabled && o.cbHead >= 0 && ds.objs[cur].ti != nil {
				ds.stats.done()
			}
			o = &ds.ods[cur]
			o.complete = true
			pending--
		}
	}); err != nil {
		Failf("error executing callbacks: %w\nfor object of type %v", err, ds.objTypeName(cur))
	}
	if pending > 0 {
		cycle := ds.findCycle()
		var buf bytes.Buffer
		buf.WriteString("dependency cycle: {")
		for i, obj := range cycle {
			if i > 0 {
				buf.WriteString(" => ")
			}
			fmt.Fprintf(&buf, "%q", ds.objTypeName(obj))
		}
		buf.WriteString("}")
		Failf("incomplete graph: %s", buf.String())
	}
}

func (ds *graphDecodeState) objTypeName(obj int32) string {
	o := &ds.objs[obj]
	ti := o.ti
	if o.exact != nil {
		ti = o.exact
	}
	switch o.kind {
	case objKindValue:
		if ti == nil {
			return "unknown value"
		}
		if o.inexact && o.exact == nil {
			return fmt.Sprintf("%v (inexact layout)", ti.typ)
		}
		return ti.typ.String()
	case objKindArray:
		if ti == nil || ti.size == 0 {
			return "array"
		}
		if o.inexact && o.exact == nil {
			return fmt.Sprintf("[%d]%v (inexact layout)", o.size/ti.size, ti.typ)
		}
		return fmt.Sprintf("[%d]%v", o.size/ti.size, ti.typ)
	case objKindMap:
		if o.mapType != nil {
			return o.mapType.typ.String()
		}
		return fmt.Sprintf("map (%d entries)", o.size)
	default:
		return fmt.Sprintf("unknown object kind %d", o.kind)
	}
}

// findCycle finds a dependency cycle after all unblocked objects have
// completed. Every remaining object has a blocker that is also incomplete.
// Following one blocker per object must reach a cycle, even if the starting
// object is only waiting on that cycle.
func (ds *graphDecodeState) findCycle() []int32 {
	blockers := make(map[int32]int32)
	first := int32(-1)
	for i := range ds.ods {
		o := &ds.ods[i]
		if o.complete {
			continue
		}
		if first < 0 {
			first = int32(i)
		}
		for c := o.cbHead; c >= 0; c = ds.cbs[c].next {
			if w := ds.cbs[c].waiter; w >= 0 {
				blockers[w] = int32(i)
			}
		}
	}
	visited := make(map[int32]int)
	var path []int32
	for obj, ok := first, true; ok; obj, ok = blockers[obj] {
		if start, ok := visited[obj]; ok {
			return append(path[start:], obj)
		}
		visited[obj] = len(path)
		path = append(path, obj)
	}
	Failf("incomplete object has no blocking dependency")
	panic("unreachable")
}

func (gd *graphStructDecoder) load(slot int, objPtr any) {
	e := efaceOf(&objPtr)
	ti := gd.st.slotType(slot, e.typ, true)
	gd.ds.decodeValue(ti, e.data)
}

func (gd *graphStructDecoder) loadWait(slot int, objPtr any) {
	e := efaceOf(&objPtr)
	ti := gd.st.slotType(slot, e.typ, true)
	ds := gd.ds
	ds.lastRef = -1
	ds.decodeValue(ti, e.data)
	if ds.lastRef >= 0 {
		ds.wait(ds.cur, ds.lastRef, decodeCallback{waiter: -1})
	}
}

func deferLoadValueCallback(objPtr any, fn func(any)) decodeCallback {
	return decodeCallback{
		fn:     func() { fn(reflect.ValueOf(objPtr).Elem().Interface()) },
		waiter: -1,
	}
}

func (gd *graphStructDecoder) loadValue(slot int, objPtr any, fn func(any)) {
	e := efaceOf(&objPtr)
	ti := gd.st.slotType(slot, e.typ, true)
	ds := gd.ds
	deferred, refs := ds.deferred, ds.refs
	ds.lastRef = -1
	keepZero := ds.keepZero
	ds.keepZero = false
	ds.decodeValue(ti, e.data)
	ds.keepZero = keepZero
	if ds.deferred != deferred {
		if ds.lastRef >= 0 && ds.lastRef != ds.cur && ds.lastRef != 0 {
			ds.wait(ds.cur, ds.lastRef, decodeCallback{waiter: -1})
		}
		if !ds.noCallbacks {
			ds.addCallback(ds.cur, deferLoadValueCallback(objPtr, fn))
		}
		return
	}
	if ds.lastRef >= 0 {
		if ds.lastRef != ds.cur && ds.lastRef != 0 {
			ds.wait(ds.cur, ds.lastRef, deferLoadValueCallback(objPtr, fn))
			return
		}
	} else if ds.refs != refs {
		if !ds.noCallbacks {
			ds.addCallback(ds.cur, deferLoadValueCallback(objPtr, fn))
		}
		return
	}
	if !ds.noCallbacks {
		ds.hooks++
		fn(reflect.ValueOf(objPtr).Elem().Interface())
	}
}

func (gd *graphStructDecoder) loadValueTo(slot int, typ any, l ValueLoader) {
	e := efaceOf(&typ)
	ti := gd.st.slotType(slot, e.typ, true)
	gd.ds.loadValue(ti, slot, l)
}

func (gd *graphStructDecoder) afterLoad(fn func()) {
	ds := gd.ds
	if !ds.noCallbacks {
		ds.addCallback(ds.cur, decodeCallback{fn: fn, waiter: -1})
	}
}

func (gd *graphStructDecoder) afterLoadTo(l AfterLoader) {
	ds := gd.ds
	if !ds.noCallbacks {
		ds.addCallback(ds.cur, decodeCallback{afterLoader: l, waiter: -1})
	}
}

func loadGraph(ctx context.Context, r io.Reader, rootPtr any, length uint64, start int64) (Stats, error) {
	ds := newGraphDecodeState(ctx)
	defer ds.release()
	ds.stats.used = true
	ds.stats.enabled = collectStats.Load()
	if length > maxStreamLength {
		return Stats{graph: ds.stats}, fmt.Errorf("invalid object graph length %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return Stats{graph: ds.stats}, err
	}
	ds.in = decBuf{b: data}
	err := safely(func() {
		e := efaceOf(&rootPtr)
		if e.typ == nil {
			Failf("Load requires a non-nil pointer, got %T", rootPtr)
		}
		ti := typeInfoForRtype(e.typ)
		if ti.kind != reflect.Pointer || e.data == nil {
			Failf("Load requires a non-nil pointer, got %T", rootPtr)
		}
		if ds.stats.enabled {
			ds.stats.init()
			defer ds.stats.done()
		}
		ds.load(e.data, ti.elem)
	})
	ds.stats.bytes = len(data)
	ds.stats.objects = len(ds.objs)
	ds.stats.elapsed = gohacks.Nanotime() - start
	return Stats{graph: ds.stats}, err
}
