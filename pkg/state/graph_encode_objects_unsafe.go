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
	"cmp"
	"reflect"
	"slices"
	"unsafe"
)

// index adds the object to the object index.
func (es *graphEncodeState) index(obj int32) {
	o := es.obj(obj)
	for b := o.addr >> blockShift; b <= (o.end-1)>>blockShift; b++ {
		head, ok := es.blocks.get(b)
		if !ok {
			head = -1
		}
		es.blockEntries = append(es.blockEntries, blockEntry{addr: o.addr, end: o.end, obj: obj, next: head})
		es.blocks.set(b, int32(len(es.blockEntries)-1))
	}
}

// query returns the live objects overlapping [addr, end). The result is only
// valid until the next call.
func (es *graphEncodeState) query(addr, end uintptr) []int32 {
	es.stamp++
	if es.stamp == 0 {
		for i := 0; i < es.objs.n; i++ {
			es.objs.at(i).stamp = 0
		}
		es.stamp = 1
	}
	es.queryResult = es.queryResult[:0]
	for b := addr >> blockShift; b <= (end-1)>>blockShift; b++ {
		e, ok := es.blocks.get(b)
		if !ok {
			continue
		}
		for ; e >= 0; e = es.blockEntries[e].next {
			be := &es.blockEntries[e]
			if be.addr >= end || addr >= be.end {
				continue
			}
			o := es.obj(be.obj)
			if o.parent >= 0 || o.dead || o.stamp == es.stamp {
				continue
			}
			o.stamp = es.stamp
			es.queryResult = append(es.queryResult, be.obj)
		}
	}
	return es.queryResult
}

// root returns the live object containing obj, and the offset of obj in it.
func (es *graphEncodeState) root(obj int32) (int32, uintptr) {
	var off uintptr
	for es.obj(obj).parent >= 0 {
		off += es.obj(obj).parentOff
		obj = es.obj(obj).parent
	}
	return obj, off
}

// newTarget adds a target.
func (es *graphEncodeState) newTarget(obj int32, off uintptr, ti *typeInfo) int32 {
	*es.targets.add() = encTarget{obj: obj, off: off, ti: ti, next: -1}
	return int32(es.targets.n - 1)
}

// lookup returns the target at addr with type ti, or -1.
func (es *graphEncodeState) lookup(addr uintptr, ti *typeInfo) int32 {
	t, ok := es.byAddr.get(addr)
	if !ok {
		return -1
	}
	for ; t >= 0; t = es.target(t).next {
		if es.target(t).ti == ti {
			return t
		}
	}
	return -1
}

// addLookup makes tid findable by lookup.
func (es *graphEncodeState) addLookup(addr uintptr, tid int32) {
	if head, ok := es.byAddr.get(addr); ok {
		es.target(tid).next = es.target(head).next
		es.target(head).next = tid
		return
	}
	es.byAddr.set(addr, tid)
}

// enqueue queues work.
func (es *graphEncodeState) enqueue(obj int32, start, end uintptr) {
	es.queue = append(es.queue, work{obj: obj, elemRange: elemRange{start, end}})
}

// cover ensures that elements [start, end) of the live object obj are
// encoded.
func (es *graphEncodeState) cover(obj int32, start, end uintptr) {
	o := es.obj(obj)
	if !o.isArray {
		return
	}
	end = min(end, o.n)
	if start >= end {
		return
	}
	covered := es.coveredList(o)
	// Fast path: already covered by a single range.
	for _, r := range covered {
		if r.start <= start && end <= r.end {
			return
		}
	}
	// Queue the uncovered parts, and merge the overlapping and adjacent
	// ranges into [start, end).
	pos := start
	merged := es.coverBuf[:0]
	inserted := false
	for _, r := range covered {
		if r.end < start {
			merged = append(merged, r)
			continue
		}
		if r.start > end {
			if !inserted {
				merged = append(merged, elemRange{start, end})
				inserted = true
			}
			merged = append(merged, r)
			continue
		}
		if r.start > pos {
			es.enqueue(obj, pos, r.start)
		}
		pos = max(pos, r.end)
		start = min(start, r.start)
		end = max(end, r.end)
	}
	if pos < end {
		es.enqueue(obj, pos, end)
	}
	if !inserted {
		merged = append(merged, elemRange{start, end})
	}
	es.coverBuf = merged
	es.setCovered(es.obj(obj), merged)
}

// markCovered marks elements of the live array obj as covered, without
// queueing them.
func (es *graphEncodeState) markCovered(obj int32, rs []elemRange, shift uintptr) {
	o := es.obj(obj)
	all := append(es.coverBuf[:0], es.coveredList(o)...)
	for _, r := range rs {
		all = append(all, elemRange{r.start + shift, r.end + shift})
	}
	slices.SortFunc(all, func(a, b elemRange) int { return cmp.Compare(a.start, b.start) })
	merged := all[:0]
	for _, r := range all {
		if n := len(merged); n > 0 && r.start <= merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, r.end)
			continue
		}
		merged = append(merged, r)
	}
	es.coverBuf = merged
	es.setCovered(o, merged)
}

func sameType(a, b *typeInfo) bool { return a == b }

// contains returns true if count consecutive values of type target at offset
// off of a value of type root are a field or elements of it.
func (es *graphEncodeState) contains(root, target *typeInfo, off, count uintptr) bool {
	k := traversalKey{root, target, off, count}
	if v, ok := es.traversals[k]; ok {
		return v
	}
	v := containsType(root, target, off, count, sameType)
	es.traversals[k] = v
	return v
}

func leafArray(ti *typeInfo, count uintptr) (*typeInfo, uintptr) {
	for ti.kind == reflect.Array {
		count *= ti.length
		ti = ti.elem
	}
	return ti, count
}

func containsType(root, target *typeInfo, off, count uintptr, match func(*typeInfo, *typeInfo) bool) bool {
	if count <= 1 && match(root, target) && off == 0 {
		return true
	}
	if off > root.size || (target.size > 0 && count > (root.size-off)/target.size) {
		return false
	}
	switch root.kind {
	case reflect.Struct:
		if root.structKind == structBinary || (root.structKind == structEmpty && root.size > 0) {
			return false
		}
		t := root.typ
		lo, hi := 0, t.NumField()
		for lo < hi {
			if mid := int(uint(lo+hi) >> 1); t.Field(mid).Offset <= off {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		for i := hi - 1; i >= 0; i-- {
			f := t.Field(i)
			if end := f.Offset + f.Type.Size(); end < off || (target.size > 0 && end == off) {
				break
			}
			if f.Name == "_" {
				continue
			}
			if f.Tag != "" {
				switch f.Tag.Get("state") {
				case "nosave", "ignore", "zerovalue":
					continue
				}
			}
			// Zero-sized fields may share an offset with other fields, so
			// keep searching on failure.
			if containsType(typeInfoOf(f.Type), target, off-f.Offset, count, match) {
				return true
			}
		}
	case reflect.Array:
		if root.length == 0 {
			return false
		}
		rElem, rLen := leafArray(root, 1)
		tElem, tCount := leafArray(target, count)
		if rElem.size > 0 && match(rElem, tElem) && off%rElem.size == 0 && off/rElem.size+tCount <= rLen {
			return true
		}
		esz := root.elem.size
		if esz == 0 {
			return containsType(root.elem, target, off, count, match)
		}
		return off/esz < root.length && containsType(root.elem, target, off%esz, count, match)
	}
	return false
}

// checkInterior checks that count values of type ti at offset off of the
// live object obj are a part of it, and ensures that the array elements they
// are in are encoded.
func (es *graphEncodeState) checkInterior(obj int32, off uintptr, ti *typeInfo, count uintptr) {
	o := es.obj(obj)
	if o.isMap {
		Failf("pointer into map %v", o.ti.typ)
	}
	if !o.isArray {
		if !es.contains(o.ti, ti, off, count) {
			Failf("%v at offset %d is not a field of %v", ti.typ, off, o.ti.typ)
		}
		return
	}
	esz := o.ti.size
	k, sub := off/esz, off%esz
	rElem, rLen := leafArray(o.ti, o.n)
	tElem, tCount := leafArray(ti, count)
	size := tElem.size * tCount
	if size == 0 {
		size = 1
	}
	if tElem == rElem && off%rElem.size == 0 && off/rElem.size+tCount <= rLen {
		// Elements.
	} else if k >= o.n || !es.contains(o.ti, ti, sub, count) {
		Failf("%v at offset %d is not within an array of %v", ti.typ, off, o.ti.typ)
	}
	es.cover(obj, k, (off+size-1)/esz+1)
}

// absorb makes the live object obj, which must be contained in the new object
// parent, part of parent.
func (es *graphEncodeState) absorb(parent, obj int32) {
	p, o := es.obj(parent), es.obj(obj)
	off := o.addr - p.addr
	o.parent = parent
	o.parentOff = off
	px := p.extra()
	px.children = append(px.children, obj)
	count := uintptr(1)
	if o.isArray {
		count = o.n
	}
	if !p.isArray {
		if !es.contains(p.ti, o.ti, off, count) {
			Failf("%v at offset %d is not a field of %v", o.ti.typ, off, p.ti.typ)
		}
		return
	}
	esz := p.ti.size
	if o.isArray && o.ti == p.ti && off%esz == 0 {
		// The absorbed array's queued and encoded elements are elements of
		// parent; its queued elements are still encoded as its own.
		rs := append([]elemRange(nil), es.coveredList(o)...)
		es.markCovered(parent, rs, off/esz)
		return
	}
	if o.isArray && o.ti.size >= esz && off%esz == 0 {
		rElem, rLen := leafArray(p.ti, p.n)
		tElem, tCount := leafArray(o.ti, count)
		if tElem == rElem && off/rElem.size+tCount <= rLen {
			mul := o.ti.size / esz
			base := off / esz
			rs := append([]elemRange(nil), es.coveredList(o)...)
			for _, r := range rs {
				es.cover(parent, base+r.start*mul, base+r.end*mul)
			}
			return
		}
	}
	es.checkInterior(parent, off, o.ti, count)
}

// containsRange returns true if the live object obj contains count values of
// type ti in [addr, end). If obj has the same range, this depends on whether
// ti is a field of obj's type, or the converse.
func (es *graphEncodeState) containsRange(obj int32, addr, end uintptr, ti *typeInfo, count uintptr) bool {
	o := es.obj(obj)
	if o.addr > addr || end > o.end {
		return false
	}
	if o.addr < addr || end < o.end || o.isMap {
		return true
	}
	if o.isArray {
		rElem, rLen := leafArray(o.ti, o.n)
		tElem, tCount := leafArray(ti, count)
		if tElem == rElem && tCount <= rLen {
			return true
		}
		return o.n == 1 && es.contains(o.ti, ti, 0, count)
	}
	// Same range: the larger type in the field hierarchy is the container.
	if es.contains(o.ti, ti, 0, count) {
		return true
	}
	return !es.contains(ti, o.ti, 0, 1) && !(count > 1 && ti == o.ti)
}

// newContainer adds an object that absorbs the live objects in ov.
func (es *graphEncodeState) newContainer(base unsafe.Pointer, end uintptr, ti *typeInfo, n uintptr, isArray bool, ov []int32) int32 {
	ov = append(es.absorbBuf[:0], ov...)
	es.absorbBuf = ov
	obj := es.newObject(base, end, ti, n, isArray)
	for _, c := range ov {
		es.absorb(obj, c)
	}
	es.index(obj)
	return obj
}

// arrayElem returns the element type of the live object o if it is an array
// object or a non-empty array value, and nil otherwise.
func arrayElem(o *encObject) *typeInfo {
	if o.isArray {
		return o.ti
	}
	if o.ti.kind == reflect.Array && o.ti.length > 0 {
		return o.ti.elem
	}
	return nil
}

// commonArrayElem returns the largest element type shared by (possibly
// nested) arrays of element types a and b whose starts differ by diff bytes,
// or nil if there is none.
func commonArrayElem(a, b *typeInfo, diff uintptr) *typeInfo {
	for a != b {
		switch {
		case a.kind == reflect.Array && a.size >= b.size:
			a = a.elem
		case b.kind == reflect.Array && b.size >= a.size:
			b = b.elem
		default:
			return nil
		}
	}
	for a.kind == reflect.Array && a.length > 0 && diff%a.size != 0 {
		a = a.elem
	}
	if a.size == 0 || diff%a.size != 0 {
		return nil
	}
	return a
}

// mergeArray creates a new array object spanning [data, end) merged with any
// partially overlapping array or array-value objects, covers [data, coverEnd),
// and returns the new array object and its start address.
func (es *graphEncodeState) mergeArray(basePtr unsafe.Pointer, data, end, coverEnd uintptr, elem, errTyp *typeInfo, isSlice bool) (int32, uintptr) {
	mergeElem := elem
	lo, hi := data, end
	for grown := true; grown; {
		grown = false
		for _, c := range es.query(lo, hi) {
			co := es.obj(c)
			if co.addr >= lo && co.end <= hi {
				continue
			}
			var nextElem *typeInfo
			if ce := arrayElem(co); ce != nil {
				nextElem = commonArrayElem(mergeElem, ce, max(co.addr, lo)-min(co.addr, lo))
			}
			if nextElem == nil {
				if isSlice {
					Failf("slice of %v at %#x overlaps %v at %#x", errTyp.typ, data, co.ti.typ, co.addr)
				}
				Failf("%v at %#x overlaps %v at %#x", errTyp.typ, data, co.ti.typ, co.addr)
			}
			mergeElem = nextElem
			lo, hi = min(lo, co.addr), max(hi, co.end)
			grown = true
		}
	}
	esz := mergeElem.size
	obj := es.newContainer(unsafe.Add(basePtr, -int(data-lo)), hi, mergeElem, (hi-lo)/esz, true, es.query(lo, hi))
	es.cover(obj, (data-lo)/esz, (coverEnd-lo)/esz)
	return obj, lo
}

// coverSliceInArray ensures that the length elements of a slice of elem with
// the given capacity at offset off of the live object obj are encoded. If obj
// is an array of elem or of a finer element type, only the slice's length
// (not its unused capacity) is covered.
func (es *graphEncodeState) coverSliceInArray(obj int32, off uintptr, elem *typeInfo, length, capacity uintptr) {
	o := es.obj(obj)
	if o.isArray {
		esz := o.ti.size
		if o.ti == elem && off%esz == 0 {
			es.cover(obj, off/esz, off/esz+length)
			return
		}
		if elem.size >= esz && off%esz == 0 {
			rElem, rLen := leafArray(o.ti, o.n)
			tElem, tCap := leafArray(elem, capacity)
			if tElem == rElem && off%rElem.size == 0 && off/rElem.size+tCap <= rLen {
				mul := elem.size / esz
				base := off / esz
				es.cover(obj, base, base+length*mul)
				return
			}
		}
	}
	es.checkInterior(obj, off, elem, capacity)
}

// ptrTarget returns the target for a pointer to a value of type ti at addr.
func (es *graphEncodeState) ptrTarget(p unsafe.Pointer, ti *typeInfo) int32 {
	addr := uintptr(p)
	if tid := es.lookup(addr, ti); tid >= 0 {
		return tid
	}
	var tid int32
	if ti.size == 0 {
		// Zero-sized values may share addresses with other values, so they
		// are not objects. They are resolved once all objects are known.
		tid = es.newTarget(-1, 0, ti)
		t := es.target(tid)
		t.ptr = p
		t.addr = addr
		es.zeroTargets = append(es.zeroTargets, tid)
	} else {
		end := addr + ti.size
		ov := es.query(addr, end)
		if len(ov) == 1 && es.containsRange(ov[0], addr, end, ti, 1) {
			obj := ov[0]
			off := addr - es.obj(obj).addr
			es.checkInterior(obj, off, ti, 1)
			tid = es.newTarget(obj, off, ti)
		} else {
			partial := false
			for _, c := range ov {
				if co := es.obj(c); co.addr < addr || co.end > end {
					partial = true
					break
				}
			}
			if partial && ti.kind == reflect.Array {
				obj, lo := es.mergeArray(p, addr, end, end, ti.elem, ti, false)
				tid = es.newTarget(obj, addr-lo, ti)
			} else {
				for _, c := range ov {
					if co := es.obj(c); co.addr < addr || co.end > end {
						Failf("%v at %#x overlaps %v at %#x", ti.typ, addr, co.ti.typ, co.addr)
					}
				}
				obj := es.newContainer(p, end, ti, 1, false, ov)
				es.enqueue(obj, 0, 1)
				tid = es.newTarget(obj, 0, ti)
			}
		}
	}
	es.addLookup(addr, tid)
	return tid
}

// sliceTarget returns the target for the data of a slice of elements of type
// elem, and ensures that its elements are encoded.
//
// Preconditions: elem.size > 0, capacity > 0.
func (es *graphEncodeState) sliceTarget(dataPtr unsafe.Pointer, elem *typeInfo, length, capacity uintptr) int32 {
	data := uintptr(dataPtr)
	esz := elem.size
	end := data + capacity*esz
	tid := es.lookup(data, elem)
	if tid >= 0 && es.target(tid).obj >= 0 {
		// Fast path: the slice is within the object of an existing target.
		r, off := es.root(es.target(tid).obj)
		off += es.target(tid).off
		if o := es.obj(r); o.addr+off+capacity*esz <= o.end {
			es.coverSliceInArray(r, off, elem, length, capacity)
			return tid
		}
	}
	ov := es.query(data, end)
	if len(ov) == 1 && es.containsRange(ov[0], data, end, elem, capacity) {
		obj := ov[0]
		off := data - es.obj(obj).addr
		es.coverSliceInArray(obj, off, elem, length, capacity)
		if tid < 0 {
			tid = es.newTarget(obj, off, elem)
			es.addLookup(data, tid)
		}
		return tid
	}
	// Create a new array object, merging partially overlapping arrays whose
	// element types are compatible with elem.
	obj, lo := es.mergeArray(dataPtr, data, end, data+length*esz, elem, elem, true)
	if tid < 0 || es.target(tid).obj < 0 {
		tid = es.newTarget(obj, data-lo, elem)
		es.addLookup(data, tid)
	}
	return tid
}

// mapTarget returns the target for a map.
func (es *graphEncodeState) mapTarget(m unsafe.Pointer, ti *typeInfo) int32 {
	if tid, ok := es.maps[m]; ok {
		return tid
	}
	obj := es.newObject(m, uintptr(m)+1, ti, 1, false)
	es.obj(obj).isMap = true
	es.enqueue(obj, 0, 1)
	tid := es.newTarget(obj, 0, ti)
	es.maps[m] = tid
	return tid
}
