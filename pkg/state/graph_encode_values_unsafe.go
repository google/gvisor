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

// encodeValue encodes the value of type ti at p.
func (es *graphEncodeState) encodeValue(ti *typeInfo, p unsafe.Pointer) {
	if uintptr(p)-es.spliceLo < es.spliceSpan && es.trySplice(uintptr(p), ti, 1) != 0 {
		return
	}
	switch ti.kind {
	case reflect.Bool, reflect.Int8, reflect.Uint8:
		es.out.byte(*(*uint8)(p))
	case reflect.Int:
		es.out.varint(int64(*(*int)(p)))
	case reflect.Int16:
		es.out.varint(int64(*(*int16)(p)))
	case reflect.Int32:
		es.out.varint(int64(*(*int32)(p)))
	case reflect.Int64:
		es.out.varint(*(*int64)(p))
	case reflect.Uint, reflect.Uintptr:
		es.out.uvarint(uint64(*(*uint)(p)))
	case reflect.Uint16:
		es.out.uvarint(uint64(*(*uint16)(p)))
	case reflect.Uint32:
		es.out.uvarint(uint64(*(*uint32)(p)))
	case reflect.Uint64:
		es.out.uvarint(*(*uint64)(p))
	case reflect.Float32:
		es.out.uint32(*(*uint32)(p))
	case reflect.Float64:
		es.out.uint64(*(*uint64)(p))
	case reflect.Complex64:
		es.out.raw(p, 8)
	case reflect.Complex128:
		es.out.raw(p, 16)
	case reflect.String:
		es.out.string(*(*string)(p))
	case reflect.Pointer:
		es.encodePointer(ti, *(*unsafe.Pointer)(p))
	case reflect.Slice:
		es.encodeSlice(ti, (*sliceHeader)(p))
	case reflect.Array:
		elem, n := leafArray(ti.elem, ti.length)
		es.encodeElems(elem, p, n)
	case reflect.Map:
		es.encodeMapRef(ti, *(*unsafe.Pointer)(p))
	case reflect.Interface:
		es.encodeInterface(ti, p)
	case reflect.Struct:
		if ti.pod {
			es.out.raw(p, ti.size)
			return
		}
		es.encodeStruct(ti, p)
	default:
		Failf("unsupported type %v", ti.typ)
	}
}

func (es *graphEncodeState) encodePointer(ti *typeInfo, v unsafe.Pointer) {
	if v == nil {
		es.out.byte(0)
		return
	}
	tid := es.ptrTarget(v, ti.elem)
	es.refs = append(es.refs, tid)
	es.out.uvarint(uint64(tid) + 1)
}

func (es *graphEncodeState) encodeMapRef(ti *typeInfo, m unsafe.Pointer) {
	if m == nil {
		es.out.byte(0)
		return
	}
	tid := es.mapTarget(m, ti)
	es.refs = append(es.refs, tid)
	es.out.uvarint(uint64(tid) + 1)
}

func (es *graphEncodeState) encodeSlice(ti *typeInfo, h *sliceHeader) {
	if h.data == nil {
		es.out.byte(0)
		return
	}
	es.out.uvarint(uint64(h.len) + 1)
	es.out.uvarint(uint64(h.cap - h.len))
	if ti.elem.size == 0 {
		if !ti.elem.pod && h.len > 0 {
			es.encodeElems(ti.elem, h.data, uintptr(h.len))
		}
		return
	}
	if h.cap == 0 {
		return
	}
	tid := es.sliceTarget(h.data, ti.elem, uintptr(h.len), uintptr(h.cap))
	es.refs = append(es.refs, tid)
	es.out.uvarint(uint64(tid))
}

// encodeElems encodes n elements of type elem at p.
func (es *graphEncodeState) encodeElems(elem *typeInfo, p unsafe.Pointer, n uintptr) {
	if elem.pod {
		es.out.raw(p, elem.size*n)
		return
	}
	esz := elem.size
	for i := uintptr(0); i < n; i++ {
		q := add(p, i*esz)
		if uintptr(q)-es.spliceLo < es.spliceSpan {
			if k := es.trySplice(uintptr(q), elem, n-i); k != 0 {
				i += k - 1
				continue
			}
		}
		es.encodeValue(elem, q)
	}
}

func (es *graphEncodeState) encodeInterface(ti *typeInfo, p unsafe.Pointer) {
	var (
		dyn  *typeInfo
		data unsafe.Pointer
	)
	if ti.emptyIface {
		e := (*eface)(p)
		if e.typ == nil {
			es.out.byte(0)
			return
		}
		dyn = es.typeCache.rtype(e.typ)
		data = e.data
	} else {
		i := (*iface)(p)
		if i.tab == nil {
			es.out.byte(0)
			return
		}
		dyn = es.typeCache.itab(p)
		data = i.data
	}
	es.out.uvarint(uint64(es.types.exactIndex(dyn)) + 1)
	es.encodeDynamic(dyn, data)
}

// encodeDynamic encodes a value of type ti held in an interface with the
// given data word.
func (es *graphEncodeState) encodeDynamic(ti *typeInfo, data unsafe.Pointer) {
	if !ti.direct {
		es.encodeValueCopy(ti, data)
		return
	}
	switch ti.kind {
	case reflect.Pointer:
		es.encodePointer(ti, data)
	case reflect.Map:
		es.encodeMapRef(ti, data)
	default:
		w := new(unsafe.Pointer)
		*w = data
		es.encodeValue(ti, unsafe.Pointer(w))
	}
}

func (es *graphEncodeState) scratchAliased(p unsafe.Pointer, ti *typeInfo, zeroBefore int) bool {
	if !ti.inlineStruct || ti.size == 0 {
		return false
	}
	addr := uintptr(p)
	end := addr + ti.size
	if len(es.query(addr, end)) > 0 {
		return true
	}
	for _, tid := range es.zeroTargets[zeroBefore:] {
		if a := es.target(tid).addr; a >= addr && a <= end {
			return true
		}
	}
	return false
}

// encodeValueCopy encodes the value of type ti at p, which may be read-only.
func (es *graphEncodeState) encodeValueCopy(ti *typeInfo, p unsafe.Pointer) {
	if !ti.inlineStruct {
		es.encodeValue(ti, p)
		return
	}
	// StateSave methods may modify the value, so encode a copy. Copies are
	// reused once encoded unless StateSave aliased the copy's memory.
	free := es.copies[ti]
	var c reflect.Value
	if n := len(free); n > 0 {
		c = free[n-1]
		es.copies[ti] = free[:n-1]
	} else {
		c = reflect.New(ti.typ).Elem()
		if es.copies == nil {
			es.copies = make(map[*typeInfo][]reflect.Value)
		}
	}
	c.Set(reflect.NewAt(ti.typ, p).Elem())
	cp := c.Addr().UnsafePointer()
	zeroBefore := len(es.zeroTargets)
	es.encodeValue(ti, cp)
	if !es.scratchAliased(cp, ti, zeroBefore) {
		c.SetZero()
		es.copies[ti] = append(es.copies[ti], c)
	}
}

func (es *graphEncodeState) encodeStruct(ti *typeInfo, p unsafe.Pointer) {
	switch ti.structKind {
	case structSaverLoader:
		var sl StructType
		*(*iface)(unsafe.Pointer(&sl)) = iface{tab: ti.methodItab, data: p}
		if es.stats.enabled {
			es.stats.start(ti)
			defer es.stats.done()
		}
		sl.StateSave(Sink{graph: graphStructEncoder{es: es, st: ti}})
	case structBinary:
		var bo binaryObject
		*(*iface)(unsafe.Pointer(&bo)) = iface{tab: ti.methodItab, data: p}
		data, err := bo.AppendBinary(es.binaryBuf[:0])
		es.binaryBuf = data
		if err != nil {
			Failf("encoding %s: %w", ti.name, err)
		}
		es.out.uvarint(uint64(len(data)))
		es.out.bytes(data)
	case structEmpty:
	default:
		Failf("struct %v does not implement SaverLoader", ti.typ)
	}
}

// encodeMap encodes the entries of a map, and returns the number of entries.
// The number of entries is in the object table, so that the decoder can
// allocate maps with the correct size.
func (es *graphEncodeState) encodeMap(ti *typeInfo, m unsafe.Pointer) int {
	es.mapPtr = m
	v := reflect.NewAt(ti.typ, unsafe.Pointer(&es.mapPtr)).Elem()
	n := v.Len()
	if n == 0 {
		return 0
	}
	// Map encoding is not reentrant, so slots can be reused.
	sc, ok := es.mapSlots[ti]
	if !ok {
		sc.k = reflect.New(ti.key.typ).Elem()
		sc.e = reflect.New(ti.elem.typ).Elem()
		if es.mapSlots == nil {
			es.mapSlots = make(map[*typeInfo]mapSlots)
		}
		es.mapSlots[ti] = sc
	}
	k, e := sc.k, sc.e
	kp, ep := k.Addr().UnsafePointer(), e.Addr().UnsafePointer()
	count := 0
	var it reflect.MapIter
	it.Reset(v)
	for ; it.Next(); count++ {
		k.SetIterKey(&it)
		e.SetIterValue(&it)
		zk := len(es.zeroTargets)
		es.encodeValue(ti.key, kp)
		if es.scratchAliased(kp, ti.key, zk) {
			k = reflect.New(ti.key.typ).Elem()
			kp = k.Addr().UnsafePointer()
			sc.k = k
			es.mapSlots[ti] = sc
		}
		ze := len(es.zeroTargets)
		es.encodeValue(ti.elem, ep)
		if es.scratchAliased(ep, ti.elem, ze) {
			e = reflect.New(ti.elem.typ).Elem()
			ep = e.Addr().UnsafePointer()
			sc.e = e
			es.mapSlots[ti] = sc
		}
	}
	it.Reset(reflect.Value{})
	if count != n {
		Failf("map %v changed while saving", ti.typ)
	}
	return n
}

func (es *graphEncodeState) updateSpliceBounds() {
	loIdx := 0
	for loIdx < len(es.splices) && es.splices[loIdx].used {
		loIdx++
	}
	if loIdx == len(es.splices) {
		es.spliceLo, es.spliceSpan = 0, 0
		return
	}
	hiIdx := len(es.splices) - 1
	for es.splices[hiIdx].used {
		hiIdx--
	}
	lo := es.splices[loIdx].addr
	es.spliceLo = lo
	es.spliceSpan = es.splices[hiIdx].addr - lo + 1
}

// trySplice reuses the encoding of up to max values of type ti at addr, if
// any. It returns the number of values encoded.
func (es *graphEncodeState) trySplice(addr uintptr, ti *typeInfo, max uintptr) uintptr {
	idx, found := slices.BinarySearchFunc(es.splices, addr, func(s splice, a uintptr) int {
		return cmp.Compare(s.addr, a)
	})
	if !found {
		return 0
	}
	for i := idx; i < len(es.splices) && es.splices[i].addr == addr; i++ {
		s := es.splices[i]
		if s.used || s.ti != ti || s.count > max {
			continue
		}
		es.out.bytes(es.out.b[s.seg.off : s.seg.off+s.seg.len])
		es.splices[i].used = true
		end := addr + ti.size*s.count
		for j := idx; j < len(es.splices) && es.splices[j].addr < end; j++ {
			if es.splices[j].addr+es.splices[j].ti.size*es.splices[j].count <= end {
				es.splices[j].used = true
			}
		}
		es.updateSpliceBounds()
		return s.count
	}
	return 0
}

// gatherSplices collects the encodings of the descendants of obj within
// [lo, hi) that must be reused.
func (es *graphEncodeState) gatherSplices(obj int32, lo, hi uintptr) {
	for _, c := range es.obj(obj).childList() {
		co := es.obj(c)
		if co.end <= lo || co.addr >= hi {
			continue
		}
		if co.isArray {
			if co.ti.inlineStruct {
				elem, mul := leafArray(co.ti, 1)
				for _, ch := range es.chunkList(co) {
					addr := co.addr + ch.start*co.ti.size
					if addr < lo || addr+(ch.end-ch.start)*co.ti.size > hi {
						continue
					}
					es.splices = append(es.splices, splice{
						addr:  addr,
						ti:    elem,
						count: (ch.end - ch.start) * mul,
						seg:   ch.seg,
					})
				}
			}
		} else if co.state == objDone {
			if co.ti.inlineStruct && co.addr >= lo && co.end <= hi {
				elem, n := leafArray(co.ti, 1)
				es.splices = append(es.splices, splice{addr: co.addr, ti: elem, count: n, seg: co.seg})
			}
			continue
		}
		es.gatherSplices(c, lo, hi)
	}
}

// setupSplices prepares the splices for encoding [lo, hi) of obj.
func (es *graphEncodeState) setupSplices(obj int32, lo, hi uintptr) {
	if len(es.obj(obj).childList()) == 0 {
		return
	}
	es.gatherSplices(obj, lo, hi)
	if len(es.splices) == 0 {
		return
	}
	slices.SortFunc(es.splices, func(a, b splice) int {
		if a.addr != b.addr {
			return cmp.Compare(a.addr, b.addr)
		}
		return cmp.Compare(b.count*b.ti.size, a.count*a.ti.size)
	})
	es.updateSpliceBounds()
}

// finishSplices resets active splices after encoding an object or chunk.
// Absorbed encodings of fields saved via value conversion (state:".(T)"),
// manual/custom StateSave logic, or omitted fields legitimately remain unused.
func (es *graphEncodeState) finishSplices() {
	es.splices = es.splices[:0]
	es.spliceLo = 0
	es.spliceSpan = 0
}

// sameTypeArrayChain returns true if obj and all objects that absorbed it are
// arrays of the same element type aligned to that element size.
func (es *graphEncodeState) sameTypeArrayChain(obj int32) bool {
	ti := es.obj(obj).ti
	esz := ti.size
	for {
		o := es.obj(obj)
		if !o.isArray || o.ti != ti {
			return false
		}
		if o.parent < 0 {
			return true
		}
		if o.parentOff%esz != 0 {
			return false
		}
		obj = o.parent
	}
}

// graphStructEncoder encodes the fields of a struct.
type graphStructEncoder struct {
	es *graphEncodeState
	st *typeInfo
}
