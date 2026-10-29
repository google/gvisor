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
	"context"
	"encoding/binary"
	"io"
	"reflect"
	"slices"
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/state/wire"
)

// process encodes queued work until none remains.
func (es *graphEncodeState) process() {
	for es.queueHead < len(es.queue) {
		w := es.queue[es.queueHead]
		es.queueHead++
		o := es.obj(w.obj)
		if o.parent >= 0 && (!o.isArray || !es.sameTypeArrayChain(w.obj)) {
			// The object that absorbed this object encodes it.
			continue
		}
		start, refStart := len(es.out.b), int32(len(es.refs))
		if o.isArray {
			esz := o.ti.size
			lo, hi := o.addr+w.start*esz, o.addr+w.end*esz
			elem, n := leafArray(o.ti, w.end-w.start)
			p := add(o.base, w.start*esz)
			es.setupSplices(w.obj, lo, hi)
			es.encodeElems(elem, p, n)
			es.finishSplices()
			o = es.obj(w.obj)
			es.addChunk(o, chunk{elemRange: w.elemRange, seg: es.newSegment(start, refStart)})
			continue
		}
		o.state = objEncoding
		if o.isMap {
			n := es.encodeMap(o.ti, o.base)
			es.obj(w.obj).n = uintptr(n)
		} else {
			base, end, ti := o.base, o.end, o.ti
			es.setupSplices(w.obj, o.addr, end)
			es.encodeValue(ti, base)
			es.finishSplices()
		}
		o = es.obj(w.obj)
		o.seg = es.newSegment(start, refStart)
		o.state = objDone
	}
}

// arrayChunks appends the encoded chunks of the live array obj and of the
// arrays of the same type that it absorbed.
func (es *graphEncodeState) arrayChunks(obj int32, shift uintptr, out []chunk) []chunk {
	o := es.obj(obj)
	for _, ch := range es.chunkList(o) {
		ch.start += shift
		ch.end += shift
		out = append(out, ch)
	}
	for _, c := range o.childList() {
		if co := es.obj(c); co.isArray && co.ti == o.ti && co.parentOff%o.ti.size == 0 {
			out = es.arrayChunks(c, shift+co.parentOff/o.ti.size, out)
		}
	}
	return out
}

// newSegment returns the segment of out from start to its end, whose
// references start at refs[refStart].
func (es *graphEncodeState) newSegment(start int, refStart int32) segment {
	seg := segment{start, len(es.out.b) - start}
	if seg.len > 0 {
		es.segRefs = append(es.segRefs, segmentRefs{off: start, ref: refStart})
	}
	return seg
}

// segmentRefs returns the targets referenced in seg.
func (es *graphEncodeState) segmentRefs(seg segment) []int32 {
	if seg.len == 0 {
		return nil
	}
	i, found := slices.BinarySearchFunc(es.segRefs, seg.off, func(r segmentRefs, off int) int {
		return cmp.Compare(r.off, off)
	})
	if !found {
		Failf("internal error: no segment at %d", seg.off)
	}
	end := int32(len(es.refs))
	if i+1 < len(es.segRefs) {
		end = es.segRefs[i+1].ref
	}
	return es.refs[es.segRefs[i].ref:end]
}

// markRefs marks the targets refs in refMarks, and unmarks all others.
func (es *graphEncodeState) markRefs(refs []int32) {
	if es.refStamp++; es.refStamp == 0 || len(es.refMarks) < es.targets.n {
		es.refMarks = slices.Grow(es.refMarks[:0], es.targets.n)[:es.targets.n]
		clear(es.refMarks)
		es.refStamp = 1
	}
	for _, tid := range refs {
		es.refMarks[tid] = es.refStamp
	}
}

// markSegmentRefs enqueues the live root objects of all targets referenced
// within seg.
func (es *graphEncodeState) markSegmentRefs(seg segment, live []bool) {
	for _, tid := range es.segmentRefs(seg) {
		t := es.target(tid)
		if t.obj < 0 {
			continue
		}
		r, _ := es.root(t.obj)
		if !live[r] {
			live[r] = true
			es.liveQueue = append(es.liveQueue, r)
		}
	}
}

// pruneUnreachable marks root objects unreachable from object 0 as dead when
// already-encoded objects were later absorbed and superseded.
func (es *graphEncodeState) pruneUnreachable() {
	// References to absorbed objects refer to their roots, so a superseded
	// encoding can only leave objects unreachable if it refers to targets
	// that the encoding of its root does not. This is rare: roots usually
	// encode the same fields again, or reuse the superseded encoding.
	hasSuperseded := false
	markedRoot := int32(-1)
	for i := int32(0); i < int32(es.objs.n) && !hasSuperseded; i++ {
		o := es.obj(i)
		if o.parent < 0 {
			continue
		}
		if !o.isArray {
			if o.state != objDone {
				continue
			}
			refs := es.segmentRefs(o.seg)
			if len(refs) == 0 {
				continue
			}
			r, _ := es.root(i)
			if ro := es.obj(r); ro.isArray || ro.isMap {
				hasSuperseded = true
				continue
			}
			if r != markedRoot {
				es.markRefs(es.segmentRefs(es.obj(r).seg))
				markedRoot = r
			}
			for _, tid := range refs {
				if es.refMarks[tid] != es.refStamp {
					hasSuperseded = true
					break
				}
			}
			continue
		}
		if es.sameTypeArrayChain(i) {
			continue
		}
		for _, ch := range es.chunkList(o) {
			if len(es.segmentRefs(ch.seg)) > 0 {
				hasSuperseded = true
				break
			}
		}
	}
	if !hasSuperseded {
		return
	}
	live := slices.Grow(es.liveBits[:0], es.objs.n)[:es.objs.n]
	clear(live)
	es.liveBits = live
	live[0] = true
	es.liveQueue = append(es.liveQueue[:0], 0)
	var chunks []chunk
	for head := 0; head < len(es.liveQueue); head++ {
		obj := es.liveQueue[head]
		o := es.obj(obj)
		if !o.isArray {
			es.markSegmentRefs(o.seg, live)
			continue
		}
		chunks = es.arrayChunks(obj, 0, chunks[:0])
		for _, ch := range chunks {
			es.markSegmentRefs(ch.seg, live)
		}
	}
	for i := int32(0); i < int32(es.objs.n); i++ {
		if o := es.obj(i); o.parent < 0 && !live[i] {
			o.dead = true
		}
	}
}

// streamMagic starts every stream.
const streamMagic = 0x32534776

// save serializes the object graph rooted at the value of type ti at root,
// and appends it to w.
//
// The stream is:
//
//   - streamMagic, and the schema fingerprint of the binary.
//   - The type table: the types of objects and of the values of interfaces.
//   - The object table: the kind and type of each object.
//   - The target table: the object and offset of each pointer target.
//   - The data of each object, in order. Pointers are target indices.
func (es *graphEncodeState) save(root unsafe.Pointer, ti *typeInfo, w *encBuf) {
	size := max(ti.size, 1)
	obj := es.newObject(root, uintptr(root)+size, ti, 1, false)
	if ti.size != 0 {
		es.index(obj)
	}
	es.enqueue(obj, 0, 1)
	es.process()
	if es.obj(0).parent >= 0 {
		Failf("root object %v is within another object", ti.typ)
	}

	// Resolve zero-sized targets within objects, and encode standalone
	// zero-sized objects that are not plain old data.
	var standaloneZero []int32
	for resolved := 0; ; {
		for ; resolved < len(es.zeroTargets); resolved++ {
			tid := es.zeroTargets[resolved]
			t := es.target(tid)
			if obj, off := es.resolveZeroTarget(t.addr, t.ti); obj >= 0 {
				t.obj, t.off = obj, off
			}
		}
		if es.queueHead < len(es.queue) {
			es.process()
			continue
		}
		queued := false
		for _, tid := range es.zeroTargets {
			t := es.target(tid)
			if t.obj < 0 && !t.ti.pod {
				obj := es.newObject(t.ptr, t.addr+1, t.ti, 1, false)
				t.obj, t.off = obj, 0
				standaloneZero = append(standaloneZero, obj)
				es.enqueue(obj, 0, 1)
				queued = true
			}
		}
		if !queued {
			break
		}
		es.process()
		for _, obj := range standaloneZero {
			o := es.obj(obj)
			if o.parent >= 0 {
				continue
			}
			if parent, off := es.resolveZeroTarget(o.addr, o.ti); parent >= 0 && parent != obj {
				o.parent = parent
				o.parentOff = off
			}
		}
		if es.queueHead < len(es.queue) {
			es.process()
		}
	}

	es.pruneUnreachable()

	// Number the live objects.
	var n int32
	for i := int32(0); i < int32(es.objs.n); i++ {
		if o := es.obj(i); o.parent < 0 && !o.dead {
			o.final = n
			n++
		}
	}

	// Object table.
	var tables encBuf
	tables.grow(int(n)*4 + es.targets.n*3 + 64)
	tables.uvarint(uint64(n))
	dataMaxBytes := 0
	for i := int32(0); i < int32(es.objs.n); i++ {
		o := es.obj(i)
		if o.isArray && es.sameTypeArrayChain(i) {
			if r, _ := es.root(i); !es.obj(r).dead {
				for _, ch := range es.chunkList(o) {
					// Each chunk writes start-delta and length uvarints plus its payload.
					dataMaxBytes += 2*binary.MaxVarintLen64 + ch.seg.len
				}
			}
		}
		if o.parent >= 0 || o.dead {
			continue
		}
		switch {
		case o.isMap:
			tables.byte(objKindMap)
			tables.uvarint(uint64(o.n))
			// Map payload is prefixed with its byte-length uvarint.
			dataMaxBytes += binary.MaxVarintLen64 + o.seg.len
		case o.isArray:
			idx, flag := es.types.objectIndex(o.ti)
			tables.byte(objKindArray | flag)
			tables.uvarint(uint64(idx))
			tables.uvarint(uint64(o.n))
			// Array payload begins with a chunk-count uvarint, plus an optional
			// byte-length uvarint when inexact.
			dataMaxBytes += 2 * binary.MaxVarintLen64
		default:
			var (
				idx  int
				flag byte
			)
			if i == 0 {
				idx = es.types.rootIndex(o.ti)
			} else {
				idx, flag = es.types.objectIndex(o.ti)
			}
			tables.byte(objKindValue | flag)
			tables.uvarint(uint64(idx))
			// Value payload has an optional byte-length uvarint when inexact.
			dataMaxBytes += binary.MaxVarintLen64 + o.seg.len
		}
	}

	// Target table.
	tables.uvarint(uint64(es.targets.n))
	for i := int32(0); i < int32(es.targets.n); i++ {
		t := es.target(i)
		if t.obj < 0 {
			tables.byte(0)
			continue
		}
		r, off := es.root(t.obj)
		if es.obj(r).dead {
			tables.byte(0)
			continue
		}
		off += t.off
		final := uint64(es.obj(r).final) + 1
		if off == 0 {
			tables.uvarint(final << 1)
		} else {
			tables.uvarint(final<<1 | 1)
			tables.uvarint(uint64(off))
		}
	}

	// Pre-size w with an upper bound on the stream size: 4-byte streamMagic +
	// 8-byte schemaFingerprint + uvarint type count + serialized tables +
	// object payload upper bound.
	const streamHeaderMaxBytes = 4 + 8 + binary.MaxVarintLen64
	w.grow(streamHeaderMaxBytes + len(es.types.buf.b) + len(tables.b) + dataMaxBytes)
	w.uint32(streamMagic)
	w.uint64(schemaFingerprint())
	w.uvarint(uint64(len(es.types.types)))
	w.bytes(es.types.buf.b)
	w.bytes(tables.b)
	var chunks []chunk
	for i := int32(0); i < int32(es.objs.n); i++ {
		o := es.obj(i)
		if o.parent >= 0 || o.dead {
			continue
		}
		inexact := !o.isMap && i != 0 && es.types.isInexact(o.ti)
		if o.isMap || (inexact && !o.isArray) {
			// Maps are allocated, and inexact objects are decoded, once
			// referred to, which may be after their data, so their data is
			// skippable.
			w.uvarint(uint64(o.seg.len))
		}
		if !o.isArray {
			w.bytes(es.out.b[o.seg.off : o.seg.off+o.seg.len])
			continue
		}
		chunks = es.arrayChunks(int32(i), 0, chunks[:0])
		if inexact {
			// Prefix the data with its length.
			var sub encBuf
			es.writeChunks(&sub, o, chunks)
			w.uvarint(uint64(len(sub.b)))
			w.bytes(sub.b)
			continue
		}
		es.writeChunks(w, o, chunks)
	}
	es.stats.objects = int(n)
	setHints(ti, len(w.b), es.targets.n)
}

// resolveZeroTarget resolves a zero-sized target at addr of type ti to an
// enclosing object and offset, or returns (-1, 0) if standalone.
func (es *graphEncodeState) resolveZeroTarget(addr uintptr, ti *typeInfo) (int32, uintptr) {
	if r0 := es.obj(0); r0.ti.size == 0 && addr == r0.addr && es.contains(r0.ti, ti, 0, 1) {
		return 0, 0
	}
	if addr == graphDummyAddr() {
		return -1, 0
	}
	if ov := es.query(addr, addr+1); len(ov) == 1 {
		o := es.obj(ov[0])
		off := addr - o.addr
		if o.isMap {
			return -1, 0
		}
		if o.isArray {
			esz := o.ti.size
			rElem, _ := leafArray(o.ti, o.n)
			tElem, _ := leafArray(ti, 1)
			if off < o.end-o.addr && ((off%rElem.size == 0 && tElem == rElem) || es.contains(o.ti, ti, off%esz, 1)) {
				es.checkInterior(ov[0], off, ti, 1)
				return ov[0], off
			}
		} else if off < o.ti.size && es.contains(o.ti, ti, off, 1) {
			return ov[0], off
		}
	}
	return -1, 0
}

// writeChunks writes the chunks of an array object.
func (es *graphEncodeState) writeChunks(w *encBuf, o *encObject, chunks []chunk) {
	if len(chunks) > 1 {
		slices.SortFunc(chunks, func(a, b chunk) int { return cmp.Compare(a.start, b.start) })
	}
	w.uvarint(uint64(len(chunks)))
	var last uintptr
	for j, ch := range chunks {
		if j > 0 && ch.start < chunks[j-1].end {
			Failf("internal error: overlapping chunks of %v", o.ti.typ)
		}
		w.uvarint(uint64(ch.start - last))
		w.uvarint(uint64(ch.end - ch.start))
		last = ch.end
		w.bytes(es.out.b[ch.seg.off : ch.seg.off+ch.seg.len])
	}
}

// maxStreamLength is the maximum length of an object graph.
const maxStreamLength = 1 << 40

func (ge *graphStructEncoder) save(slot int, objPtr any) {
	e := efaceOf(&objPtr)
	ti := ge.st.slotType(slot, e.typ, true)
	ge.es.encodeValue(ti, e.data)
}

func (ge *graphStructEncoder) saveValue(slot int, obj any) {
	e := efaceOf(&obj)
	ti := ge.st.slotType(slot, e.typ, false)
	ge.es.encodeDynamic(ti, e.data)
}

func saveGraph(ctx context.Context, w io.Writer, rootPtr any) (Stats, error) {
	start := gohacks.Nanotime()
	e := efaceOf(&rootPtr)
	var ti *typeInfo
	if err := safely(func() {
		ti = typeInfoForRtype(e.typ)
		if ti.kind != reflect.Pointer || e.data == nil {
			Failf("Save requires a non-nil pointer, got %T", rootPtr)
		}
	}); err != nil {
		return Stats{graph: graphStats{used: true}}, err
	}
	es := newGraphEncodeState(ctx, ti.elem)
	defer es.release()
	es.stats.used = true
	es.stats.enabled = collectStats.Load()
	out := &es.final
	err := safely(func() {
		if es.stats.enabled {
			es.stats.init()
			defer es.stats.done()
		}
		es.save(e.data, ti.elem, out)
	})
	es.stats.bytes = len(out.b)
	es.stats.elapsed = gohacks.Nanotime() - start
	if err != nil {
		return Stats{graph: es.stats}, err
	}
	ww := wire.Writer{Writer: w}
	if err := writeGraphHeader(&ww, uint64(len(out.b))); err != nil {
		return Stats{graph: es.stats}, err
	}
	if _, err := w.Write(out.b); err != nil {
		return Stats{graph: es.stats}, err
	}
	return Stats{graph: es.stats}, nil
}
