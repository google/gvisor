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
	"sync"
	"unsafe"
)

// objectState is the encoding state of an object.
type objectState uint8

const (
	// objQueued objects are waiting to be encoded.
	objQueued objectState = iota
	// objEncoding objects are being encoded.
	objEncoding
	// objDone objects have been encoded.
	objDone
)

// segment is a range of graphEncodeState.out.
type segment struct {
	off, len int
}

// segmentRefs is the index in graphEncodeState.refs of the first target
// referenced in the non-empty segment at off.
type segmentRefs struct {
	off int
	ref int32
}

// elemRange is a range of array elements [start, end).
type elemRange struct {
	start, end uintptr
}

// chunk is the encoding of a range of array elements.
type chunk struct {
	elemRange
	seg segment
}

// encObject is an object: a region of memory saved as a unit, which pointers
// may point into.
//
// Objects are either single values, arrays (the backing arrays of slices, of
// which only the elements within slices or pointed to are saved) or maps
// (which are referred to by their map pointer).
//
// Top-level ("live") objects never overlap. Because graph traversal follows
// pointers in discovery order, an interior pointer or sub-slice (such as
// &s.field or arr[2:4]) may be visited and given an encObject before its
// enclosing value or backing array (&s or arr[0:8]) is discovered. When the
// enclosing object is later discovered, it "absorbs" any earlier objects within
// its address range so the restored stream allocates a single combined object:
//   - Each absorbed object's parent and parentOff record its container and byte
//     offset within it, removing it from the top-level object table and
//     redirecting existing pointer targets into the container.
//   - Absorbed objects still queued are skipped when popped; if an absorbed
//     object with StateSave hooks was already encoded, its encoded bytes (seg
//     or chunks) are spliced verbatim into the container's encoding so
//     StateSave runs at most once per value.
type encObject struct {
	// base is the address of the object, and keeps it alive.
	base      unsafe.Pointer
	addr, end uintptr
	ti        *typeInfo
	n         uintptr
	isArray   bool
	isMap     bool
	state     objectState
	// dead is set during save when all references to a root object came from
	// absorbed encodings that were later superseded.
	dead bool

	// parent is the object that absorbed this object, or -1.
	parent    int32
	parentOff uintptr

	// seg is the encoding of single values and maps.
	seg segment
	// cov and ch are the covered elements and the encoded chunk of arrays
	// with a single range of each. Further ranges are in x.
	cov    elemRange
	ch     chunk
	hasCov bool
	hasCh  bool

	// x holds the state of arrays and of objects that absorbed others.
	x *objExtra

	// stamp deduplicates query results.
	stamp uint32
	// final is the index of the object in the stream.
	final int32
}

// objExtra is the state of arrays and of objects that absorbed others.
type objExtra struct {
	// children are the objects absorbed by this object.
	children []int32
	// covered are the non-overlapping, non-adjacent element index ranges of
	// arrays that are encoded or queued, sorted by ascending start index.
	covered []elemRange
	// chunks are the encoded elements of arrays.
	chunks []chunk
}

func (o *encObject) extra() *objExtra {
	if o.x == nil {
		o.x = &objExtra{}
	}
	return o.x
}

func (o *encObject) childList() []int32 {
	if o.x == nil {
		return nil
	}
	return o.x.children
}

// coveredList returns the covered elements of the array o. The result is only
// valid until the next call.
func (es *graphEncodeState) coveredList(o *encObject) []elemRange {
	if o.hasCov {
		es.tmpRange[0] = o.cov
		return es.tmpRange[:]
	}
	if o.x == nil {
		return nil
	}
	return o.x.covered
}

// setCovered sets the covered elements of the array o.
func (es *graphEncodeState) setCovered(o *encObject, rs []elemRange) {
	if len(rs) == 1 && (o.x == nil || o.x.covered == nil) {
		o.cov, o.hasCov = rs[0], true
		return
	}
	o.hasCov = false
	x := o.extra()
	x.covered = append(x.covered[:0], rs...)
}

// chunkList returns the encoded chunks of the array o. The result is only
// valid until the next call.
func (es *graphEncodeState) chunkList(o *encObject) []chunk {
	if o.hasCh {
		es.tmpChunk[0] = o.ch
		return es.tmpChunk[:]
	}
	if o.x == nil {
		return nil
	}
	return o.x.chunks
}

// addChunk adds an encoded chunk of the array o.
func (es *graphEncodeState) addChunk(o *encObject, ch chunk) {
	if !o.hasCh && (o.x == nil || o.x.chunks == nil) {
		o.ch, o.hasCh = ch, true
		return
	}
	x := o.extra()
	if o.hasCh {
		x.chunks = append(x.chunks, o.ch)
		o.hasCh = false
	}
	x.chunks = append(x.chunks, ch)
}

// encTarget is the target of pointers: a location within an object.
type encTarget struct {
	obj int32
	off uintptr
	ti  *typeInfo
	// next is the next target with the same address, or -1.
	next int32
	// ptr keeps zero-sized pointees alive until save resolves addr.
	ptr  unsafe.Pointer
	addr uintptr
}

// work is an object, or a range of array elements, to encode.
type work struct {
	obj int32
	elemRange
}

// blockShift is the log2 byte size (512 B) of each address-space bucket in
// graphEncodeState.blocks for overlap queries. 512 B balances two costs:
// smaller blocks cause multi-KiB structs and slice backing arrays to span many
// buckets on insertion and query, while page-sized blocks (4-8 KiB) group
// dozens of unrelated small heap allocations from the same Go size-class span
// into long bucket chains.
const blockShift = 9

// blockEntry is an entry in a list of objects intersecting a block.
type blockEntry struct {
	// addr and end bound the indexed portion of the object in this block.
	// Earlier full blocks keep their cached end when an array grows.
	addr, end uintptr
	obj, next int32
}

// splice is an encoding to reuse when encoding a containing object.
type splice struct {
	addr  uintptr
	ti    *typeInfo
	count uintptr
	seg   segment
	used  bool
}

// traversalKey identifies a containment check.
type traversalKey struct {
	root, target *typeInfo
	off          uintptr
	count        uintptr
}

// graphEncodeState is the state of Save.
type graphEncodeState struct {
	ctx context.Context

	// out holds the encodings of objects.
	out encBuf

	// final holds the stream.
	final encBuf

	objs    chunked[encObject]
	targets chunked[encTarget]

	typeCache typeCache

	// byAddr maps addresses to the first target at that address.
	byAddr addrMap
	// maps maps map pointers to their targets.
	maps map[unsafe.Pointer]int32
	// blocks maps blocks of memory to the objects that intersect them.
	blocks       addrMap
	blockEntries []blockEntry
	stamp        uint32
	queryResult  []int32

	queue     []work
	queueHead int

	// zeroTargets are targets of zero-sized types.
	zeroTargets []int32

	traversals map[traversalKey]bool

	// splices are the encodings to reuse while encoding the current work,
	// sorted by address. [spliceLo, spliceLo+spliceSpan) bounds the addresses
	// of remaining unused splices (spliceSpan == 0 when none remain).
	splices              []splice
	spliceLo, spliceSpan uintptr

	// refs are the targets referenced in out, in order. segRefs indexes
	// refs by the non-empty segments of out, which are created in order and
	// cover it. They are kept outside of segments to keep encObject small.
	refs      []int32
	segRefs   []segmentRefs
	liveBits  []bool
	liveQueue []int32
	// refMarks marks targets with refStamp, for pruneUnreachable.
	refMarks []uint32
	refStamp uint32

	types typeTable

	binaryBuf []byte

	mapSlots map[*typeInfo]mapSlots

	// coverBuf and absorbBuf are scratch slices reused across cover and
	// newContainer calls.
	coverBuf  []elemRange
	absorbBuf []int32
	// tmpRange and tmpChunk are 1-element arrays sliced via [:] in coveredList
	// and chunkList to return a 1-element slice for inline single-range arrays
	// (o.cov / o.ch) without heap allocation or taking a slice into movable
	// chunked[encObject] storage.
	tmpRange [1]elemRange
	tmpChunk [1]chunk

	// mapPtr holds the map being encoded.
	mapPtr unsafe.Pointer

	// copies are storage for copies of values, by type.
	copies map[*typeInfo][]reflect.Value

	stats graphStats
}

// graphDummyAddr returns the runtime address of zero-sized allocations.
func graphDummyAddr() uintptr {
	return uintptr(zeroSizedPtr())
}

// graphEncodeStatePool holds encodeStates for reuse, which avoids growing their
// buffers and maps for each Save.
var graphEncodeStatePool sync.Pool

// maxPooledBytes limits the buffer capacity of pooled states.
const maxPooledBytes = 16 << 20

func newGraphEncodeState(ctx context.Context, root *typeInfo) *graphEncodeState {
	if es, ok := graphEncodeStatePool.Get().(*graphEncodeState); ok {
		es.ctx = ctx
		return es
	}
	// Graphs with the same root type tend to have similar sizes, so start
	// with the size of the last such graph saved or loaded.
	bytes, targets := int(root.hintBytes.Load()), int(root.hintTargets.Load())
	es := &graphEncodeState{
		ctx:          ctx,
		maps:         make(map[unsafe.Pointer]int32),
		blockEntries: make([]blockEntry, 0, targets),
		queue:        make([]work, 0, targets),
		refs:         make([]int32, 0, targets),
		segRefs:      make([]segmentRefs, 0, targets),
		traversals:   make(map[traversalKey]bool),
		out:          encBuf{b: make([]byte, 0, max(bytes, 4<<10))},
	}
	es.byAddr.init(targets)
	es.blocks.init(targets)
	return es
}

// setHints records the length and number of targets of a graph with the
// given root type, capped to limit the effect of outliers.
func setHints(root *typeInfo, bytes, targets int) {
	root.hintBytes.Store(int32(min(bytes, maxPooledBytes/2)))
	root.hintTargets.Store(int32(min(targets, maxPooledBytes/64)))
}

// chunkedShift is the log2 of the number of elements (1024) per slab in
// chunked[T]. It sizes the encoder's internal metadata slabs (objs and targets)
// and is unrelated to blockShift (which buckets target virtual addresses).
// 1024 elements (~128 KiB for encObject, ~48 KiB for encTarget) amortizes slab
// allocations on large checkpoints while letting chunks[0] grow incrementally
// for small graphs.
const chunkedShift = 10

// chunked is an append-only array that is not copied as it grows.
type chunked[T any] struct {
	chunks [][]T
	n      int
}

// add appends a zero element and returns a pointer to it. Pointers to the
// first chunk's elements are invalidated as it grows.
func (c *chunked[T]) add() *T {
	i := c.n
	c.n++
	if i < 1<<chunkedShift {
		// The first chunk grows as needed, for small graphs.
		if len(c.chunks) == 0 {
			c.chunks = append(c.chunks, nil)
		}
		var zero T
		c.chunks[0] = append(c.chunks[0], zero)
		return &c.chunks[0][i]
	}
	if i>>chunkedShift == len(c.chunks) {
		c.chunks = append(c.chunks, make([]T, 1<<chunkedShift))
	}
	return &c.chunks[i>>chunkedShift][i&(1<<chunkedShift-1)]
}

// at returns a pointer to element i.
func (c *chunked[T]) at(i int) *T {
	return &c.chunks[i>>chunkedShift][i&(1<<chunkedShift-1)]
}

func (es *graphEncodeState) obj(i int32) *encObject {
	return es.objs.at(int(i))
}

func (es *graphEncodeState) target(i int32) *encTarget {
	return es.targets.at(int(i))
}

const maxPooledChunks = 8

// reset clears all elements before returning the owning state to sync.Pool.
func (c *chunked[T]) reset() {
	if len(c.chunks) > maxPooledChunks {
		// Nil excess chunk headers in the backing array up to cap(c.chunks) so
		// Go's GC can reclaim those oversized slab allocations.
		clear(c.chunks[maxPooledChunks:])
		c.chunks = c.chunks[:maxPooledChunks]
	}
	n := c.n
	for i := range c.chunks {
		if n <= 0 {
			break
		}
		end := min(n, len(c.chunks[i]))
		// Zero used elements so pointer fields (such as encObject.base,
		// encObject.x, and encTarget.ptr) do not pin the saved object graph in
		// memory while pooled, and so reused slab slots start zeroed.
		clear(c.chunks[i][:end])
		n -= 1 << chunkedShift
	}
	if len(c.chunks) > 0 {
		c.chunks[0] = c.chunks[0][:0]
	}
	c.n = 0
}

const maxPooledSlots = 1 << 18

// release returns es to graphEncodeStatePool, if it is not too large.
func (es *graphEncodeState) release() {
	if cap(es.out.b)+cap(es.final.b)+cap(es.binaryBuf) > maxPooledBytes ||
		len(es.byAddr.slots)+len(es.blocks.slots) > maxPooledSlots ||
		cap(es.blockEntries)+cap(es.queue) > maxPooledSlots ||
		cap(es.refs)+cap(es.segRefs) > maxPooledSlots {
		return
	}
	es.ctx = nil
	es.out.b = es.out.b[:0]
	es.final.b = es.final.b[:0]
	es.objs.reset()
	es.targets.reset()
	es.byAddr.reset()
	clear(es.maps)
	es.blocks.reset()
	es.blockEntries = es.blockEntries[:0]
	es.stamp = 0
	es.queryResult = es.queryResult[:0]
	es.queue = es.queue[:0]
	es.queueHead = 0
	es.zeroTargets = es.zeroTargets[:0]
	// traversals caches pure static type-layout containment queries
	// ((*typeInfo, *typeInfo, off, count) -> bool) that remain valid across
	// Save calls; only reallocate it if an outlier graph grew it too large.
	if len(es.traversals) > 1024 {
		es.traversals = make(map[traversalKey]bool)
	}
	es.splices = es.splices[:0]
	es.spliceLo = 0
	es.spliceSpan = 0
	es.refs = es.refs[:0]
	es.segRefs = es.segRefs[:0]
	es.refStamp = 0
	es.refMarks = es.refMarks[:0]
	es.liveBits = es.liveBits[:0]
	es.liveQueue = es.liveQueue[:0]
	es.types.reset()
	es.binaryBuf = es.binaryBuf[:0]
	es.coverBuf = es.coverBuf[:0]
	es.absorbBuf = es.absorbBuf[:0]
	for _, sc := range es.mapSlots {
		sc.k.SetZero()
		sc.e.SetZero()
	}
	if len(es.mapSlots) > 256 {
		es.mapSlots = nil
	}
	// copies holds pre-allocated reflect.Value scratch buffers that were
	// already zeroed via SetZero after use, kept across Save calls to avoid
	// re-allocating per type unless the map grew too large.
	if len(es.copies) > 256 {
		es.copies = nil
	}
	es.mapPtr = nil
	es.stats = graphStats{}
	graphEncodeStatePool.Put(es)
}

// newObject adds an object, without indexing it.
func (es *graphEncodeState) newObject(base unsafe.Pointer, end uintptr, ti *typeInfo, n uintptr, isArray bool) int32 {
	o := es.objs.add()
	*o = encObject{
		base:    base,
		addr:    uintptr(base),
		end:     end,
		ti:      ti,
		n:       n,
		isArray: isArray,
		parent:  -1,
	}
	return int32(es.objs.n - 1)
}

// mapSlots are storage for the keys and values of maps being encoded.
type mapSlots struct {
	k, e reflect.Value
}
