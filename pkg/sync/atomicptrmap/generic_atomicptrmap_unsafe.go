// Copyright 2020 The gVisor Authors.
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

// Package atomicptrmap doesn't exist. This file must be instantiated using the
// go_template_instance rule in tools/go_generics/defs.bzl.
package atomicptrmap

import (
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

// Key is a required type parameter.
type Key struct{}

// Value is a required type parameter.
type Value struct{}

const (
	// ShardOrder is an optional parameter specifying the base-2 log of the
	// number of shards per AtomicPtrMap. Higher values of ShardOrder reduce
	// unnecessary synchronization between unrelated concurrent operations,
	// improving performance for write-heavy workloads, but increase memory
	// usage for small maps.
	ShardOrder = 0
)

// Hasher is an optional type parameter. If Hasher is provided, it must define
// the Init and Hash methods. One Hasher will be shared by all AtomicPtrMaps.
type Hasher struct {
	defaultHasher
}

// defaultHasher is the default Hasher. This indirection exists because
// defaultHasher must exist even if a custom Hasher is provided, to prevent the
// Go compiler from complaining about defaultHasher's unused imports.
type defaultHasher struct {
	fn   func(unsafe.Pointer, uintptr) uintptr
	seed uintptr
}

// Init initializes the Hasher.
func (h *defaultHasher) Init() {
	h.fn = sync.MapKeyHasher(map[Key]*Value(nil))
	h.seed = sync.RandUintptr()
}

// Hash returns the hash value for the given Key.
func (h *defaultHasher) Hash(key Key) uintptr {
	return h.fn(gohacks.Noescape(unsafe.Pointer(&key)), h.seed)
}

var hasher Hasher

func init() {
	hasher.Init()
}

// An AtomicPtrMap maps Keys to non-nil pointers to Values. AtomicPtrMap are
// safe for concurrent use from multiple goroutines without additional
// synchronization.
//
// The zero value of AtomicPtrMap is empty (maps all Keys to nil) and ready for
// use. AtomicPtrMaps must not be copied after first use.
//
// sync.Map may be faster than AtomicPtrMap if most operations on the map are
// concurrent writes to a fixed set of keys. AtomicPtrMap is usually faster in
// other circumstances.
type AtomicPtrMap struct {
	// AtomicPtrMap is implemented as a hash table with the following
	// properties:
	//
	//	* Collisions are resolved with quadratic probing. Of the two major
	//		alternatives, Robin Hood linear probing makes it difficult for writers
	//		to execute in parallel, and bucketing is less effective in Go due to
	//		lack of SIMD.
	//
	//	* The table is optionally divided into shards indexed by hash to further
	//		reduce unnecessary synchronization.

	shards [1 << ShardOrder]apmShard
}

func (m *AtomicPtrMap) shard(hash uintptr) *apmShard {
	// Go defines right shifts >= width of shifted unsigned operand as 0, so
	// this is correct even if ShardOrder is 0 (although nogo complains because
	// nogo is dumb).
	const indexLSB = unsafe.Sizeof(uintptr(0))*8 - ShardOrder
	index := hash >> indexLSB
	return (*apmShard)(unsafe.Pointer(uintptr(unsafe.Pointer(&m.shards)) + (index * unsafe.Sizeof(apmShard{}))))
}

type apmShard struct {
	apmShardMutationData
	_ [apmShardMutationDataPadding]byte
	apmShardLookupData
	_ [apmShardLookupDataPadding]byte
}

type apmShardMutationData struct {
	dirtyMu  sync.Mutex // serializes slot transitions out of empty
	dirty    uintptr    // # slots with val != nil
	count    uintptr    // # slots with val != nil and val != tombstone()
	rehashMu sync.Mutex // serializes rehashing
}

type apmShardLookupData struct {
	seq   sync.SeqCount  // allows atomic reads of slots+mask
	slots unsafe.Pointer // [mask+1]slot or nil; protected by rehashMu/seq
	mask  uintptr        // always (a power of 2) - 1; protected by rehashMu/seq
}

const (
	cacheLineBytes = 64
	// Cache line padding is enabled if sharding is.
	apmEnablePadding = (ShardOrder + 63) >> 6 // 0 if ShardOrder == 0, 1 otherwise
	// The -1 and +1 below are required to ensure that if unsafe.Sizeof(T) %
	// cacheLineBytes == 0, then padding is 0 (rather than cacheLineBytes).
	apmShardMutationDataRequiredPadding = cacheLineBytes - (((unsafe.Sizeof(apmShardMutationData{}) - 1) % cacheLineBytes) + 1)
	apmShardMutationDataPadding         = apmEnablePadding * apmShardMutationDataRequiredPadding
	apmShardLookupDataRequiredPadding   = cacheLineBytes - (((unsafe.Sizeof(apmShardLookupData{}) - 1) % cacheLineBytes) + 1)
	apmShardLookupDataPadding           = apmEnablePadding * apmShardLookupDataRequiredPadding

	// These define fractional thresholds for when apmShard.rehash() is called
	// (i.e. the load factor) and when it rehases to a larger table
	// respectively. They are chosen such that the rehash threshold = the
	// expansion threshold + 1/2, so that when reuse of deleted slots is rare
	// or non-existent, rehashing occurs after the insertion of at least 1/2
	// the table's size in new entries, which is acceptably infrequent.
	apmRehashThresholdNum    = 2
	apmRehashThresholdDen    = 3
	apmExpansionThresholdNum = 1
	apmExpansionThresholdDen = 6
)

type apmSlot struct {
	// slot states are indicated by val:
	//
	//	* Empty: val == nil; key is meaningless. May transition to full or
	//		evacuated with dirtyMu locked.
	//
	//	* Full: val != nil, tombstone(), or evacuated(); key is immutable. val
	//		is the Value mapped to key. May transition to deleted or evacuated.
	//
	//	* Deleted: val == tombstone(); key is still immutable. key is mapped to
	//		no Value. May transition to full or evacuated.
	//
	//	* Evacuated: val == evacuated(); key is immutable. Set by rehashing on
	//		slots that have already been moved, requiring readers to wait for
	//		rehashing to complete and use the new table. Terminal state.
	//
	// Note that once val is non-nil, it cannot become nil again. That is, the
	// transition from empty to non-empty is irreversible for a given slot;
	// the only way to create more empty slots is by rehashing.
	val unsafe.Pointer
	key Key
}

func apmSlotAt(slots unsafe.Pointer, pos uintptr) *apmSlot {
	return (*apmSlot)(unsafe.Pointer(uintptr(slots) + pos*unsafe.Sizeof(apmSlot{})))
}

var tombstoneObj byte

func tombstone() unsafe.Pointer {
	return unsafe.Pointer(&tombstoneObj)
}

var evacuatedObj byte

func evacuated() unsafe.Pointer {
	return unsafe.Pointer(&evacuatedObj)
}

// Load returns the Value stored in m for key.
func (m *AtomicPtrMap) Load(key Key) *Value {
	hash := hasher.Hash(key)
	shard := m.shard(hash)

retry:
	epoch := shard.seq.BeginRead()
	slots := atomic.LoadPointer(&shard.slots)
	mask := atomic.LoadUintptr(&shard.mask)
	if !shard.seq.ReadOk(epoch) {
		goto retry
	}
	if slots == nil {
		return nil
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := apmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {
			// Empty slot; end of probe sequence.
			return nil
		}
		if slotVal == evacuated() {
			// Racing with rehashing.
			goto retry
		}
		if slot.key == key {
			if slotVal == tombstone() {
				return nil
			}
			return (*Value)(slotVal)
		}
		i = (i + inc) & mask
		inc++
	}
}

// Store stores the Value val for key.
func (m *AtomicPtrMap) Store(key Key, val *Value) {
	m.maybeCompareAndSwap(key, false, nil, val)
}

// Swap stores the Value val for key and returns the previously-mapped Value.
func (m *AtomicPtrMap) Swap(key Key, val *Value) *Value {
	return m.maybeCompareAndSwap(key, false, nil, val)
}

// CompareAndSwap checks that the Value stored for key is oldVal; if it is, it
// stores the Value newVal for key. CompareAndSwap returns the previous Value
// stored for key, whether or not it stores newVal.
func (m *AtomicPtrMap) CompareAndSwap(key Key, oldVal, newVal *Value) *Value {
	return m.maybeCompareAndSwap(key, true, oldVal, newVal)
}

func (m *AtomicPtrMap) maybeCompareAndSwap(key Key, compare bool, typedOldVal, typedNewVal *Value) *Value {
	hash := hasher.Hash(key)
	shard := m.shard(hash)
	oldVal := tombstone()
	if typedOldVal != nil {
		oldVal = unsafe.Pointer(typedOldVal)
	}
	newVal := tombstone()
	if typedNewVal != nil {
		newVal = unsafe.Pointer(typedNewVal)
	}

retry:
	epoch := shard.seq.BeginRead()
	slots := atomic.LoadPointer(&shard.slots)
	mask := atomic.LoadUintptr(&shard.mask)
	if !shard.seq.ReadOk(epoch) {
		goto retry
	}
	if slots == nil {
		if (compare && oldVal != tombstone()) || newVal == tombstone() {
			return nil
		}
		// Need to allocate a table before insertion.
		shard.rehash(nil)
		goto retry
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := apmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {
			if (compare && oldVal != tombstone()) || newVal == tombstone() {
				return nil
			}
			// Try to grab this slot for ourselves.
			shard.dirtyMu.Lock()
			slotVal = atomic.LoadPointer(&slot.val)
			if slotVal == nil {
				// Check if we need to rehash before dirtying a slot.
				if dirty, capacity := shard.dirty+1, mask+1; dirty*apmRehashThresholdDen >= capacity*apmRehashThresholdNum {
					shard.dirtyMu.Unlock()
					shard.rehash(slots)
					goto retry
				}
				slot.key = key
				atomic.StorePointer(&slot.val, newVal) // transitions slot to full
				shard.dirty++
				atomic.AddUintptr(&shard.count, 1)
				shard.dirtyMu.Unlock()
				return nil
			}
			// Raced with another store; the slot is no longer empty. Continue
			// with the new value of slotVal since we may have raced with
			// another store of key.
			shard.dirtyMu.Unlock()
		}
		if slotVal == evacuated() {
			// Racing with rehashing.
			goto retry
		}
		if slot.key == key {
			// We're reusing an existing slot, so rehashing isn't necessary.
			for {
				if (compare && oldVal != slotVal) || newVal == slotVal {
					if slotVal == tombstone() {
						return nil
					}
					return (*Value)(slotVal)
				}
				if atomic.CompareAndSwapPointer(&slot.val, slotVal, newVal) {
					if slotVal == tombstone() {
						atomic.AddUintptr(&shard.count, 1)
						return nil
					}
					if newVal == tombstone() {
						atomic.AddUintptr(&shard.count, ^uintptr(0) /* -1 */)
					}
					return (*Value)(slotVal)
				}
				slotVal = atomic.LoadPointer(&slot.val)
				if slotVal == evacuated() {
					goto retry
				}
			}
		}
		// This produces a triangular number sequence of offsets from the
		// initially-probed position.
		i = (i + inc) & mask
		inc++
	}
}

// rehash is marked nosplit to avoid preemption during table copying.
//
//go:nosplit
func (shard *apmShard) rehash(oldSlots unsafe.Pointer) {
	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()

	if shard.slots != oldSlots {
		// Raced with another call to rehash().
		return
	}

	// Determine the size of the new table. Constraints:
	//
	//	* The size of the table must be a power of two to ensure that every slot
	//		is visitable by every probe sequence under quadratic probing with
	//		triangular numbers.
	//
	//	* The size of the table cannot decrease because even if shard.count is
	//		currently smaller than shard.dirty, concurrent stores that reuse
	//		existing slots can drive shard.count back up to a maximum of
	//		shard.dirty.
	newSize := uintptr(8) // arbitrary initial size
	if oldSlots != nil {
		oldSize := shard.mask + 1
		newSize = oldSize
		if count := atomic.LoadUintptr(&shard.count) + 1; count*apmExpansionThresholdDen > oldSize*apmExpansionThresholdNum {
			newSize *= 2
		}
	}

	// Allocate the new table.
	newSlotsSlice := make([]apmSlot, newSize)
	newSlotsHeader := (*gohacks.SliceHeader)(unsafe.Pointer(&newSlotsSlice))
	newSlots := newSlotsHeader.Data
	newMask := newSize - 1

	// Start a writer critical section now so that racing users of the old
	// table that observe evacuated() wait for the new table. (But lock dirtyMu
	// first since doing so may block, which we don't want to do during the
	// writer critical section.)
	shard.dirtyMu.Lock()
	shard.seq.BeginWrite()

	if oldSlots != nil {
		realCount := uintptr(0)
		// Copy old entries to the new table.
		oldMask := shard.mask
		for i := uintptr(0); i <= oldMask; i++ {
			oldSlot := apmSlotAt(oldSlots, i)
			val := atomic.SwapPointer(&oldSlot.val, evacuated())
			if val == nil || val == tombstone() {
				continue
			}
			hash := hasher.Hash(oldSlot.key)
			j := hash & newMask
			inc := uintptr(1)
			for {
				newSlot := apmSlotAt(newSlots, j)
				if newSlot.val == nil {
					newSlot.val = val
					newSlot.key = oldSlot.key
					break
				}
				j = (j + inc) & newMask
				inc++
			}
			realCount++
		}
		// Update dirty to reflect that tombstones were not copied to the new
		// table. Use realCount since a concurrent mutator may not have updated
		// shard.count yet.
		shard.dirty = realCount
	}

	// Switch to the new table.
	atomic.StorePointer(&shard.slots, newSlots)
	atomic.StoreUintptr(&shard.mask, newMask)

	shard.seq.EndWrite()
	shard.dirtyMu.Unlock()
}

// Range invokes f on each Key-Value pair stored in m. If any call to f returns
// false, Range stops iteration and returns.
//
// Range does not necessarily correspond to any consistent snapshot of the
// Map's contents: no Key will be visited more than once, but if the Value for
// any Key is stored or deleted concurrently, Range may reflect any mapping for
// that Key from any point during the Range call.
//
// f must not call other methods on m.
func (m *AtomicPtrMap) Range(f func(key Key, val *Value) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]
		if !shard.doRange(f) {
			return
		}
	}
}

func (shard *apmShard) doRange(f func(key Key, val *Value) bool) bool {
	// We have to lock rehashMu because if we handled races with rehashing by
	// retrying, f could see the same key twice.
	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()
	slots := shard.slots
	if slots == nil {
		return true
	}
	mask := shard.mask
	for i := uintptr(0); i <= mask; i++ {
		slot := apmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil || slotVal == tombstone() {
			continue
		}
		if !f(slot.key, (*Value)(slotVal)) {
			return false
		}
	}
	return true
}

// RangeRepeatable is like Range, but:
//
//   - RangeRepeatable may visit the same Key multiple times in the presence of
//     concurrent mutators, possibly passing different Values to f in different
//     calls.
//
//   - It is safe for f to call other methods on m.
func (m *AtomicPtrMap) RangeRepeatable(f func(key Key, val *Value) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]

	retry:
		epoch := shard.seq.BeginRead()
		slots := atomic.LoadPointer(&shard.slots)
		mask := atomic.LoadUintptr(&shard.mask)
		if !shard.seq.ReadOk(epoch) {
			goto retry
		}
		if slots == nil {
			continue
		}

		for i := uintptr(0); i <= mask; i++ {
			slot := apmSlotAt(slots, i)
			slotVal := atomic.LoadPointer(&slot.val)
			if slotVal == evacuated() {
				goto retry
			}
			if slotVal == nil || slotVal == tombstone() {
				continue
			}
			if !f(slot.key, (*Value)(slotVal)) {
				return
			}
		}
	}
}
