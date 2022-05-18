package locking

import (
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// ShardOrder is an optional parameter specifying the base-2 log of the
	// number of shards per AtomicPtrMap. Higher values of ShardOrder reduce
	// unnecessary synchronization between unrelated concurrent operations,
	// improving performance for write-heavy workloads, but increase memory
	// usage for small maps.
	subclassShardOrder = 0
)

// Hasher is an optional type parameter. If Hasher is provided, it must define
// the Init and Hash methods. One Hasher will be shared by all AtomicPtrMaps.
type subclassHasher struct {
	subclassdefaultHasher
}

// defaultHasher is the default Hasher. This indirection exists because
// defaultHasher must exist even if a custom Hasher is provided, to prevent the
// Go compiler from complaining about defaultHasher's unused imports.
type subclassdefaultHasher struct {
	fn   func(unsafe.Pointer, uintptr) uintptr
	seed uintptr
}

// Init initializes the Hasher.
func (h *subclassdefaultHasher) Init() {
	h.fn = sync.MapKeyHasher(map[uint32]*MutexClass(nil))
	h.seed = sync.RandUintptr()
}

// Hash returns the hash value for the given Key.
func (h *subclassdefaultHasher) Hash(key uint32) uintptr {
	return h.fn(gohacks.Noescape(unsafe.Pointer(&key)), h.seed)
}

var subclasshasher subclassHasher

func init() {
	subclasshasher.Init()
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
type subclassAtomicPtrMap struct {
	shards [1 << subclassShardOrder]subclassapmShard
}

func (m *subclassAtomicPtrMap) shard(hash uintptr) *subclassapmShard {
	// Go defines right shifts >= width of shifted unsigned operand as 0, so
	// this is correct even if ShardOrder is 0 (although nogo complains because
	// nogo is dumb).
	const indexLSB = unsafe.Sizeof(uintptr(0))*8 - subclassShardOrder
	index := hash >> indexLSB
	return (*subclassapmShard)(unsafe.Pointer(uintptr(unsafe.Pointer(&m.shards)) + (index * unsafe.Sizeof(subclassapmShard{}))))
}

type subclassapmShard struct {
	subclassapmShardMutationData
	_ [subclassapmShardMutationDataPadding]byte
	subclassapmShardLookupData
	_ [subclassapmShardLookupDataPadding]byte
}

type subclassapmShardMutationData struct {
	dirtyMu  sync.Mutex // serializes slot transitions out of empty
	dirty    uintptr    // # slots with val != nil
	count    uintptr    // # slots with val != nil and val != tombstone()
	rehashMu sync.Mutex // serializes rehashing
}

type subclassapmShardLookupData struct {
	seq   sync.SeqCount  // allows atomic reads of slots+mask
	slots unsafe.Pointer // [mask+1]slot or nil; protected by rehashMu/seq
	mask  uintptr        // always (a power of 2) - 1; protected by rehashMu/seq
}

const (
	subclasscacheLineBytes = 64
	// Cache line padding is enabled if sharding is.
	subclassapmEnablePadding = (subclassShardOrder + 63) >> 6 // 0 if ShardOrder == 0, 1 otherwise
	// The -1 and +1 below are required to ensure that if unsafe.Sizeof(T) %
	// cacheLineBytes == 0, then padding is 0 (rather than cacheLineBytes).
	subclassapmShardMutationDataRequiredPadding = subclasscacheLineBytes - (((unsafe.Sizeof(subclassapmShardMutationData{}) - 1) % subclasscacheLineBytes) + 1)
	subclassapmShardMutationDataPadding         = subclassapmEnablePadding * subclassapmShardMutationDataRequiredPadding
	subclassapmShardLookupDataRequiredPadding   = subclasscacheLineBytes - (((unsafe.Sizeof(subclassapmShardLookupData{}) - 1) % subclasscacheLineBytes) + 1)
	subclassapmShardLookupDataPadding           = subclassapmEnablePadding * subclassapmShardLookupDataRequiredPadding

	// These define fractional thresholds for when apmShard.rehash() is called
	// (i.e. the load factor) and when it rehases to a larger table
	// respectively. They are chosen such that the rehash threshold = the
	// expansion threshold + 1/2, so that when reuse of deleted slots is rare
	// or non-existent, rehashing occurs after the insertion of at least 1/2
	// the table's size in new entries, which is acceptably infrequent.
	subclassapmRehashThresholdNum    = 2
	subclassapmRehashThresholdDen    = 3
	subclassapmExpansionThresholdNum = 1
	subclassapmExpansionThresholdDen = 6
)

type subclassapmSlot struct {
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
	key uint32
}

func subclassapmSlotAt(slots unsafe.Pointer, pos uintptr) *subclassapmSlot {
	return (*subclassapmSlot)(unsafe.Pointer(uintptr(slots) + pos*unsafe.Sizeof(subclassapmSlot{})))
}

var subclasstombstoneObj byte

func subclasstombstone() unsafe.Pointer {
	return unsafe.Pointer(&subclasstombstoneObj)
}

var subclassevacuatedObj byte

func subclassevacuated() unsafe.Pointer {
	return unsafe.Pointer(&subclassevacuatedObj)
}

// Load returns the Value stored in m for key.
func (m *subclassAtomicPtrMap) Load(key uint32) *MutexClass {
	hash := subclasshasher.Hash(key)
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
		slot := subclassapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {

			return nil
		}
		if slotVal == subclassevacuated() {

			goto retry
		}
		if slot.key == key {
			if slotVal == subclasstombstone() {
				return nil
			}
			return (*MutexClass)(slotVal)
		}
		i = (i + inc) & mask
		inc++
	}
}

// Store stores the Value val for key.
func (m *subclassAtomicPtrMap) Store(key uint32, val *MutexClass) {
	m.maybeCompareAndSwap(key, false, nil, val)
}

// Swap stores the Value val for key and returns the previously-mapped Value.
func (m *subclassAtomicPtrMap) Swap(key uint32, val *MutexClass) *MutexClass {
	return m.maybeCompareAndSwap(key, false, nil, val)
}

// CompareAndSwap checks that the Value stored for key is oldVal; if it is, it
// stores the Value newVal for key. CompareAndSwap returns the previous Value
// stored for key, whether or not it stores newVal.
func (m *subclassAtomicPtrMap) CompareAndSwap(key uint32, oldVal, newVal *MutexClass) *MutexClass {
	return m.maybeCompareAndSwap(key, true, oldVal, newVal)
}

func (m *subclassAtomicPtrMap) maybeCompareAndSwap(key uint32, compare bool, typedOldVal, typedNewVal *MutexClass) *MutexClass {
	hash := subclasshasher.Hash(key)
	shard := m.shard(hash)
	oldVal := subclasstombstone()
	if typedOldVal != nil {
		oldVal = unsafe.Pointer(typedOldVal)
	}
	newVal := subclasstombstone()
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
		if (compare && oldVal != subclasstombstone()) || newVal == subclasstombstone() {
			return nil
		}

		shard.rehash(nil)
		goto retry
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := subclassapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {
			if (compare && oldVal != subclasstombstone()) || newVal == subclasstombstone() {
				return nil
			}

			shard.dirtyMu.Lock()
			slotVal = atomic.LoadPointer(&slot.val)
			if slotVal == nil {

				if dirty, capacity := shard.dirty+1, mask+1; dirty*subclassapmRehashThresholdDen >= capacity*subclassapmRehashThresholdNum {
					shard.dirtyMu.Unlock()
					shard.rehash(slots)
					goto retry
				}
				slot.key = key
				atomic.StorePointer(&slot.val, newVal)
				shard.dirty++
				atomic.AddUintptr(&shard.count, 1)
				shard.dirtyMu.Unlock()
				return nil
			}

			shard.dirtyMu.Unlock()
		}
		if slotVal == subclassevacuated() {

			goto retry
		}
		if slot.key == key {

			for {
				if (compare && oldVal != slotVal) || newVal == slotVal {
					if slotVal == subclasstombstone() {
						return nil
					}
					return (*MutexClass)(slotVal)
				}
				if atomic.CompareAndSwapPointer(&slot.val, slotVal, newVal) {
					if slotVal == subclasstombstone() {
						atomic.AddUintptr(&shard.count, 1)
						return nil
					}
					if newVal == subclasstombstone() {
						atomic.AddUintptr(&shard.count, ^uintptr(0))
					}
					return (*MutexClass)(slotVal)
				}
				slotVal = atomic.LoadPointer(&slot.val)
				if slotVal == subclassevacuated() {
					goto retry
				}
			}
		}

		i = (i + inc) & mask
		inc++
	}
}

// rehash is marked nosplit to avoid preemption during table copying.
//
//go:nosplit
func (shard *subclassapmShard) rehash(oldSlots unsafe.Pointer) {
	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()

	if shard.slots != oldSlots {

		return
	}

	newSize := uintptr(8)
	if oldSlots != nil {
		oldSize := shard.mask + 1
		newSize = oldSize
		if count := atomic.LoadUintptr(&shard.count) + 1; count*subclassapmExpansionThresholdDen > oldSize*subclassapmExpansionThresholdNum {
			newSize *= 2
		}
	}

	newSlotsSlice := make([]subclassapmSlot, newSize)
	newSlotsHeader := (*gohacks.SliceHeader)(unsafe.Pointer(&newSlotsSlice))
	newSlots := newSlotsHeader.Data
	newMask := newSize - 1

	shard.dirtyMu.Lock()
	shard.seq.BeginWrite()

	if oldSlots != nil {
		realCount := uintptr(0)

		oldMask := shard.mask
		for i := uintptr(0); i <= oldMask; i++ {
			oldSlot := subclassapmSlotAt(oldSlots, i)
			val := atomic.SwapPointer(&oldSlot.val, subclassevacuated())
			if val == nil || val == subclasstombstone() {
				continue
			}
			hash := subclasshasher.Hash(oldSlot.key)
			j := hash & newMask
			inc := uintptr(1)
			for {
				newSlot := subclassapmSlotAt(newSlots, j)
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

		shard.dirty = realCount
	}

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
func (m *subclassAtomicPtrMap) Range(f func(key uint32, val *MutexClass) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]
		if !shard.doRange(f) {
			return
		}
	}
}

func (shard *subclassapmShard) doRange(f func(key uint32, val *MutexClass) bool) bool {

	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()
	slots := shard.slots
	if slots == nil {
		return true
	}
	mask := shard.mask
	for i := uintptr(0); i <= mask; i++ {
		slot := subclassapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil || slotVal == subclasstombstone() {
			continue
		}
		if !f(slot.key, (*MutexClass)(slotVal)) {
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
func (m *subclassAtomicPtrMap) RangeRepeatable(f func(key uint32, val *MutexClass) bool) {
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
			slot := subclassapmSlotAt(slots, i)
			slotVal := atomic.LoadPointer(&slot.val)
			if slotVal == subclassevacuated() {
				goto retry
			}
			if slotVal == nil || slotVal == subclasstombstone() {
				continue
			}
			if !f(slot.key, (*MutexClass)(slotVal)) {
				return
			}
		}
	}
}
