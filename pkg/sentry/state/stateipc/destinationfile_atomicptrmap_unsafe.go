package stateipc

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
	destinationFileShardOrder = 0
)

// defaultHasher is the default Hasher. This indirection exists because
// defaultHasher must exist even if a custom Hasher is provided, to prevent the
// Go compiler from complaining about defaultHasher's unused imports.
type destinationFiledefaultHasher struct {
	fn   func(unsafe.Pointer, uintptr) uintptr
	seed uintptr
}

// Init initializes the Hasher.
func (h *destinationFiledefaultHasher) Init() {
	h.fn = sync.MapKeyHasher(map[uint32]*destinationFile(nil))
	h.seed = sync.RandUintptr()
}

// Hash returns the hash value for the given Key.
func (h *destinationFiledefaultHasher) Hash(key uint32) uintptr {
	return h.fn(gohacks.Noescape(unsafe.Pointer(&key)), h.seed)
}

var destinationFilehasher clientFileHandleHasher

func init() {
	destinationFilehasher.Init()
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
type destinationFileAtomicPtrMap struct {
	shards [1 << destinationFileShardOrder]destinationFileapmShard
}

func (m *destinationFileAtomicPtrMap) shard(hash uintptr) *destinationFileapmShard {
	// Go defines right shifts >= width of shifted unsigned operand as 0, so
	// this is correct even if ShardOrder is 0 (although nogo complains because
	// nogo is dumb).
	const indexLSB = unsafe.Sizeof(uintptr(0))*8 - destinationFileShardOrder
	index := hash >> indexLSB
	return (*destinationFileapmShard)(unsafe.Pointer(uintptr(unsafe.Pointer(&m.shards)) + (index * unsafe.Sizeof(destinationFileapmShard{}))))
}

type destinationFileapmShard struct {
	destinationFileapmShardMutationData
	_ [destinationFileapmShardMutationDataPadding]byte
	destinationFileapmShardLookupData
	_ [destinationFileapmShardLookupDataPadding]byte
}

type destinationFileapmShardMutationData struct {
	dirtyMu  sync.Mutex // serializes slot transitions out of empty
	dirty    uintptr    // # slots with val != nil
	count    uintptr    // # slots with val != nil and val != tombstone()
	rehashMu sync.Mutex // serializes rehashing
}

type destinationFileapmShardLookupData struct {
	seq   sync.SeqCount  // allows atomic reads of slots+mask
	slots unsafe.Pointer // [mask+1]slot or nil; protected by rehashMu/seq
	mask  uintptr        // always (a power of 2) - 1; protected by rehashMu/seq
}

const (
	destinationFilecacheLineBytes = 64
	// Cache line padding is enabled if sharding is.
	destinationFileapmEnablePadding = (destinationFileShardOrder + 63) >> 6 // 0 if ShardOrder == 0, 1 otherwise
	// The -1 and +1 below are required to ensure that if unsafe.Sizeof(T) %
	// cacheLineBytes == 0, then padding is 0 (rather than cacheLineBytes).
	destinationFileapmShardMutationDataRequiredPadding = destinationFilecacheLineBytes - (((unsafe.Sizeof(destinationFileapmShardMutationData{}) - 1) % destinationFilecacheLineBytes) + 1)
	destinationFileapmShardMutationDataPadding         = destinationFileapmEnablePadding * destinationFileapmShardMutationDataRequiredPadding
	destinationFileapmShardLookupDataRequiredPadding   = destinationFilecacheLineBytes - (((unsafe.Sizeof(destinationFileapmShardLookupData{}) - 1) % destinationFilecacheLineBytes) + 1)
	destinationFileapmShardLookupDataPadding           = destinationFileapmEnablePadding * destinationFileapmShardLookupDataRequiredPadding

	// These define fractional thresholds for when apmShard.rehash() is called
	// (i.e. the load factor) and when it rehases to a larger table
	// respectively. They are chosen such that the rehash threshold = the
	// expansion threshold + 1/2, so that when reuse of deleted slots is rare
	// or non-existent, rehashing occurs after the insertion of at least 1/2
	// the table's size in new entries, which is acceptably infrequent.
	destinationFileapmRehashThresholdNum    = 2
	destinationFileapmRehashThresholdDen    = 3
	destinationFileapmExpansionThresholdNum = 1
	destinationFileapmExpansionThresholdDen = 6
)

type destinationFileapmSlot struct {
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

func destinationFileapmSlotAt(slots unsafe.Pointer, pos uintptr) *destinationFileapmSlot {
	return (*destinationFileapmSlot)(unsafe.Pointer(uintptr(slots) + pos*unsafe.Sizeof(destinationFileapmSlot{})))
}

var destinationFiletombstoneObj byte

func destinationFiletombstone() unsafe.Pointer {
	return unsafe.Pointer(&destinationFiletombstoneObj)
}

var destinationFileevacuatedObj byte

func destinationFileevacuated() unsafe.Pointer {
	return unsafe.Pointer(&destinationFileevacuatedObj)
}

// Load returns the Value stored in m for key.
func (m *destinationFileAtomicPtrMap) Load(key uint32) *destinationFile {
	hash := destinationFilehasher.Hash(key)
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
		slot := destinationFileapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {

			return nil
		}
		if slotVal == destinationFileevacuated() {

			goto retry
		}
		if slot.key == key {
			if slotVal == destinationFiletombstone() {
				return nil
			}
			return (*destinationFile)(slotVal)
		}
		i = (i + inc) & mask
		inc++
	}
}

// Store stores the Value val for key.
func (m *destinationFileAtomicPtrMap) Store(key uint32, val *destinationFile) {
	m.maybeCompareAndSwap(key, false, nil, val)
}

// Swap stores the Value val for key and returns the previously-mapped Value.
func (m *destinationFileAtomicPtrMap) Swap(key uint32, val *destinationFile) *destinationFile {
	return m.maybeCompareAndSwap(key, false, nil, val)
}

// CompareAndSwap checks that the Value stored for key is oldVal; if it is, it
// stores the Value newVal for key. CompareAndSwap returns the previous Value
// stored for key, whether or not it stores newVal.
func (m *destinationFileAtomicPtrMap) CompareAndSwap(key uint32, oldVal, newVal *destinationFile) *destinationFile {
	return m.maybeCompareAndSwap(key, true, oldVal, newVal)
}

func (m *destinationFileAtomicPtrMap) maybeCompareAndSwap(key uint32, compare bool, typedOldVal, typedNewVal *destinationFile) *destinationFile {
	hash := destinationFilehasher.Hash(key)
	shard := m.shard(hash)
	oldVal := destinationFiletombstone()
	if typedOldVal != nil {
		oldVal = unsafe.Pointer(typedOldVal)
	}
	newVal := destinationFiletombstone()
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
		if (compare && oldVal != destinationFiletombstone()) || newVal == destinationFiletombstone() {
			return nil
		}

		shard.rehash(nil)
		goto retry
	}

	i := hash & mask
	inc := uintptr(1)
	for {
		slot := destinationFileapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil {
			if (compare && oldVal != destinationFiletombstone()) || newVal == destinationFiletombstone() {
				return nil
			}

			shard.dirtyMu.Lock()
			slotVal = atomic.LoadPointer(&slot.val)
			if slotVal == nil {

				if dirty, capacity := shard.dirty+1, mask+1; dirty*destinationFileapmRehashThresholdDen >= capacity*destinationFileapmRehashThresholdNum {
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
		if slotVal == destinationFileevacuated() {

			goto retry
		}
		if slot.key == key {

			for {
				if (compare && oldVal != slotVal) || newVal == slotVal {
					if slotVal == destinationFiletombstone() {
						return nil
					}
					return (*destinationFile)(slotVal)
				}
				if atomic.CompareAndSwapPointer(&slot.val, slotVal, newVal) {
					if slotVal == destinationFiletombstone() {
						atomic.AddUintptr(&shard.count, 1)
						return nil
					}
					if newVal == destinationFiletombstone() {
						atomic.AddUintptr(&shard.count, ^uintptr(0))
					}
					return (*destinationFile)(slotVal)
				}
				slotVal = atomic.LoadPointer(&slot.val)
				if slotVal == destinationFileevacuated() {
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
func (shard *destinationFileapmShard) rehash(oldSlots unsafe.Pointer) {
	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()

	if shard.slots != oldSlots {

		return
	}

	newSize := uintptr(8)
	if oldSlots != nil {
		oldSize := shard.mask + 1
		newSize = oldSize
		if count := atomic.LoadUintptr(&shard.count) + 1; count*destinationFileapmExpansionThresholdDen > oldSize*destinationFileapmExpansionThresholdNum {
			newSize *= 2
		}
	}

	newSlotsSlice := make([]destinationFileapmSlot, newSize)
	newSlots := unsafe.Pointer(&newSlotsSlice[0])
	newMask := newSize - 1

	shard.dirtyMu.Lock()
	shard.seq.BeginWrite()

	if oldSlots != nil {
		realCount := uintptr(0)

		oldMask := shard.mask
		for i := uintptr(0); i <= oldMask; i++ {
			oldSlot := destinationFileapmSlotAt(oldSlots, i)
			val := atomic.SwapPointer(&oldSlot.val, destinationFileevacuated())
			if val == nil || val == destinationFiletombstone() {
				continue
			}
			hash := destinationFilehasher.Hash(oldSlot.key)
			j := hash & newMask
			inc := uintptr(1)
			for {
				newSlot := destinationFileapmSlotAt(newSlots, j)
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
func (m *destinationFileAtomicPtrMap) Range(f func(key uint32, val *destinationFile) bool) {
	for si := 0; si < len(m.shards); si++ {
		shard := &m.shards[si]
		if !shard.doRange(f) {
			return
		}
	}
}

func (shard *destinationFileapmShard) doRange(f func(key uint32, val *destinationFile) bool) bool {

	shard.rehashMu.Lock()
	defer shard.rehashMu.Unlock()
	slots := shard.slots
	if slots == nil {
		return true
	}
	mask := shard.mask
	for i := uintptr(0); i <= mask; i++ {
		slot := destinationFileapmSlotAt(slots, i)
		slotVal := atomic.LoadPointer(&slot.val)
		if slotVal == nil || slotVal == destinationFiletombstone() {
			continue
		}
		if !f(slot.key, (*destinationFile)(slotVal)) {
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
func (m *destinationFileAtomicPtrMap) RangeRepeatable(f func(key uint32, val *destinationFile) bool) {
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
			slot := destinationFileapmSlotAt(slots, i)
			slotVal := atomic.LoadPointer(&slot.val)
			if slotVal == destinationFileevacuated() {
				goto retry
			}
			if slotVal == nil || slotVal == destinationFiletombstone() {
				continue
			}
			if !f(slot.key, (*destinationFile)(slotVal)) {
				return
			}
		}
	}
}
