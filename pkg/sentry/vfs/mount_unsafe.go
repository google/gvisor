// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"fmt"
	"math/bits"
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

// mountKey represents the location at which a Mount is mounted. It is
// structurally identical to VirtualDentry, but stores its fields as
// unsafe.Pointer since mutators synchronize with VFS path traversal using
// seqcounts.
//
// This is explicitly not savable.
type mountKey struct {
	parent unsafe.Pointer // *Mount
	point  unsafe.Pointer // *Dentry
}

var (
	mountKeyHasher = sync.MapKeyHasher(map[mountKey]struct{}(nil))
	mountKeySeed   = sync.RandUintptr()
)

func (k *mountKey) hash() uintptr {
	return mountKeyHasher(gohacks.Noescape(unsafe.Pointer(k)), mountKeySeed)
}

func (mnt *Mount) parent() *Mount {
	return (*Mount)(atomic.LoadPointer(&mnt.key.parent))
}

func (mnt *Mount) point() *Dentry {
	return (*Dentry)(atomic.LoadPointer(&mnt.key.point))
}

func (mnt *Mount) getKey() VirtualDentry {
	return VirtualDentry{
		mount:  mnt.parent(),
		dentry: mnt.point(),
	}
}

// Invariant: mnt.key.parent == nil. vd.Ok().
func (mnt *Mount) setKey(vd VirtualDentry) {
	atomic.StorePointer(&mnt.key.parent, unsafe.Pointer(vd.mount))
	atomic.StorePointer(&mnt.key.point, unsafe.Pointer(vd.dentry))
}

// mountTable maps (mount parent, mount point) pairs to mounts. It supports
// efficient concurrent lookup, even in the presence of concurrent mutators
// (provided mutation is sufficiently uncommon).
//
// mountTable.Init() must be called on new mountTables before use.
type mountTable struct {
	// mountTable is implemented as a seqcount-protected hash table that
	// resolves collisions with linear probing, featuring Robin Hood insertion
	// and backward shift deletion. These minimize probe length variance,
	// significantly improving the performance of linear probing at high load
	// factors. (mountTable doesn't use bucketing, which is the other major
	// technique commonly used in high-performance hash tables; the efficiency
	// of bucketing is largely due to SIMD lookup, and Go lacks both SIMD
	// intrinsics and inline assembly, limiting the performance of this
	// approach.)

	seq sync.SeqCount `state:"nosave"`

	// size holds both length (number of elements) and capacity (number of
	// slots): capacity is stored as its base-2 log (referred to as order) in
	// the least significant bits of size, and length is stored in the
	// remaining bits. Go defines bit shifts >= width of shifted unsigned
	// operand as shifting to 0, which differs from x86's SHL, so the Go
	// compiler inserts a bounds check for each bit shift unless we mask order
	// anyway (cf. runtime.bucketShift()), and length isn't used by lookup;
	// thus this bit packing gets us more bits for the length (vs. storing
	// length and cap in separate uint32s) for ~free.
	size atomicbitops.Uint64

	slots unsafe.Pointer `state:"nosave"` // []mountSlot; never nil after Init
}

type mountSlot struct {
	// We don't store keys in slots; instead, we just check Mount.parent and
	// Mount.point directly. Any practical use of lookup will need to touch
	// Mounts anyway, and comparing hashes means that false positives are
	// extremely rare, so this isn't an extra cache line touch overall.
	value unsafe.Pointer // *Mount
	hash  uintptr
}

const (
	mtSizeOrderBits = 6 // log2 of pointer size in bits
	mtSizeOrderMask = (1 << mtSizeOrderBits) - 1
	mtSizeOrderOne  = 1
	mtSizeLenLSB    = mtSizeOrderBits
	mtSizeLenOne    = 1 << mtSizeLenLSB
	mtSizeLenNegOne = ^uint64(mtSizeOrderMask) // uint64(-1) << mtSizeLenLSB

	mountSlotBytes = unsafe.Sizeof(mountSlot{})
	mountKeyBytes  = unsafe.Sizeof(mountKey{})

	// Tuning parameters.
	//
	// Essentially every mountTable will contain at least /proc, /sys, and
	// /dev/shm, so there is ~no reason for mtInitCap to be < 4.
	mtInitOrder  = 2
	mtInitCap    = 1 << mtInitOrder
	mtMaxLoadNum = 13
	mtMaxLoadDen = 16
)

func init() {
	// We can't just define mtSizeOrderBits as follows because Go doesn't have
	// constexpr.
	if ptrBits := uint(unsafe.Sizeof(uintptr(0)) * 8); mtSizeOrderBits != bits.TrailingZeros(ptrBits) {
		panic(fmt.Sprintf("mtSizeOrderBits (%d) must be %d = log2 of pointer size in bits (%d)", mtSizeOrderBits, bits.TrailingZeros(ptrBits), ptrBits))
	}
	if bits.OnesCount(uint(mountSlotBytes)) != 1 {
		panic(fmt.Sprintf("sizeof(mountSlotBytes) (%d) must be a power of 2 to use bit masking for wraparound", mountSlotBytes))
	}
	if mtInitCap <= 1 {
		panic(fmt.Sprintf("mtInitCap (%d) must be at least 2 since mountTable methods assume that there will always be at least one empty slot", mtInitCap))
	}
	if mtMaxLoadNum >= mtMaxLoadDen {
		panic(fmt.Sprintf("invalid mountTable maximum load factor (%d/%d)", mtMaxLoadNum, mtMaxLoadDen))
	}
}

// Init must be called exactly once on each mountTable before use.
func (mt *mountTable) Init() {
	mt.size = atomicbitops.FromUint64(mtInitOrder)
	mt.slots = newMountTableSlots(mtInitCap)
}

func newMountTableSlots(cap uintptr) unsafe.Pointer {
	slice := make([]mountSlot, cap, cap)
	hdr := (*gohacks.SliceHeader)(unsafe.Pointer(&slice))
	return hdr.Data
}

// Lookup returns the Mount with the given parent, mounted at the given point.
// If no such Mount exists, Lookup returns nil.
//
// Lookup may be called even if there are concurrent mutators of mt.
func (mt *mountTable) Lookup(parent *Mount, point *Dentry) *Mount {
	key := mountKey{parent: unsafe.Pointer(parent), point: unsafe.Pointer(point)}
	hash := key.hash()

loop:
	for {
		epoch := mt.seq.BeginRead()
		size := mt.size.Load()
		slots := atomic.LoadPointer(&mt.slots)
		if !mt.seq.ReadOk(epoch) {
			continue
		}
		tcap := uintptr(1) << (size & mtSizeOrderMask)
		mask := tcap - 1
		off := (hash & mask) * mountSlotBytes
		offmask := mask * mountSlotBytes
		for {
			// This avoids bounds checking.
			slot := (*mountSlot)(unsafe.Pointer(uintptr(slots) + off))
			slotValue := atomic.LoadPointer(&slot.value)
			slotHash := atomic.LoadUintptr(&slot.hash)
			if !mt.seq.ReadOk(epoch) {
				// The element we're looking for might have been moved into a
				// slot we've previously checked, so restart entirely.
				continue loop
			}
			if slotValue == nil {
				return nil
			}
			if slotHash == hash {
				mount := (*Mount)(slotValue)
				var mountKey mountKey
				mountKey.parent = atomic.LoadPointer(&mount.key.parent)
				mountKey.point = atomic.LoadPointer(&mount.key.point)
				if !mt.seq.ReadOk(epoch) {
					continue loop
				}
				if key == mountKey {
					return mount
				}
			}
			off = (off + mountSlotBytes) & offmask
		}
	}
}

// Range calls f on each Mount in mt. If f returns false, Range stops iteration
// and returns immediately.
func (mt *mountTable) Range(f func(*Mount) bool) {
	tcap := uintptr(1) << (mt.size.Load() & mtSizeOrderMask)
	slotPtr := mt.slots
	last := unsafe.Pointer(uintptr(mt.slots) + ((tcap - 1) * mountSlotBytes))
	for {
		slot := (*mountSlot)(slotPtr)
		if slot.value != nil {
			if !f((*Mount)(slot.value)) {
				return
			}
		}
		if slotPtr == last {
			return
		}
		slotPtr = unsafe.Pointer(uintptr(slotPtr) + mountSlotBytes)
	}
}

// Insert inserts the given mount into mt.
//
// Preconditions: mt must not already contain a Mount with the same mount point
// and parent.
func (mt *mountTable) Insert(mount *Mount) {
	mt.seq.BeginWrite()
	mt.insertSeqed(mount)
	mt.seq.EndWrite()
}

// insertSeqed inserts the given mount into mt.
//
// Preconditions:
//   - mt.seq must be in a writer critical section.
//   - mt must not already contain a Mount with the same mount point and parent.
func (mt *mountTable) insertSeqed(mount *Mount) {
	hash := mount.key.hash()

	// We're under the maximum load factor if:
	//
	//          (len+1) / cap <= mtMaxLoadNum / mtMaxLoadDen
	// (len+1) * mtMaxLoadDen <= mtMaxLoadNum * cap
	tlen := mt.size.RacyLoad() >> mtSizeLenLSB
	order := mt.size.RacyLoad() & mtSizeOrderMask
	tcap := uintptr(1) << order
	if ((tlen + 1) * mtMaxLoadDen) <= (uint64(mtMaxLoadNum) << order) {
		// Atomically insert the new element into the table.
		mt.size.Add(mtSizeLenOne)
		mtInsertLocked(mt.slots, tcap, unsafe.Pointer(mount), hash)
		return
	}

	// Otherwise, we have to expand. Double the number of slots in the new
	// table.
	newOrder := order + 1
	if newOrder > mtSizeOrderMask {
		panic("mount table size overflow")
	}
	newCap := uintptr(1) << newOrder
	newSlots := newMountTableSlots(newCap)
	// Copy existing elements to the new table.
	oldCur := mt.slots
	// Go does not permit pointers to the end of allocated objects, so we
	// must use a pointer to the last element of the old table. The
	// following expression is equivalent to
	// `slots+(cap-1)*mountSlotBytes` but has a critical path length of 2
	// arithmetic instructions instead of 3.
	oldLast := unsafe.Pointer((uintptr(mt.slots) - mountSlotBytes) + (tcap * mountSlotBytes))
	for {
		oldSlot := (*mountSlot)(oldCur)
		if oldSlot.value != nil {
			mtInsertLocked(newSlots, newCap, oldSlot.value, oldSlot.hash)
		}
		if oldCur == oldLast {
			break
		}
		oldCur = unsafe.Pointer(uintptr(oldCur) + mountSlotBytes)
	}
	// Insert the new element into the new table.
	mtInsertLocked(newSlots, newCap, unsafe.Pointer(mount), hash)
	// Switch to the new table.
	mt.size.Add(mtSizeLenOne | mtSizeOrderOne)
	atomic.StorePointer(&mt.slots, newSlots)
}

// Preconditions:
//   - There are no concurrent mutators of the table (slots, cap).
//   - If the table is visible to readers, then mt.seq must be in a writer
//     critical section.
//   - cap must be a power of 2.
func mtInsertLocked(slots unsafe.Pointer, cap uintptr, value unsafe.Pointer, hash uintptr) {
	mask := cap - 1
	off := (hash & mask) * mountSlotBytes
	offmask := mask * mountSlotBytes
	disp := uintptr(0)
	for {
		slot := (*mountSlot)(unsafe.Pointer(uintptr(slots) + off))
		slotValue := slot.value
		if slotValue == nil {
			atomic.StorePointer(&slot.value, value)
			atomic.StoreUintptr(&slot.hash, hash)
			return
		}
		// If we've been displaced farther from our first-probed slot than the
		// element stored in this one, swap elements and switch to inserting
		// the replaced one. (This is Robin Hood insertion.)
		slotHash := slot.hash
		slotDisp := ((off / mountSlotBytes) - slotHash) & mask
		if disp > slotDisp {
			atomic.StorePointer(&slot.value, value)
			atomic.StoreUintptr(&slot.hash, hash)
			value = slotValue
			hash = slotHash
			disp = slotDisp
		}
		off = (off + mountSlotBytes) & offmask
		disp++
	}
}

// Remove removes the given mount from mt.
//
// Preconditions: mt must contain mount.
func (mt *mountTable) Remove(mount *Mount) {
	mt.seq.BeginWrite()
	mt.removeSeqed(mount)
	mt.seq.EndWrite()
}

// removeSeqed removes the given mount from mt.
//
// Preconditions:
//   - mt.seq must be in a writer critical section.
//   - mt must contain mount.
func (mt *mountTable) removeSeqed(mount *Mount) {
	hash := mount.key.hash()
	tcap := uintptr(1) << (mt.size.RacyLoad() & mtSizeOrderMask)
	mask := tcap - 1
	slots := mt.slots
	off := (hash & mask) * mountSlotBytes
	offmask := mask * mountSlotBytes
	for {
		slot := (*mountSlot)(unsafe.Pointer(uintptr(slots) + off))
		slotValue := slot.value
		if slotValue == unsafe.Pointer(mount) {
			// Found the element to remove. Move all subsequent elements
			// backward until we either find an empty slot, or an element that
			// is already in its first-probed slot. (This is backward shift
			// deletion.)
			for {
				nextOff := (off + mountSlotBytes) & offmask
				nextSlot := (*mountSlot)(unsafe.Pointer(uintptr(slots) + nextOff))
				nextSlotValue := nextSlot.value
				if nextSlotValue == nil {
					break
				}
				nextSlotHash := nextSlot.hash
				if (nextOff / mountSlotBytes) == (nextSlotHash & mask) {
					break
				}
				atomic.StorePointer(&slot.value, nextSlotValue)
				atomic.StoreUintptr(&slot.hash, nextSlotHash)
				off = nextOff
				slot = nextSlot
			}
			atomic.StorePointer(&slot.value, nil)
			mt.size.Add(mtSizeLenNegOne)
			return
		}
		if checkInvariants && slotValue == nil {
			panic(fmt.Sprintf("mountTable.Remove() called on missing Mount %v", mount))
		}
		off = (off + mountSlotBytes) & offmask
	}
}
