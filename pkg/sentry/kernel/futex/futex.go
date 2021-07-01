// Copyright 2018 The gVisor Authors.
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

// Package futex provides an implementation of the futex interface as found in
// the Linux kernel. It allows one to easily transform Wait() calls into waits
// on a channel, which is useful in a Go-based kernel, for example.
package futex

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// KeyKind indicates the type of a Key.
type KeyKind int

const (
	// KindPrivate indicates a private futex (a futex syscall with the
	// FUTEX_PRIVATE_FLAG set).
	KindPrivate KeyKind = iota

	// KindSharedPrivate indicates a shared futex on a private memory mapping.
	// Although KindPrivate and KindSharedPrivate futexes both use memory
	// addresses to identify futexes, they do not interoperate (in Linux, the
	// two are distinguished by the FUT_OFF_MMSHARED flag, which is used in key
	// comparison).
	KindSharedPrivate

	// KindSharedMappable indicates a shared futex on a memory mapping other
	// than a private anonymous memory mapping.
	KindSharedMappable
)

// Key represents something that a futex waiter may wait on.
type Key struct {
	// Kind is the type of the Key.
	Kind KeyKind

	// Mappable is the memory-mapped object that is represented by the Key.
	// Mappable is always nil if Kind is not KindSharedMappable, and may be nil
	// even if it is.
	Mappable memmap.Mappable

	// MappingIdentity is the MappingIdentity associated with Mappable.
	// MappingIdentity is always nil is Mappable is nil, and may be nil even if
	// it isn't.
	MappingIdentity memmap.MappingIdentity

	// If Kind is KindPrivate or KindSharedPrivate, Offset is the represented
	// memory address. Otherwise, Offset is the represented offset into
	// Mappable.
	Offset uint64
}

func (k *Key) release(t Target) {
	if k.MappingIdentity != nil {
		k.MappingIdentity.DecRef(t)
	}
	k.Mappable = nil
	k.MappingIdentity = nil
}

func (k *Key) clone() Key {
	if k.MappingIdentity != nil {
		k.MappingIdentity.IncRef()
	}
	return *k
}

// Preconditions: k.Kind == KindPrivate or KindSharedPrivate.
func (k *Key) addr() hostarch.Addr {
	return hostarch.Addr(k.Offset)
}

// matches returns true if a wakeup on k2 should wake a waiter waiting on k.
func (k *Key) matches(k2 *Key) bool {
	// k.MappingIdentity is ignored; it's only used for reference counting.
	return k.Kind == k2.Kind && k.Mappable == k2.Mappable && k.Offset == k2.Offset
}

// Target abstracts memory accesses and keys.
type Target interface {
	context.Context

	// SwapUint32 gives access to hostarch.IO.SwapUint32.
	SwapUint32(addr hostarch.Addr, new uint32) (uint32, error)

	// CompareAndSwap gives access to hostarch.IO.CompareAndSwapUint32.
	CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error)

	// LoadUint32 gives access to hostarch.IO.LoadUint32.
	LoadUint32(addr hostarch.Addr) (uint32, error)

	// GetSharedKey returns a Key with kind KindSharedPrivate or
	// KindSharedMappable corresponding to the memory mapped at address addr.
	//
	// If GetSharedKey returns a Key with a non-nil MappingIdentity, a
	// reference is held on the MappingIdentity, which must be dropped by the
	// caller when the Key is no longer in use.
	GetSharedKey(addr hostarch.Addr) (Key, error)
}

// check performs a basic equality check on the given address.
func check(t Target, addr hostarch.Addr, val uint32) error {
	cur, err := t.LoadUint32(addr)
	if err != nil {
		return err
	}
	if cur != val {
		return linuxerr.EAGAIN
	}
	return nil
}

// atomicOp performs a complex operation on the given address.
func atomicOp(t Target, addr hostarch.Addr, opIn uint32) (bool, error) {
	opType := (opIn >> 28) & 0xf
	cmp := (opIn >> 24) & 0xf
	opArg := (opIn >> 12) & 0xfff
	cmpArg := opIn & 0xfff

	if opType&linux.FUTEX_OP_OPARG_SHIFT != 0 {
		opArg = 1 << opArg
		opType &^= linux.FUTEX_OP_OPARG_SHIFT // Clear flag.
	}

	var (
		oldVal uint32
		err    error
	)
	if opType == linux.FUTEX_OP_SET {
		oldVal, err = t.SwapUint32(addr, opArg)
		if err != nil {
			return false, err
		}
	} else {
		for {
			oldVal, err = t.LoadUint32(addr)
			if err != nil {
				return false, err
			}
			var newVal uint32
			switch opType {
			case linux.FUTEX_OP_ADD:
				newVal = oldVal + opArg
			case linux.FUTEX_OP_OR:
				newVal = oldVal | opArg
			case linux.FUTEX_OP_ANDN:
				newVal = oldVal &^ opArg
			case linux.FUTEX_OP_XOR:
				newVal = oldVal ^ opArg
			default:
				return false, syserror.ENOSYS
			}
			prev, err := t.CompareAndSwapUint32(addr, oldVal, newVal)
			if err != nil {
				return false, err
			}
			if prev == oldVal {
				break // Success.
			}
		}
	}

	switch cmp {
	case linux.FUTEX_OP_CMP_EQ:
		return oldVal == cmpArg, nil
	case linux.FUTEX_OP_CMP_NE:
		return oldVal != cmpArg, nil
	case linux.FUTEX_OP_CMP_LT:
		return oldVal < cmpArg, nil
	case linux.FUTEX_OP_CMP_LE:
		return oldVal <= cmpArg, nil
	case linux.FUTEX_OP_CMP_GT:
		return oldVal > cmpArg, nil
	case linux.FUTEX_OP_CMP_GE:
		return oldVal >= cmpArg, nil
	default:
		return false, syserror.ENOSYS
	}
}

// Waiter is the struct which gets enqueued into buckets for wake up routines
// and requeue routines to scan and notify. Once a Waiter has been enqueued by
// WaitPrepare(), callers may listen on C for wake up events.
type Waiter struct {
	// Synchronization:
	//
	// - A Waiter that is not enqueued in a bucket is exclusively owned (no
	// synchronization applies).
	//
	// - A Waiter is enqueued in a bucket by calling WaitPrepare(). After this,
	// waiterEntry, bucket, and key are protected by the bucket.mu ("bucket
	// lock") of the containing bucket, and bitmask is immutable. Note that
	// since bucket is mutated using atomic memory operations, bucket.Load()
	// may be called without holding the bucket lock, although it may change
	// racily. See WaitComplete().
	//
	// - A Waiter is only guaranteed to be no longer queued after calling
	// WaitComplete().

	// waiterEntry links Waiter into bucket.waiters.
	waiterEntry

	// bucket is the bucket this waiter is queued in. If bucket is nil, the
	// waiter is not waiting and is not in any bucket.
	bucket AtomicPtrBucket

	// C is sent to when the Waiter is woken.
	C chan struct{}

	// key is what this waiter is waiting on.
	key Key

	// The bitmask we're waiting on.
	// This is used the case of a FUTEX_WAKE_BITSET.
	bitmask uint32

	// tid is the thread ID for the waiter in case this is a PI mutex.
	tid uint32
}

// NewWaiter returns a new unqueued Waiter.
func NewWaiter() *Waiter {
	return &Waiter{
		C: make(chan struct{}, 1),
	}
}

// woken returns true if w has been woken since the last call to WaitPrepare.
func (w *Waiter) woken() bool {
	return len(w.C) != 0
}

// bucket holds a list of waiters for a given address hash.
//
// +stateify savable
type bucket struct {
	// mu protects waiters and contained Waiter state. See comment in Waiter.
	mu sync.Mutex `state:"nosave"`

	waiters waiterList `state:"zerovalue"`
}

// wakeLocked wakes up to n waiters matching the bitmask at the addr for this
// bucket and returns the number of waiters woken.
//
// Preconditions: b.mu must be locked.
func (b *bucket) wakeLocked(key *Key, bitmask uint32, n int) int {
	done := 0
	for w := b.waiters.Front(); done < n && w != nil; {
		if !w.key.matches(key) || w.bitmask&bitmask == 0 {
			// Not matching.
			w = w.Next()
			continue
		}

		// Remove from the bucket and wake the waiter.
		woke := w
		w = w.Next() // Next iteration.
		b.wakeWaiterLocked(woke)
		done++
	}
	return done
}

func (b *bucket) wakeWaiterLocked(w *Waiter) {
	// Remove from the bucket and wake the waiter.
	b.waiters.Remove(w)
	w.C <- struct{}{}

	// NOTE: The above channel write establishes a write barrier according
	// to the memory model, so nothing may be ordered around it. Since
	// we've dequeued w and will never touch it again, we can safely
	// store nil to w.bucket here and allow the WaitComplete() to
	// short-circuit grabbing the bucket lock. If they somehow miss the
	// store, we are still holding the lock, so we can know that they won't
	// dequeue w, assume it's free and have the below operation
	// afterwards.
	w.bucket.Store(nil)
}

// requeueLocked takes n waiters from the bucket and moves them to naddr on the
// bucket "to".
//
// Preconditions: b and to must be locked.
func (b *bucket) requeueLocked(t Target, to *bucket, key, nkey *Key, n int) int {
	done := 0
	for w := b.waiters.Front(); done < n && w != nil; {
		if !w.key.matches(key) {
			// Not matching.
			w = w.Next()
			continue
		}

		requeued := w
		w = w.Next() // Next iteration.
		b.waiters.Remove(requeued)
		requeued.key.release(t)
		requeued.key = nkey.clone()
		to.waiters.PushBack(requeued)
		requeued.bucket.Store(to)
		done++
	}
	return done
}

const (
	// bucketCount is the number of buckets per Manager. By having many of
	// these we reduce contention when concurrent yet unrelated calls are made.
	bucketCount     = 1 << bucketCountBits
	bucketCountBits = 10
)

// getKey returns a Key representing address addr in c.
func getKey(t Target, addr hostarch.Addr, private bool) (Key, error) {
	// Ensure the address is aligned.
	// It must be a DWORD boundary.
	if addr&0x3 != 0 {
		return Key{}, linuxerr.EINVAL
	}
	if private {
		return Key{Kind: KindPrivate, Offset: uint64(addr)}, nil
	}
	return t.GetSharedKey(addr)
}

// bucketIndexForAddr returns the index into Manager.buckets for addr.
func bucketIndexForAddr(addr hostarch.Addr) uintptr {
	// - The bottom 2 bits of addr must be 0, per getKey.
	//
	// - On amd64, the top 16 bits of addr (bits 48-63) must be equal to bit 47
	// for a canonical address, and (on all existing platforms) bit 47 must be
	// 0 for an application address.
	//
	// Thus 19 bits of addr are "useless" for hashing, leaving only 45 "useful"
	// bits. We choose one of the simplest possible hash functions that at
	// least uses all 45 useful bits in the output, given that bucketCountBits
	// == 10. This hash function also has the property that it will usually map
	// adjacent addresses to adjacent buckets, slightly improving memory
	// locality when an application synchronization structure uses multiple
	// nearby futexes.
	//
	// Note that despite the large number of arithmetic operations in the
	// function, many components can be computed in parallel, such that the
	// critical path is 1 bit shift + 3 additions (2 in h1, then h1 + h2). This
	// is also why h1 and h2 are grouped separately; for "(addr >> 2) + ... +
	// (addr >> 42)" without any additional grouping, the compiler puts all 4
	// additions in the critical path.
	h1 := uintptr(addr>>2) + uintptr(addr>>12) + uintptr(addr>>22)
	h2 := uintptr(addr>>32) + uintptr(addr>>42)
	return (h1 + h2) % bucketCount
}

// Manager holds futex state for a single virtual address space.
//
// +stateify savable
type Manager struct {
	// privateBuckets holds buckets for KindPrivate and KindSharedPrivate
	// futexes.
	privateBuckets [bucketCount]bucket `state:"zerovalue"`

	// sharedBucket is the bucket for KindSharedMappable futexes. sharedBucket
	// may be shared by multiple Managers. The sharedBucket pointer is
	// immutable.
	sharedBucket *bucket
}

// NewManager returns an initialized futex manager.
func NewManager() *Manager {
	return &Manager{
		sharedBucket: &bucket{},
	}
}

// Fork returns a new Manager. Shared futex clients using the returned Manager
// may interoperate with those using m.
func (m *Manager) Fork() *Manager {
	return &Manager{
		sharedBucket: m.sharedBucket,
	}
}

// lockBucket returns a locked bucket for the given key.
func (m *Manager) lockBucket(k *Key) *bucket {
	var b *bucket
	if k.Kind == KindSharedMappable {
		b = m.sharedBucket
	} else {
		b = &m.privateBuckets[bucketIndexForAddr(k.addr())]
	}
	b.mu.Lock()
	return b
}

// lockBuckets returns locked buckets for the given keys.
func (m *Manager) lockBuckets(k1, k2 *Key) (*bucket, *bucket) {
	// Buckets must be consistently ordered to avoid circular lock
	// dependencies. We order buckets in m.privateBuckets by index (lowest
	// index first), and all buckets in m.privateBuckets precede
	// m.sharedBucket.

	// Handle the common case first:
	if k1.Kind != KindSharedMappable && k2.Kind != KindSharedMappable {
		i1 := bucketIndexForAddr(k1.addr())
		i2 := bucketIndexForAddr(k2.addr())
		b1 := &m.privateBuckets[i1]
		b2 := &m.privateBuckets[i2]
		switch {
		case i1 < i2:
			b1.mu.Lock()
			b2.mu.Lock()
		case i2 < i1:
			b2.mu.Lock()
			b1.mu.Lock()
		default:
			b1.mu.Lock()
		}
		return b1, b2
	}

	// At least one of b1 or b2 should be m.sharedBucket.
	b1 := m.sharedBucket
	b2 := m.sharedBucket
	if k1.Kind != KindSharedMappable {
		b1 = m.lockBucket(k1)
	} else if k2.Kind != KindSharedMappable {
		b2 = m.lockBucket(k2)
	}
	m.sharedBucket.mu.Lock()
	return b1, b2
}

// Wake wakes up to n waiters matching the bitmask on the given addr.
// The number of waiters woken is returned.
func (m *Manager) Wake(t Target, addr hostarch.Addr, private bool, bitmask uint32, n int) (int, error) {
	// This function is very hot; avoid defer.
	k, err := getKey(t, addr, private)
	if err != nil {
		return 0, err
	}

	b := m.lockBucket(&k)
	r := b.wakeLocked(&k, bitmask, n)

	b.mu.Unlock()
	k.release(t)
	return r, nil
}

func (m *Manager) doRequeue(t Target, addr, naddr hostarch.Addr, private bool, checkval bool, val uint32, nwake int, nreq int) (int, error) {
	k1, err := getKey(t, addr, private)
	if err != nil {
		return 0, err
	}
	defer k1.release(t)
	k2, err := getKey(t, naddr, private)
	if err != nil {
		return 0, err
	}
	defer k2.release(t)

	b1, b2 := m.lockBuckets(&k1, &k2)
	defer b1.mu.Unlock()
	if b2 != b1 {
		defer b2.mu.Unlock()
	}

	if checkval {
		if err := check(t, addr, val); err != nil {
			return 0, err
		}
	}

	// Wake the number required.
	done := b1.wakeLocked(&k1, ^uint32(0), nwake)

	// Requeue the number required.
	b1.requeueLocked(t, b2, &k1, &k2, nreq)

	return done, nil
}

// Requeue wakes up to nwake waiters on the given addr, and unconditionally
// requeues up to nreq waiters on naddr.
func (m *Manager) Requeue(t Target, addr, naddr hostarch.Addr, private bool, nwake int, nreq int) (int, error) {
	return m.doRequeue(t, addr, naddr, private, false, 0, nwake, nreq)
}

// RequeueCmp atomically checks that the addr contains val (via the Target),
// wakes up to nwake waiters on addr and then unconditionally requeues nreq
// waiters on naddr.
func (m *Manager) RequeueCmp(t Target, addr, naddr hostarch.Addr, private bool, val uint32, nwake int, nreq int) (int, error) {
	return m.doRequeue(t, addr, naddr, private, true, val, nwake, nreq)
}

// WakeOp atomically applies op to the memory address addr2, wakes up to nwake1
// waiters unconditionally from addr1, and, based on the original value at addr2
// and a comparison encoded in op, wakes up to nwake2 waiters from addr2.
// It returns the total number of waiters woken.
func (m *Manager) WakeOp(t Target, addr1, addr2 hostarch.Addr, private bool, nwake1 int, nwake2 int, op uint32) (int, error) {
	k1, err := getKey(t, addr1, private)
	if err != nil {
		return 0, err
	}
	defer k1.release(t)
	k2, err := getKey(t, addr2, private)
	if err != nil {
		return 0, err
	}
	defer k2.release(t)

	b1, b2 := m.lockBuckets(&k1, &k2)
	defer b1.mu.Unlock()
	if b2 != b1 {
		defer b2.mu.Unlock()
	}

	done := 0
	cond, err := atomicOp(t, addr2, op)
	if err != nil {
		return 0, err
	}

	// Wake up up to nwake1 entries from the first bucket.
	done = b1.wakeLocked(&k1, ^uint32(0), nwake1)

	// Wake up up to nwake2 entries from the second bucket if the
	// operation yielded true.
	if cond {
		done += b2.wakeLocked(&k2, ^uint32(0), nwake2)
	}

	return done, nil
}

// WaitPrepare atomically checks that addr contains val (via the Checker), then
// enqueues w to be woken by a send to w.C. If WaitPrepare returns nil, the
// Waiter must be subsequently removed by calling WaitComplete, whether or not
// a wakeup is received on w.C.
func (m *Manager) WaitPrepare(w *Waiter, t Target, addr hostarch.Addr, private bool, val uint32, bitmask uint32) error {
	k, err := getKey(t, addr, private)
	if err != nil {
		return err
	}
	// Ownership of k is transferred to w below.

	// Prepare the Waiter before taking the bucket lock.
	select {
	case <-w.C:
	default:
	}
	w.key = k
	w.bitmask = bitmask

	b := m.lockBucket(&k)
	// This function is very hot; avoid defer.

	// Perform our atomic check.
	if err := check(t, addr, val); err != nil {
		b.mu.Unlock()
		w.key.release(t)
		return err
	}

	// Add the waiter to the bucket.
	b.waiters.PushBack(w)
	w.bucket.Store(b)

	b.mu.Unlock()
	return nil
}

// WaitComplete must be called when a Waiter previously added by WaitPrepare is
// no longer eligible to be woken.
func (m *Manager) WaitComplete(w *Waiter, t Target) {
	// Remove w from the bucket it's in.
	for {
		b := w.bucket.Load()

		// If b is nil, the waiter isn't in any bucket anymore. This can't be
		// racy because the waiter can't be concurrently re-queued in another
		// bucket.
		if b == nil {
			break
		}

		// Take the bucket lock. Note that without holding the bucket lock, the
		// waiter is not guaranteed to stay in that bucket, so after we take
		// the bucket lock, we must ensure that the bucket hasn't changed: if
		// it happens to have changed, we release the old bucket lock and try
		// again with the new bucket; if it hasn't changed, we know it won't
		// change now because we hold the lock.
		b.mu.Lock()
		if b != w.bucket.Load() {
			b.mu.Unlock()
			continue
		}

		// Remove waiter from bucket.
		b.waiters.Remove(w)
		w.bucket.Store(nil)
		b.mu.Unlock()
		break
	}

	// Release references held by the waiter.
	w.key.release(t)
}

// LockPI attempts to lock the futex following the Priority-inheritance futex
// rules. The lock is acquired only when 'addr' points to 0. The TID of the
// calling task is set to 'addr' to indicate the futex is owned. It returns true
// if the futex was successfully acquired.
//
// FUTEX_OWNER_DIED is only set by the Linux when robust lists are in use (see
// exit_robust_list()). Given we don't support robust lists, although handled
// below, it's never set.
func (m *Manager) LockPI(w *Waiter, t Target, addr hostarch.Addr, tid uint32, private, try bool) (bool, error) {
	k, err := getKey(t, addr, private)
	if err != nil {
		return false, err
	}
	// Ownership of k is transferred to w below.

	// Prepare the Waiter before taking the bucket lock.
	select {
	case <-w.C:
	default:
	}
	w.key = k
	w.tid = tid

	b := m.lockBucket(&k)
	// Hot function: avoid defers.

	success, err := m.lockPILocked(w, t, addr, tid, b, try)
	if err != nil {
		w.key.release(t)
		b.mu.Unlock()
		return false, err
	}
	if success || try {
		// Release waiter if it's not going to be a wait.
		w.key.release(t)
	}
	b.mu.Unlock()
	return success, nil
}

func (m *Manager) lockPILocked(w *Waiter, t Target, addr hostarch.Addr, tid uint32, b *bucket, try bool) (bool, error) {
	for {
		cur, err := t.LoadUint32(addr)
		if err != nil {
			return false, err
		}
		if (cur & linux.FUTEX_TID_MASK) == tid {
			return false, linuxerr.EDEADLK
		}

		if (cur & linux.FUTEX_TID_MASK) == 0 {
			// No owner and no waiters, try to acquire the futex.

			// Set TID and preserve owner died status.
			val := tid
			val |= cur & linux.FUTEX_OWNER_DIED
			prev, err := t.CompareAndSwapUint32(addr, cur, val)
			if err != nil {
				return false, err
			}
			if prev != cur {
				// CAS failed, retry...
				// Linux reacquires the bucket lock on retries, which will re-lookup the
				// mapping at the futex address. However, retrying while holding the
				// lock is more efficient and reduces the chance of another conflict.
				continue
			}
			// Futex acquired.
			return true, nil
		}

		// Futex is already owned, prepare to wait.

		if try {
			// Caller doesn't want to wait.
			return false, nil
		}

		// Set waiters bit if not set yet.
		if cur&linux.FUTEX_WAITERS == 0 {
			prev, err := t.CompareAndSwapUint32(addr, cur, cur|linux.FUTEX_WAITERS)
			if err != nil {
				return false, err
			}
			if prev != cur {
				// CAS failed, retry...
				continue
			}
		}

		// Add the waiter to the bucket.
		b.waiters.PushBack(w)
		w.bucket.Store(b)
		return false, nil
	}
}

// UnlockPI unlocks the futex following the Priority-inheritance futex rules.
// The address provided must contain the caller's TID. If there are waiters,
// TID of the next waiter (FIFO) is set to the given address, and the waiter
// woken up. If there are no waiters, 0 is set to the address.
func (m *Manager) UnlockPI(t Target, addr hostarch.Addr, tid uint32, private bool) error {
	k, err := getKey(t, addr, private)
	if err != nil {
		return err
	}
	b := m.lockBucket(&k)

	err = m.unlockPILocked(t, addr, tid, b, &k)

	k.release(t)
	b.mu.Unlock()
	return err
}

func (m *Manager) unlockPILocked(t Target, addr hostarch.Addr, tid uint32, b *bucket, key *Key) error {
	cur, err := t.LoadUint32(addr)
	if err != nil {
		return err
	}

	if (cur & linux.FUTEX_TID_MASK) != tid {
		return linuxerr.EPERM
	}

	var next *Waiter  // Who's the next owner?
	var next2 *Waiter // Who's the one after that?
	for w := b.waiters.Front(); w != nil; w = w.Next() {
		if !w.key.matches(key) {
			continue
		}

		if next == nil {
			next = w
		} else {
			next2 = w
			break
		}
	}

	if next == nil {
		// It's safe to set 0 because there are no waiters, no new owner, and the
		// executing task is the current owner (no owner died bit).
		prev, err := t.CompareAndSwapUint32(addr, cur, 0)
		if err != nil {
			return err
		}
		if prev != cur {
			// Let user mode handle CAS races. This is different than lock, which
			// retries when CAS fails.
			return linuxerr.EAGAIN
		}
		return nil
	}

	// Set next owner's TID, waiters if there are any. Resets owner died bit, if
	// set, because the executing task takes over as the owner.
	val := next.tid
	if next2 != nil {
		val |= linux.FUTEX_WAITERS
	}

	prev, err := t.CompareAndSwapUint32(addr, cur, val)
	if err != nil {
		return err
	}
	if prev != cur {
		return linuxerr.EINVAL
	}

	b.wakeWaiterLocked(next)
	return nil
}
