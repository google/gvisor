// Copyright 2018 Google Inc.
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
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Checker abstracts memory accesses. This is useful because the "addresses"
// used in this package may not be real addresses (they could be indices of an
// array, for example), or they could be mapped via some special mechanism.
//
// TODO: Replace this with usermem.IO.
type Checker interface {
	// Check should validate that given address contains the given value.
	// If it does not contain the value, syserror.EAGAIN must be returned.
	// Any other error may be returned, which will be propagated.
	Check(addr uintptr, val uint32) error

	// Op should atomically perform the operation encoded in op on the data
	// pointed to by addr, then apply the comparison encoded in op to the
	// original value at addr, returning the result.
	// Note that op is an opaque operation whose behaviour is defined
	// outside of the futex manager.
	Op(addr uintptr, op uint32) (bool, error)
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
	// waiterEntry, complete, and addr are protected by the bucket.mu ("bucket
	// lock") of the containing bucket, and bitmask is immutable. complete and
	// addr are additionally mutated using atomic memory operations, ensuring
	// that they can be read using atomic memory operations without holding the
	// bucket lock.
	//
	// - A Waiter is only guaranteed to be no longer queued after calling
	// WaitComplete().

	// waiterEntry links Waiter into bucket.waiters.
	waiterEntry

	// complete is 1 if the Waiter was removed from its bucket by a wakeup and
	// 0 otherwise.
	complete int32

	// C is sent to when the Waiter is woken.
	C chan struct{}

	// addr is the address being waited on.
	addr uintptr

	// The bitmask we're waiting on.
	// This is used the case of a FUTEX_WAKE_BITSET.
	bitmask uint32
}

// NewWaiter returns a new unqueued Waiter.
func NewWaiter() *Waiter {
	return &Waiter{
		C: make(chan struct{}, 1),
	}
}

// bucket holds a list of waiters for a given address hash.
type bucket struct {
	// mu protects waiters and contained Waiter state. See comment in Waiter.
	mu sync.Mutex `state:"nosave"`

	waiters waiterList `state:"zerovalue"`
}

// wakeLocked wakes up to n waiters matching the bitmask at the addr for this
// bucket and returns the number of waiters woken.
//
// Preconditions: b.mu must be locked.
func (b *bucket) wakeLocked(addr uintptr, bitmask uint32, n int) int {
	done := 0
	for w := b.waiters.Front(); done < n && w != nil; {
		if w.addr != addr || w.bitmask&bitmask == 0 {
			// Not matching.
			w = w.Next()
			continue
		}

		// Remove from the bucket and wake the waiter.
		woke := w
		w = w.Next() // Next iteration.
		b.waiters.Remove(woke)
		woke.C <- struct{}{}

		// NOTE: The above channel write establishes a write barrier
		// according to the memory model, so nothing may be ordered
		// around it. Since we've dequeued w and will never touch it
		// again, we can safely store 1 to w.complete here and allow
		// the WaitComplete() to short-circuit grabbing the bucket
		// lock. If they somehow miss the w.complete, we are still
		// holding the lock, so we can know that they won't dequeue w,
		// assume it's free and have the below operation afterwards.
		atomic.StoreInt32(&woke.complete, 1)
		done++
	}
	return done
}

// requeueLocked takes n waiters from the bucket and moves them to naddr on the
// bucket "to".
//
// Preconditions: b and to must be locked.
func (b *bucket) requeueLocked(to *bucket, addr, naddr uintptr, n int) int {
	done := 0
	for w := b.waiters.Front(); done < n && w != nil; {
		if w.addr != addr {
			// Not matching.
			w = w.Next()
			continue
		}

		requeued := w
		w = w.Next() // Next iteration.
		b.waiters.Remove(requeued)
		atomic.StoreUintptr(&requeued.addr, naddr)
		to.waiters.PushBack(requeued)
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

func checkAddr(addr uintptr) error {
	// Ensure the address is aligned.
	// It must be a DWORD boundary.
	if addr&0x3 != 0 {
		return syserror.EINVAL
	}

	return nil
}

// bucketIndexForAddr returns the index into Manager.buckets for addr.
func bucketIndexForAddr(addr uintptr) uintptr {
	// - The bottom 2 bits of addr must be 0, per checkAddr.
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
	h1 := (addr >> 2) + (addr >> 12) + (addr >> 22)
	h2 := (addr >> 32) + (addr >> 42)
	return (h1 + h2) % bucketCount
}

// Manager holds futex state for a single virtual address space.
//
// +stateify savable
type Manager struct {
	buckets [bucketCount]bucket `state:"zerovalue"`
}

// NewManager returns an initialized futex manager.
// N.B. we use virtual address to tag futexes, so it only works for private
// (within a single process) futex.
func NewManager() *Manager {
	return &Manager{}
}

// lockBucket returns a locked bucket for the given addr.
//
// Preconditions: checkAddr(addr) == nil.
func (m *Manager) lockBucket(addr uintptr) *bucket {
	b := &m.buckets[bucketIndexForAddr(addr)]
	b.mu.Lock()
	return b
}

// lockBuckets returns locked buckets for the given addrs.
//
// Preconditions: checkAddr(addr1) == checkAddr(addr2) == nil.
func (m *Manager) lockBuckets(addr1 uintptr, addr2 uintptr) (*bucket, *bucket) {
	i1 := bucketIndexForAddr(addr1)
	i2 := bucketIndexForAddr(addr2)
	b1 := &m.buckets[i1]
	b2 := &m.buckets[i2]

	// Ensure that buckets are locked in a consistent order (lowest index
	// first) to avoid circular locking.
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

// Wake wakes up to n waiters matching the bitmask on the given addr.
// The number of waiters woken is returned.
func (m *Manager) Wake(addr uintptr, bitmask uint32, n int) (int, error) {
	if err := checkAddr(addr); err != nil {
		return 0, err
	}

	b := m.lockBucket(addr)
	// This function is very hot; avoid defer.
	r := b.wakeLocked(addr, bitmask, n)
	b.mu.Unlock()
	return r, nil
}

func (m *Manager) doRequeue(c Checker, addr uintptr, val uint32, naddr uintptr, nwake int, nreq int) (int, error) {
	if err := checkAddr(addr); err != nil {
		return 0, err
	}
	if err := checkAddr(naddr); err != nil {
		return 0, err
	}

	b1, b2 := m.lockBuckets(addr, naddr)
	defer b1.mu.Unlock()
	if b2 != b1 {
		defer b2.mu.Unlock()
	}

	// Check our value.
	// This only applied for RequeueCmp().
	if c != nil {
		if err := c.Check(addr, val); err != nil {
			return 0, err
		}
	}

	// Wake the number required.
	done := b1.wakeLocked(addr, ^uint32(0), nwake)

	// Requeue the number required.
	b1.requeueLocked(b2, addr, naddr, nreq)

	return done, nil
}

// Requeue wakes up to nwake waiters on the given addr, and unconditionally
// requeues up to nreq waiters on naddr.
func (m *Manager) Requeue(addr uintptr, naddr uintptr, nwake int, nreq int) (int, error) {
	return m.doRequeue(nil, addr, 0, naddr, nwake, nreq)
}

// RequeueCmp atomically checks that the addr contains val (via the Checker),
// wakes up to nwake waiters on addr and then unconditionally requeues nreq
// waiters on naddr.
func (m *Manager) RequeueCmp(c Checker, addr uintptr, val uint32, naddr uintptr, nwake int, nreq int) (int, error) {
	return m.doRequeue(c, addr, val, naddr, nwake, nreq)
}

// WakeOp atomically applies op to the memory address addr2, wakes up to nwake1
// waiters unconditionally from addr1, and, based on the original value at addr2
// and a comparison encoded in op, wakes up to nwake2 waiters from addr2.
// It returns the total number of waiters woken.
func (m *Manager) WakeOp(c Checker, addr1 uintptr, addr2 uintptr, nwake1 int, nwake2 int, op uint32) (int, error) {
	if err := checkAddr(addr1); err != nil {
		return 0, err
	}
	if err := checkAddr(addr2); err != nil {
		return 0, err
	}

	b1, b2 := m.lockBuckets(addr1, addr2)

	done := 0
	cond, err := c.Op(addr2, op)
	if err == nil {
		// Wake up up to nwake1 entries from the first bucket.
		done = b1.wakeLocked(addr1, ^uint32(0), nwake1)

		// Wake up up to nwake2 entries from the second bucket if the
		// operation yielded true.
		if cond {
			done += b2.wakeLocked(addr2, ^uint32(0), nwake2)
		}
	}

	b1.mu.Unlock()
	if b2 != b1 {
		b2.mu.Unlock()
	}
	return done, err
}

// WaitPrepare atomically checks that addr contains val (via the Checker), then
// enqueues w to be woken by a send to w.C. If WaitPrepare returns nil, the
// Waiter must be subsequently removed by calling WaitComplete, whether or not
// a wakeup is received on w.C.
func (m *Manager) WaitPrepare(w *Waiter, c Checker, addr uintptr, val uint32, bitmask uint32) error {
	if err := checkAddr(addr); err != nil {
		return err
	}

	// Prepare the Waiter before taking the bucket lock.
	w.complete = 0
	select {
	case <-w.C:
	default:
	}
	w.addr = addr
	w.bitmask = bitmask

	b := m.lockBucket(addr)
	// This function is very hot; avoid defer.

	// Perform our atomic check.
	if err := c.Check(addr, val); err != nil {
		b.mu.Unlock()
		return err
	}

	// Add the waiter to the bucket.
	b.waiters.PushBack(w)

	b.mu.Unlock()
	return nil
}

// WaitComplete must be called when a Waiter previously added by WaitPrepare is
// no longer eligible to be woken.
func (m *Manager) WaitComplete(w *Waiter) {
	// Can we short-circuit acquiring the lock?
	// This is the happy path where a notification
	// was received and we don't need to dequeue this
	// waiter from any list (or take any locks).
	if atomic.LoadInt32(&w.complete) != 0 {
		return
	}

	// Take the bucket lock. Note that without holding the bucket lock, the
	// waiter is not guaranteed to stay in that bucket, so after we take the
	// bucket lock, we must ensure that the bucket hasn't changed: if it
	// happens to have changed, we release the old bucket lock and try again
	// with the new bucket; if it hasn't changed, we know it won't change now
	// because we hold the lock.
	var b *bucket
	for {
		addr := atomic.LoadUintptr(&w.addr)
		b = m.lockBucket(addr)
		// We still have to use an atomic load here, because if w was racily
		// requeued then w.addr is not protected by b.mu.
		if addr == atomic.LoadUintptr(&w.addr) {
			break
		}
		b.mu.Unlock()
	}

	// Remove waiter from the bucket. w.complete can only be stored with b.mu
	// locked, so this load doesn't need to use sync/atomic.
	if w.complete == 0 {
		b.waiters.Remove(w)
	}
	b.mu.Unlock()
}
