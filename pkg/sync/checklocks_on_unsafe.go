// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build checklocks

package sync

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"gvisor.dev/gvisor/pkg/goid"
)

// Lock order checking.
//
// This file implements lock order checking. That is, verifying that locks are
// taken in an application defined order. The mechanism for this is simple:
//
// 1. Locks are assigned a ranking with SetRank at initialization. Rank values
// should be statically assigned by the developer such that locks with higher
// rank are taken after locks with lower rank.
//
// 2. When a lock is taken, the lock and its rank are recorded. The new lock's
// rank is compared against previous locks' to ensure the next lock is of
// higher rank. If not, we have an ordering problem.
//
// This mechanism requires that locks are locked and unlocked on the same
// goroutine to allow for tracking which locks are still held. We detect
// violations of this invariant as well.

// lockRank is the internal type for a lock rank. A named type is used so that
// !checklocks builds can use a zero-size field (see checklocks_off_unsafe.go).
type lockRank struct {
	// val is the rank of the lock.
	val int32

	// recursive indicates that multiple locks of this rank may be taken.
	// i.e., following locks must have rank >= val, rather than rank > val
	// for non-recursive lock ranks.
	recursive bool
}

const (
	// recordLockStack enables recording the lock call stack trace for more
	// detailed reports.
	//
	// This is a number so it can be used to adjust the size of gLock.pcs.
	recordLockStack = 1

	// enforceLeaf enables enforcement of leaf lock ordering.
	//
	// When enabled, leaf locks (i.e., locks that don't specify a rank)
	// must be taken after all other locks. This includes ensuring that two
	// leaf locks are not taken one after another.
	//
	// When disabled, leaf locks are ignored when performing checks.
	//
	// This should be disabled when the application has not yet assigned
	// ranks to all locks.
	enforceLeaf = false

	// lockRankLeaf is the implicit rank of leaf locks. Leaf locks must be
	// taken after all other locks. Zero-value Mutex/RWMutex have leaf
	// rank.
	lockRankLeaf = math.MaxInt32
)

func init() {
	RegisterRank(lockRankLeaf, "LEAF")
}

// SetRank sets the ranking of this mutex for lock order checking.
//
// SetRank is a no-op when lock order checking is disabled.
//
// Preconditions:
// * Must be called before first use of the mutex.
func (m *Mutex) SetRank(rank int32) {
	m.rank = lockRank{
		val:       rank,
		recursive: false,
	}
}

// SetRankRecursive sets the ranking of this mutex for lock order checking, and
// marks the rank as recursive.
//
// A "recursive" lock rank allows multiple locks of the same rank to be taken.
// i.e., following locks must have rank >= prev, rather than rank > prev. Note
// that recursive lock ranks still need a defined lock ordering to avoid
// deadlocks (e.g., lock in address order, or parent before child), but
// checklocks will not enforce these more complex mechanisms.
//
// SetRankRecursive is a no-op when lock order checking is disabled.
//
// Preconditions:
// * Must be called before first use of the mutex.
func (m *Mutex) SetRankRecursive(rank int32) {
	m.rank = lockRank{
		val:       rank,
		recursive: true,
	}
}

// SetRank sets the ranking of this mutex for lock order checking.
//
// SetRank is a no-op when lock order checking is disabled.
//
// Preconditions:
// * Must be called before first use of the mutex.
func (rw *RWMutex) SetRank(rank int32) {
	rw.rank = lockRank{
		val:       rank,
		recursive: false,
	}
}

// SetRankRecursive sets the ranking of this mutex for lock order checking, and
// marks the rank as recursive.
//
// A "recursive" lock rank allows multiple locks of the same rank to be taken.
// i.e., following locks must have rank >= prev, rather than rank > prev. Note
// that recursive lock ranks still need a defined lock ordering to avoid
// deadlocks (e.g., lock in address order, or parent before child), but
// checklocks will not enforce these more complex mechanisms.
//
// SetRankRecursive is a no-op when lock order checking is disabled.
//
// Preconditions:
// * Must be called before first use of the mutex.
func (rw *RWMutex) SetRankRecursive(rank int32) {
	rw.rank = lockRank{
		val:       rank,
		recursive: true,
	}
}

// rankNames contains the human-readable names for lock ranks.
var rankNames = make(map[int32]string)

// RegisterRank registers a lock type name with specified rank.
//
// Registration is not strictly required for lock rank checking, but it
// provides naming in reports and verifies that there are no rank conflicts.

// RegisterRank is a no-op when lock order checking is disabled.
//
// Preconditions:
// * RegisterRank is only called during initialization.
func RegisterRank(rank int32, name string) {
	if rank == 0 {
		panic("Rank 0 is reserved for zero-value leaf mutexes")
	}
	if n, ok := rankNames[rank]; ok {
		panic(fmt.Sprintf("Rank conflict: %q and %q both registered as rank %d", n, name, rank))
	}
	rankNames[rank] = name
}

// gLock describes a single lock held by a goroutine.
type gLock struct {
	addr unsafe.Pointer
	rank lockRank

	// pcs is the call stack that locked this lock.
	pcs [16 * recordLockStack]uintptr
}

func (l gLock) String() string {
	name, ok := rankNames[l.rank.val]
	if !ok {
		name = "UNKNOWN"
	}

	rs := ""
	if l.rank.recursive {
		rs = ", recursive"
	}
	var s strings.Builder
	fmt.Fprintf(&s, "%s (rank %d%s): %p", name, l.rank.val, rs, l.addr)

	if recordLockStack == 1 {
		frames := runtime.CallersFrames(l.pcs[:])
		for {
			frame, more := frames.Next()

			fmt.Fprintf(&s, "\n\t%s()\n\t\t%s:%d", frame.Function, frame.File, frame.Line)

			if !more {
				break
			}
		}
	}

	return s.String()
}

// gLocks contains metadata about the locks held by a goroutine.
type gLocks struct {
	locksHeld []gLock
}

// map[goid int]*gLocks
//
// Each key may only be written by the G with the goid it refers to.
//
// Note that entries are not evicted when a G exit, causing unbounded growth
// with new G creation / destruction. If this proves problematic, entries could
// be evicted when no locks are held at the expense of more allocations when
// taking top-level locks.
var locksHeld sync.Map

// getGLocks returns the lock metadata for the calling goroutine.
func getGLocks() *gLocks {
	id := goid.Get()

	var locks *gLocks
	if l, ok := locksHeld.Load(id); ok {
		locks = l.(*gLocks)
	} else {
		locks = &gLocks{
			// Initialize space for a few locks.
			locksHeld: make([]gLock, 0, 8),
		}
		locksHeld.Store(id, locks)
	}

	return locks
}

// checkRank panics if next is not ordered after prev.
func checkRank(locks *gLocks, prev, next gLock) {
	if !enforceLeaf && next.rank.val == lockRankLeaf {
		// Ignore leaf locks.
		return
	}

	if prev.rank.val < next.rank.val {
		// Next lock is higher rank, we're fine.
		return
	} else if next.rank.recursive && prev.rank.val == next.rank.val {
		// Recursive lock OK.
		return
	}

	var s strings.Builder
	s.WriteString("lock ordering problem:")

	var i int
	for i = 0; i < len(locks.locksHeld); i++ {
		lock := locks.locksHeld[i]
		fmt.Fprintf(&s, "\n%d: %s", i, lock)
	}
	fmt.Fprintf(&s, "\n%d: %s", i, next)

	panic(s.String())
}

// noteLock records a lock of l with specified rank.
//
// noteLock panics if this is an invalid lock.
func noteLock(l unsafe.Pointer, rank lockRank) {
	locks := getGLocks()

	// Locks without initialized rank are considered leaves.
	if rank.val == 0 {
		rank.val = lockRankLeaf
	}

	lock := gLock{
		addr: l,
		rank: rank,
	}
	if recordLockStack == 1 {
		// skip 2 for Callers and noteLock.
		runtime.Callers(2, lock.pcs[:])
	}

	if len(locks.locksHeld) > 0 {
		prev := locks.locksHeld[len(locks.locksHeld)-1]
		if enforceLeaf {
			checkRank(locks, prev, lock)
		} else {
			// Only check against previous non-leaf lock.
			for i := len(locks.locksHeld) - 1; i >= 0; i-- {
				prev = locks.locksHeld[i]
				if prev.rank.val != lockRankLeaf {
					break
				}
			}
			if prev.rank.val != lockRankLeaf {
				checkRank(locks, prev, lock)
			}
		}
	}

	// Commit only after checking for panic conditions so that this lock
	// isn't on the list if the above panic is recovered.
	locks.locksHeld = append(locks.locksHeld, lock)
}

// noteUnlock records an unlock of l.
//
// noteUnlock panics if this is an invalid unlock.
func noteUnlock(l unsafe.Pointer) {
	locks := getGLocks()

	if len(locks.locksHeld) == 0 {
		panic(fmt.Sprintf("Unlock of %p on goroutine %d without any locks held! All locks:\n%s", l, goid.Get(), dumpLocks()))
	}

	// Search backwards since callers are most likely to unlock in LIFO order.
	length := len(locks.locksHeld)
	for i := length - 1; i >= 0; i-- {
		if l == locks.locksHeld[i].addr {
			copy(locks.locksHeld[i:length-1], locks.locksHeld[i+1:length])
			// Clear last entry to ensure addr can be GC'd.
			locks.locksHeld[length-1] = gLock{}
			locks.locksHeld = locks.locksHeld[:length-1]
			return
		}
	}

	panic(fmt.Sprintf("Unlock of %p on goroutine %d without matching lock! All locks:\n%s", l, goid.Get(), dumpLocks()))
}

// dumpLocks returns all locks held by all goroutines.
func dumpLocks() string {
	var s strings.Builder
	locksHeld.Range(func(key, value interface{}) bool {
		goid := key.(int64)
		locks := value.(*gLocks)

		// N.B. accessing gLocks of another G is fundamentally racy.

		fmt.Fprintf(&s, "goroutine %d:\n", goid)
		if len(locks.locksHeld) == 0 {
			fmt.Fprintf(&s, "\t<none>\n")
		}
		for _, lock := range locks.locksHeld {
			fmt.Fprintf(&s, "\t%s\n", lock)
		}
		fmt.Fprintf(&s, "\n")

		return true
	})

	return s.String()
}
