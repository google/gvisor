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

// Package lock is the API for POSIX-style advisory regional file locks and
// BSD-style full file locks.
//
// Callers needing to enforce these types of locks, like sys_fcntl, can call
// LockRegion and UnlockRegion on a thread-safe set of Locks.  Locks are
// specific to a unique file (unique device/inode pair) and for this reason
// should not be shared between files.
//
// A Lock has a set of holders identified by UniqueID.  Normally this is the
// pid of the thread attempting to acquire the lock.
//
// Since these are advisory locks, they do not need to be integrated into
// Reads/Writes and for this reason there is no way to *check* if a lock is
// held.  One can only attempt to take a lock or unlock an existing lock.
//
// A Lock in a set of Locks is typed: it is either a read lock with any number
// of readers and no writer, or a write lock with no readers.
//
// As expected from POSIX, any attempt to acquire a write lock on a file region
// when there already exits a write lock held by a different uid will fail. Any
// attempt to acquire a write lock on a file region when there is more than one
// reader will fail.  Any attempt to acquire a read lock on a file region when
// there is already a writer will fail.
//
// In special cases, a read lock may be upgraded to a write lock and a write lock
// can be downgraded to a read lock.  This can only happen if:
//
//  * read lock upgrade to write lock: There can be only one reader and the reader
//    must be the same as the requested write lock holder.
//
//  * write lock downgrade to read lock: The writer must be the same as the requested
//    read lock holder.
//
// UnlockRegion always succeeds.  If LockRegion fails the caller should normally
// interpret this as "try again later".
package lock

import (
	"fmt"
	"math"
	"syscall"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LockType is a type of regional file lock.
type LockType int

// UniqueID is a unique identifier of the holder of a regional file lock.
type UniqueID interface{}

const (
	// ReadLock describes a POSIX regional file lock to be taken
	// read only.  There may be multiple of these locks on a single
	// file region as long as there is no writer lock on the same
	// region.
	ReadLock LockType = iota

	// WriteLock describes a POSIX regional file lock to be taken
	// write only.  There may be only a single holder of this lock
	// and no read locks.
	WriteLock
)

// LockEOF is the maximal possible end of a regional file lock.
//
// A BSD-style full file lock can be represented as a regional file lock from
// offset 0 to LockEOF.
const LockEOF = math.MaxUint64

// Lock is a regional file lock.  It consists of either a single writer
// or a set of readers.
//
// A Lock may be upgraded from a read lock to a write lock only if there
// is a single reader and that reader has the same uid as the write lock.
//
// A Lock may be downgraded from a write lock to a read lock only if
// the write lock's uid is the same as the read lock.
//
// +stateify savable
type Lock struct {
	// Readers are the set of read lock holders identified by UniqueID.
	// If len(Readers) > 0 then HasWriter must be false.
	Readers map[UniqueID]bool

	// Writer holds the writer unique ID. It's nil if there are no writers.
	Writer UniqueID
}

// Locks is a thread-safe wrapper around a LockSet.
//
// +stateify savable
type Locks struct {
	// mu protects locks below.
	mu sync.Mutex `state:"nosave"`

	// locks is the set of region locks currently held on an Inode.
	locks LockSet

	// blockedQueue is the queue of waiters that are waiting on a lock.
	blockedQueue waiter.Queue `state:"zerovalue"`
}

// Blocker is the interface used for blocking locks. Passing a nil Blocker
// will be treated as non-blocking.
type Blocker interface {
	Block(C <-chan struct{}) error
}

const (
	// EventMaskAll is the mask we will always use for locks, by using the
	// same mask all the time we can wake up everyone anytime the lock
	// changes state.
	EventMaskAll waiter.EventMask = 0xFFFF
)

// LockRegion attempts to acquire a typed lock for the uid on a region
// of a file. Returns true if successful in locking the region. If false
// is returned, the caller should normally interpret this as "try again later" if
// acquiring the lock in a non-blocking mode or "interrupted" if in a blocking mode.
// Blocker is the interface used to provide blocking behavior, passing a nil Blocker
// will result in non-blocking behavior.
func (l *Locks) LockRegion(uid UniqueID, t LockType, r LockRange, block Blocker) bool {
	for {
		l.mu.Lock()

		// Blocking locks must run in a loop because we'll be woken up whenever an unlock event
		// happens for this lock. We will then attempt to take the lock again and if it fails
		// continue blocking.
		res := l.locks.lock(uid, t, r)
		if !res && block != nil {
			e, ch := waiter.NewChannelEntry(nil)
			l.blockedQueue.EventRegister(&e, EventMaskAll)
			l.mu.Unlock()
			if err := block.Block(ch); err != nil {
				// We were interrupted, the caller can translate this to EINTR if applicable.
				l.blockedQueue.EventUnregister(&e)
				return false
			}
			l.blockedQueue.EventUnregister(&e)
			continue // Try again now that someone has unlocked.
		}

		l.mu.Unlock()
		return res
	}
}

// UnlockRegion attempts to release a lock for the uid on a region of a file.
// This operation is always successful, even if there did not exist a lock on
// the requested region held by uid in the first place.
func (l *Locks) UnlockRegion(uid UniqueID, r LockRange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locks.unlock(uid, r)

	// Now that we've released the lock, we need to wake up any waiters.
	l.blockedQueue.Notify(EventMaskAll)
}

// makeLock returns a new typed Lock that has either uid as its only reader
// or uid as its only writer.
func makeLock(uid UniqueID, t LockType) Lock {
	value := Lock{Readers: make(map[UniqueID]bool)}
	switch t {
	case ReadLock:
		value.Readers[uid] = true
	case WriteLock:
		value.Writer = uid
	default:
		panic(fmt.Sprintf("makeLock: invalid lock type %d", t))
	}
	return value
}

// isHeld returns true if uid is a holder of Lock.
func (l Lock) isHeld(uid UniqueID) bool {
	return l.Writer == uid || l.Readers[uid]
}

// lock sets uid as a holder of a typed lock on Lock.
//
// Preconditions: canLock is true for the range containing this Lock.
func (l *Lock) lock(uid UniqueID, t LockType) {
	switch t {
	case ReadLock:
		// If we are already a reader, then this is a no-op.
		if l.Readers[uid] {
			return
		}
		// We cannot downgrade a write lock to a read lock unless the
		// uid is the same.
		if l.Writer != nil {
			if l.Writer != uid {
				panic(fmt.Sprintf("lock: cannot downgrade write lock to read lock for uid %d, writer is %d", uid, l.Writer))
			}
			// Ensure that there is only one reader if upgrading.
			l.Readers = make(map[UniqueID]bool)
			// Ensure that there is no longer a writer.
			l.Writer = nil
		}
		l.Readers[uid] = true
		return
	case WriteLock:
		// If we are already the writer, then this is a no-op.
		if l.Writer == uid {
			return
		}
		// We can only upgrade a read lock to a write lock if there
		// is only one reader and that reader has the same uid as
		// the write lock.
		if readers := len(l.Readers); readers > 0 {
			if readers != 1 {
				panic(fmt.Sprintf("lock: cannot upgrade read lock to write lock for uid %d, too many readers %v", uid, l.Readers))
			}
			if !l.Readers[uid] {
				panic(fmt.Sprintf("lock: cannot upgrade read lock to write lock for uid %d, conflicting reader %v", uid, l.Readers))
			}
		}
		// Ensure that there is only a writer.
		l.Readers = make(map[UniqueID]bool)
		l.Writer = uid
	default:
		panic(fmt.Sprintf("lock: invalid lock type %d", t))
	}
}

// lockable returns true if check returns true for every Lock in LockRange.
// Further, check should return true if Lock meets the callers requirements
// for locking Lock.
func (l LockSet) lockable(r LockRange, check func(value Lock) bool) bool {
	// Get our starting point.
	seg := l.LowerBoundSegment(r.Start)
	for seg.Ok() && seg.Start() < r.End {
		// Note that we don't care about overruning the end of the
		// last segment because if everything checks out we'll just
		// split the last segment.
		if !check(seg.Value()) {
			return false
		}
		// Jump to the next segment, ignoring gaps, for the same
		// reason we ignored the first gap.
		seg = seg.NextSegment()
	}
	// No conflict, we can get a lock for uid over the entire range.
	return true
}

// canLock returns true if uid will be able to take a Lock of type t on the
// entire range specified by LockRange.
func (l LockSet) canLock(uid UniqueID, t LockType, r LockRange) bool {
	switch t {
	case ReadLock:
		return l.lockable(r, func(value Lock) bool {
			// If there is no writer, there's no problem adding another reader.
			if value.Writer == nil {
				return true
			}
			// If there is a writer, then it must be the same uid
			// in order to downgrade the lock to a read lock.
			return value.Writer == uid
		})
	case WriteLock:
		return l.lockable(r, func(value Lock) bool {
			// If there are only readers.
			if value.Writer == nil {
				// Then this uid can only take a write lock if this is a private
				// upgrade, meaning that the only reader is uid.
				return len(value.Readers) == 1 && value.Readers[uid]
			}
			// If the uid is already a writer on this region, then
			// adding a write lock would be a no-op.
			return value.Writer == uid
		})
	default:
		panic(fmt.Sprintf("canLock: invalid lock type %d", t))
	}
}

// lock returns true if uid took a lock of type t on the entire range of
// LockRange.
//
// Preconditions: r.Start <= r.End (will panic otherwise).
func (l *LockSet) lock(uid UniqueID, t LockType, r LockRange) bool {
	if r.Start > r.End {
		panic(fmt.Sprintf("lock: r.Start %d > r.End %d", r.Start, r.End))
	}

	// Don't attempt to insert anything with a range of 0 and treat this
	// as a successful no-op.
	if r.Length() == 0 {
		return true
	}

	// Do a first-pass check.  We *could* hold onto the segments we
	// checked if canLock would return true, but traversing the segment
	// set should be fast and this keeps things simple.
	if !l.canLock(uid, t, r) {
		return false
	}
	// Get our starting point.
	seg, gap := l.Find(r.Start)
	if gap.Ok() {
		// Fill in the gap and get the next segment to modify.
		seg = l.Insert(gap, gap.Range().Intersect(r), makeLock(uid, t)).NextSegment()
	} else if seg.Start() < r.Start {
		// Get our first segment to modify.
		_, seg = l.Split(seg, r.Start)
	}
	for seg.Ok() && seg.Start() < r.End {
		// Split the last one if necessary.
		if seg.End() > r.End {
			seg, _ = l.SplitUnchecked(seg, r.End)
		}

		// Set the lock on the segment. This is guaranteed to
		// always be safe, given canLock above.
		value := seg.ValuePtr()
		value.lock(uid, t)

		// Fill subsequent gaps.
		gap = seg.NextGap()
		if gr := gap.Range().Intersect(r); gr.Length() > 0 {
			seg = l.Insert(gap, gr, makeLock(uid, t)).NextSegment()
		} else {
			seg = gap.NextSegment()
		}
	}
	return true
}

// unlock is always successful.  If uid has no locks held for the range LockRange,
// unlock is a no-op.
//
// Preconditions: same as lock.
func (l *LockSet) unlock(uid UniqueID, r LockRange) {
	if r.Start > r.End {
		panic(fmt.Sprintf("unlock: r.Start %d > r.End %d", r.Start, r.End))
	}

	// Same as setlock.
	if r.Length() == 0 {
		return
	}

	// Get our starting point.
	seg := l.LowerBoundSegment(r.Start)
	for seg.Ok() && seg.Start() < r.End {
		// If this segment doesn't have a lock from uid then
		// there is no need to fragment the set with Isolate (below).
		// In this case just move on to the next segment.
		if !seg.Value().isHeld(uid) {
			seg = seg.NextSegment()
			continue
		}

		// Ensure that if we need to unlock a sub-segment that
		// we don't unlock/remove that entire segment.
		seg = l.Isolate(seg, r)

		value := seg.Value()
		var remove bool
		if value.Writer == uid {
			// If we are unlocking a writer, then since there can
			// only ever be one writer and no readers, then this
			// lock should always be removed from the set.
			remove = true
		} else if value.Readers[uid] {
			// If uid is the last reader, then just remove the entire
			// segment.
			if len(value.Readers) == 1 {
				remove = true
			} else {
				// Otherwise we need to remove this reader without
				// affecting any other segment's readers.  To do
				// this, we need to make a copy of the Readers map
				// and not add this uid.
				newValue := Lock{Readers: make(map[UniqueID]bool)}
				for k, v := range value.Readers {
					if k != uid {
						newValue.Readers[k] = v
					}
				}
				seg.SetValue(newValue)
			}
		}
		if remove {
			seg = l.Remove(seg).NextSegment()
		} else {
			seg = seg.NextSegment()
		}
	}
}

// ComputeRange takes a positive file offset and computes the start of a LockRange
// using start (relative to offset) and the end of the LockRange using length. The
// values of start and length may be negative but the resulting LockRange must
// preserve that LockRange.Start < LockRange.End and LockRange.Start > 0.
func ComputeRange(start, length, offset int64) (LockRange, error) {
	offset += start
	// fcntl(2): "l_start can be a negative number provided the offset
	// does not lie before the start of the file"
	if offset < 0 {
		return LockRange{}, syscall.EINVAL
	}

	// fcntl(2): Specifying 0 for l_len has the  special meaning: lock all
	// bytes starting at the location specified by l_whence and l_start
	// through to the end of file, no matter how large the file grows.
	end := uint64(LockEOF)
	if length > 0 {
		// fcntl(2): If l_len is positive, then the range to be locked
		// covers bytes l_start up to and including l_start+l_len-1.
		//
		// Since LockRange.End is exclusive we need not -1 from length..
		end = uint64(offset + length)
	} else if length < 0 {
		// fcntl(2): If l_len is negative, the interval described by
		// lock covers bytes l_start+l_len up to and including l_start-1.
		//
		// Since LockRange.End is exclusive we need not -1 from offset.
		signedEnd := offset
		// Add to offset using a negative length (subtract).
		offset += length
		if offset < 0 {
			return LockRange{}, syscall.EINVAL
		}
		if signedEnd < offset {
			return LockRange{}, syscall.EOVERFLOW
		}
		// At this point signedEnd cannot be negative,
		// since we asserted that offset is not negative
		// and it is not less than offset.
		end = uint64(signedEnd)
	}
	// Offset is guaranteed to be positive at this point.
	return LockRange{Start: uint64(offset), End: end}, nil
}
