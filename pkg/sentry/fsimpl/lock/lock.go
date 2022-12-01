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
//   - read lock upgrade to write lock: There can be only one reader and the reader
//     must be the same as the requested write lock holder.
//
//   - write lock downgrade to read lock: The writer must be the same as the requested
//     read lock holder.
//
// UnlockRegion always succeeds.  If LockRegion fails the caller should normally
// interpret this as "try again later".
package lock

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LockType is a type of regional file lock.
type LockType int

// UniqueID is a unique identifier of the holder of a regional file lock.
type UniqueID any

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

// OwnerInfo describes the owner of a lock.
//
// TODO(gvisor.dev/issue/5264): We may need to add other fields in the future
// (e.g., Linux's file_lock.fl_flags to support open file-descriptor locks).
//
// +stateify savable
type OwnerInfo struct {
	// PID is the process ID of the lock owner.
	PID int32
}

// Lock is a regional file lock.  It consists of either a single writer
// or a set of readers.
//
// A Lock may be upgraded from a read lock to a write lock only if there
// is a single reader and that reader has the same uid as the write lock.
//
// A Lock may be downgraded from a write lock to a read lock only if
// the write lock's uid is the same as the read lock.
//
// Accesses to Lock are synchronized through the Locks object to which it
// belongs.
//
// +stateify savable
type Lock struct {
	// Readers are the set of read lock holders identified by UniqueID.
	// If len(Readers) > 0 then Writer must be nil.
	Readers map[UniqueID]OwnerInfo

	// Writer holds the writer unique ID. It's nil if there are no writers.
	Writer UniqueID

	// WriterInfo describes the writer. It is only meaningful if Writer != nil.
	WriterInfo OwnerInfo
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
	blockedQueue waiter.Queue
}

// LockRegion attempts to acquire a typed lock for the uid on a region of a
// file. Returns nil if successful in locking the region, otherwise an
// appropriate error is returned.
func (l *Locks) LockRegion(ctx context.Context, uid UniqueID, ownerPID int32, t LockType, r LockRange, block bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {

		// Blocking locks must run in a loop because we'll be woken up whenever an unlock event
		// happens for this lock. We will then attempt to take the lock again and if it fails
		// continue blocking.
		err := l.locks.lock(uid, ownerPID, t, r)
		if err == linuxerr.ErrWouldBlock && block {
			// Note: we release the lock in EventRegister below, in
			// order to avoid a possible race.
			ok := ctx.BlockOn(l, waiter.EventIn)
			l.mu.Lock() // +checklocksforce: see above.
			if ok {
				continue // Try again now that someone has unlocked.
			}
			// Must be interrupted.
			return linuxerr.ErrInterrupted
		}

		return err
	}
}

// Readiness always returns zero.
func (l *Locks) Readiness(waiter.EventMask) waiter.EventMask {
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (l *Locks) EventRegister(e *waiter.Entry) error {
	defer l.mu.Unlock() // +checklocksforce: see above.
	l.blockedQueue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (l *Locks) EventUnregister(e *waiter.Entry) {
	l.blockedQueue.EventUnregister(e)
}

// UnlockRegion attempts to release a lock for the uid on a region of a file.
// This operation is always successful, even if there did not exist a lock on
// the requested region held by uid in the first place.
func (l *Locks) UnlockRegion(uid UniqueID, r LockRange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locks.unlock(uid, r)

	// Now that we've released the lock, we need to wake up any waiters.
	// We track how many notifications have happened since the last attempt
	// to acquire the lock, in order to ensure that we avoid races.
	l.blockedQueue.Notify(waiter.EventIn)
}

// makeLock returns a new typed Lock that has either uid as its only reader
// or uid as its only writer.
func makeLock(uid UniqueID, ownerPID int32, t LockType) Lock {
	value := Lock{Readers: make(map[UniqueID]OwnerInfo)}
	switch t {
	case ReadLock:
		value.Readers[uid] = OwnerInfo{PID: ownerPID}
	case WriteLock:
		value.Writer = uid
		value.WriterInfo = OwnerInfo{PID: ownerPID}
	default:
		panic(fmt.Sprintf("makeLock: invalid lock type %d", t))
	}
	return value
}

// isHeld returns true if uid is a holder of Lock.
func (l Lock) isHeld(uid UniqueID) bool {
	if _, ok := l.Readers[uid]; ok {
		return true
	}
	return l.Writer == uid
}

// lock sets uid as a holder of a typed lock on Lock.
//
// Preconditions: canLock is true for the range containing this Lock.
func (l *Lock) lock(uid UniqueID, ownerPID int32, t LockType) {
	switch t {
	case ReadLock:
		// If we are already a reader, then this is a no-op.
		if _, ok := l.Readers[uid]; ok {
			return
		}
		// We cannot downgrade a write lock to a read lock unless the
		// uid is the same.
		if l.Writer != nil {
			if l.Writer != uid {
				panic(fmt.Sprintf("lock: cannot downgrade write lock to read lock for uid %d, writer is %d", uid, l.Writer))
			}
			// Ensure that there is only one reader if upgrading.
			l.Readers = make(map[UniqueID]OwnerInfo)
			// Ensure that there is no longer a writer.
			l.Writer = nil
		}
		l.Readers[uid] = OwnerInfo{PID: ownerPID}
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
			if _, ok := l.Readers[uid]; !ok {
				panic(fmt.Sprintf("lock: cannot upgrade read lock to write lock for uid %d, conflicting reader %v", uid, l.Readers))
			}
		}
		// Ensure that there is only a writer.
		l.Readers = make(map[UniqueID]OwnerInfo)
		l.Writer = uid
		l.WriterInfo = OwnerInfo{PID: ownerPID}
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
		// Note that we don't care about overrunning the end of the
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
				return value.isOnlyReader(uid)
			}
			// If the uid is already a writer on this region, then
			// adding a write lock would be a no-op.
			return value.Writer == uid
		})
	default:
		panic(fmt.Sprintf("canLock: invalid lock type %d", t))
	}
}

func (l *Lock) isOnlyReader(uid UniqueID) bool {
	if len(l.Readers) != 1 {
		return false
	}
	_, ok := l.Readers[uid]
	return ok
}

// lock returns nil if uid took a lock of type t on the entire range of
// LockRange. Otherwise, linuxerr.ErrWouldBlock is returned.
//
// Preconditions: r.Start <= r.End (will panic otherwise).
func (l *LockSet) lock(uid UniqueID, ownerPID int32, t LockType, r LockRange) error {
	if r.Start > r.End {
		panic(fmt.Sprintf("lock: r.Start %d > r.End %d", r.Start, r.End))
	}

	// Don't attempt to insert anything with a range of 0 and treat this
	// as a successful no-op.
	if r.Length() == 0 {
		return nil
	}

	// Do a first-pass check. We *could* hold onto the segments we checked
	// if canLock would return true, but traversing the segment set should
	// be fast and this keeps things simple.
	if !l.canLock(uid, t, r) {
		return linuxerr.ErrWouldBlock
	}

	// Get our starting point.
	seg, gap := l.Find(r.Start)
	if gap.Ok() {
		// Fill in the gap and get the next segment to modify.
		seg = l.Insert(gap, gap.Range().Intersect(r), makeLock(uid, ownerPID, t)).NextSegment()
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
		value.lock(uid, ownerPID, t)

		// Fill subsequent gaps.
		gap = seg.NextGap()
		if gr := gap.Range().Intersect(r); gr.Length() > 0 {
			seg = l.Insert(gap, gr, makeLock(uid, ownerPID, t)).NextSegment()
		} else {
			seg = gap.NextSegment()
		}
	}

	return nil
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
		} else if _, ok := value.Readers[uid]; ok {
			// If uid is the last reader, then just remove the entire
			// segment.
			if len(value.Readers) == 1 {
				remove = true
			} else {
				// Otherwise we need to remove this reader without
				// affecting any other segment's readers.  To do
				// this, we need to make a copy of the Readers map
				// and not add this uid.
				newValue := Lock{Readers: make(map[UniqueID]OwnerInfo)}
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
		return LockRange{}, unix.EINVAL
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
			return LockRange{}, unix.EINVAL
		}
		if signedEnd < offset {
			return LockRange{}, unix.EOVERFLOW
		}
		// At this point signedEnd cannot be negative,
		// since we asserted that offset is not negative
		// and it is not less than offset.
		end = uint64(signedEnd)
	}
	// Offset is guaranteed to be positive at this point.
	return LockRange{Start: uint64(offset), End: end}, nil
}

// TestRegion checks whether the lock holder identified by uid can hold a lock
// of type t on range r. It returns a Flock struct representing this
// information as the F_GETLK fcntl does.
//
// Note that the PID returned in the flock structure is relative to the root PID
// namespace. It needs to be converted to the caller's PID namespace before
// returning to userspace.
//
// TODO(gvisor.dev/issue/5264): we don't support OFD locks through fcntl, which
// would return a struct with pid = -1.
func (l *Locks) TestRegion(ctx context.Context, uid UniqueID, t LockType, r LockRange) linux.Flock {
	f := linux.Flock{Type: linux.F_UNLCK}
	switch t {
	case ReadLock:
		l.testRegion(r, func(lock Lock, start, length uint64) bool {
			if lock.Writer == nil || lock.Writer == uid {
				return true
			}
			f.Type = linux.F_WRLCK
			f.PID = lock.WriterInfo.PID
			f.Start = int64(start)
			f.Len = int64(length)
			return false
		})
	case WriteLock:
		l.testRegion(r, func(lock Lock, start, length uint64) bool {
			if lock.Writer == nil {
				for k, v := range lock.Readers {
					if k != uid {
						// Stop at the first conflict detected.
						f.Type = linux.F_RDLCK
						f.PID = v.PID
						f.Start = int64(start)
						f.Len = int64(length)
						return false
					}
				}
				return true
			}
			if lock.Writer == uid {
				return true
			}
			f.Type = linux.F_WRLCK
			f.PID = lock.WriterInfo.PID
			f.Start = int64(start)
			f.Len = int64(length)
			return false
		})
	default:
		panic(fmt.Sprintf("TestRegion: invalid lock type %d", t))
	}
	return f
}

func (l *Locks) testRegion(r LockRange, check func(lock Lock, start, length uint64) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	seg := l.locks.LowerBoundSegment(r.Start)
	for seg.Ok() && seg.Start() < r.End {
		lock := seg.Value()
		if !check(lock, seg.Start(), seg.End()-seg.Start()) {
			// Stop at the first conflict detected.
			return
		}
		seg = seg.NextSegment()
	}
}
