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

// Package lock provides POSIX and BSD style file locking for VFS2 file
// implementations.
//
// The actual implementations can be found in the lock package under
// sentry/fs/lock.
package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/syserror"
)

// FileLocks supports POSIX and BSD style locks, which correspond to fcntl(2)
// and flock(2) respectively in Linux. It can be embedded into various file
// implementations for VFS2 that support locking.
//
// Note that in Linux these two types of locks are _not_ cooperative, because
// race and deadlock conditions make merging them prohibitive. We do the same
// and keep them oblivious to each other.
type FileLocks struct {
	// bsd is a set of BSD-style advisory file wide locks, see flock(2).
	bsd fslock.Locks

	// posix is a set of POSIX-style regional advisory locks, see fcntl(2).
	posix fslock.Locks
}

// LockBSD tries to acquire a BSD-style lock on the entire file.
func (fl *FileLocks) LockBSD(uid fslock.UniqueID, t fslock.LockType, block fslock.Blocker) error {
	if fl.bsd.LockRegion(uid, t, fslock.LockRange{0, fslock.LockEOF}, block) {
		return nil
	}
	return syserror.ErrWouldBlock
}

// UnlockBSD releases a BSD-style lock on the entire file.
//
// This operation is always successful, even if there did not exist a lock on
// the requested region held by uid in the first place.
func (fl *FileLocks) UnlockBSD(uid fslock.UniqueID) {
	fl.bsd.UnlockRegion(uid, fslock.LockRange{0, fslock.LockEOF})
}

// LockPOSIX tries to acquire a POSIX-style lock on a file region.
func (fl *FileLocks) LockPOSIX(ctx context.Context, fd *FileDescription, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	rng, err := computeRange(ctx, fd, start, length, whence)
	if err != nil {
		return err
	}
	if fl.posix.LockRegion(uid, t, rng, block) {
		return nil
	}
	return syserror.ErrWouldBlock
}

// UnlockPOSIX releases a POSIX-style lock on a file region.
//
// This operation is always successful, even if there did not exist a lock on
// the requested region held by uid in the first place.
func (fl *FileLocks) UnlockPOSIX(ctx context.Context, fd *FileDescription, uid fslock.UniqueID, start, length uint64, whence int16) error {
	rng, err := computeRange(ctx, fd, start, length, whence)
	if err != nil {
		return err
	}
	fl.posix.UnlockRegion(uid, rng)
	return nil
}

func computeRange(ctx context.Context, fd *FileDescription, start uint64, length uint64, whence int16) (fslock.LockRange, error) {
	var off int64
	switch whence {
	case linux.SEEK_SET:
		off = 0
	case linux.SEEK_CUR:
		// Note that Linux does not hold any mutexes while retrieving the file
		// offset, see fs/locks.c:flock_to_posix_lock and fs/locks.c:fcntl_setlk.
		curOff, err := fd.Seek(ctx, 0, linux.SEEK_CUR)
		if err != nil {
			return fslock.LockRange{}, err
		}
		off = curOff
	case linux.SEEK_END:
		stat, err := fd.Stat(ctx, StatOptions{Mask: linux.STATX_SIZE})
		if err != nil {
			return fslock.LockRange{}, err
		}
		off = int64(stat.Size)
	default:
		return fslock.LockRange{}, syserror.EINVAL
	}

	return fslock.ComputeRange(int64(start), int64(length), off)
}
