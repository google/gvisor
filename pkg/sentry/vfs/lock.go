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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
)

// FileLocks supports POSIX and BSD style locks, which correspond to fcntl(2)
// and flock(2) respectively in Linux. It can be embedded into various file
// implementations for VFS2 that support locking.
//
// Note that in Linux these two types of locks are _not_ cooperative, because
// race and deadlock conditions make merging them prohibitive. We do the same
// and keep them oblivious to each other.
//
// +stateify savable
type FileLocks struct {
	// bsd is a set of BSD-style advisory file wide locks, see flock(2).
	bsd fslock.Locks

	// posix is a set of POSIX-style regional advisory locks, see fcntl(2).
	posix fslock.Locks
}

// LockBSD tries to acquire a BSD-style lock on the entire file.
func (fl *FileLocks) LockBSD(ctx context.Context, uid fslock.UniqueID, ownerID int32, t fslock.LockType, block bool) error {
	if err := fl.bsd.LockRegion(ctx, uid, ownerID, t, fslock.LockRange{0, fslock.LockEOF}, block); err == nil || err == linuxerr.ErrWouldBlock {
		return err
	}
	return linuxerr.ERESTARTSYS
}

// UnlockBSD releases a BSD-style lock on the entire file.
//
// This operation is always successful, even if there did not exist a lock on
// the requested region held by uid in the first place.
func (fl *FileLocks) UnlockBSD(uid fslock.UniqueID) {
	fl.bsd.UnlockRegion(uid, fslock.LockRange{0, fslock.LockEOF})
}

// LockPOSIX tries to acquire a POSIX-style lock on a file region.
func (fl *FileLocks) LockPOSIX(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, r fslock.LockRange, block bool) error {
	if err := fl.posix.LockRegion(ctx, uid, ownerPID, t, r, block); err == nil || err == linuxerr.ErrWouldBlock {
		return err
	}
	return linuxerr.ERESTARTSYS
}

// UnlockPOSIX releases a POSIX-style lock on a file region.
//
// This operation is always successful, even if there did not exist a lock on
// the requested region held by uid in the first place.
func (fl *FileLocks) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, r fslock.LockRange) error {
	fl.posix.UnlockRegion(uid, r)
	return nil
}

// TestPOSIX returns information about whether the specified lock can be held, in the style of the F_GETLK fcntl.
func (fl *FileLocks) TestPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, r fslock.LockRange) (linux.Flock, error) {
	return fl.posix.TestRegion(ctx, uid, t, r), nil
}
