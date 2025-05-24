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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func dentryTimestamp(t linux.StatxTimestamp) int64 {
	return t.ToNsec()
}

func dentryTimestampFromUnix(t unix.Timespec) int64 {
	return dentryTimestamp(linux.StatxTimestamp{Sec: t.Sec, Nsec: uint32(t.Nsec)})
}

// Preconditions: d.cachedMetadataAuthoritative() == true.
func (d *dentry) touchAtime(mnt *vfs.Mount) {
	if opts := mnt.Options(); opts.Flags.NoATime || opts.ReadOnly {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	now := d.inode.fs.clock.Now().Nanoseconds()
	d.inode.metadataMu.Lock()
	d.inode.atime.Store(now)
	d.inode.atimeDirty.Store(1)
	d.inode.metadataMu.Unlock()
	mnt.EndWrite()
}

// Preconditions: d.inode.metadataMu is locked. d.cachedMetadataAuthoritative() == true.
func (d *dentry) touchAtimeLocked(mnt *vfs.Mount) {
	if opts := mnt.Options(); opts.Flags.NoATime || opts.ReadOnly {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	now := d.inode.fs.clock.Now().Nanoseconds()
	d.inode.atime.Store(now)
	d.inode.atimeDirty.Store(1)
	mnt.EndWrite()
}

// Preconditions:
//   - d.cachedMetadataAuthoritative() == true.
//   - The caller has successfully called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCtime() {
	now := d.inode.fs.clock.Now().Nanoseconds()
	d.inode.metadataMu.Lock()
	d.inode.ctime.Store(now)
	d.inode.metadataMu.Unlock()
}

// Preconditions:
//   - d.cachedMetadataAuthoritative() == true.
//   - The caller has successfully called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCMtime() {
	now := d.inode.fs.clock.Now().Nanoseconds()
	d.inode.metadataMu.Lock()
	d.inode.mtime.Store(now)
	d.inode.ctime.Store(now)
	d.inode.mtimeDirty.Store(1)
	d.inode.metadataMu.Unlock()
}

// Preconditions:
//   - d.cachedMetadataAuthoritative() == true.
//   - The caller has locked d.inode.metadataMu.
func (d *dentry) touchCMtimeLocked() {
	now := d.inode.fs.clock.Now().Nanoseconds()
	d.inode.mtime.Store(now)
	d.inode.ctime.Store(now)
	d.inode.mtimeDirty.Store(1)
}
