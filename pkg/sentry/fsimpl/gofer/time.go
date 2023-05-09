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
	if mnt.Flags.NoATime || mnt.ReadOnly() {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	now := d.fs.clock.Now().Nanoseconds()
	d.metadataMu.Lock()
	d.atime.Store(now)
	d.atimeDirty.Store(1)
	d.metadataMu.Unlock()
	mnt.EndWrite()
}

// Preconditions: d.metadataMu is locked. d.cachedMetadataAuthoritative() == true.
func (d *dentry) touchAtimeLocked(mnt *vfs.Mount) {
	if mnt.Flags.NoATime || mnt.ReadOnly() {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	now := d.fs.clock.Now().Nanoseconds()
	d.atime.Store(now)
	d.atimeDirty.Store(1)
	mnt.EndWrite()
}

// Preconditions:
//   - d.cachedMetadataAuthoritative() == true.
//   - The caller has successfully called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCtime() {
	now := d.fs.clock.Now().Nanoseconds()
	d.metadataMu.Lock()
	d.ctime.Store(now)
	d.metadataMu.Unlock()
}

// Preconditions:
//   - d.cachedMetadataAuthoritative() == true.
//   - The caller has successfully called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCMtime() {
	now := d.fs.clock.Now().Nanoseconds()
	d.metadataMu.Lock()
	d.mtime.Store(now)
	d.ctime.Store(now)
	d.mtimeDirty.Store(1)
	d.metadataMu.Unlock()
}

// Preconditions:
//   - d.cachedMetadataAuthoritative() == true.
//   - The caller has locked d.metadataMu.
func (d *dentry) touchCMtimeLocked() {
	now := d.fs.clock.Now().Nanoseconds()
	d.mtime.Store(now)
	d.ctime.Store(now)
	d.mtimeDirty.Store(1)
}
