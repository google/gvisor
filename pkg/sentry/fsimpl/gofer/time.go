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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func dentryTimestampFromP9(s, ns uint64) int64 {
	return int64(s*1e9 + ns)
}

func dentryTimestampFromLisa(t linux.StatxTimestamp) int64 {
	return t.Sec*1e9 + int64(t.Nsec)
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
	atomic.StoreInt64(&d.atime, now)
	atomic.StoreUint32(&d.atimeDirty, 1)
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
	atomic.StoreInt64(&d.atime, now)
	atomic.StoreUint32(&d.atimeDirty, 1)
	mnt.EndWrite()
}

// Preconditions:
// * d.cachedMetadataAuthoritative() == true.
// * The caller has successfully called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCtime() {
	now := d.fs.clock.Now().Nanoseconds()
	d.metadataMu.Lock()
	atomic.StoreInt64(&d.ctime, now)
	d.metadataMu.Unlock()
}

// Preconditions:
// * d.cachedMetadataAuthoritative() == true.
// * The caller has successfully called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCMtime() {
	now := d.fs.clock.Now().Nanoseconds()
	d.metadataMu.Lock()
	atomic.StoreInt64(&d.mtime, now)
	atomic.StoreInt64(&d.ctime, now)
	atomic.StoreUint32(&d.mtimeDirty, 1)
	d.metadataMu.Unlock()
}

// Preconditions:
// * d.cachedMetadataAuthoritative() == true.
// * The caller has locked d.metadataMu.
func (d *dentry) touchCMtimeLocked() {
	now := d.fs.clock.Now().Nanoseconds()
	atomic.StoreInt64(&d.mtime, now)
	atomic.StoreInt64(&d.ctime, now)
	atomic.StoreUint32(&d.mtimeDirty, 1)
}
