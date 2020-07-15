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

package fuse

import (
	"sync"

	"gvisor.dev/gvisor/pkg/refs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	refs.AtomicRefCount

	// the owning filesystem. fs is immutable.
	fs *filesystem

	// size identify the size of file.
	size uint64

	// Access, Modification and Change time of the file.
	atime ktime.Time
	mtime ktime.Time
	ctime ktime.Time

	// protects metadata.
	metaDataMu sync.Mutex

	inode *Inode
}

func (fs *filesystem) newDentry(inode *Inode) *dentry {
	d := &dentry{
		fs:    fs,
		inode: inode,
	}
	d.vfsd.Init(d)
	return d
}

func (d *dentry) VFSDentry() *vfs.Dentry {
	return &d.vfsd
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	d.AtomicRefCount.IncRef()
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	return d.AtomicRefCount.TryIncRef()
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef() {
	d.AtomicRefCount.DecRefWithDestructor(d.destroy)
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(events, cookie uint32, et vfs.EventType) {}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return nil
}

// OnZeroWatches implements vfs.Dentry.OnZeroWatches.
func (d *dentry) OnZeroWatches() {}

func (d *dentry) destroy() {}
