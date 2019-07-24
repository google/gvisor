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

package ext

import (
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	// inode is the inode represented by this dentry. Multiple Dentries may
	// share a single non-directory Inode (with hard links). inode is
	// immutable.
	inode *inode
}

// Compiles only if dentry implements vfs.DentryImpl.
var _ vfs.DentryImpl = (*dentry)(nil)

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef(vfsfs *vfs.Filesystem) {
	d.inode.incRef()
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef(vfsfs *vfs.Filesystem) bool {
	return d.inode.tryIncRef()
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(vfsfs *vfs.Filesystem) {
	d.inode.decRef(vfsfs.Impl().(*filesystem))
}
