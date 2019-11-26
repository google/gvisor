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

// Package vfs implements a virtual filesystem layer.
//
// Lock order:
//
// FilesystemImpl/FileDescriptionImpl locks
//   VirtualFilesystem.mountMu
//     Dentry.mu
//       Locks acquired by FilesystemImpls between Prepare{Delete,Rename}Dentry and Commit{Delete,Rename*}Dentry
// VirtualFilesystem.fsTypesMu
//
// Locking Dentry.mu in multiple Dentries requires holding
// VirtualFilesystem.mountMu.
package vfs

import (
	"sync"
)

// A VirtualFilesystem (VFS for short) combines Filesystems in trees of Mounts.
//
// There is no analogue to the VirtualFilesystem type in Linux, as the
// equivalent state in Linux is global.
type VirtualFilesystem struct {
	// mountMu serializes mount mutations.
	//
	// mountMu is analogous to Linux's namespace_sem.
	mountMu sync.Mutex

	// mounts maps (mount parent, mount point) pairs to mounts. (Since mounts
	// are uniquely namespaced, including mount parent in the key correctly
	// handles both bind mounts and mount namespaces; Linux does the same.)
	// Synchronization between mutators and readers is provided by mounts.seq;
	// synchronization between mutators is provided by mountMu.
	//
	// mounts is used to follow mount points during path traversal. We use a
	// single table rather than per-Dentry tables to reduce size (and therefore
	// cache footprint) for the vast majority of Dentries that are not mount
	// points.
	//
	// mounts is analogous to Linux's mount_hashtable.
	mounts mountTable

	// mountpoints maps mount points to mounts at those points in all
	// namespaces. mountpoints is protected by mountMu.
	//
	// mountpoints is used to find mounts that must be umounted due to
	// removal of a mount point Dentry from another mount namespace. ("A file
	// or directory that is a mount point in one namespace that is not a mount
	// point in another namespace, may be renamed, unlinked, or removed
	// (rmdir(2)) in the mount namespace in which it is not a mount point
	// (subject to the usual permission checks)." - mount_namespaces(7))
	//
	// mountpoints is analogous to Linux's mountpoint_hashtable.
	mountpoints map[*Dentry]map[*Mount]struct{}

	// fsTypes contains all FilesystemTypes that are usable in the
	// VirtualFilesystem. fsTypes is protected by fsTypesMu.
	fsTypesMu sync.RWMutex
	fsTypes   map[string]FilesystemType
}

// New returns a new VirtualFilesystem with no mounts or FilesystemTypes.
func New() *VirtualFilesystem {
	vfs := &VirtualFilesystem{
		mountpoints: make(map[*Dentry]map[*Mount]struct{}),
		fsTypes:     make(map[string]FilesystemType),
	}
	vfs.mounts.Init()
	return vfs
}

// A VirtualDentry represents a node in a VFS tree, by combining a Dentry
// (which represents a node in a Filesystem's tree) and a Mount (which
// represents the Filesystem's position in a VFS mount tree).
//
// VirtualDentry's semantics are similar to that of a Go interface object
// representing a pointer: it is a copyable value type that represents
// references to another entity. The zero value of VirtualDentry is an "empty
// VirtualDentry", directly analogous to a nil interface object.
// VirtualDentry.Ok() checks that a VirtualDentry is not zero-valued; unless
// otherwise specified, all other VirtualDentry methods require
// VirtualDentry.Ok() == true.
//
// Mounts and Dentries are reference-counted, requiring that users call
// VirtualDentry.{Inc,Dec}Ref() as appropriate. We often colloquially refer to
// references on the Mount and Dentry referred to by a VirtualDentry as
// references on the VirtualDentry itself. Unless otherwise specified, all
// VirtualDentry methods require that a reference is held on the VirtualDentry.
//
// VirtualDentry is analogous to Linux's struct path.
type VirtualDentry struct {
	mount  *Mount
	dentry *Dentry
}

// Ok returns true if vd is not empty. It does not require that a reference is
// held.
func (vd VirtualDentry) Ok() bool {
	return vd.mount != nil
}

// IncRef increments the reference counts on the Mount and Dentry represented
// by vd.
func (vd VirtualDentry) IncRef() {
	vd.mount.IncRef()
	vd.dentry.IncRef()
}

// DecRef decrements the reference counts on the Mount and Dentry represented
// by vd.
func (vd VirtualDentry) DecRef() {
	vd.dentry.DecRef()
	vd.mount.DecRef()
}

// Mount returns the Mount associated with vd. It does not take a reference on
// the returned Mount.
func (vd VirtualDentry) Mount() *Mount {
	return vd.mount
}

// Dentry returns the Dentry associated with vd. It does not take a reference
// on the returned Dentry.
func (vd VirtualDentry) Dentry() *Dentry {
	return vd.dentry
}
