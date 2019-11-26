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

package vfs

import (
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/syserror"
)

// Dentry represents a node in a Filesystem tree which may represent a file.
//
// Dentries are reference-counted. Unless otherwise specified, all Dentry
// methods require that a reference is held.
//
// A Dentry transitions through up to 3 different states through its lifetime:
//
// - Dentries are initially "independent". Independent Dentries have no parent,
// and consequently no name.
//
// - Dentry.InsertChild() causes an independent Dentry to become a "child" of
// another Dentry. A child node has a parent node, and a name in that parent,
// both of which are mutable by DentryMoveChild(). Each child Dentry's name is
// unique within its parent.
//
// - Dentry.RemoveChild() causes a child Dentry to become "disowned". A
// disowned Dentry can still refer to its former parent and its former name in
// said parent, but the disowned Dentry is no longer reachable from its parent,
// and a new Dentry with the same name may become a child of the parent. (This
// is analogous to a struct dentry being "unhashed" in Linux.)
//
// Dentry is loosely analogous to Linux's struct dentry, but:
//
// - VFS does not associate Dentries with inodes. gVisor interacts primarily
// with filesystems that are accessed through filesystem APIs (as opposed to
// raw block devices); many such APIs support only paths and file descriptors,
// and not inodes. Furthermore, when parties outside the scope of VFS can
// rename inodes on such filesystems, VFS generally cannot "follow" the rename,
// both due to synchronization issues and because it may not even be able to
// name the destination path; this implies that it would in fact be incorrect
// for Dentries to be associated with inodes on such filesystems. Consequently,
// operations that are inode operations in Linux are FilesystemImpl methods
// and/or FileDescriptionImpl methods in gVisor's VFS. Filesystems that do
// support inodes may store appropriate state in implementations of DentryImpl.
//
// - VFS does not provide synchronization for mutable Dentry fields, other than
// mount-related ones.
//
// - VFS does not require that Dentries are instantiated for all paths accessed
// through VFS, only those that are tracked beyond the scope of a single
// Filesystem operation. This includes file descriptions, mount points, mount
// roots, process working directories, and chroots. This avoids instantiation
// of Dentries for operations on mutable remote filesystems that can't actually
// cache any state in the Dentry.
//
// - For the reasons above, VFS is not directly responsible for managing Dentry
// lifetime. Dentry reference counts only indicate the extent to which VFS
// requires Dentries to exist; Filesystems may elect to cache or discard
// Dentries with zero references.
type Dentry struct {
	// parent is this Dentry's parent in this Filesystem. If this Dentry is
	// independent, parent is nil.
	parent *Dentry

	// name is this Dentry's name in parent.
	name string

	flags uint32

	// mounts is the number of Mounts for which this Dentry is Mount.point.
	// mounts is accessed using atomic memory operations.
	mounts uint32

	// mu synchronizes disowning and mounting over this Dentry.
	mu sync.Mutex

	// children are child Dentries.
	children map[string]*Dentry

	// impl is the DentryImpl associated with this Dentry. impl is immutable.
	// This should be the last field in Dentry.
	impl DentryImpl
}

const (
	// dflagsDisownedMask is set in Dentry.flags if the Dentry has been
	// disowned.
	dflagsDisownedMask = 1 << iota
)

// Init must be called before first use of d.
func (d *Dentry) Init(impl DentryImpl) {
	d.impl = impl
}

// Impl returns the DentryImpl associated with d.
func (d *Dentry) Impl() DentryImpl {
	return d.impl
}

// DentryImpl contains implementation details for a Dentry. Implementations of
// DentryImpl should contain their associated Dentry by value as their first
// field.
type DentryImpl interface {
	// IncRef increments the Dentry's reference count. A Dentry with a non-zero
	// reference count must remain coherent with the state of the filesystem.
	IncRef()

	// TryIncRef increments the Dentry's reference count and returns true. If
	// the Dentry's reference count is zero, TryIncRef may do nothing and
	// return false. (It is also permitted to succeed if it can restore the
	// guarantee that the Dentry is coherent with the state of the filesystem.)
	//
	// TryIncRef does not require that a reference is held on the Dentry.
	TryIncRef() bool

	// DecRef decrements the Dentry's reference count.
	DecRef()
}

// IsDisowned returns true if d is disowned.
func (d *Dentry) IsDisowned() bool {
	return atomic.LoadUint32(&d.flags)&dflagsDisownedMask != 0
}

// Preconditions: !d.IsDisowned().
func (d *Dentry) setDisowned() {
	atomic.AddUint32(&d.flags, dflagsDisownedMask)
}

func (d *Dentry) isMounted() bool {
	return atomic.LoadUint32(&d.mounts) != 0
}

// IncRef increments d's reference count.
func (d *Dentry) IncRef() {
	d.impl.IncRef()
}

// TryIncRef increments d's reference count and returns true. If d's reference
// count is zero, TryIncRef may instead do nothing and return false.
func (d *Dentry) TryIncRef() bool {
	return d.impl.TryIncRef()
}

// DecRef decrements d's reference count.
func (d *Dentry) DecRef() {
	d.impl.DecRef()
}

// These functions are exported so that filesystem implementations can use
// them. The vfs package, and users of VFS, should not call these functions.
// Unless otherwise specified, these methods require that there are no
// concurrent mutators of d.

// Name returns d's name in its parent in its owning Filesystem. If d is
// independent, Name returns an empty string.
func (d *Dentry) Name() string {
	return d.name
}

// Parent returns d's parent in its owning Filesystem. It does not take a
// reference on the returned Dentry. If d is independent, Parent returns nil.
func (d *Dentry) Parent() *Dentry {
	return d.parent
}

// ParentOrSelf is equivalent to Parent, but returns d if d is independent.
func (d *Dentry) ParentOrSelf() *Dentry {
	if d.parent == nil {
		return d
	}
	return d.parent
}

// Child returns d's child with the given name in its owning Filesystem. It
// does not take a reference on the returned Dentry. If no such child exists,
// Child returns nil.
func (d *Dentry) Child(name string) *Dentry {
	return d.children[name]
}

// HasChildren returns true if d has any children.
func (d *Dentry) HasChildren() bool {
	return len(d.children) != 0
}

// InsertChild makes child a child of d with the given name.
//
// InsertChild is a mutator of d and child.
//
// Preconditions: child must be an independent Dentry. d and child must be from
// the same Filesystem. d must not already have a child with the given name.
func (d *Dentry) InsertChild(child *Dentry, name string) {
	if checkInvariants {
		if _, ok := d.children[name]; ok {
			panic(fmt.Sprintf("parent already contains a child named %q", name))
		}
		if child.parent != nil || child.name != "" {
			panic(fmt.Sprintf("child is not independent: parent = %v, name = %q", child.parent, child.name))
		}
	}
	if d.children == nil {
		d.children = make(map[string]*Dentry)
	}
	d.children[name] = child
	child.parent = d
	child.name = name
}

// PrepareDeleteDentry must be called before attempting to delete the file
// represented by d. If PrepareDeleteDentry succeeds, the caller must call
// AbortDeleteDentry or CommitDeleteDentry depending on the deletion's outcome.
//
// Preconditions: d is a child Dentry.
func (vfs *VirtualFilesystem) PrepareDeleteDentry(mntns *MountNamespace, d *Dentry) error {
	if checkInvariants {
		if d.parent == nil {
			panic("d is independent")
		}
		if d.IsDisowned() {
			panic("d is already disowned")
		}
	}
	vfs.mountMu.Lock()
	if mntns.mountpoints[d] != 0 {
		vfs.mountMu.Unlock()
		return syserror.EBUSY
	}
	d.mu.Lock()
	vfs.mountMu.Unlock()
	// Return with d.mu locked to block attempts to mount over it; it will be
	// unlocked by AbortDeleteDentry or CommitDeleteDentry.
	return nil
}

// AbortDeleteDentry must be called after PrepareDeleteDentry if the deletion
// fails.
func (vfs *VirtualFilesystem) AbortDeleteDentry(d *Dentry) {
	d.mu.Unlock()
}

// CommitDeleteDentry must be called after the file represented by d is
// deleted, and causes d to become disowned.
//
// CommitDeleteDentry is a mutator of d and d.Parent().
//
// Preconditions: PrepareDeleteDentry was previously called on d.
func (vfs *VirtualFilesystem) CommitDeleteDentry(d *Dentry) {
	if d.parent != nil {
		delete(d.parent.children, d.name)
	}
	d.setDisowned()
	d.mu.Unlock()
	if d.isMounted() {
		vfs.forgetDisownedMountpoint(d)
	}
}

// DeleteDentry combines PrepareDeleteDentry and CommitDeleteDentry, as
// appropriate for in-memory filesystems that don't need to ensure that some
// external state change succeeds before committing the deletion.
//
// DeleteDentry is a mutator of d and d.Parent().
//
// Preconditions: d is a child Dentry.
func (vfs *VirtualFilesystem) DeleteDentry(mntns *MountNamespace, d *Dentry) error {
	if err := vfs.PrepareDeleteDentry(mntns, d); err != nil {
		return err
	}
	vfs.CommitDeleteDentry(d)
	return nil
}

// ForceDeleteDentry causes d to become disowned. It should only be used in
// cases where VFS has no ability to stop the deletion (e.g. d represents the
// local state of a file on a remote filesystem on which the file has already
// been deleted).
//
// ForceDeleteDentry is a mutator of d and d.Parent().
//
// Preconditions: d is a child Dentry.
func (vfs *VirtualFilesystem) ForceDeleteDentry(d *Dentry) {
	if checkInvariants {
		if d.parent == nil {
			panic("d is independent")
		}
		if d.IsDisowned() {
			panic("d is already disowned")
		}
	}
	d.mu.Lock()
	vfs.CommitDeleteDentry(d)
}

// PrepareRenameDentry must be called before attempting to rename the file
// represented by from. If to is not nil, it represents the file that will be
// replaced or exchanged by the rename. If PrepareRenameDentry succeeds, the
// caller must call AbortRenameDentry, CommitRenameReplaceDentry, or
// CommitRenameExchangeDentry depending on the rename's outcome.
//
// Preconditions: from is a child Dentry. If to is not nil, it must be a child
// Dentry from the same Filesystem.
func (vfs *VirtualFilesystem) PrepareRenameDentry(mntns *MountNamespace, from, to *Dentry) error {
	if checkInvariants {
		if from.parent == nil {
			panic("from is independent")
		}
		if from.IsDisowned() {
			panic("from is already disowned")
		}
		if to != nil {
			if to.parent == nil {
				panic("to is independent")
			}
			if to.IsDisowned() {
				panic("to is already disowned")
			}
		}
	}
	vfs.mountMu.Lock()
	if mntns.mountpoints[from] != 0 {
		vfs.mountMu.Unlock()
		return syserror.EBUSY
	}
	if to != nil {
		if mntns.mountpoints[to] != 0 {
			vfs.mountMu.Unlock()
			return syserror.EBUSY
		}
		to.mu.Lock()
	}
	from.mu.Lock()
	vfs.mountMu.Unlock()
	// Return with from.mu and to.mu locked, which will be unlocked by
	// AbortRenameDentry, CommitRenameReplaceDentry, or
	// CommitRenameExchangeDentry.
	return nil
}

// AbortRenameDentry must be called after PrepareRenameDentry if the rename
// fails.
func (vfs *VirtualFilesystem) AbortRenameDentry(from, to *Dentry) {
	from.mu.Unlock()
	if to != nil {
		to.mu.Unlock()
	}
}

// CommitRenameReplaceDentry must be called after the file represented by from
// is renamed without RENAME_EXCHANGE. If to is not nil, it represents the file
// that was replaced by from.
//
// CommitRenameReplaceDentry is a mutator of from, to, from.Parent(), and
// to.Parent().
//
// Preconditions: PrepareRenameDentry was previously called on from and to.
// newParent.Child(newName) == to.
func (vfs *VirtualFilesystem) CommitRenameReplaceDentry(from, newParent *Dentry, newName string, to *Dentry) {
	if newParent.children == nil {
		newParent.children = make(map[string]*Dentry)
	}
	newParent.children[newName] = from
	from.parent = newParent
	from.name = newName
	from.mu.Unlock()
	if to != nil {
		to.setDisowned()
		to.mu.Unlock()
		if to.isMounted() {
			vfs.forgetDisownedMountpoint(to)
		}
	}
}

// CommitRenameExchangeDentry must be called after the files represented by
// from and to are exchanged by rename(RENAME_EXCHANGE).
//
// CommitRenameExchangeDentry is a mutator of from, to, from.Parent(), and
// to.Parent().
//
// Preconditions: PrepareRenameDentry was previously called on from and to.
func (vfs *VirtualFilesystem) CommitRenameExchangeDentry(from, to *Dentry) {
	from.parent, to.parent = to.parent, from.parent
	from.name, to.name = to.name, from.name
	from.parent.children[from.name] = from
	to.parent.children[to.name] = to
	from.mu.Unlock()
	to.mu.Unlock()
}

// forgetDisownedMountpoint is called when a mount point is deleted to umount
// all mounts using it in all other mount namespaces.
//
// forgetDisownedMountpoint is analogous to Linux's
// fs/namespace.c:__detach_mounts().
func (vfs *VirtualFilesystem) forgetDisownedMountpoint(d *Dentry) {
	var (
		vdsToDecRef    []VirtualDentry
		mountsToDecRef []*Mount
	)
	vfs.mountMu.Lock()
	vfs.mounts.seq.BeginWrite()
	for mnt := range vfs.mountpoints[d] {
		vdsToDecRef, mountsToDecRef = vfs.umountRecursiveLocked(mnt, &umountRecursiveOptions{}, vdsToDecRef, mountsToDecRef)
	}
	vfs.mounts.seq.EndWrite()
	vfs.mountMu.Unlock()
	for _, vd := range vdsToDecRef {
		vd.DecRef()
	}
	for _, mnt := range mountsToDecRef {
		mnt.DecRef()
	}
}
