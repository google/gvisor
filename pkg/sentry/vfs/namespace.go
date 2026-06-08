// Copyright 2023 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// A MountNamespace is a collection of Mounts.//
// MountNamespaces are reference-counted. Unless otherwise specified, all
// MountNamespace methods require that a reference is held.
//
// MountNamespace is analogous to Linux's struct mnt_namespace.
//
// +stateify savable
type MountNamespace struct {
	// ID is the immutable mount namespace ID.
	ID uint64

	// Refs is the reference count for this mount namespace.
	Refs refs.TryRefCounter

	// Owner is the usernamespace that owns this mount namespace.
	Owner *auth.UserNamespace

	// vfs is the vfs this namespace belongs to.
	// vfs is immutable.
	vfs *VirtualFilesystem

	// root is the MountNamespace's root mount.
	root *Mount

	// mountpoints maps all Dentries which are mount points in this namespace
	// to the number of Mounts for which they are mount points. mountpoints is
	// protected by VirtualFilesystem.mountMu.
	//
	// mountpoints is used to determine if a Dentry can be moved or removed
	// (which requires that the Dentry is not a mount point in the calling
	// namespace).
	//
	// mountpoints is maintained even if there are no references held on the
	// MountNamespace; this is required to ensure that
	// VFS.PrepareDeleteDentry() and VFS.PrepareRemoveDentry() operate
	// correctly on unreferenced MountNamespaces.
	mountpoints map[*Dentry]uint32

	// mounts is the total number of mounts in this mount namespace.
	mounts uint32

	// pending is the total number of pending mounts in this mount namespace.
	pending uint32

	// anon indicates whether the mount namespace is anonymous.
	anon bool

	// For anonymous mount namespaces, originatorID is the ID of the mount
	// namespace where the tree originated from. Used for permission checks.
	// 0 is a special value that indicates "no permission checks required."
	// All non-anonymous mount namespaces will have originatorID == 0. Some
	// anonymous mount namespaces may have originatorID == 0 (such as "fresh"
	// trees created using fsmount(2)).
	originatorID uint64
}

// Namespace is the namespace interface.
type Namespace interface {
	Type() string
	Destroy(ctx context.Context)
	UserNamespace() *auth.UserNamespace
}

// newMountNamespace initializes a new mount namespace.
// This method is not intended to be used directly; instead, use one of the
// NewMountNamespace*() methods, which will set up the ns root as well.
func (vfs *VirtualFilesystem) newMountNamespace(owner *auth.UserNamespace, anon bool) *MountNamespace {
	return &MountNamespace{
		ID:          vfs.lastMountNamespaceID.Add(1),
		vfs:         vfs,
		Owner:       owner,
		mountpoints: make(map[*Dentry]uint32),
		anon:        anon,
	}
}

// NewMountNamespace returns a new mount namespace with a root filesystem
// configured by the given arguments. A reference is taken on the returned
// MountNamespace.
//
// If nsfs is nil, the default reference counter is used.
func (vfs *VirtualFilesystem) NewMountNamespace(
	ctx context.Context,
	creds *auth.Credentials,
	source, fsTypeName string,
	opts *MountOptions,
	nsfs NamespaceInodeGetter,
) (*MountNamespace, error) {
	rft := vfs.getFilesystemType(fsTypeName)
	if rft == nil {
		ctx.Warningf("Unknown filesystem type: %s", fsTypeName)
		return nil, linuxerr.ENODEV
	}
	fs, root, err := rft.fsType.GetFilesystem(ctx, vfs, creds, source, opts.GetFilesystemOptions)
	if err != nil {
		return nil, err
	}
	return vfs.NewMountNamespaceFrom(ctx, creds, fs, root, opts, nsfs, false /* anon */), nil
}

type namespaceDefaultRefs struct {
	namespaceRefs
	destroy func(ctx context.Context)
}

func (r *namespaceDefaultRefs) DecRef(ctx context.Context) {
	r.namespaceRefs.DecRef(
		func() {
			r.destroy(ctx)
		},
	)
}

// NewMountNamespaceFrom constructs a new mount namespace from an existing
// filesystem and its root dentry. This is similar to NewMountNamespace, but
// uses an existing filesystem instead of constructing a new one.
func (vfs *VirtualFilesystem) NewMountNamespaceFrom(
	ctx context.Context,
	creds *auth.Credentials,
	fs *Filesystem,
	root *Dentry,
	opts *MountOptions,
	nsfs NamespaceInodeGetter,
	anon bool,
) *MountNamespace {
	mntns := vfs.newMountNamespace(creds.UserNamespace, anon)
	if nsfs == nil {
		refs := &namespaceDefaultRefs{destroy: mntns.Destroy}
		refs.InitRefs()
		mntns.Refs = refs
	} else {
		mntns.Refs = nsfs.GetNamespaceInode(ctx, mntns)
	}
	mntns.root = newMount(vfs, fs, root, mntns, opts)
	return mntns
}

type cloneEntry struct {
	prevMount   *Mount
	parentMount *Mount
}

// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) updateRootAndCWD(ctx context.Context, root *VirtualDentry, cwd *VirtualDentry, src *Mount, dst *Mount) {
	if root.mount == src {
		vfs.delayDecRef(root.mount)
		root.mount = dst
		root.mount.IncRef()
	}
	if cwd.mount == src {
		vfs.delayDecRef(cwd.mount)
		cwd.mount = dst
		cwd.mount.IncRef()
	}
}

// NamespaceInodeGetter is an interface that provides the GetNamespaceInode method.
type NamespaceInodeGetter interface {
	GetNamespaceInode(ctx context.Context, ns Namespace) refs.TryRefCounter
}

// CloneMountNamespace makes a copy of the specified mount namespace.
//
// If `root` or `cwd` have mounts in the old namespace, they will be replaced
// with proper mounts from the new namespace.
func (vfs *VirtualFilesystem) CloneMountNamespace(
	ctx context.Context,
	uns *auth.UserNamespace,
	ns *MountNamespace,
	root *VirtualDentry,
	cwd *VirtualDentry,
	nsfs NamespaceInodeGetter,
) (*MountNamespace, error) {
	newns := vfs.newMountNamespace(uns, false)
	newns.Refs = nsfs.GetNamespaceInode(ctx, newns)
	vfs.lockMounts()
	defer vfs.unlockMounts(ctx)

	cloneType := 0
	if ns.Owner != newns.Owner {
		cloneType = sharedToFollowerClone
	}
	newRoot, err := vfs.cloneMountTree(ctx, ns.root, ns.root.root, cloneType,
		func(ctx context.Context, src, dst *Mount) {
			vfs.updateRootAndCWD(ctx, root, cwd, src, dst) // +checklocksforce: vfs.mountMu is locked.
		})
	if err != nil {
		newns.DecRef(ctx)
		return nil, err
	}
	newns.root = newRoot
	newns.root.ns = newns
	vfs.commitChildren(ctx, newRoot)
	if ns.Owner != newns.Owner {
		vfs.lockMountTree(newRoot)
	}
	return newns, nil
}

// CloneTreeToAnonNS implements open_tree(2)'s OPEN_TREE_CLONE. It makes a copy of the existing
// mount tree at fromVd, placing it at the root of a new anonymous mount namespace.
func (vfs *VirtualFilesystem) CloneTreeToAnonNS(
	ctx context.Context,
	taskMountNs *MountNamespace,
	fromVd VirtualDentry,
	nsfs NamespaceInodeGetter,
	recursive bool,
) (*MountNamespace, error) {
	newNs := vfs.newMountNamespace(taskMountNs.Owner, true)
	newNs.Refs = nsfs.GetNamespaceInode(ctx, newNs)
	newNsCleanup := cleanup.Make(func() {
		newNs.DecRef(ctx)
	})
	defer newNsCleanup.Clean()

	fromMnt := fromVd.mount

	vfs.lockMounts()
	defer vfs.unlockMounts(ctx)

	// Keep track of the originator of this anon ns for later permission checking.
	if fromMnt.ns != nil {
		if fromMnt.ns.anon {
			newNs.originatorID = fromMnt.ns.originatorID
		} else {
			newNs.originatorID = fromMnt.ns.ID
		}
	}

	// Sanity checks

	// TODO(b/305893463): When MS_UNBINDABLE is added,
	// MS_UNBINDABLE mounts should be rejected here.

	fsName := fromMnt.Filesystem().FilesystemType().Name()
	// fromMnt must be either:
	// - In the same mount ns as the current task
	// - In an appropriate anonymous mount namespace
	// nsfs mounts are exempted from these requirements.
	// TODO(b/513023394): when pidfd-fs is implemented, it will also be exempted.
	if fromMnt.ns != taskMountNs && (fromMnt.ns == nil || !fromMnt.ns.anonCanBeOperatedOn(taskMountNs)) && fsName != nsfsName {
		return nil, linuxerr.EINVAL
	}

	if !recursive && vfs.mountHasLockedChildren(fromMnt, fromVd) {
		return nil, linuxerr.EINVAL
	}

	var newRoot *Mount
	var err error
	if recursive {
		newRoot, err = vfs.cloneMountTree(ctx, fromMnt, fromVd.dentry, 0, nil)
	} else {
		newRoot, err = vfs.cloneMount(fromMnt, fromVd.dentry, nil, 0)
	}
	if err != nil {
		return nil, err
	}
	newNs.root = newRoot
	newNs.root.ns = newNs
	vfs.commitChildren(ctx, newRoot)
	newNsCleanup.Release()
	return newNs, nil
}

// Destroy implements nsfs.Namespace.Destroy.
func (mntns *MountNamespace) Destroy(ctx context.Context) {
	vfs := mntns.vfs
	vfs.lockMounts()
	if mntns.root != nil {
		vfs.umountTreeLocked(mntns.root, &umountRecursiveOptions{
			disconnectHierarchy: true,
		})
	}
	vfs.unlockMounts(ctx)
}

// Type implements nsfs.Namespace.Type.
func (mntns *MountNamespace) Type() string {
	return "mnt"
}

// UserNamespace implements nsfs.Namespace.UserNamespace.
func (mntns *MountNamespace) UserNamespace() *auth.UserNamespace {
	return mntns.Owner
}

// IncRef increments mntns' refcount.
func (mntns *MountNamespace) IncRef() {
	mntns.Refs.IncRef()
}

// DecRef decrements mntns' reference count.
func (mntns *MountNamespace) DecRef(ctx context.Context) {
	mntns.Refs.DecRef(ctx)
}

// TryIncRef attempts to increment mntns' reference count.
func (mntns *MountNamespace) TryIncRef() bool {
	return mntns.Refs.TryIncRef()
}

// Root returns mntns' root. If the root is over-mounted, it returns the top
// mount.
// May return an empty virtual dentry if mntns is an anonymous mount namespace and its root
// has been moved to another mountpoint.
func (mntns *MountNamespace) Root(ctx context.Context) VirtualDentry {
	if mntns.root == nil {
		return VirtualDentry{}
	}
	vfs := mntns.root.fs.VirtualFilesystem()
	vd := VirtualDentry{
		mount:  mntns.root,
		dentry: mntns.root.root,
	}
	vd.IncRef()
	if !vd.dentry.isMounted() {
		return vd
	}
	m := vfs.getMountAt(ctx, vd.mount, vd.dentry)
	if m == nil {
		return vd
	}
	vd.DecRef(ctx)
	vd.mount = m
	vd.dentry = m.root
	vd.dentry.IncRef()
	return vd
}

func (mntns *MountNamespace) checkMountCount(ctx context.Context, mnt *Mount) error {
	if mntns.mounts > MountMax {
		return linuxerr.ENOSPC
	}
	if mntns.mounts+mntns.pending > MountMax {
		return linuxerr.ENOSPC
	}
	mnts := mnt.countSubmountsLocked()
	if mntns.mounts+mntns.pending+mnts > MountMax {
		return linuxerr.ENOSPC
	}
	mntns.pending += mnts
	return nil
}

// anonCanBeOperatedOn checks whether the mount namespace is both anonymous
// and accessible by the mount namespace `by`.
//
// It is analogous to fs/namespace.c:check_anonymous_mnt() in Linux.
func (mntns *MountNamespace) anonCanBeOperatedOn(by *MountNamespace) bool {
	if !mntns.anon {
		return false
	}

	return mntns.originatorID == 0 || mntns.originatorID == by.ID
}
