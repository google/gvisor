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
	// Refs is the reference count for this mount namespace.
	Refs refs.TryRefCounter

	// Owner is the usernamespace that owns this mount namespace.
	Owner *auth.UserNamespace

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
}

// Namespace is the namespace interface.
type Namespace interface {
	Type() string
	Destroy(ctx context.Context)
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
	return vfs.NewMountNamespaceFrom(ctx, creds, fs, root, opts, nsfs), nil
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
) *MountNamespace {
	mntns := &MountNamespace{
		Owner:       creds.UserNamespace,
		mountpoints: make(map[*Dentry]uint32),
	}
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
	creds *auth.Credentials,
	ns *MountNamespace,
	root *VirtualDentry,
	cwd *VirtualDentry,
	nsfs NamespaceInodeGetter,
) (*MountNamespace, error) {
	newns := &MountNamespace{
		Owner:       creds.UserNamespace,
		mountpoints: make(map[*Dentry]uint32),
	}

	newns.Refs = nsfs.GetNamespaceInode(ctx, newns)
	vfs.lockMounts()
	defer vfs.unlockMounts(ctx)

	ns.root.root.IncRef()
	ns.root.fs.IncRef()
	newns.root = newMount(vfs, ns.root.fs, ns.root.root, newns, &MountOptions{Flags: ns.root.Flags, ReadOnly: ns.root.ReadOnly()})
	if ns.root.isShared {
		vfs.addPeer(ns.root, newns.root)
	}
	vfs.updateRootAndCWD(ctx, root, cwd, ns.root, newns.root)

	queue := []cloneEntry{cloneEntry{ns.root, newns.root}}
	for len(queue) != 0 {
		p := queue[0]
		queue = queue[1:]
		for c := range p.prevMount.children {
			m := vfs.cloneMount(c, c.root, nil)
			vd := VirtualDentry{
				mount:  p.parentMount,
				dentry: c.point(),
			}
			vd.IncRef()

			err := vfs.connectMountAtLocked(ctx, m, vd)
			vfs.delayDecRef(m)
			if err != nil {
				newns.DecRef(ctx)
				return nil, err
			}
			vfs.updateRootAndCWD(ctx, root, cwd, c, m)
			if len(c.children) != 0 {
				queue = append(queue, cloneEntry{c, m})
			}
		}
	}
	return newns, nil
}

// Destroy implements nsfs.Namespace.Destroy.
func (mntns *MountNamespace) Destroy(ctx context.Context) {
	vfs := mntns.root.fs.VirtualFilesystem()
	vfs.lockMounts()
	vfs.mounts.seq.BeginWrite()
	vfs.umountRecursiveLocked(mntns.root, &umountRecursiveOptions{
		disconnectHierarchy: true,
	})
	vfs.mounts.seq.EndWrite()
	vfs.unlockMounts(ctx)
}

// Type implements nsfs.Namespace.Type.
func (mntns *MountNamespace) Type() string {
	return "mnt"
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
func (mntns *MountNamespace) Root(ctx context.Context) VirtualDentry {
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
