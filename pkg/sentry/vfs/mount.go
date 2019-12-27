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
	"math"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

// A Mount is a replacement of a Dentry (Mount.key.point) from one Filesystem
// (Mount.key.parent.fs) with a Dentry (Mount.root) from another Filesystem
// (Mount.fs), which applies to path resolution in the context of a particular
// Mount (Mount.key.parent).
//
// Mounts are reference-counted. Unless otherwise specified, all Mount methods
// require that a reference is held.
//
// Mount and Filesystem are distinct types because it's possible for a single
// Filesystem to be mounted at multiple locations and/or in multiple mount
// namespaces.
//
// Mount is analogous to Linux's struct mount. (gVisor does not distinguish
// between struct mount and struct vfsmount.)
type Mount struct {
	// vfs, fs, and root are immutable. References are held on fs and root.
	//
	// Invariant: root belongs to fs.
	vfs  *VirtualFilesystem
	fs   *Filesystem
	root *Dentry

	// key is protected by VirtualFilesystem.mountMu and
	// VirtualFilesystem.mounts.seq, and may be nil. References are held on
	// key.parent and key.point if they are not nil.
	//
	// Invariant: key.parent != nil iff key.point != nil. key.point belongs to
	// key.parent.fs.
	key mountKey

	// ns is the namespace in which this Mount was mounted. ns is protected by
	// VirtualFilesystem.mountMu.
	ns *MountNamespace

	// The lower 63 bits of refs are a reference count. The MSB of refs is set
	// if the Mount has been eagerly umounted, as by umount(2) without the
	// MNT_DETACH flag. refs is accessed using atomic memory operations.
	refs int64

	// children is the set of all Mounts for which Mount.key.parent is this
	// Mount. children is protected by VirtualFilesystem.mountMu.
	children map[*Mount]struct{}

	// umounted is true if VFS.umountRecursiveLocked() has been called on this
	// Mount. VirtualFilesystem does not hold a reference on Mounts for which
	// umounted is true. umounted is protected by VirtualFilesystem.mountMu.
	umounted bool

	// The lower 63 bits of writers is the number of calls to
	// Mount.CheckBeginWrite() that have not yet been paired with a call to
	// Mount.EndWrite(). The MSB of writers is set if MS_RDONLY is in effect.
	// writers is accessed using atomic memory operations.
	writers int64
}

// A MountNamespace is a collection of Mounts.
//
// MountNamespaces are reference-counted. Unless otherwise specified, all
// MountNamespace methods require that a reference is held.
//
// MountNamespace is analogous to Linux's struct mnt_namespace.
type MountNamespace struct {
	// root is the MountNamespace's root mount. root is immutable.
	root *Mount

	// refs is the reference count. refs is accessed using atomic memory
	// operations.
	refs int64

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
}

// NewMountNamespace returns a new mount namespace with a root filesystem
// configured by the given arguments. A reference is taken on the returned
// MountNamespace.
func (vfs *VirtualFilesystem) NewMountNamespace(ctx context.Context, creds *auth.Credentials, source, fsTypeName string, opts *GetFilesystemOptions) (*MountNamespace, error) {
	rft := vfs.getFilesystemType(fsTypeName)
	if rft == nil {
		return nil, syserror.ENODEV
	}
	fs, root, err := rft.fsType.GetFilesystem(ctx, vfs, creds, source, *opts)
	if err != nil {
		return nil, err
	}
	mntns := &MountNamespace{
		refs:        1,
		mountpoints: make(map[*Dentry]uint32),
	}
	mntns.root = &Mount{
		vfs:  vfs,
		fs:   fs,
		root: root,
		ns:   mntns,
		refs: 1,
	}
	return mntns, nil
}

// MountAt creates and mounts a Filesystem configured by the given arguments.
func (vfs *VirtualFilesystem) MountAt(ctx context.Context, creds *auth.Credentials, source string, target *PathOperation, fsTypeName string, opts *MountOptions) error {
	rft := vfs.getFilesystemType(fsTypeName)
	if rft == nil {
		return syserror.ENODEV
	}
	if !opts.InternalMount && !rft.opts.AllowUserMount {
		return syserror.ENODEV
	}
	fs, root, err := rft.fsType.GetFilesystem(ctx, vfs, creds, source, opts.GetFilesystemOptions)
	if err != nil {
		return err
	}
	// We can't hold vfs.mountMu while calling FilesystemImpl methods due to
	// lock ordering.
	vd, err := vfs.GetDentryAt(ctx, creds, target, &GetDentryOptions{})
	if err != nil {
		root.DecRef()
		fs.DecRef()
		return err
	}
	vfs.mountMu.Lock()
	vd.dentry.mu.Lock()
	for {
		if vd.dentry.IsDisowned() {
			vd.dentry.mu.Unlock()
			vfs.mountMu.Unlock()
			vd.DecRef()
			root.DecRef()
			fs.DecRef()
			return syserror.ENOENT
		}
		// vd might have been mounted over between vfs.GetDentryAt() and
		// vfs.mountMu.Lock().
		if !vd.dentry.isMounted() {
			break
		}
		nextmnt := vfs.mounts.Lookup(vd.mount, vd.dentry)
		if nextmnt == nil {
			break
		}
		// It's possible that nextmnt has been umounted but not disconnected,
		// in which case vfs no longer holds a reference on it, and the last
		// reference may be concurrently dropped even though we're holding
		// vfs.mountMu.
		if !nextmnt.tryIncMountedRef() {
			break
		}
		// This can't fail since we're holding vfs.mountMu.
		nextmnt.root.IncRef()
		vd.dentry.mu.Unlock()
		vd.DecRef()
		vd = VirtualDentry{
			mount:  nextmnt,
			dentry: nextmnt.root,
		}
		vd.dentry.mu.Lock()
	}
	// TODO: Linux requires that either both the mount point and the mount root
	// are directories, or neither are, and returns ENOTDIR if this is not the
	// case.
	mntns := vd.mount.ns
	mnt := &Mount{
		vfs:  vfs,
		fs:   fs,
		root: root,
		ns:   mntns,
		refs: 1,
	}
	vfs.mounts.seq.BeginWrite()
	vfs.connectLocked(mnt, vd, mntns)
	vfs.mounts.seq.EndWrite()
	vd.dentry.mu.Unlock()
	vfs.mountMu.Unlock()
	return nil
}

// UmountAt removes the Mount at the given path.
func (vfs *VirtualFilesystem) UmountAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *UmountOptions) error {
	if opts.Flags&^(linux.MNT_FORCE|linux.MNT_DETACH) != 0 {
		return syserror.EINVAL
	}

	// MNT_FORCE is currently unimplemented except for the permission check.
	if opts.Flags&linux.MNT_FORCE != 0 && creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, creds.UserNamespace.Root()) {
		return syserror.EPERM
	}

	vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
	if err != nil {
		return err
	}
	defer vd.DecRef()
	if vd.dentry != vd.mount.root {
		return syserror.EINVAL
	}
	vfs.mountMu.Lock()
	if mntns := MountNamespaceFromContext(ctx); mntns != nil && mntns != vd.mount.ns {
		vfs.mountMu.Unlock()
		return syserror.EINVAL
	}

	// TODO(jamieliu): Linux special-cases umount of the caller's root, which
	// we don't implement yet (we'll just fail it since the caller holds a
	// reference on it).

	vfs.mounts.seq.BeginWrite()
	if opts.Flags&linux.MNT_DETACH == 0 {
		if len(vd.mount.children) != 0 {
			vfs.mounts.seq.EndWrite()
			vfs.mountMu.Unlock()
			return syserror.EBUSY
		}
		// We are holding a reference on vd.mount.
		expectedRefs := int64(1)
		if !vd.mount.umounted {
			expectedRefs = 2
		}
		if atomic.LoadInt64(&vd.mount.refs)&^math.MinInt64 != expectedRefs { // mask out MSB
			vfs.mounts.seq.EndWrite()
			vfs.mountMu.Unlock()
			return syserror.EBUSY
		}
	}
	vdsToDecRef, mountsToDecRef := vfs.umountRecursiveLocked(vd.mount, &umountRecursiveOptions{
		eager:               opts.Flags&linux.MNT_DETACH == 0,
		disconnectHierarchy: true,
	}, nil, nil)
	vfs.mounts.seq.EndWrite()
	vfs.mountMu.Unlock()
	for _, vd := range vdsToDecRef {
		vd.DecRef()
	}
	for _, mnt := range mountsToDecRef {
		mnt.DecRef()
	}
	return nil
}

type umountRecursiveOptions struct {
	// If eager is true, ensure that future calls to Mount.tryIncMountedRef()
	// on umounted mounts fail.
	//
	// eager is analogous to Linux's UMOUNT_SYNC.
	eager bool

	// If disconnectHierarchy is true, Mounts that are umounted hierarchically
	// should be disconnected from their parents. (Mounts whose parents are not
	// umounted, which in most cases means the Mount passed to the initial call
	// to umountRecursiveLocked, are unconditionally disconnected for
	// consistency with Linux.)
	//
	// disconnectHierarchy is analogous to Linux's !UMOUNT_CONNECTED.
	disconnectHierarchy bool
}

// umountRecursiveLocked marks mnt and its descendants as umounted. It does not
// release mount or dentry references; instead, it appends VirtualDentries and
// Mounts on which references must be dropped to vdsToDecRef and mountsToDecRef
// respectively, and returns updated slices. (This is necessary because
// filesystem locks possibly taken by DentryImpl.DecRef() may precede
// vfs.mountMu in the lock order, and Mount.DecRef() may lock vfs.mountMu.)
//
// umountRecursiveLocked is analogous to Linux's fs/namespace.c:umount_tree().
//
// Preconditions: vfs.mountMu must be locked. vfs.mounts.seq must be in a
// writer critical section.
func (vfs *VirtualFilesystem) umountRecursiveLocked(mnt *Mount, opts *umountRecursiveOptions, vdsToDecRef []VirtualDentry, mountsToDecRef []*Mount) ([]VirtualDentry, []*Mount) {
	if !mnt.umounted {
		mnt.umounted = true
		mountsToDecRef = append(mountsToDecRef, mnt)
		if parent := mnt.parent(); parent != nil && (opts.disconnectHierarchy || !parent.umounted) {
			vdsToDecRef = append(vdsToDecRef, vfs.disconnectLocked(mnt))
		}
	}
	if opts.eager {
		for {
			refs := atomic.LoadInt64(&mnt.refs)
			if refs < 0 {
				break
			}
			if atomic.CompareAndSwapInt64(&mnt.refs, refs, refs|math.MinInt64) {
				break
			}
		}
	}
	for child := range mnt.children {
		vdsToDecRef, mountsToDecRef = vfs.umountRecursiveLocked(child, opts, vdsToDecRef, mountsToDecRef)
	}
	return vdsToDecRef, mountsToDecRef
}

// connectLocked makes vd the mount parent/point for mnt. It consumes
// references held by vd.
//
// Preconditions: vfs.mountMu must be locked. vfs.mounts.seq must be in a
// writer critical section. d.mu must be locked. mnt.parent() == nil.
func (vfs *VirtualFilesystem) connectLocked(mnt *Mount, vd VirtualDentry, mntns *MountNamespace) {
	mnt.storeKey(vd)
	if vd.mount.children == nil {
		vd.mount.children = make(map[*Mount]struct{})
	}
	vd.mount.children[mnt] = struct{}{}
	atomic.AddUint32(&vd.dentry.mounts, 1)
	mntns.mountpoints[vd.dentry]++
	vfs.mounts.insertSeqed(mnt)
	vfsmpmounts, ok := vfs.mountpoints[vd.dentry]
	if !ok {
		vfsmpmounts = make(map[*Mount]struct{})
		vfs.mountpoints[vd.dentry] = vfsmpmounts
	}
	vfsmpmounts[mnt] = struct{}{}
}

// disconnectLocked makes vd have no mount parent/point and returns its old
// mount parent/point with a reference held.
//
// Preconditions: vfs.mountMu must be locked. vfs.mounts.seq must be in a
// writer critical section. mnt.parent() != nil.
func (vfs *VirtualFilesystem) disconnectLocked(mnt *Mount) VirtualDentry {
	vd := mnt.loadKey()
	mnt.storeKey(VirtualDentry{})
	delete(vd.mount.children, mnt)
	atomic.AddUint32(&vd.dentry.mounts, math.MaxUint32) // -1
	mnt.ns.mountpoints[vd.dentry]--
	if mnt.ns.mountpoints[vd.dentry] == 0 {
		delete(mnt.ns.mountpoints, vd.dentry)
	}
	vfs.mounts.removeSeqed(mnt)
	vfsmpmounts := vfs.mountpoints[vd.dentry]
	delete(vfsmpmounts, mnt)
	if len(vfsmpmounts) == 0 {
		delete(vfs.mountpoints, vd.dentry)
	}
	return vd
}

// tryIncMountedRef increments mnt's reference count and returns true. If mnt's
// reference count is already zero, or has been eagerly umounted,
// tryIncMountedRef does nothing and returns false.
//
// tryIncMountedRef does not require that a reference is held on mnt.
func (mnt *Mount) tryIncMountedRef() bool {
	for {
		refs := atomic.LoadInt64(&mnt.refs)
		if refs <= 0 { // refs < 0 => MSB set => eagerly unmounted
			return false
		}
		if atomic.CompareAndSwapInt64(&mnt.refs, refs, refs+1) {
			return true
		}
	}
}

// IncRef increments mnt's reference count.
func (mnt *Mount) IncRef() {
	// In general, negative values for mnt.refs are valid because the MSB is
	// the eager-unmount bit.
	atomic.AddInt64(&mnt.refs, 1)
}

// DecRef decrements mnt's reference count.
func (mnt *Mount) DecRef() {
	refs := atomic.AddInt64(&mnt.refs, -1)
	if refs&^math.MinInt64 == 0 { // mask out MSB
		var vd VirtualDentry
		if mnt.parent() != nil {
			mnt.vfs.mountMu.Lock()
			mnt.vfs.mounts.seq.BeginWrite()
			vd = mnt.vfs.disconnectLocked(mnt)
			mnt.vfs.mounts.seq.EndWrite()
			mnt.vfs.mountMu.Unlock()
		}
		mnt.root.DecRef()
		mnt.fs.DecRef()
		if vd.Ok() {
			vd.DecRef()
		}
	}
}

// IncRef increments mntns' reference count.
func (mntns *MountNamespace) IncRef() {
	if atomic.AddInt64(&mntns.refs, 1) <= 1 {
		panic("MountNamespace.IncRef() called without holding a reference")
	}
}

// DecRef decrements mntns' reference count.
func (mntns *MountNamespace) DecRef(vfs *VirtualFilesystem) {
	if refs := atomic.AddInt64(&mntns.refs, -1); refs == 0 {
		vfs.mountMu.Lock()
		vfs.mounts.seq.BeginWrite()
		vdsToDecRef, mountsToDecRef := vfs.umountRecursiveLocked(mntns.root, &umountRecursiveOptions{
			disconnectHierarchy: true,
		}, nil, nil)
		vfs.mounts.seq.EndWrite()
		vfs.mountMu.Unlock()
		for _, vd := range vdsToDecRef {
			vd.DecRef()
		}
		for _, mnt := range mountsToDecRef {
			mnt.DecRef()
		}
	} else if refs < 0 {
		panic("MountNamespace.DecRef() called without holding a reference")
	}
}

// getMountAt returns the last Mount in the stack mounted at (mnt, d). It takes
// a reference on the returned Mount. If (mnt, d) is not a mount point,
// getMountAt returns nil.
//
// getMountAt is analogous to Linux's fs/namei.c:follow_mount().
//
// Preconditions: References are held on mnt and d.
func (vfs *VirtualFilesystem) getMountAt(mnt *Mount, d *Dentry) *Mount {
	// The first mount is special-cased:
	//
	// - The caller is assumed to have checked d.isMounted() already. (This
	// isn't a precondition because it doesn't matter for correctness.)
	//
	// - We return nil, instead of mnt, if there is no mount at (mnt, d).
	//
	// - We don't drop the caller's references on mnt and d.
retryFirst:
	next := vfs.mounts.Lookup(mnt, d)
	if next == nil {
		return nil
	}
	if !next.tryIncMountedRef() {
		// Raced with umount.
		goto retryFirst
	}
	mnt = next
	d = next.root
	// We don't need to take Dentry refs anywhere in this function because
	// Mounts hold references on Mount.root, which is immutable.
	for d.isMounted() {
		next := vfs.mounts.Lookup(mnt, d)
		if next == nil {
			break
		}
		if !next.tryIncMountedRef() {
			// Raced with umount.
			continue
		}
		mnt.DecRef()
		mnt = next
		d = next.root
	}
	return mnt
}

// getMountpointAt returns the mount point for the stack of Mounts including
// mnt. It takes a reference on the returned VirtualDentry. If no such mount
// point exists (i.e. mnt is a root mount), getMountpointAt returns (nil, nil).
//
// Preconditions: References are held on mnt and root. vfsroot is not (mnt,
// mnt.root).
func (vfs *VirtualFilesystem) getMountpointAt(mnt *Mount, vfsroot VirtualDentry) VirtualDentry {
	// The first mount is special-cased:
	//
	// - The caller must have already checked mnt against vfsroot.
	//
	// - We return nil, instead of mnt, if there is no mount point for mnt.
	//
	// - We don't drop the caller's reference on mnt.
retryFirst:
	epoch := vfs.mounts.seq.BeginRead()
	parent, point := mnt.parent(), mnt.point()
	if !vfs.mounts.seq.ReadOk(epoch) {
		goto retryFirst
	}
	if parent == nil {
		return VirtualDentry{}
	}
	if !parent.tryIncMountedRef() {
		// Raced with umount.
		goto retryFirst
	}
	if !point.TryIncRef() {
		// Since Mount holds a reference on Mount.key.point, this can only
		// happen due to a racing change to Mount.key.
		parent.DecRef()
		goto retryFirst
	}
	if !vfs.mounts.seq.ReadOk(epoch) {
		point.DecRef()
		parent.DecRef()
		goto retryFirst
	}
	mnt = parent
	d := point
	for {
		if mnt == vfsroot.mount && d == vfsroot.dentry {
			break
		}
		if d != mnt.root {
			break
		}
	retryNotFirst:
		epoch := vfs.mounts.seq.BeginRead()
		parent, point := mnt.parent(), mnt.point()
		if !vfs.mounts.seq.ReadOk(epoch) {
			goto retryNotFirst
		}
		if parent == nil {
			break
		}
		if !parent.tryIncMountedRef() {
			// Raced with umount.
			goto retryNotFirst
		}
		if !point.TryIncRef() {
			// Since Mount holds a reference on Mount.key.point, this can
			// only happen due to a racing change to Mount.key.
			parent.DecRef()
			goto retryNotFirst
		}
		if !vfs.mounts.seq.ReadOk(epoch) {
			point.DecRef()
			parent.DecRef()
			goto retryNotFirst
		}
		d.DecRef()
		mnt.DecRef()
		mnt = parent
		d = point
	}
	return VirtualDentry{mnt, d}
}

// CheckBeginWrite increments the counter of in-progress write operations on
// mnt. If mnt is mounted MS_RDONLY, CheckBeginWrite does nothing and returns
// EROFS.
//
// If CheckBeginWrite succeeds, EndWrite must be called when the write
// operation is finished.
func (mnt *Mount) CheckBeginWrite() error {
	if atomic.AddInt64(&mnt.writers, 1) < 0 {
		atomic.AddInt64(&mnt.writers, -1)
		return syserror.EROFS
	}
	return nil
}

// EndWrite indicates that a write operation signaled by a previous successful
// call to CheckBeginWrite has finished.
func (mnt *Mount) EndWrite() {
	atomic.AddInt64(&mnt.writers, -1)
}

// Preconditions: VirtualFilesystem.mountMu must be locked.
func (mnt *Mount) setReadOnlyLocked(ro bool) error {
	if oldRO := atomic.LoadInt64(&mnt.writers) < 0; oldRO == ro {
		return nil
	}
	if ro {
		if !atomic.CompareAndSwapInt64(&mnt.writers, 0, math.MinInt64) {
			return syserror.EBUSY
		}
		return nil
	}
	// Unset MSB without dropping any temporary increments from failed calls to
	// mnt.CheckBeginWrite().
	atomic.AddInt64(&mnt.writers, math.MinInt64)
	return nil
}

// Filesystem returns the mounted Filesystem. It does not take a reference on
// the returned Filesystem.
func (mnt *Mount) Filesystem() *Filesystem {
	return mnt.fs
}

// Root returns mntns' root. A reference is taken on the returned
// VirtualDentry.
func (mntns *MountNamespace) Root() VirtualDentry {
	vd := VirtualDentry{
		mount:  mntns.root,
		dentry: mntns.root.root,
	}
	vd.IncRef()
	return vd
}
