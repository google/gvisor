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
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// MountMax is the maximum number of mounts allowed. In Linux this can be
// configured by the user at /proc/sys/fs/mount-max, but the default is
// 100,000. We set the gVisor limit to 10,000.
const MountMax = 10000

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
//
// +stateify savable
type Mount struct {
	// vfs, fs, root are immutable. References are held on fs and root.
	// Note that for a disconnected mount, root may be nil.
	//
	// Invariant: if not nil, root belongs to fs.
	vfs  *VirtualFilesystem
	fs   *Filesystem
	root *Dentry

	// ID is the immutable mount ID.
	ID uint64

	// Flags contains settings as specified for mount(2), e.g. MS_NOEXEC, except
	// for MS_RDONLY which is tracked in "writers". Immutable.
	Flags MountFlags

	// key is protected by VirtualFilesystem.mountMu and
	// VirtualFilesystem.mounts.seq, and may be nil. References are held on
	// key.parent and key.point if they are not nil.
	//
	// Invariant: key.parent != nil iff key.point != nil. key.point belongs to
	// key.parent.fs.
	key mountKey `state:".(VirtualDentry)"`

	// ns is the namespace in which this Mount was mounted. ns is protected by
	// VirtualFilesystem.mountMu.
	ns *MountNamespace

	// The lower 63 bits of refs are a reference count. The MSB of refs is set
	// if the Mount has been eagerly umounted, as by umount(2) without the
	// MNT_DETACH flag. refs is accessed using atomic memory operations.
	refs atomicbitops.Int64

	// children is the set of all Mounts for which Mount.key.parent is this
	// Mount. children is protected by VirtualFilesystem.mountMu.
	children map[*Mount]struct{}

	// propagationType is propagation type of this mount. It can be shared or
	// private.
	propType PropagationType

	// sharedList is a list of mounts in the shared peer group. It is nil if
	// propType is not Shared. All mounts in a shared peer group hold the same
	// sharedList. The mounts in sharedList do not need an extra reference taken
	// because it would be redundant with the taken for being attached to a
	// parent mount. If a mount is in a shared list if and only if it is attached
	// and has the shared propagation type.
	sharedList  *sharedList
	sharedEntry sharedEntry

	// groupID is the ID for this mount's shared peer group. If the mount is not
	// in a peer group, this is 0.
	groupID uint32

	// umounted is true if VFS.umountRecursiveLocked() has been called on this
	// Mount. VirtualFilesystem does not hold a reference on Mounts for which
	// umounted is true. umounted is protected by VirtualFilesystem.mountMu.
	umounted bool

	// The lower 63 bits of writers is the number of calls to
	// Mount.CheckBeginWrite() that have not yet been paired with a call to
	// Mount.EndWrite(). The MSB of writers is set if MS_RDONLY is in effect.
	// writers is accessed using atomic memory operations.
	writers atomicbitops.Int64
}

type sharedMapper struct{}

func (sharedMapper) linkerFor(mnt *Mount) *sharedEntry { return &mnt.sharedEntry }

func newMount(vfs *VirtualFilesystem, fs *Filesystem, root *Dentry, mntns *MountNamespace, opts *MountOptions) *Mount {
	mnt := &Mount{
		ID:       vfs.lastMountID.Add(1),
		Flags:    opts.Flags,
		vfs:      vfs,
		fs:       fs,
		root:     root,
		ns:       mntns,
		propType: Private,
		refs:     atomicbitops.FromInt64(1),
	}
	if opts.ReadOnly {
		mnt.setReadOnlyLocked(true)
	}
	refs.Register(mnt)
	return mnt
}

// Options returns a copy of the MountOptions currently applicable to mnt.
func (mnt *Mount) Options() MountOptions {
	mnt.vfs.mountMu.Lock()
	defer mnt.vfs.mountMu.Unlock()
	return MountOptions{
		Flags:    mnt.Flags,
		ReadOnly: mnt.ReadOnly(),
	}
}

func (mnt *Mount) generateOptionalTags() string {
	mnt.vfs.mountMu.Lock()
	defer mnt.vfs.mountMu.Unlock()
	// TODO(b/249777195): Support MS_SLAVE and MS_UNBINDABLE propagation types.
	var optional string
	if mnt.propType == Shared {
		optional = fmt.Sprintf("shared:%d", mnt.groupID)
	}
	return optional
}

// A MountNamespace is a collection of Mounts.//
// MountNamespaces are reference-counted. Unless otherwise specified, all
// MountNamespace methods require that a reference is held.
//
// MountNamespace is analogous to Linux's struct mnt_namespace.
//
// +stateify savable
type MountNamespace struct {
	MountNamespaceRefs

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

// NewMountNamespace returns a new mount namespace with a root filesystem
// configured by the given arguments. A reference is taken on the returned
// MountNamespace.
func (vfs *VirtualFilesystem) NewMountNamespace(ctx context.Context, creds *auth.Credentials, source, fsTypeName string, opts *MountOptions) (*MountNamespace, error) {
	rft := vfs.getFilesystemType(fsTypeName)
	if rft == nil {
		ctx.Warningf("Unknown filesystem type: %s", fsTypeName)
		return nil, linuxerr.ENODEV
	}
	fs, root, err := rft.fsType.GetFilesystem(ctx, vfs, creds, source, opts.GetFilesystemOptions)
	if err != nil {
		return nil, err
	}
	mntns := &MountNamespace{
		Owner:       creds.UserNamespace,
		mountpoints: make(map[*Dentry]uint32),
	}
	mntns.InitRefs()
	mntns.root = newMount(vfs, fs, root, mntns, opts)
	return mntns, nil
}

// NewFilesystem creates a new filesystem object not yet associated with any
// mounts. It can be installed into the filesystem tree with ConnectMountAt.
// Note that only the filesystem-specific mount options from opts are used by
// this function, mount flags are ignored. To set mount flags, pass them to a
// corresponding ConnectMountAt.
func (vfs *VirtualFilesystem) NewFilesystem(ctx context.Context, creds *auth.Credentials, source, fsTypeName string, opts *MountOptions) (*Filesystem, *Dentry, error) {
	rft := vfs.getFilesystemType(fsTypeName)
	if rft == nil {
		return nil, nil, linuxerr.ENODEV
	}
	if !opts.InternalMount && !rft.opts.AllowUserMount {
		return nil, nil, linuxerr.ENODEV
	}
	return rft.fsType.GetFilesystem(ctx, vfs, creds, source, opts.GetFilesystemOptions)
}

// NewDisconnectedMount returns a Mount representing fs with the given root
// (which may be nil). The new Mount is not associated with any MountNamespace
// and is not connected to any other Mounts. References are taken on fs and
// root.
func (vfs *VirtualFilesystem) NewDisconnectedMount(fs *Filesystem, root *Dentry, opts *MountOptions) *Mount {
	fs.IncRef()
	if root != nil {
		root.IncRef()
	}
	return newMount(vfs, fs, root, nil /* mntns */, opts)
}

// MountDisconnected creates a Filesystem configured by the given arguments,
// then returns a Mount representing it. The new Mount is not associated with
// any MountNamespace and is not connected to any other Mounts.
func (vfs *VirtualFilesystem) MountDisconnected(ctx context.Context, creds *auth.Credentials, source string, fsTypeName string, opts *MountOptions) (*Mount, error) {
	fs, root, err := vfs.NewFilesystem(ctx, creds, source, fsTypeName, opts)
	if err != nil {
		return nil, err
	}
	return newMount(vfs, fs, root, nil /* mntns */, opts), nil
}

// ConnectMountAt connects mnt at the path represented by target.
//
// Preconditions: mnt must be disconnected.
func (vfs *VirtualFilesystem) ConnectMountAt(ctx context.Context, creds *auth.Credentials, mnt *Mount, target *PathOperation) error {
	// We can't hold vfs.mountMu while calling FilesystemImpl methods due to
	// lock ordering.
	vd, err := vfs.GetDentryAt(ctx, creds, target, &GetDentryOptions{})
	if err != nil {
		return err
	}
	vfs.mountMu.Lock()
	defer vfs.mountMu.Unlock()
	tree := vfs.preparePropagationTree(mnt, vd)

	cleanup := cleanup.Make(func() {
		vfs.abortPropagationTree(ctx, tree) // +checklocksforce
	})
	defer cleanup.Clean()
	// Check if the new mount + all the propagation mounts puts us over the max.
	if uint32(len(tree)+1)+vd.mount.ns.mounts > MountMax {
		vd.DecRef(ctx)
		return linuxerr.ENOSPC
	}
	if err := vfs.connectMountAt(ctx, mnt, vd); err != nil {
		return err
	}
	vfs.commitPropagationTree(ctx, tree)
	cleanup.Release()
	return nil
}

// connectMountAtLocked attaches mnt at vd. It returns the new mountpoint of mnt
// if no error occurred.
//
// Preconditions:
//   - mnt must be disconnected.
//   - vfs.mountMu must be locked.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) connectMountAt(ctx context.Context, mnt *Mount, vd VirtualDentry) error {
	vdDentry := vd.dentry
	vdDentry.mu.Lock()
	for {
		if vd.mount.umounted || vdDentry.dead {
			vdDentry.mu.Unlock()
			vd.DecRef(ctx)
			return linuxerr.ENOENT
		}
		// vd might have been mounted over between vfs.GetDentryAt() and
		// vfs.mountMu.Lock().
		if !vdDentry.isMounted() {
			break
		}
		nextmnt := vfs.mounts.Lookup(vd.mount, vdDentry)
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
		vdDentry.mu.Unlock()
		vd.DecRef(ctx)
		vd = VirtualDentry{
			mount:  nextmnt,
			dentry: nextmnt.root,
		}
		vdDentry.mu.Lock()
	}
	// TODO(gvisor.dev/issue/1035): Linux requires that either both the mount
	// point and the mount root are directories, or neither are, and returns
	// ENOTDIR if this is not the case.
	mntns := vd.mount.ns
	vfs.mounts.seq.BeginWrite()
	vfs.connectLocked(mnt, vd, mntns)
	vfs.mounts.seq.EndWrite()
	vdDentry.mu.Unlock()
	return nil
}

// CloneMountAt returns a new mount with the same fs, specified root and
// mount options. If mnt's propagation type is shared the new mount is
// automatically made a peer of mnt. If mount options are nil, mnt's
// options are copied.
func (vfs *VirtualFilesystem) CloneMountAt(mnt *Mount, root *Dentry, mopts *MountOptions) *Mount {
	vfs.mountMu.Lock()
	defer vfs.mountMu.Unlock()
	clone := vfs.cloneMount(mnt, root, mopts)
	vfs.addPeer(mnt, clone)
	return clone
}

// cloneMount returns a new mount with mnt.fs as the filesystem and root as the
// root. The returned mount has an extra reference.
//
// +checklocks:vfs.mountMu
// +checklocksalias:mnt.vfs.mountMu=vfs.mountMu
func (vfs *VirtualFilesystem) cloneMount(mnt *Mount, root *Dentry, mopts *MountOptions) *Mount {
	opts := mopts
	if opts == nil {
		opts = &MountOptions{
			Flags:    mnt.Flags,
			ReadOnly: mnt.ReadOnly(),
		}
	}
	return vfs.NewDisconnectedMount(mnt.fs, root, opts)
}

// BindAt creates a clone of the source path's parent mount and mounts it at
// the target path. The new mount's root dentry is one pointed to by the source
// path.
//
// TODO(b/249121230): Support recursive bind mounting.
func (vfs *VirtualFilesystem) BindAt(ctx context.Context, creds *auth.Credentials, source, target *PathOperation) (*Mount, error) {
	sourceVd, err := vfs.GetDentryAt(ctx, creds, source, &GetDentryOptions{})
	if err != nil {
		return nil, err
	}
	defer sourceVd.DecRef(ctx)
	targetVd, err := vfs.GetDentryAt(ctx, creds, target, &GetDentryOptions{})
	if err != nil {
		return nil, err
	}

	vfs.mountMu.Lock()
	defer vfs.mountMu.Unlock()
	clone := vfs.cloneMount(sourceVd.mount, sourceVd.dentry, nil)
	defer clone.DecRef(ctx)
	tree := vfs.preparePropagationTree(clone, targetVd)
	if sourceVd.mount.propType == Shared {
		if clone.propType == Private {
			vfs.addPeer(sourceVd.mount, clone)
		} else {
			vfs.mergePeerGroup(sourceVd.mount, clone)
		}
	}
	cleanup := cleanup.Make(func() {
		// Checklocks doesn't work with anon functions.
		vfs.setPropagation(clone, Private)  // +checklocksforce
		vfs.abortPropagationTree(ctx, tree) // +checklocksforce
	})
	defer cleanup.Clean()
	if uint32(1+len(tree))+targetVd.mount.ns.mounts > MountMax {
		targetVd.DecRef(ctx)
		return nil, linuxerr.ENOSPC
	}
	if err := vfs.connectMountAt(ctx, clone, targetVd); err != nil {
		return nil, err
	}
	vfs.commitPropagationTree(ctx, tree)
	cleanup.Release()
	return clone, nil
}

// MountAt creates and mounts a Filesystem configured by the given arguments.
// The VirtualFilesystem will hold a reference to the Mount until it is
// unmounted.
//
// This method returns the mounted Mount without a reference, for convenience
// during VFS setup when there is no chance of racing with unmount.
func (vfs *VirtualFilesystem) MountAt(ctx context.Context, creds *auth.Credentials, source string, target *PathOperation, fsTypeName string, opts *MountOptions) (*Mount, error) {
	mnt, err := vfs.MountDisconnected(ctx, creds, source, fsTypeName, opts)
	if err != nil {
		return nil, err
	}
	defer mnt.DecRef(ctx)
	if err := vfs.ConnectMountAt(ctx, creds, mnt, target); err != nil {
		return nil, err
	}
	return mnt, nil
}

// UmountAt removes the Mount at the given path.
func (vfs *VirtualFilesystem) UmountAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *UmountOptions) error {
	if opts.Flags&^(linux.MNT_FORCE|linux.MNT_DETACH) != 0 {
		return linuxerr.EINVAL
	}

	// MNT_FORCE is currently unimplemented except for the permission check.
	// Force unmounting specifically requires CAP_SYS_ADMIN in the root user
	// namespace, and not in the owner user namespace for the target mount. See
	// fs/namespace.c:SYSCALL_DEFINE2(umount, ...)
	if opts.Flags&linux.MNT_FORCE != 0 && creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, creds.UserNamespace.Root()) {
		return linuxerr.EPERM
	}

	vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
	if err != nil {
		return err
	}
	// This defer statement is encapsulated in a function because vd.mount can be
	// modified in the block below. The arguments to defer are evaluated during
	// the construction of a defer statement, so if vd.DecRef() was not
	// encapsulated, the vd structure and its underlying pointers _at this point_
	// would be copied and DecRefd at the end of this function.
	defer func() {
		vd.DecRef(ctx)
	}()
	// Linux passes the LOOKUP_MOUNPOINT flag to user_path_at in ksys_umount to
	// resolve to the toppmost mount in the stack located at the specified path.
	// vfs.GetMountAt() imitiates this behavior. See fs/namei.c:user_path_at(...)
	// and fs/namespace.c:ksys_umount(...).
	if vd.dentry.isMounted() {
		if realmnt := vfs.getMountAt(ctx, vd.mount, vd.dentry); realmnt != nil {
			vd.mount.DecRef(ctx)
			vd.mount = realmnt
		}
	} else if vd.dentry != vd.mount.root {
		return linuxerr.EINVAL
	}

	vfs.mountMu.Lock()
	if mntns := MountNamespaceFromContext(ctx); mntns != nil {
		defer mntns.DecRef(ctx)
		if mntns != vd.mount.ns {
			vfs.mountMu.Unlock()
			return linuxerr.EINVAL
		}

		if vd.mount == vd.mount.ns.root {
			vfs.mountMu.Unlock()
			return linuxerr.EINVAL
		}
	}

	umountTree := []*Mount{vd.mount}
	parent, mountpoint := vd.mount.parent(), vd.mount.point()
	if parent != nil && parent.propType == Shared {
		for peer := parent.sharedList.Front(); peer != nil; peer = peer.sharedEntry.Next() {
			if peer == parent {
				continue
			}
			umountMnt := vfs.mounts.Lookup(peer, mountpoint)
			// From https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt:
			// If any peer has some child mounts, then that mount is not unmounted,
			// but all other mounts are unmounted.
			if umountMnt != nil && len(umountMnt.children) == 0 {
				umountTree = append(umountTree, umountMnt)
			}
		}
	}

	// TODO(gvisor.dev/issue/1035): Linux special-cases umount of the caller's
	// root, which we don't implement yet (we'll just fail it since the caller
	// holds a reference on it).

	vfs.mounts.seq.BeginWrite()
	if opts.Flags&linux.MNT_DETACH == 0 {
		if len(vd.mount.children) != 0 {
			vfs.mounts.seq.EndWrite()
			vfs.mountMu.Unlock()
			return linuxerr.EBUSY
		}
		// We are holding a reference on vd.mount.
		expectedRefs := int64(1)
		if !vd.mount.umounted {
			expectedRefs = 2
		}
		if vd.mount.refs.Load()&^math.MinInt64 != expectedRefs { // mask out MSB
			vfs.mounts.seq.EndWrite()
			vfs.mountMu.Unlock()
			return linuxerr.EBUSY
		}
	}
	var (
		vdsToDecRef    []VirtualDentry
		mountsToDecRef []*Mount
	)
	for _, mnt := range umountTree {
		vdsToDecRef, mountsToDecRef = vfs.umountRecursiveLocked(mnt, &umountRecursiveOptions{
			eager:               opts.Flags&linux.MNT_DETACH == 0,
			disconnectHierarchy: true,
		}, vdsToDecRef, mountsToDecRef)
	}
	vfs.mounts.seq.EndWrite()
	vfs.mountMu.Unlock()
	for _, vd := range vdsToDecRef {
		vd.DecRef(ctx)
	}
	for _, m := range mountsToDecRef {
		m.DecRef(ctx)
	}
	return nil
}

// +stateify savable
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
// Preconditions:
//   - vfs.mountMu must be locked.
//   - vfs.mounts.seq must be in a writer critical section.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) umountRecursiveLocked(mnt *Mount, opts *umountRecursiveOptions, vdsToDecRef []VirtualDentry, mountsToDecRef []*Mount) ([]VirtualDentry, []*Mount) {
	if !mnt.umounted {
		mnt.umounted = true
		mountsToDecRef = append(mountsToDecRef, mnt)
		if parent := mnt.parent(); parent != nil && (opts.disconnectHierarchy || !parent.umounted) {
			vdsToDecRef = append(vdsToDecRef, vfs.disconnectLocked(mnt))
		}
		if mnt.propType == Shared {
			vfs.setPropagation(mnt, Private)
		}
	}
	if opts.eager {
		for {
			refs := mnt.refs.Load()
			if refs < 0 {
				break
			}
			if mnt.refs.CompareAndSwap(refs, refs|math.MinInt64) {
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
// Preconditions:
//   - vfs.mountMu must be locked.
//   - vfs.mounts.seq must be in a writer critical section.
//   - d.mu must be locked.
//   - mnt.parent() == nil, i.e. mnt must not already be connected.
func (vfs *VirtualFilesystem) connectLocked(mnt *Mount, vd VirtualDentry, mntns *MountNamespace) {
	if checkInvariants {
		if mnt.parent() != nil {
			panic("VFS.connectLocked called on connected mount")
		}
	}
	mnt.IncRef() // dropped by callers of umountRecursiveLocked
	mnt.setKey(vd)
	if vd.mount.children == nil {
		vd.mount.children = make(map[*Mount]struct{})
	}
	vd.mount.children[mnt] = struct{}{}
	vd.dentry.mounts.Add(1)
	mnt.ns = mntns
	mntns.mountpoints[vd.dentry]++
	mntns.mounts++
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
// Preconditions:
//   - vfs.mountMu must be locked.
//   - vfs.mounts.seq must be in a writer critical section.
//   - mnt.parent() != nil.
func (vfs *VirtualFilesystem) disconnectLocked(mnt *Mount) VirtualDentry {
	vd := mnt.getKey()
	if checkInvariants {
		if vd.mount != nil {
			panic("VFS.disconnectLocked called on disconnected mount")
		}
		if mnt.ns.mountpoints[vd.dentry] == 0 {
			panic("VFS.disconnectLocked called on dentry with zero mountpoints.")
		}
		if mnt.ns.mounts == 0 {
			panic("VFS.disconnectLocked called on namespace with zero mounts.")
		}
	}
	mnt.loadKey(VirtualDentry{})
	delete(vd.mount.children, mnt)
	vd.dentry.mounts.Add(math.MaxUint32) // -1
	mnt.ns.mountpoints[vd.dentry]--
	mnt.ns.mounts--
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
		r := mnt.refs.Load()
		if r <= 0 { // r < 0 => MSB set => eagerly unmounted
			return false
		}
		if mnt.refs.CompareAndSwap(r, r+1) {
			if mnt.LogRefs() {
				refs.LogTryIncRef(mnt, r+1)
			}
			return true
		}
	}
}

// IncRef increments mnt's reference count.
func (mnt *Mount) IncRef() {
	// In general, negative values for mnt.refs are valid because the MSB is
	// the eager-unmount bit.
	r := mnt.refs.Add(1)
	if mnt.LogRefs() {
		refs.LogIncRef(mnt, r)
	}
}

// DecRef decrements mnt's reference count.
func (mnt *Mount) DecRef(ctx context.Context) {
	r := mnt.refs.Add(-1)
	if mnt.LogRefs() {
		refs.LogDecRef(mnt, r)
	}
	if r&^math.MinInt64 == 0 { // mask out MSB
		refs.Unregister(mnt)
		mnt.destroy(ctx)
	}
}

func (mnt *Mount) destroy(ctx context.Context) {
	var vd VirtualDentry
	if mnt.parent() != nil {
		mnt.vfs.mountMu.Lock()
		mnt.vfs.mounts.seq.BeginWrite()
		vd = mnt.vfs.disconnectLocked(mnt)
		mnt.vfs.mounts.seq.EndWrite()
		mnt.vfs.mountMu.Unlock()
	}
	if mnt.root != nil {
		mnt.root.DecRef(ctx)
	}
	mnt.fs.DecRef(ctx)
	if vd.Ok() {
		vd.DecRef(ctx)
	}
}

// RefType implements refs.CheckedObject.Type.
func (mnt *Mount) RefType() string {
	return "vfs.Mount"
}

// LeakMessage implements refs.CheckedObject.LeakMessage.
func (mnt *Mount) LeakMessage() string {
	return fmt.Sprintf("[vfs.Mount %p] reference count of %d instead of 0", mnt, mnt.refs.Load())
}

// LogRefs implements refs.CheckedObject.LogRefs.
//
// This should only be set to true for debugging purposes, as it can generate an
// extremely large amount of output and drastically degrade performance.
func (mnt *Mount) LogRefs() bool {
	return false
}

// DecRef decrements mntns' reference count.
func (mntns *MountNamespace) DecRef(ctx context.Context) {
	vfs := mntns.root.fs.VirtualFilesystem()
	mntns.MountNamespaceRefs.DecRef(func() {
		vfs.mountMu.Lock()
		vfs.mounts.seq.BeginWrite()
		vdsToDecRef, mountsToDecRef := vfs.umountRecursiveLocked(mntns.root, &umountRecursiveOptions{
			disconnectHierarchy: true,
		}, nil, nil)
		vfs.mounts.seq.EndWrite()
		vfs.mountMu.Unlock()
		for _, vd := range vdsToDecRef {
			vd.DecRef(ctx)
		}
		for _, mnt := range mountsToDecRef {
			mnt.DecRef(ctx)
		}
	})
}

// getMountAt returns the last Mount in the stack mounted at (mnt, d). It takes
// a reference on the returned Mount. If (mnt, d) is not a mount point,
// getMountAt returns nil.
//
// getMountAt is analogous to Linux's fs/namei.c:follow_mount().
//
// Preconditions: References are held on mnt and d.
func (vfs *VirtualFilesystem) getMountAt(ctx context.Context, mnt *Mount, d *Dentry) *Mount {
	// The first mount is special-cased:
	//
	//	- The caller is assumed to have checked d.isMounted() already. (This
	//		isn't a precondition because it doesn't matter for correctness.)
	//
	//	- We return nil, instead of mnt, if there is no mount at (mnt, d).
	//
	//	- We don't drop the caller's references on mnt and d.
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
		mnt.DecRef(ctx)
		mnt = next
		d = next.root
	}
	return mnt
}

// getMountpointAt returns the mount point for the stack of Mounts including
// mnt. It takes a reference on the returned VirtualDentry. If no such mount
// point exists (i.e. mnt is a root mount), getMountpointAt returns (nil, nil).
//
// Preconditions:
//   - References are held on mnt and root.
//   - vfsroot is not (mnt, mnt.root).
func (vfs *VirtualFilesystem) getMountpointAt(ctx context.Context, mnt *Mount, vfsroot VirtualDentry) VirtualDentry {
	// The first mount is special-cased:
	//
	//	- The caller must have already checked mnt against vfsroot.
	//
	//	- We return nil, instead of mnt, if there is no mount point for mnt.
	//
	//	- We don't drop the caller's reference on mnt.
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
		parent.DecRef(ctx)
		goto retryFirst
	}
	if !vfs.mounts.seq.ReadOk(epoch) {
		point.DecRef(ctx)
		parent.DecRef(ctx)
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
			parent.DecRef(ctx)
			goto retryNotFirst
		}
		if !vfs.mounts.seq.ReadOk(epoch) {
			point.DecRef(ctx)
			parent.DecRef(ctx)
			goto retryNotFirst
		}
		d.DecRef(ctx)
		mnt.DecRef(ctx)
		mnt = parent
		d = point
	}
	return VirtualDentry{mnt, d}
}

// PivotRoot makes location pointed to by newRootPop the root of the current
// namespace, and moves the current root to the location pointed to by
// putOldPop.
func (vfs *VirtualFilesystem) PivotRoot(ctx context.Context, creds *auth.Credentials, newRootPop *PathOperation, putOldPop *PathOperation) error {
	newRootVd, err := vfs.GetDentryAt(ctx, creds, newRootPop, &GetDentryOptions{CheckSearchable: true})
	if err != nil {
		return err
	}
	defer newRootVd.DecRef(ctx)
	putOldVd, err := vfs.GetDentryAt(ctx, creds, putOldPop, &GetDentryOptions{CheckSearchable: true})
	if err != nil {
		return err
	}
	defer putOldVd.DecRef(ctx)
	rootVd := RootFromContext(ctx)
	defer rootVd.DecRef(ctx)

retry:
	epoch := vfs.mounts.seq.BeginRead()
	// Neither new_root nor put_old can be on the same mount as the current
	//root mount.
	if newRootVd.mount == rootVd.mount || putOldVd.mount == rootVd.mount {
		return linuxerr.EBUSY
	}
	// new_root must be a mountpoint.
	if newRootVd.mount.root != newRootVd.dentry {
		return linuxerr.EINVAL
	}
	// put_old must be at or underneath new_root.
	path, err := vfs.PathnameReachable(ctx, newRootVd, putOldVd)
	if err != nil || len(path) == 0 {
		return linuxerr.EINVAL
	}
	// The current root directory must be a mountpoint
	// (in the case it has been chrooted).
	if rootVd.mount.root != rootVd.dentry {
		return linuxerr.EINVAL
	}
	// The current root and the new root cannot be on the rootfs mount.
	if rootVd.mount.parent() == nil || newRootVd.mount.parent() == nil {
		return linuxerr.EINVAL
	}
	// The current root and the new root must be in the context's mount namespace.
	ns := MountNamespaceFromContext(ctx)
	defer ns.DecRef(ctx)
	if rootVd.mount.ns != ns || newRootVd.mount.ns != ns {
		return linuxerr.EINVAL
	}

	vfs.mountMu.Lock()
	// Either the mount point at new_root, or the parent mount of that mount
	// point, has propagation type MS_SHARED.
	if newRootParent := newRootVd.mount.parent(); newRootVd.mount.propType == Shared || newRootParent.propType == Shared {
		vfs.mountMu.Unlock()
		return linuxerr.EINVAL
	}
	// put_old is a mount point and has the propagation type MS_SHARED.
	if putOldVd.mount.root == putOldVd.dentry && putOldVd.mount.propType == Shared {
		vfs.mountMu.Unlock()
		return linuxerr.EINVAL
	}

	if !vfs.mounts.seq.BeginWriteOk(epoch) {
		// Checks above raced with a mount change.
		vfs.mountMu.Unlock()
		goto retry
	}
	defer vfs.mountMu.Unlock()
	mp := vfs.disconnectLocked(newRootVd.mount)
	mp.DecRef(ctx)
	rootMp := vfs.disconnectLocked(rootVd.mount)

	putOldVd.IncRef()
	putOldVd.dentry.mu.Lock()
	vfs.connectLocked(rootVd.mount, putOldVd, ns)
	putOldVd.dentry.mu.Unlock()

	rootMp.dentry.mu.Lock()
	vfs.connectLocked(newRootVd.mount, rootMp, ns)
	rootMp.dentry.mu.Unlock()
	vfs.mounts.seq.EndWrite()

	newRootVd.mount.DecRef(ctx)
	rootVd.mount.DecRef(ctx)
	return nil
}

// SetMountReadOnly sets the mount as ReadOnly.
func (vfs *VirtualFilesystem) SetMountReadOnly(mnt *Mount, ro bool) error {
	vfs.mountMu.Lock()
	defer vfs.mountMu.Unlock()
	return mnt.setReadOnlyLocked(ro)
}

// CheckBeginWrite increments the counter of in-progress write operations on
// mnt. If mnt is mounted MS_RDONLY, CheckBeginWrite does nothing and returns
// EROFS.
//
// If CheckBeginWrite succeeds, EndWrite must be called when the write
// operation is finished.
func (mnt *Mount) CheckBeginWrite() error {
	if mnt.writers.Add(1) < 0 {
		mnt.writers.Add(-1)
		return linuxerr.EROFS
	}
	return nil
}

// EndWrite indicates that a write operation signaled by a previous successful
// call to CheckBeginWrite has finished.
func (mnt *Mount) EndWrite() {
	mnt.writers.Add(-1)
}

// Preconditions: VirtualFilesystem.mountMu must be locked.
func (mnt *Mount) setReadOnlyLocked(ro bool) error {
	if oldRO := mnt.writers.Load() < 0; oldRO == ro {
		return nil
	}
	if ro {
		if !mnt.writers.CompareAndSwap(0, math.MinInt64) {
			return linuxerr.EBUSY
		}
		return nil
	}
	// Unset MSB without dropping any temporary increments from failed calls to
	// mnt.CheckBeginWrite().
	mnt.writers.Add(math.MinInt64)
	return nil
}

// ReadOnly returns true if mount is readonly.
func (mnt *Mount) ReadOnly() bool {
	return mnt.writers.Load() < 0
}

// Filesystem returns the mounted Filesystem. It does not take a reference on
// the returned Filesystem.
func (mnt *Mount) Filesystem() *Filesystem {
	return mnt.fs
}

// submountsLocked returns this Mount and all Mounts that are descendents of
// it.
//
// Precondition: mnt.vfs.mountMu must be held.
func (mnt *Mount) submountsLocked() []*Mount {
	mounts := []*Mount{mnt}
	for m := range mnt.children {
		mounts = append(mounts, m.submountsLocked()...)
	}
	return mounts
}

// Root returns the mount's root. It does not take a reference on the returned
// Dentry.
func (mnt *Mount) Root() *Dentry {
	return mnt.root
}

// Root returns mntns' root. It does not take a reference on the returned
// Dentry.
func (mntns *MountNamespace) Root() VirtualDentry {
	vd := VirtualDentry{
		mount:  mntns.root,
		dentry: mntns.root.root,
	}
	return vd
}

// GenerateProcMounts emits the contents of /proc/[pid]/mounts for vfs to buf.
//
// Preconditions: taskRootDir.Ok().
func (vfs *VirtualFilesystem) GenerateProcMounts(ctx context.Context, taskRootDir VirtualDentry, buf *bytes.Buffer) {
	rootMnt := taskRootDir.mount

	vfs.mountMu.Lock()
	mounts := rootMnt.submountsLocked()
	// Take a reference on mounts since we need to drop vfs.mountMu before
	// calling vfs.PathnameReachable() (=> FilesystemImpl.PrependPath()).
	for _, mnt := range mounts {
		mnt.IncRef()
	}
	vfs.mountMu.Unlock()
	defer func() {
		for _, mnt := range mounts {
			mnt.DecRef(ctx)
		}
	}()
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].ID < mounts[j].ID })

	for _, mnt := range mounts {
		// Get the path to this mount relative to task root.
		mntRootVD := VirtualDentry{
			mount:  mnt,
			dentry: mnt.root,
		}
		path, err := vfs.PathnameReachable(ctx, taskRootDir, mntRootVD)
		if err != nil {
			// For some reason we didn't get a path. Log a warning
			// and run with empty path.
			ctx.Warningf("VFS.GenerateProcMounts: error getting pathname for mount root %+v: %v", mnt.root, err)
			path = ""
		}
		if path == "" {
			// Either an error occurred, or path is not reachable
			// from root.
			break
		}

		opts := "rw"
		if mnt.ReadOnly() {
			opts = "ro"
		}
		if mnt.Flags.NoATime {
			opts = ",noatime"
		}
		if mnt.Flags.NoExec {
			opts += ",noexec"
		}
		if mopts := mnt.fs.Impl().MountOptions(); mopts != "" {
			opts += "," + mopts
		}

		// Format:
		// <special device or remote filesystem> <mount point> <filesystem type> <mount options> <needs dump> <fsck order>
		//
		// The "needs dump" and "fsck order" flags are always 0, which
		// is allowed.
		fmt.Fprintf(buf, "%s %s %s %s %d %d\n", "none", path, mnt.fs.FilesystemType().Name(), opts, 0, 0)
	}
}

// GenerateProcMountInfo emits the contents of /proc/[pid]/mountinfo for vfs to
// buf.
//
// Preconditions: taskRootDir.Ok().
func (vfs *VirtualFilesystem) GenerateProcMountInfo(ctx context.Context, taskRootDir VirtualDentry, buf *bytes.Buffer) {
	rootMnt := taskRootDir.mount

	vfs.mountMu.Lock()
	mounts := rootMnt.submountsLocked()
	// Take a reference on mounts since we need to drop vfs.mountMu before
	// calling vfs.PathnameReachable() (=> FilesystemImpl.PrependPath()) or
	// vfs.StatAt() (=> FilesystemImpl.StatAt()).
	for _, mnt := range mounts {
		mnt.IncRef()
	}
	vfs.mountMu.Unlock()
	defer func() {
		for _, mnt := range mounts {
			mnt.DecRef(ctx)
		}
	}()
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].ID < mounts[j].ID })

	creds := auth.CredentialsFromContext(ctx)
	for _, mnt := range mounts {
		// Get the path to this mount relative to task root.
		mntRootVD := VirtualDentry{
			mount:  mnt,
			dentry: mnt.root,
		}
		pathFromRoot, err := vfs.PathnameReachable(ctx, taskRootDir, mntRootVD)
		if err != nil {
			// For some reason we didn't get a path. Log a warning
			// and run with empty path.
			ctx.Warningf("VFS.GenerateProcMountInfo: error getting pathname for mount root %+v: %v", mnt.root, err)
			continue
		}
		if pathFromRoot == "" {
			// The path is not reachable from root.
			continue
		}
		var pathFromFS string
		pathFromFS, err = vfs.PathnameInFilesystem(ctx, mntRootVD)
		if err != nil {
			// For some reason we didn't get a path. Log a warning
			// and run with empty path.
			ctx.Warningf("VFS.GenerateProcMountInfo: error getting pathname for mount root %+v: %v", mnt.root, err)
			continue
		}
		if pathFromFS == "" {
			// The path is not reachable from root.
			continue
		}
		// Stat the mount root to get the major/minor device numbers.
		pop := &PathOperation{
			Root:  mntRootVD,
			Start: mntRootVD,
		}
		statx, err := vfs.StatAt(ctx, creds, pop, &StatOptions{})
		if err != nil {
			// Well that's not good. Ignore this mount.
			ctx.Warningf("VFS.GenerateProcMountInfo: failed to stat mount root %+v: %v", mnt.root, err)
			continue
		}

		// Format:
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		// (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

		// (1) Mount ID.
		fmt.Fprintf(buf, "%d ", mnt.ID)

		// (2)  Parent ID (or this ID if there is no parent).
		// Note that even if the call to mnt.parent() races with Mount
		// destruction (which is possible since we're not holding vfs.mountMu),
		// its Mount.ID will still be valid.
		pID := mnt.ID
		if p := mnt.parent(); p != nil {
			pID = p.ID
		}
		fmt.Fprintf(buf, "%d ", pID)

		// (3) Major:Minor device ID. We don't have a superblock, so we
		// just use the root inode device number.
		fmt.Fprintf(buf, "%d:%d ", statx.DevMajor, statx.DevMinor)

		// (4) Root: the pathname of the directory in the filesystem
		// which forms the root of this mount.
		fmt.Fprintf(buf, "%s ", manglePath(pathFromFS))

		// (5) Mount point (relative to process root).
		fmt.Fprintf(buf, "%s ", manglePath(pathFromRoot))

		// (6) Mount options.
		opts := "rw"
		if mnt.ReadOnly() {
			opts = "ro"
		}
		if mnt.Flags.NoATime {
			opts = ",noatime"
		}
		if mnt.Flags.NoExec {
			opts += ",noexec"
		}
		fmt.Fprintf(buf, "%s ", opts)

		// (7) Optional fields: zero or more fields of the form "tag[:value]".
		fmt.Fprintf(buf, "%s ", mnt.generateOptionalTags())
		// (8) Separator: the end of the optional fields is marked by a single hyphen.
		fmt.Fprintf(buf, "- ")

		// (9) Filesystem type.
		fmt.Fprintf(buf, "%s ", mnt.fs.FilesystemType().Name())

		// (10) Mount source: filesystem-specific information or "none".
		fmt.Fprintf(buf, "none ")

		// (11) Superblock options, and final newline.
		fmt.Fprintf(buf, "%s\n", superBlockOpts(pathFromRoot, mnt))
	}
}

// manglePath replaces ' ', '\t', '\n', and '\\' with their octal equivalents.
// See Linux fs/seq_file.c:mangle_path.
func manglePath(p string) string {
	r := strings.NewReplacer(" ", "\\040", "\t", "\\011", "\n", "\\012", "\\", "\\134")
	return r.Replace(p)
}

// superBlockOpts returns the super block options string for the the mount at
// the given path.
func superBlockOpts(mountPath string, mnt *Mount) string {
	// Compose super block options by combining global mount flags with
	// FS-specific mount options.
	opts := "rw"
	if mnt.ReadOnly() {
		opts = "ro"
	}

	if mopts := mnt.fs.Impl().MountOptions(); mopts != "" {
		opts += "," + mopts
	}

	// NOTE(b/147673608): If the mount is a ramdisk-based fake cgroupfs, we also
	// need to include the cgroup name in the options. For now we just read that
	// from the path. Note that this is only possible when "cgroup" isn't
	// registered as a valid filesystem type.
	//
	// TODO(gvisor.dev/issue/190): Once we removed fake cgroupfs support, we
	// should remove this.
	if cgroupfs := mnt.vfs.getFilesystemType("cgroup"); cgroupfs != nil && cgroupfs.opts.AllowUserMount {
		// Real cgroupfs available.
		return opts
	}
	if mnt.fs.FilesystemType().Name() == "cgroup" {
		splitPath := strings.Split(mountPath, "/")
		cgroupType := splitPath[len(splitPath)-1]
		opts += "," + cgroupType
	}

	return opts
}

// allocateGroupID returns a new mount group id if one is available, and
// error otherwise. If the group ID bitmap is full, double the size of the
// bitmap before allocating the new group id.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) allocateGroupID() (uint32, error) {
	groupID, err := vfs.groupIDBitmap.FirstZero(1)
	if err != nil {
		if err := vfs.groupIDBitmap.Grow(uint32(vfs.groupIDBitmap.Size())); err != nil {
			return 0, err
		}
	}
	vfs.groupIDBitmap.Add(groupID)
	return groupID, nil
}

// freeGroupID marks a groupID as available for reuse.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) freeGroupID(id uint32) {
	vfs.groupIDBitmap.Remove(id)
}
