// Copyright 2026 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/refs"
)

// InodeIdentity identifies the file underlying a Dentry, in the sense in which
// Linux's struct inode identifies a file. Two Dentries have equal identities
// exactly when they name the same file, whether they reach it as hard links to
// each other, through different mounts of the same filesystem, or through the
// same path before and after a rename.
//
// The zero value is the "no identity" value, for which Ok returns false. It is
// returned for Dentries whose filesystem cannot name the underlying file, which
// as of this writing means only anonymous inodes; no path reaches those, so
// they never appear in a path walk.
//
// InodeIdentity is comparable, so it can be used as a map key. Its components
// are filesystem-defined and are not necessarily the ones that stat(2) reports,
// so identities are only meaningful when compared against each other.
//
// +stateify savable
type InodeIdentity struct {
	ok   bool
	fsID uint64
	ino  uint64
}

// MakeInodeIdentity returns the InodeIdentity of the file on fs identified by
// ino.
//
// ino need not be the inode number that stat(2) reports; it need only identify
// the file uniquely within its filesystem. It must, however, be stable across
// destruction and re-instantiation of the Dentries naming the file, since
// Dentries are cached and callers hold identities for longer than a Dentry
// necessarily lives. In particular, a pointer to a cached per-inode structure
// is not a valid ino.
//
// The identity is scoped to fs because an inode number only names a file
// within its own filesystem. Device numbers, which is how stat(2) tells
// filesystems apart, would not be a safe scope: they are recycled, since an
// anonymous block device minor is returned to the pool when its filesystem is
// destroyed, and the next filesystem to be created may be given the same one.
// An identity held from the destroyed filesystem could then come to match a
// file on the new one. fs identifies the filesystem for as long as the sentry
// runs, so identities from distinct filesystems never collide even if their
// device numbers do.
func MakeInodeIdentity(fs *Filesystem, ino uint64) InodeIdentity {
	return InodeIdentity{
		ok:   true,
		fsID: fs.id,
		ino:  ino,
	}
}

// Ok returns whether id identifies a file.
func (id InodeIdentity) Ok() bool {
	return id.ok
}

// InodeIdentity returns the identity of the file underlying d, which may be the
// zero InodeIdentity if d's filesystem cannot name it.
func (d *Dentry) InodeIdentity() InodeIdentity {
	return d.impl.InodeIdentity()
}

// inodeIdentityPinner is an optional interface implemented by DentryImpls whose
// identities are not naturally stable for the lifetime of the filesystem.
type inodeIdentityPinner interface {
	// PinInodeIdentity asks the FilesystemImpl to keep returning the current
	// identity for the file underlying the Dentry for as long as the file
	// exists, at whatever cost that carries.
	PinInodeIdentity()
}

// PinInodeIdentity tells d's filesystem that d's identity is about to be
// remembered, so that it must keep naming the same file afterwards even if the
// filesystem's own idea of that file changes.
//
// Only the overlay needs this, and only for a file that is copied up: the copy
// the overlay switches to lives in a different filesystem, with an inode number
// of its own, and a Dentry instantiated after the copy-up cannot see the
// original. Linux has nothing to do here because a Landlock rule takes a
// reference to the overlayfs inode itself, which outlives any dentry naming it;
// gVisor's overlay has no such inode to hold, so it is told instead.
//
// Callers must call this before recording an identity that later checks have to
// agree with, which as of this writing means adding a Landlock rule. The caller
// must hold a reference on d.
func (d *Dentry) PinInodeIdentity() {
	if pinner, ok := d.impl.(inodeIdentityPinner); ok {
		pinner.PinInodeIdentity()
	}
}

// WalkAncestors calls fn on vd's Dentry and then on each of its ancestors, from
// vd upward toward the root of vd's mount namespace, crossing mount boundaries
// as it goes. The walk stops when fn returns false, or when it reaches a mount
// that has no mount point to continue from — the root of the mount namespace,
// or a mount that was never connected to one.
//
// Dentries covered by a mount are skipped, since no path names them; the mount
// root that covers them is visited in their place. This mirrors the way Linux's
// follow_up() moves past a mount point without examining it.
//
// A Dentry that has been moved out of the subtree its mount exposes no longer
// has that mount's root among its ancestors. The walk from it reaches the root
// of the filesystem instead, and the mount root is visited there before the
// walk crosses to the mount point.
//
// Dentries passed to fn are not referenced and are only valid for the duration
// of the call. FilesystemImpls may hold filesystem locks across the walk, so fn
// must not reenter the filesystem.
//
// Moving above a mount point takes references on it. WalkAncestors appends them
// to *toDecRef instead of dropping them itself, because a caller holding
// filesystem locks cannot drop them safely: releasing the last reference to a
// mount point can release the filesystem it is on, which acquires that
// filesystem's own locks. The caller must drop them once it holds none.
func (vfs *VirtualFilesystem) WalkAncestors(ctx context.Context, vd VirtualDentry, toDecRef *[]refs.RefCounter, fn func(d *Dentry) bool) {
	// crossed reports whether vd is a mount point that this walk arrived at from
	// the mount covering it, in which case vd's Dentry itself is skipped.
	crossed := false
	for {
		stopped := false
		first := true
		var last *Dentry
		vd.mount.fs.impl.WalkAncestors(ctx, vd, func(d *Dentry) bool {
			last = d
			if first {
				first = false
				if crossed {
					return true
				}
			}
			if fn(d) {
				return true
			}
			stopped = true
			return false
		})
		if stopped {
			return
		}
		// A walk that ends at the root of the filesystem without passing
		// through the root of the mount started from a disconnected Dentry:
		// one that was moved out of the subtree the mount exposes, so that the
		// mount's root is no longer its ancestor. The mount root is visited
		// anyway, since the rights that reaching the file through this mount
		// carries are the ones the mount root's ancestry gives, and the walk
		// then continues from the mount point as usual.
		//
		// Linux does the same in [security/landlock/fs.c]:
		// is_access_to_paths_allowed(), since commit 49c9e09d9610 ("landlock:
		// Fix handling of disconnected directories"), reported by
		// LANDLOCK_CREATE_RULESET_ERRATA as erratum 3.
		if root := vd.mount.root; root != nil && last != root {
			if !fn(root) {
				return
			}
		}

		// toDecRef is passed through so that references taken on intermediate
		// mounts in a stack are not dropped here either: any of them can be
		// the last one after a racing umount.
		nextVD := vfs.getMountpointAt(ctx, vd.mount, VirtualDentry{}, toDecRef)
		if !nextVD.Ok() {
			return
		}
		*toDecRef = append(*toDecRef, nextVD.dentry, nextVD.mount)
		vd = nextVD
		crossed = true
	}
}
