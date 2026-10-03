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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
)

var fspathBuilderPool = sync.Pool{
	New: func() any {
		return &fspath.Builder{}
	},
}

func getFSPathBuilder() *fspath.Builder {
	return fspathBuilderPool.Get().(*fspath.Builder)
}

func putFSPathBuilder(b *fspath.Builder) {
	// No methods can be called on b after b.String(), so reset it to its zero
	// value (as returned by fspathBuilderPool.New) instead.
	*b = fspath.Builder{}
	fspathBuilderPool.Put(b)
}

// PathnameWithDeleted returns an absolute pathname to vd, consistent with
// Linux's d_path(). In particular, if vd.Dentry() has been disowned,
// PathnameWithDeleted appends " (deleted)" to the returned pathname.
func (vfs *VirtualFilesystem) PathnameWithDeleted(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef(ctx)
		}
	}()

	origD := vd.dentry
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				// genericfstree.PrependPath() will have returned
				// PrependPathAtVFSRootError in this case since it checks
				// against vfsroot before mnt.root, but other implementations
				// of FilesystemImpl.PrependPath() may return nil instead.
				break loop
			}
			nextVD := vfs.getMountpointAt(ctx, vd.mount, vfsroot, nil)
			if !nextVD.Ok() {
				break loop
			}
			if haveRef {
				vd.DecRef(ctx)
			}
			vd = nextVD
			haveRef = true
			// continue loop
		case PrependPathSyntheticError:
			// Skip prepending "/" and appending " (deleted)".
			return b.String(), nil
		case PrependPathAtVFSRootError, PrependPathAtNonMountRootError:
			break loop
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	if origD.IsDead() {
		b.AppendString(" (deleted)")
	}
	return b.String(), nil
}

// PathnameReachable returns an absolute pathname to vd, consistent with
// Linux's __d_path() (as used by seq_path_root()). If vfsroot.Ok() and vd is
// not reachable from vfsroot, such that seq_path_root() would return SEQ_SKIP
// (causing the entire containing entry to be skipped), PathnameReachable
// returns ("", nil).
func (vfs *VirtualFilesystem) PathnameReachable(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef(ctx)
		}
	}()
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				break loop
			}
			nextVD := vfs.getMountpointAt(ctx, vd.mount, vfsroot, nil)
			if !nextVD.Ok() {
				return "", nil
			}
			if haveRef {
				vd.DecRef(ctx)
			}
			vd = nextVD
			haveRef = true
		case PrependPathAtVFSRootError:
			break loop
		case PrependPathAtNonMountRootError, PrependPathSyntheticError:
			return "", nil
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	return b.String(), nil
}

// PathnameInFilesystem returns an absolute path to vd relative to vd's
// Filesystem root. It also appends //deleted to for disowned entries. It is
// equivalent to Linux's dentry_path().
func (vfs *VirtualFilesystem) PathnameInFilesystem(ctx context.Context, vd VirtualDentry) (string, error) {
	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	if vd.dentry.IsDead() {
		b.PrependString("//deleted")
	}
	if err := vd.mount.fs.impl.PrependPath(ctx, VirtualDentry{}, VirtualDentry{dentry: vd.dentry}, b); err != nil {
		// PrependPath returns an error if it encounters a filesystem root before
		// the provided vfsroot. We don't provide a vfsroot, so encountering this
		// error is expected and can be ignored.
		switch err.(type) {
		case PrependPathAtNonMountRootError:
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	return b.String(), nil
}

// PathnameForGetcwd returns an absolute pathname to vd, consistent with
// Linux's sys_getcwd().
func (vfs *VirtualFilesystem) PathnameForGetcwd(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	if vd.dentry.IsDead() {
		return "", linuxerr.ENOENT
	}

	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef(ctx)
		}
	}()
	unreachable := false
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				break loop
			}
			nextVD := vfs.getMountpointAt(ctx, vd.mount, vfsroot, nil)
			if !nextVD.Ok() {
				unreachable = true
				break loop
			}
			if haveRef {
				vd.DecRef(ctx)
			}
			vd = nextVD
			haveRef = true
		case PrependPathAtVFSRootError:
			break loop
		case PrependPathAtNonMountRootError, PrependPathSyntheticError:
			unreachable = true
			break loop
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	if unreachable {
		b.PrependString("(unreachable)")
	}
	return b.String(), nil
}

// As of this writing, we do not have equivalents to:
//
//	- d_absolute_path(), which returns EINVAL if (effectively) any call to
//		FilesystemImpl.PrependPath() would return PrependPathAtNonMountRootError.
//
// These should be added as necessary.

// WalkAncestors calls fn on vd's Dentry and each ancestor up to the mount
// namespace root, crossing mounts, until fn returns false or there is no mount
// point to continue from. Covered mount points are skipped, like follow_up().
// E.g. from /mnt/a/b, with a mount at /mnt, it visits b, a, then / (skipping
// the mountpoint dentry /mnt).
//
// Dentries passed to fn are unreferenced and valid only during the call; fn
// must not reenter the filesystem, whose locks may be held. References taken
// on mount points are appended to *toDecRef for the caller to drop once it
// holds no filesystem locks.
func (vfs *VirtualFilesystem) WalkAncestors(ctx context.Context, vd VirtualDentry, toDecRef *[]refs.RefCounter, fn func(d *Dentry) bool) {
	// crossed is true if vd is a mount point reached from the mount covering
	// it, so vd's Dentry is skipped.
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
		// If the walk missed the mount root, vd was disconnected (moved out of
		// the mount's subtree). Visit the mount root anyway, then continue
		// from the mount point as usual.
		//
		// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
		// since commit 49c9e09d9610 ("landlock: Fix handling of disconnected
		// directories"), erratum 3.
		if root := vd.mount.root; root != nil && last != root {
			if !fn(root) {
				return
			}
		}

		// Pass toDecRef through: intermediate mount references may be the last
		// after a racing umount.
		nextVD := vfs.getMountpointAt(ctx, vd.mount, VirtualDentry{}, toDecRef)
		if !nextVD.Ok() {
			return
		}
		*toDecRef = append(*toDecRef, nextVD.dentry, nextVD.mount)
		vd = nextVD
		crossed = true
	}
}
