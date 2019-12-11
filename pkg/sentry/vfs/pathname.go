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
	"sync"

	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/syserror"
)

var fspathBuilderPool = sync.Pool{
	New: func() interface{} {
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
			vd.DecRef()
		}
	}()

	origD := vd.dentry
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				// GenericPrependPath() will have returned
				// PrependPathAtVFSRootError in this case since it checks
				// against vfsroot before mnt.root, but other implementations
				// of FilesystemImpl.PrependPath() may return nil instead.
				break loop
			}
			nextVD := vfs.getMountpointAt(vd.mount, vfsroot)
			if !nextVD.Ok() {
				break loop
			}
			if haveRef {
				vd.DecRef()
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
	if origD.IsDisowned() {
		b.AppendString(" (deleted)")
	}
	return b.String(), nil
}

// PathnameForGetcwd returns an absolute pathname to vd, consistent with
// Linux's sys_getcwd().
func (vfs *VirtualFilesystem) PathnameForGetcwd(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	if vd.dentry.IsDisowned() {
		return "", syserror.ENOENT
	}

	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef()
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
			nextVD := vfs.getMountpointAt(vd.mount, vfsroot)
			if !nextVD.Ok() {
				unreachable = true
				break loop
			}
			if haveRef {
				vd.DecRef()
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
// - d_absolute_path(), which returns EINVAL if (effectively) any call to
// FilesystemImpl.PrependPath() would return PrependPathAtNonMountRootError.
//
// - dentry_path(), which does not walk up mounts (and only returns the path
// relative to Filesystem root), but also appends "//deleted" for disowned
// Dentries.
//
// These should be added as necessary.
