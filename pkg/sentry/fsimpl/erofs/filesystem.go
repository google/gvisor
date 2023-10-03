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

package erofs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// step resolves rp.Component() to an existing file, starting from the given directory.
//
// step is loosely analogous to fs/namei.c:walk_component().
//
// Preconditions:
//   - !rp.Done().
func step(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, bool, error) {
	if !d.inode.IsDir() {
		return nil, false, linuxerr.ENOTDIR
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, false, err
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, false, nil
	}
	if name == ".." {
		parent := d.parent.Load()
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, false, err
		} else if isRoot || parent == nil {
			rp.Advance()
			return d, false, nil
		}
		if err := rp.CheckMount(ctx, &parent.vfsd); err != nil {
			return nil, false, err
		}
		rp.Advance()
		return parent, false, nil
	}
	if len(name) > erofs.MaxNameLen {
		return nil, false, linuxerr.ENAMETOOLONG
	}
	child, err := d.lookup(ctx, name)
	if err != nil {
		return nil, false, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, false, err
	}
	if child.inode.IsSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.inode.Readlink()
		if err != nil {
			return nil, false, err
		}
		followedSymlink, err := rp.HandleSymlink(target)
		return d, followedSymlink, err
	}
	rp.Advance()
	return child, false, nil
}

// walkParentDir resolves all but the last path component of rp to an existing
// directory, starting from the gvien directory. It does not check that the
// returned directory is searchable by the provider of rp.
//
// walkParentDir is loosely analogous to Linux's fs/namei.c:path_parentat().
//
// Preconditions:
//   - !rp.Done().
func walkParentDir(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, error) {
	for !rp.Final() {
		next, _, err := step(ctx, rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.inode.IsDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// resolve resolves rp to an existing file.
//
// resolve is loosely analogous to Linux's fs/namei.c:path_lookupat().
func resolve(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	for !rp.Done() {
		next, _, err := step(ctx, rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.inode.IsDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// doCreateAt checks that creating a file at rp is permitted.
//
// doCreateAt is loosely analogous to a conjunction of Linux's
// fs/namei.c:filename_create() and done_path_create().
//
// Preconditions:
//   - !rp.Done().
//   - For the final path component in rp, !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool) error {
	parentDir, err := walkParentDir(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	// Order of checks is important. First check if parent directory can be
	// executed, then check for existence, and lastly check if mount is writable.
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	if len(name) > erofs.MaxNameLen {
		return linuxerr.ENAMETOOLONG
	}
	if _, err := parentDir.lookup(ctx, name); err == nil {
		return linuxerr.EEXIST
	} else if !linuxerr.Equals(linuxerr.ENOENT, err) {
		return err
	}
	if !dir && rp.MustBeDir() {
		return linuxerr.ENOENT
	}
	return linuxerr.EROFS
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	return nil
}

// AccessAt implements vfs.FilesystemImpl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	d, err := resolve(ctx, rp)
	if err != nil {
		return err
	}
	if ats.MayWrite() {
		return linuxerr.EROFS
	}
	return d.inode.checkPermissions(creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	d, err := resolve(ctx, rp)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.inode.IsDir() {
			return nil, linuxerr.ENOTDIR
		}
		if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	dir, err := walkParentDir(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	dir.IncRef()
	return &dir.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false /* dir */)
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true /* dir */)
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false /* dir */)
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_TMPFILE != 0 {
		return nil, linuxerr.EOPNOTSUPP
	}

	if opts.Flags&linux.O_CREAT == 0 {
		d, err := resolve(ctx, rp)
		if err != nil {
			return nil, err
		}
		return d.open(ctx, rp, &opts)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	if rp.Done() {
		// Reject attempts to open mount root directory with O_CREAT.
		if rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		return start.open(ctx, rp, &opts)
	}
afterTrailingSymlink:
	parentDir, err := walkParentDir(ctx, rp, start)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	// Reject attempts to open directories with O_CREAT.
	if rp.MustBeDir() {
		return nil, linuxerr.EISDIR
	}
	child, followedSymlink, err := step(ctx, rp, parentDir)
	if followedSymlink {
		if mustCreate {
			// EEXIST must be returned if an existing symlink is opened with O_EXCL.
			return nil, linuxerr.EEXIST
		}
		if err != nil {
			// If followedSymlink && err != nil, then this symlink resolution error
			// must be handled by the VFS layer.
			return nil, err
		}
		start = parentDir
		goto afterTrailingSymlink
	}
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		return nil, linuxerr.EROFS
	}
	if err != nil {
		return nil, err
	}
	if mustCreate {
		return nil, linuxerr.EEXIST
	}
	if rp.MustBeDir() && !child.inode.IsDir() {
		return nil, linuxerr.ENOTDIR
	}
	return child.open(ctx, rp, &opts)
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	d, err := resolve(ctx, rp)
	if err != nil {
		return "", err
	}
	return d.inode.Readlink()
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// Resolve newParent first to verify that it's on this Mount.
	newParentDir, err := walkParentDir(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	newName := rp.Component()
	if len(newName) > erofs.MaxNameLen {
		return linuxerr.ENAMETOOLONG
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	if err := newParentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	oldParentDir := oldParentVD.Dentry().Impl().(*dentry)
	if err := oldParentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	return linuxerr.EROFS
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	parentDir, err := walkParentDir(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	return linuxerr.EROFS
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	if _, err := resolve(ctx, rp); err != nil {
		return err
	}
	return linuxerr.EROFS
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	d, err := resolve(ctx, rp)
	if err != nil {
		return linux.Statx{}, err
	}
	var stat linux.Statx
	d.inode.statTo(&stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	if _, err := resolve(ctx, rp); err != nil {
		return linux.Statfs{}, err
	}
	return fs.statFS(), nil
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false /* dir */)
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	parentDir, err := walkParentDir(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	return linuxerr.EROFS
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	d, err := resolve(ctx, rp)
	if err != nil {
		return nil, err
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	return nil, linuxerr.ECONNREFUSED
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	if _, err := resolve(ctx, rp); err != nil {
		return nil, err
	}
	return nil, linuxerr.ENOTSUP
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	if _, err := resolve(ctx, rp); err != nil {
		return "", err
	}
	return "", linuxerr.ENOTSUP
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	if _, err := resolve(ctx, rp); err != nil {
		return err
	}
	return linuxerr.EROFS
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	if _, err := resolve(ctx, rp); err != nil {
		return err
	}
	return linuxerr.EROFS
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	return genericPrependPath(vfsroot, vd.Mount(), vd.Dentry().Impl().(*dentry), b)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return fs.mopts
}

// IsDescendant implements vfs.FilesystemImpl.IsDescendant.
func (fs *filesystem) IsDescendant(vfsroot, vd vfs.VirtualDentry) bool {
	return genericIsDescendant(vfsroot.Dentry(), vd.Dentry().Impl().(*dentry))
}
