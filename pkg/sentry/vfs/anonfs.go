// Copyright 2020 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// NewAnonVirtualDentry returns a VirtualDentry with the given synthetic name,
// consistent with Linux's fs/anon_inodes.c:anon_inode_getfile(). References
// are taken on the returned VirtualDentry.
func (vfs *VirtualFilesystem) NewAnonVirtualDentry(name string) VirtualDentry {
	d := anonDentry{
		name: name,
	}
	d.vfsd.Init(&d)
	vfs.anonMount.IncRef()
	// anonDentry no-ops refcounting.
	return VirtualDentry{
		mount:  vfs.anonMount,
		dentry: &d.vfsd,
	}
}

const (
	anonfsBlockSize = usermem.PageSize // via fs/libfs.c:pseudo_fs_fill_super()

	// Mode, UID, and GID for a generic anonfs file.
	anonFileMode = 0600 // no type is correct
	anonFileUID  = auth.RootKUID
	anonFileGID  = auth.RootKGID
)

// anonFilesystemType implements FilesystemType.
type anonFilesystemType struct{}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (anonFilesystemType) GetFilesystem(context.Context, *VirtualFilesystem, *auth.Credentials, string, GetFilesystemOptions) (*Filesystem, *Dentry, error) {
	panic("cannot instaniate an anon filesystem")
}

// Name implemenents FilesystemType.Name.
func (anonFilesystemType) Name() string {
	return "none"
}

// anonFilesystem is the implementation of FilesystemImpl that backs
// VirtualDentries returned by VirtualFilesystem.NewAnonVirtualDentry().
//
// Since all Dentries in anonFilesystem are non-directories, all FilesystemImpl
// methods that would require an anonDentry to be a directory return ENOTDIR.
type anonFilesystem struct {
	vfsfs Filesystem

	devMinor uint32
}

type anonDentry struct {
	vfsd Dentry

	name string
}

// Release implements FilesystemImpl.Release.
func (fs *anonFilesystem) Release() {
}

// Sync implements FilesystemImpl.Sync.
func (fs *anonFilesystem) Sync(ctx context.Context) error {
	return nil
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
//
// TODO(gvisor.dev/issue/1965): Implement access permissions.
func (fs *anonFilesystem) AccessAt(ctx context.Context, rp *ResolvingPath, creds *auth.Credentials, ats AccessTypes) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}
	return GenericCheckPermissions(creds, ats, anonFileMode, anonFileUID, anonFileGID)
}

// GetDentryAt implements FilesystemImpl.GetDentryAt.
func (fs *anonFilesystem) GetDentryAt(ctx context.Context, rp *ResolvingPath, opts GetDentryOptions) (*Dentry, error) {
	if !rp.Done() {
		return nil, syserror.ENOTDIR
	}
	if opts.CheckSearchable {
		return nil, syserror.ENOTDIR
	}
	// anonDentry no-ops refcounting.
	return rp.Start(), nil
}

// GetParentDentryAt implements FilesystemImpl.GetParentDentryAt.
func (fs *anonFilesystem) GetParentDentryAt(ctx context.Context, rp *ResolvingPath) (*Dentry, error) {
	if !rp.Final() {
		return nil, syserror.ENOTDIR
	}
	// anonDentry no-ops refcounting.
	return rp.Start(), nil
}

// LinkAt implements FilesystemImpl.LinkAt.
func (fs *anonFilesystem) LinkAt(ctx context.Context, rp *ResolvingPath, vd VirtualDentry) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// MkdirAt implements FilesystemImpl.MkdirAt.
func (fs *anonFilesystem) MkdirAt(ctx context.Context, rp *ResolvingPath, opts MkdirOptions) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// MknodAt implements FilesystemImpl.MknodAt.
func (fs *anonFilesystem) MknodAt(ctx context.Context, rp *ResolvingPath, opts MknodOptions) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// OpenAt implements FilesystemImpl.OpenAt.
func (fs *anonFilesystem) OpenAt(ctx context.Context, rp *ResolvingPath, opts OpenOptions) (*FileDescription, error) {
	if !rp.Done() {
		return nil, syserror.ENOTDIR
	}
	return nil, syserror.ENODEV
}

// ReadlinkAt implements FilesystemImpl.ReadlinkAt.
func (fs *anonFilesystem) ReadlinkAt(ctx context.Context, rp *ResolvingPath) (string, error) {
	if !rp.Done() {
		return "", syserror.ENOTDIR
	}
	return "", syserror.EINVAL
}

// RenameAt implements FilesystemImpl.RenameAt.
func (fs *anonFilesystem) RenameAt(ctx context.Context, rp *ResolvingPath, oldParentVD VirtualDentry, oldName string, opts RenameOptions) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// RmdirAt implements FilesystemImpl.RmdirAt.
func (fs *anonFilesystem) RmdirAt(ctx context.Context, rp *ResolvingPath) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// SetStatAt implements FilesystemImpl.SetStatAt.
func (fs *anonFilesystem) SetStatAt(ctx context.Context, rp *ResolvingPath, opts SetStatOptions) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}
	// Linux actually permits anon_inode_inode's metadata to be set, which is
	// visible to all users of anon_inode_inode. We just silently ignore
	// metadata changes.
	return nil
}

// StatAt implements FilesystemImpl.StatAt.
func (fs *anonFilesystem) StatAt(ctx context.Context, rp *ResolvingPath, opts StatOptions) (linux.Statx, error) {
	if !rp.Done() {
		return linux.Statx{}, syserror.ENOTDIR
	}
	// See fs/anon_inodes.c:anon_inode_init() => fs/libfs.c:alloc_anon_inode().
	return linux.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS,
		Blksize:  anonfsBlockSize,
		Nlink:    1,
		UID:      uint32(anonFileUID),
		GID:      uint32(anonFileGID),
		Mode:     anonFileMode,
		Ino:      1,
		Size:     0,
		Blocks:   0,
		DevMajor: 0,
		DevMinor: fs.devMinor,
	}, nil
}

// StatFSAt implements FilesystemImpl.StatFSAt.
func (fs *anonFilesystem) StatFSAt(ctx context.Context, rp *ResolvingPath) (linux.Statfs, error) {
	if !rp.Done() {
		return linux.Statfs{}, syserror.ENOTDIR
	}
	return linux.Statfs{
		Type:      linux.ANON_INODE_FS_MAGIC,
		BlockSize: anonfsBlockSize,
	}, nil
}

// SymlinkAt implements FilesystemImpl.SymlinkAt.
func (fs *anonFilesystem) SymlinkAt(ctx context.Context, rp *ResolvingPath, target string) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// UnlinkAt implements FilesystemImpl.UnlinkAt.
func (fs *anonFilesystem) UnlinkAt(ctx context.Context, rp *ResolvingPath) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// BoundEndpointAt implements FilesystemImpl.BoundEndpointAt.
func (fs *anonFilesystem) BoundEndpointAt(ctx context.Context, rp *ResolvingPath) (transport.BoundEndpoint, error) {
	if !rp.Final() {
		return nil, syserror.ENOTDIR
	}
	return nil, syserror.ECONNREFUSED
}

// ListxattrAt implements FilesystemImpl.ListxattrAt.
func (fs *anonFilesystem) ListxattrAt(ctx context.Context, rp *ResolvingPath) ([]string, error) {
	if !rp.Done() {
		return nil, syserror.ENOTDIR
	}
	return nil, nil
}

// GetxattrAt implements FilesystemImpl.GetxattrAt.
func (fs *anonFilesystem) GetxattrAt(ctx context.Context, rp *ResolvingPath, name string) (string, error) {
	if !rp.Done() {
		return "", syserror.ENOTDIR
	}
	return "", syserror.ENOTSUP
}

// SetxattrAt implements FilesystemImpl.SetxattrAt.
func (fs *anonFilesystem) SetxattrAt(ctx context.Context, rp *ResolvingPath, opts SetxattrOptions) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// RemovexattrAt implements FilesystemImpl.RemovexattrAt.
func (fs *anonFilesystem) RemovexattrAt(ctx context.Context, rp *ResolvingPath, name string) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// PrependPath implements FilesystemImpl.PrependPath.
func (fs *anonFilesystem) PrependPath(ctx context.Context, vfsroot, vd VirtualDentry, b *fspath.Builder) error {
	b.PrependComponent(fmt.Sprintf("anon_inode:%s", vd.dentry.impl.(*anonDentry).name))
	return PrependPathSyntheticError{}
}

// IncRef implements DentryImpl.IncRef.
func (d *anonDentry) IncRef() {
	// no-op
}

// TryIncRef implements DentryImpl.TryIncRef.
func (d *anonDentry) TryIncRef() bool {
	return true
}

// DecRef implements DentryImpl.DecRef.
func (d *anonDentry) DecRef() {
	// no-op
}
