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
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

const anonfsBlockSize = usermem.PageSize // via fs/libfs.c:pseudo_fs_fill_super()

// AnonFilesystem is the implementation of FilesystemImpl that backs
// VirtualDentries returned by VirtualFilesystem.NewAnonVirtualDentry().
//
// Since all dentries in AnonFilesystem are non-directories, all FilesystemImpl
// methods that expect a directory return ENOTDIR.
type AnonFilesystem struct {
	vfsfs Filesystem

	devMinor uint32
}

// Release implements FilesystemImpl.Release.
func (fs *AnonFilesystem) Release() {
}

// Sync implements FilesystemImpl.Sync.
func (fs *AnonFilesystem) Sync(ctx context.Context) error {
	return nil
}

// GetDentryAt implements FilesystemImpl.GetDentryAt.
func (fs *AnonFilesystem) GetDentryAt(ctx context.Context, rp *ResolvingPath, opts GetDentryOptions) (*Dentry, error) {
	if !rp.Done() {
		return nil, syserror.ENOTDIR
	}
	if opts.CheckSearchable {
		return nil, syserror.ENOTDIR
	}
	d := rp.Start()
	d.IncRef()
	return d, nil
}

// GetParentDentryAt implements FilesystemImpl.GetParentDentryAt.
func (fs *AnonFilesystem) GetParentDentryAt(ctx context.Context, rp *ResolvingPath) (*Dentry, error) {
	if !rp.Final() {
		return nil, syserror.ENOTDIR
	}
	d := rp.Start()
	d.IncRef()
	return d, nil
}

// LinkAt implements FilesystemImpl.LinkAt.
func (fs *AnonFilesystem) LinkAt(ctx context.Context, rp *ResolvingPath, vd VirtualDentry) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// MkdirAt implements FilesystemImpl.MkdirAt.
func (fs *AnonFilesystem) MkdirAt(ctx context.Context, rp *ResolvingPath, opts MkdirOptions) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// MknodAt implements FilesystemImpl.MknodAt.
func (fs *AnonFilesystem) MknodAt(ctx context.Context, rp *ResolvingPath, opts MknodOptions) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// OpenAt implements FilesystemImpl.OpenAt.
func (fs *AnonFilesystem) OpenAt(ctx context.Context, rp *ResolvingPath, opts OpenOptions) (*FileDescription, error) {
	if !rp.Done() {
		return nil, syserror.ENOTDIR
	}
	return rp.Start().impl.(AnonDentryImpl).Open(ctx, opts)
}

// ReadlinkAt implements FilesystemImpl.ReadlinkAt.
func (fs *AnonFilesystem) ReadlinkAt(ctx context.Context, rp *ResolvingPath) (string, error) {
	if !rp.Done() {
		return "", syserror.ENOTDIR
	}
	return "", syserror.EINVAL
}

// RenameAt implements FilesystemImpl.RenameAt.
func (fs *AnonFilesystem) RenameAt(ctx context.Context, rp *ResolvingPath, oldParentVD VirtualDentry, oldName string, opts RenameOptions) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// RmdirAt implements FilesystemImpl.RmdirAt.
func (fs *AnonFilesystem) RmdirAt(ctx context.Context, rp *ResolvingPath) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// SetStatAt implements FilesystemImpl.SetStatAt.
func (fs *AnonFilesystem) SetStatAt(ctx context.Context, rp *ResolvingPath, opts SetStatOptions) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}

	return rp.Start().impl.(AnonDentryImpl).SetStat(ctx, opts)
}

// StatAt implements FilesystemImpl.StatAt.
func (fs *AnonFilesystem) StatAt(ctx context.Context, rp *ResolvingPath, opts StatOptions) (linux.Statx, error) {
	if !rp.Done() {
		return linux.Statx{}, syserror.ENOTDIR
	}
	return rp.Start().impl.(AnonDentryImpl).Stat(ctx, fs, opts)
}

// StatFSAt implements FilesystemImpl.StatFSAt.
func (fs *AnonFilesystem) StatFSAt(ctx context.Context, rp *ResolvingPath) (linux.Statfs, error) {
	if !rp.Done() {
		return linux.Statfs{}, syserror.ENOTDIR
	}
	return linux.Statfs{
		Type:      linux.ANON_INODE_FS_MAGIC,
		BlockSize: anonfsBlockSize,
	}, nil
}

// SymlinkAt implements FilesystemImpl.SymlinkAt.
func (fs *AnonFilesystem) SymlinkAt(ctx context.Context, rp *ResolvingPath, target string) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// UnlinkAt implements FilesystemImpl.UnlinkAt.
func (fs *AnonFilesystem) UnlinkAt(ctx context.Context, rp *ResolvingPath) error {
	if !rp.Final() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// ListxattrAt implements FilesystemImpl.ListxattrAt.
func (fs *AnonFilesystem) ListxattrAt(ctx context.Context, rp *ResolvingPath) ([]string, error) {
	if !rp.Done() {
		return nil, syserror.ENOTDIR
	}
	return nil, nil
}

// GetxattrAt implements FilesystemImpl.GetxattrAt.
func (fs *AnonFilesystem) GetxattrAt(ctx context.Context, rp *ResolvingPath, name string) (string, error) {
	if !rp.Done() {
		return "", syserror.ENOTDIR
	}
	return "", syserror.ENOTSUP
}

// SetxattrAt implements FilesystemImpl.SetxattrAt.
func (fs *AnonFilesystem) SetxattrAt(ctx context.Context, rp *ResolvingPath, opts SetxattrOptions) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// RemovexattrAt implements FilesystemImpl.RemovexattrAt.
func (fs *AnonFilesystem) RemovexattrAt(ctx context.Context, rp *ResolvingPath, name string) error {
	if !rp.Done() {
		return syserror.ENOTDIR
	}
	return syserror.EPERM
}

// PrependPath implements FilesystemImpl.PrependPath.
func (fs *AnonFilesystem) PrependPath(ctx context.Context, vfsroot, vd VirtualDentry, b *fspath.Builder) error {
	b.PrependComponent(fmt.Sprintf("anon_inode:%s", vd.dentry.impl.(AnonDentryImpl).Name()))
	return PrependPathSyntheticError{}
}

// AnonDentryImpl represents a DentryImpl in anonfs. In addition to the
// DentryImpl interface, dentries in anonfs may have distinct implementations
// of a few other operations, e.g. ones representing /proc/[pid]/fd/[fd].
type AnonDentryImpl interface {
	DentryImpl

	Open(context.Context, OpenOptions) (*FileDescription, error)

	SetStat(context.Context, SetStatOptions) error

	Stat(context.Context, *AnonFilesystem, StatOptions) (linux.Statx, error)

	VFSDentry() *Dentry

	Name() string
}

// NewAnonVirtualDentry creates a VirtualDentry with the given AnonDentryImpl.
func (vfs *VirtualFilesystem) NewAnonVirtualDentry(d AnonDentryImpl) VirtualDentry {
	vfsd := d.VFSDentry()
	vfsd.Init(d)
	vfs.anonMount.IncRef()
	return VirtualDentry{
		mount:  vfs.anonMount,
		dentry: vfsd,
	}
}

// AnonDentryDefaultImpl implements AnonDentryImpl (and by extension, DentryImpl).
// It can be embedded into other implementations of AnonDentryImpl as a default.
type AnonDentryDefaultImpl struct {
	// VFSD is the containing Dentry.
	VFSD Dentry

	// SyntheticName is the synthetic name of this dentry, consistent with Linux's
	// fs/anon_inodes.c:anon_inode_getfile().
	SyntheticName string
}

// IncRef implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) IncRef() {
	// no-op
}

// TryIncRef implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) TryIncRef() bool {
	return true
}

// DecRef implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) DecRef() {
	// no-op
}

// DecRef implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) Open(context.Context, OpenOptions) (*FileDescription, error) {
	return nil, syserror.ENODEV
}

// SetStat implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) SetStat(context.Context, SetStatOptions) error {
	return nil
}

// Stat implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) Stat(_ context.Context, fs *AnonFilesystem, _ StatOptions) (linux.Statx, error) {
	// See fs/anon_inodes.c:anon_inode_init() => fs/libfs.c:alloc_anon_inode().
	return linux.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS,
		Blksize:  anonfsBlockSize,
		Nlink:    1,
		UID:      uint32(auth.RootKUID),
		GID:      uint32(auth.RootKGID),
		Mode:     0600, // no type is correct
		Ino:      1,
		Size:     0,
		Blocks:   0,
		DevMajor: 0,
		DevMinor: fs.devMinor,
	}, nil
}

// VFSDentry implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) VFSDentry() *Dentry {
	return &d.VFSD
}

// Name implements AnonDentryImpl.
func (d *AnonDentryDefaultImpl) Name() string {
	return d.SyntheticName
}

// NewDefaultAnonVirtualDentry creates a VirtualDentry with an
// AnonDentryDefaultImpl and the given name. References are taken on the
// returned VirtualDentry.
func (vfs *VirtualFilesystem) NewDefaultAnonVirtualDentry(name string) VirtualDentry {
	d := AnonDentryDefaultImpl{
		SyntheticName: name,
	}
	return vfs.NewAnonVirtualDentry(&d)
}
