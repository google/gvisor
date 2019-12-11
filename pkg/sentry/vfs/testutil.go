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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

// FDTestFilesystemType is a test-only FilesystemType that produces Filesystems
// for which all FilesystemImpl methods taking a path return EPERM. It is used
// to produce Mounts and Dentries for testing of FileDescriptionImpls that do
// not depend on their originating Filesystem.
type FDTestFilesystemType struct{}

// FDTestFilesystem is a test-only FilesystemImpl produced by
// FDTestFilesystemType.
type FDTestFilesystem struct {
	vfsfs Filesystem
}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (fstype FDTestFilesystemType) GetFilesystem(ctx context.Context, vfsObj *VirtualFilesystem, creds *auth.Credentials, source string, opts GetFilesystemOptions) (*Filesystem, *Dentry, error) {
	var fs FDTestFilesystem
	fs.vfsfs.Init(vfsObj, &fs)
	return &fs.vfsfs, fs.NewDentry(), nil
}

// Release implements FilesystemImpl.Release.
func (fs *FDTestFilesystem) Release() {
}

// Sync implements FilesystemImpl.Sync.
func (fs *FDTestFilesystem) Sync(ctx context.Context) error {
	return nil
}

// GetDentryAt implements FilesystemImpl.GetDentryAt.
func (fs *FDTestFilesystem) GetDentryAt(ctx context.Context, rp *ResolvingPath, opts GetDentryOptions) (*Dentry, error) {
	return nil, syserror.EPERM
}

// LinkAt implements FilesystemImpl.LinkAt.
func (fs *FDTestFilesystem) LinkAt(ctx context.Context, rp *ResolvingPath, vd VirtualDentry) error {
	return syserror.EPERM
}

// MkdirAt implements FilesystemImpl.MkdirAt.
func (fs *FDTestFilesystem) MkdirAt(ctx context.Context, rp *ResolvingPath, opts MkdirOptions) error {
	return syserror.EPERM
}

// MknodAt implements FilesystemImpl.MknodAt.
func (fs *FDTestFilesystem) MknodAt(ctx context.Context, rp *ResolvingPath, opts MknodOptions) error {
	return syserror.EPERM
}

// OpenAt implements FilesystemImpl.OpenAt.
func (fs *FDTestFilesystem) OpenAt(ctx context.Context, rp *ResolvingPath, opts OpenOptions) (*FileDescription, error) {
	return nil, syserror.EPERM
}

// ReadlinkAt implements FilesystemImpl.ReadlinkAt.
func (fs *FDTestFilesystem) ReadlinkAt(ctx context.Context, rp *ResolvingPath) (string, error) {
	return "", syserror.EPERM
}

// RenameAt implements FilesystemImpl.RenameAt.
func (fs *FDTestFilesystem) RenameAt(ctx context.Context, rp *ResolvingPath, vd VirtualDentry, opts RenameOptions) error {
	return syserror.EPERM
}

// RmdirAt implements FilesystemImpl.RmdirAt.
func (fs *FDTestFilesystem) RmdirAt(ctx context.Context, rp *ResolvingPath) error {
	return syserror.EPERM
}

// SetStatAt implements FilesystemImpl.SetStatAt.
func (fs *FDTestFilesystem) SetStatAt(ctx context.Context, rp *ResolvingPath, opts SetStatOptions) error {
	return syserror.EPERM
}

// StatAt implements FilesystemImpl.StatAt.
func (fs *FDTestFilesystem) StatAt(ctx context.Context, rp *ResolvingPath, opts StatOptions) (linux.Statx, error) {
	return linux.Statx{}, syserror.EPERM
}

// StatFSAt implements FilesystemImpl.StatFSAt.
func (fs *FDTestFilesystem) StatFSAt(ctx context.Context, rp *ResolvingPath) (linux.Statfs, error) {
	return linux.Statfs{}, syserror.EPERM
}

// SymlinkAt implements FilesystemImpl.SymlinkAt.
func (fs *FDTestFilesystem) SymlinkAt(ctx context.Context, rp *ResolvingPath, target string) error {
	return syserror.EPERM
}

// UnlinkAt implements FilesystemImpl.UnlinkAt.
func (fs *FDTestFilesystem) UnlinkAt(ctx context.Context, rp *ResolvingPath) error {
	return syserror.EPERM
}

// PrependPath implements FilesystemImpl.PrependPath.
func (fs *FDTestFilesystem) PrependPath(ctx context.Context, vfsroot, vd VirtualDentry, b *fspath.Builder) error {
	b.PrependComponent(fmt.Sprintf("vfs.fdTestDentry:%p", vd.dentry.impl.(*fdTestDentry)))
	return PrependPathSyntheticError{}
}

type fdTestDentry struct {
	vfsd Dentry
}

// NewDentry returns a new Dentry.
func (fs *FDTestFilesystem) NewDentry() *Dentry {
	var d fdTestDentry
	d.vfsd.Init(&d)
	return &d.vfsd
}

// IncRef implements DentryImpl.IncRef.
func (d *fdTestDentry) IncRef() {
}

// TryIncRef implements DentryImpl.TryIncRef.
func (d *fdTestDentry) TryIncRef() bool {
	return true
}

// DecRef implements DentryImpl.DecRef.
func (d *fdTestDentry) DecRef() {
}
