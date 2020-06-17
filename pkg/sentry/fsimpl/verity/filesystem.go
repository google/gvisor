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

package verity

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// All files should be read-only.
	return nil
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	// verity file system is read-only.
	if ats&vfs.MayWrite != 0 || ats&vfs.MayExec != 0 {
		return syserror.EACCES
	}
	return fs.childFs.AccessAt(ctx, rp, creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	return fs.childFs.GetDentryAt(ctx, rp, opts)
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	return fs.childFs.GetParentDentryAt(ctx, rp)
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return syserror.EACCES
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// TODO(b/159261227): Implement OpenAt by opening both the target file and
	// corresponding Merkle tree file.
	return fs.childFs.OpenAt(ctx, rp, opts)
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	return fs.childFs.ReadlinkAt(ctx, rp)
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	return fs.childFs.StatAt(ctx, rp, opts)
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	return fs.childFs.StatFSAt(ctx, rp)
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// BoundEndpointAt implements FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	return fs.childFs.BoundEndpointAt(ctx, rp, opts)
}

// ListxattrAt implements vfs.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	return fs.childFs.ListxattrAt(ctx, rp, size)
}

// GetxattrAt implements vfs.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetxattrOptions) (string, error) {
	return fs.childFs.GetxattrAt(ctx, rp, opts)
}

// SetxattrAt implements vfs.FilesystemImpl.SetxattrAt.
func (fs *filesystem) SetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetxattrOptions) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// RemovexattrAt implements vfs.FilesystemImpl.RemovexattrAt.
func (fs *filesystem) RemovexattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	// verity file system is read-only.
	return syserror.EACCES
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	// verity file system is read-only.
	return syserror.EACCES
}
