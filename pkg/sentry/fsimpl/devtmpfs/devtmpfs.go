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

// Package devtmpfs provides a singleton fsimpl/dev filesystem instance,
// analogous to Linux's devtmpfs.
package devtmpfs

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/dev"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Name is the default filesystem name.
const Name = "devtmpfs"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct {
	initOnce sync.Once `state:"nosave"`
	initErr  error

	// fs is the tmpfs filesystem that backs all mounts of this FilesystemType.
	// root is fs' root. fs and root are immutable.
	fs   *vfs.Filesystem
	root *vfs.Dentry
}

// Name implements vfs.FilesystemType.Name.
func (*FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fst *FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fst.initOnce.Do(func() {
		fs, root, err := dev.FilesystemType{}.GetFilesystem(ctx, vfsObj, creds, source, opts)
		if err != nil {
			fst.initErr = err
			return
		}
		fst.fs = fs
		fst.root = root
	})
	if fst.initErr != nil {
		return nil, nil, fst.initErr
	}
	fst.fs.IncRef()
	fst.root.IncRef()
	return fst.fs, fst.root, nil
}

// Release implements vfs.FilesystemType.Release.
func (fst *FilesystemType) Release(ctx context.Context) {
	if fst.fs != nil {
		// Release the original reference obtained when creating the filesystem.
		fst.root.DecRef(ctx)
		fst.fs.DecRef(ctx)
	}
}
