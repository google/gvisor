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

// Package verity provides a filesystem implementation that is a wrapper of
// another file system. This file system accesses the underlying file system to
// access files, but provide an additional step to verify the read content
// through Merkle trees.
package verity

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Name is the default filesystem name.
const Name = "verity"

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// verityPath is the path to the verity manifest file.
	verityPath string

	// childFs is the underlying file system impl.
	childFs vfs.FilesystemImpl
}

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
type InternalFilesystemOptions struct {
	VerityPath        string
	ChildFsName       string
	ChildGetFsOptions vfs.GetFilesystemOptions
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: verity without specified child file system")
		return nil, nil, syserror.EINVAL
	}

	cft, err := vfsObj.GetFilesystemType(iopts.ChildFsName)
	if cft == nil || err != nil {
		ctx.Warningf("Unknown filesystem type: %s", iopts.ChildFsName)
		return nil, nil, syserror.ENODEV
	}

	childFs, childDentry, err := cft.GetFilesystem(ctx, vfsObj, creds, source, iopts.ChildGetFsOptions)
	if err != nil {
		return nil, nil, err
	}
	fs := &filesystem{
		verityPath: iopts.VerityPath,
		childFs:    childFs.Impl(),
	}
	fs.vfsfs.Init(vfsObj, &fstype, fs)

	return &fs.vfsfs, childDentry, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	fs.childFs.Release()
}

// FileDescription implements FileDescriptionImpl for verity fds.
// FileDescription is a wrapper of the underlying childFd, with support to build
// Merkle trees through fs-verity APIs and verity read content.
type FileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	childFd vfs.FileDescriptionImpl
	treeFd  vfs.FileDescriptionImpl
}
