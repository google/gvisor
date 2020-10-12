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

// Package proc implements a partial in-memory file system for procfs.
package proc

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Name is the default filesystem name.
const Name = "proc"

// FilesystemType is the factory class for procfs.
//
// +stateify savable
type FilesystemType struct{}

var _ vfs.FilesystemType = (*FilesystemType)(nil)

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (ft FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, nil, fmt.Errorf("procfs requires a kernel")
	}
	pidns := kernel.PIDNamespaceFromContext(ctx)
	if pidns == nil {
		return nil, nil, fmt.Errorf("procfs requires a PID namespace")
	}
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	procfs := &filesystem{
		devMinor: devMinor,
	}
	procfs.VFSFilesystem().Init(vfsObj, &ft, procfs)

	var cgroups map[string]string
	if opts.InternalData != nil {
		data := opts.InternalData.(*InternalData)
		cgroups = data.Cgroups
	}

	inode := procfs.newTasksInode(k, pidns, cgroups)
	var dentry kernfs.Dentry
	dentry.Init(&procfs.Filesystem, inode)
	return procfs.VFSFilesystem(), dentry.VFSDentry(), nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// dynamicInode is an overfitted interface for common Inodes with
// dynamicByteSource types used in procfs.
//
// +stateify savable
type dynamicInode interface {
	kernfs.Inode
	vfs.DynamicBytesSource

	Init(creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, data vfs.DynamicBytesSource, perm linux.FileMode)
}

func (fs *filesystem) newInode(creds *auth.Credentials, perm linux.FileMode, inode dynamicInode) dynamicInode {
	inode.Init(creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), inode, perm)
	return inode
}

// +stateify savable
type staticFile struct {
	kernfs.DynamicBytesFile
	vfs.StaticData
}

var _ dynamicInode = (*staticFile)(nil)

func newStaticFile(data string) *staticFile {
	return &staticFile{StaticData: vfs.StaticData{Data: data}}
}

func (fs *filesystem) newStaticDir(creds *auth.Credentials, children map[string]kernfs.Inode) kernfs.Inode {
	return kernfs.NewStaticDir(creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), 0555, children, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndZero,
	})
}

// InternalData contains internal data passed in to the procfs mount via
// vfs.GetFilesystemOptions.InternalData.
//
// +stateify savable
type InternalData struct {
	Cgroups map[string]string
}

// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.PROC_SUPER_MAGIC), nil
}
