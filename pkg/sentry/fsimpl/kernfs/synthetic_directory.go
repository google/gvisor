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

package kernfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// syntheticDirectory implements kernfs.Inode for a directory created by
// MkdirAt(ForSyntheticMountpoint=true).
//
// +stateify savable
type syntheticDirectory struct {
	InodeAttrs
	InodeNoStatFS
	InodeNoopRefCount
	InodeNoDynamicLookup
	InodeNotSymlink
	OrderedChildren

	locks vfs.FileLocks
}

var _ Inode = (*syntheticDirectory)(nil)

func newSyntheticDirectory(creds *auth.Credentials, perm linux.FileMode) *vfs.Dentry {
	inode := &syntheticDirectory{}
	inode.Init(creds, 0 /* devMajor */, 0 /* devMinor */, 0 /* ino */, perm)
	d := &Dentry{}
	d.Init(inode)
	return &d.vfsd
}

func (dir *syntheticDirectory) Init(creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("perm contains non-permission bits: %#o", perm))
	}
	dir.InodeAttrs.Init(creds, devMajor, devMinor, ino, linux.S_IFDIR|perm)
	dir.OrderedChildren.Init(OrderedChildrenOptions{
		Writable: true,
	})
}

// Open implements Inode.Open.
func (dir *syntheticDirectory) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := NewGenericDirectoryFD(rp.Mount(), vfsd, &dir.OrderedChildren, &dir.locks, &opts, GenericDirectoryFDOptions{})
	if err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// NewFile implements Inode.NewFile.
func (dir *syntheticDirectory) NewFile(ctx context.Context, name string, opts vfs.OpenOptions) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewDir implements Inode.NewDir.
func (dir *syntheticDirectory) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (*vfs.Dentry, error) {
	if !opts.ForSyntheticMountpoint {
		return nil, syserror.EPERM
	}
	subdird := newSyntheticDirectory(auth.CredentialsFromContext(ctx), opts.Mode&linux.PermissionsMask)
	if err := dir.OrderedChildren.Insert(name, subdird); err != nil {
		subdird.DecRef(ctx)
		return nil, err
	}
	return subdird, nil
}

// NewLink implements Inode.NewLink.
func (dir *syntheticDirectory) NewLink(ctx context.Context, name string, target Inode) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewSymlink implements Inode.NewSymlink.
func (dir *syntheticDirectory) NewSymlink(ctx context.Context, name, target string) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewNode implements Inode.NewNode.
func (dir *syntheticDirectory) NewNode(ctx context.Context, name string, opts vfs.MknodOptions) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}
