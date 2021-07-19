// Copyright 2021 The gVisor Authors.
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

package mqfs

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// rootInode represents inode for filesystem's root directory (/dev/mqueue).
//
// +stateify savable
type rootInode struct {
	rootInodeRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary
	kernfs.OrderedChildren
	implStatFS

	locks vfs.FileLocks
}

var _ kernfs.Inode = (*rootInode)(nil)

// newRootInode returns a new, initialized rootInode.
func (fs *filesystem) newRootInode(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	inode := &rootInode{}
	inode.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|linux.FileMode(0555))
	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	inode.InitRefs()
	return inode
}

// Open implements kernfs.Inode.Open.
func (i *rootInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), d, &i.OrderedChildren, &i.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndZero,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// DecRef implements kernfs.Inode.DecRef.
func (i *rootInode) DecRef(ctx context.Context) {
	i.rootInodeRefs.DecRef(func() { i.Destroy(ctx) })
}

// Rename implements Inode.Rename and overrides OrderedChildren.Rename. mqueue
// filesystem allows files to be unlinked, but not renamed.
func (i *rootInode) Rename(ctx context.Context, oldname, newname string, child, dstDir kernfs.Inode) error {
	return linuxerr.EPERM
}

// SetStat implements kernfs.Inode.SetStat not allowing inode attributes to be changed.
func (*rootInode) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// implStatFS provides an implementation of kernfs.Inode.StatFS for message
// queues to be embedded in inodes.
//
// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.MQUEUE_MAGIC), nil
}
