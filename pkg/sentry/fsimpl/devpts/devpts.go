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

// Package devpts provides a filesystem implementation that behaves like
// devpts.
package devpts

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Name is the filesystem name.
const Name = "devpts"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct {
	initOnce sync.Once `state:"nosave"` // FIXME(gvisor.dev/issue/1663): not yet supported.
	initErr  error

	// fs backs all mounts of this FilesystemType. root is fs' root. fs and root
	// are immutable.
	fs   *vfs.Filesystem
	root *vfs.Dentry
}

// Name implements vfs.FilesystemType.Name.
func (*FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype *FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	// No data allowed.
	if opts.Data != "" {
		return nil, nil, syserror.EINVAL
	}

	fstype.initOnce.Do(func() {
		fs, root, err := fstype.newFilesystem(ctx, vfsObj, creds)
		if err != nil {
			fstype.initErr = err
			return
		}
		fstype.fs = fs.VFSFilesystem()
		fstype.root = root.VFSDentry()
	})
	if fstype.initErr != nil {
		return nil, nil, fstype.initErr
	}
	fstype.fs.IncRef()
	fstype.root.IncRef()
	return fstype.fs, fstype.root, nil
}

// Release implements vfs.FilesystemType.Release.
func (fstype *FilesystemType) Release(ctx context.Context) {
	if fstype.fs != nil {
		fstype.root.DecRef(ctx)
		fstype.fs.DecRef(ctx)
	}
}

// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// newFilesystem creates a new devpts filesystem with root directory and ptmx
// master inode. It returns the filesystem and root Dentry.
func (fstype *FilesystemType) newFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (*filesystem, *kernfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	fs := &filesystem{
		devMinor: devMinor,
	}
	fs.Filesystem.VFSFilesystem().Init(vfsObj, fstype, fs)

	// Construct the root directory. This is always inode id 1.
	root := &rootInode{
		replicas: make(map[uint32]*replicaInode),
	}
	root.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, devMinor, 1, linux.ModeDirectory|0555)
	root.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	root.InitRefs()

	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)

	// Construct the pts master inode and dentry. Linux always uses inode
	// id 2 for ptmx. See fs/devpts/inode.c:mknod_ptmx.
	master := &masterInode{
		root: root,
	}
	master.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, devMinor, 2, linux.ModeCharacterDevice|0666)

	// Add the master as a child of the root.
	links := root.OrderedChildren.Populate(map[string]kernfs.Inode{
		"ptmx": master,
	})
	root.IncLinks(links)

	return fs, &rootD, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

// rootInode is the root directory inode for the devpts mounts.
//
// +stateify savable
type rootInode struct {
	implStatFS
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary // This holds no meaning as this inode can't be Looked up and is always valid.
	kernfs.OrderedChildren
	rootInodeRefs

	locks vfs.FileLocks

	// master is the master pty inode. Immutable.
	master *masterInode

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// replicas maps pty ids to replica inodes.
	replicas map[uint32]*replicaInode

	// nextIdx is the next pty index to use. Must be accessed atomically.
	//
	// TODO(b/29356795): reuse indices when ptys are closed.
	nextIdx uint32
}

var _ kernfs.Inode = (*rootInode)(nil)

// allocateTerminal creates a new Terminal and installs a pts node for it.
func (i *rootInode) allocateTerminal(ctx context.Context, creds *auth.Credentials) (*Terminal, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.nextIdx == math.MaxUint32 {
		return nil, syserror.ENOMEM
	}
	idx := i.nextIdx
	i.nextIdx++

	// Sanity check that replica with idx does not exist.
	if _, ok := i.replicas[idx]; ok {
		panic(fmt.Sprintf("pty index collision; index %d already exists", idx))
	}

	// Create the new terminal and replica.
	t := newTerminal(idx)
	replica := &replicaInode{
		root: i,
		t:    t,
	}
	// Linux always uses pty index + 3 as the inode id. See
	// fs/devpts/inode.c:devpts_pty_new().
	replica.InodeAttrs.Init(ctx, creds, i.InodeAttrs.DevMajor(), i.InodeAttrs.DevMinor(), uint64(idx+3), linux.ModeCharacterDevice|0600)
	i.replicas[idx] = replica

	return t, nil
}

// masterClose is called when the master end of t is closed.
func (i *rootInode) masterClose(ctx context.Context, t *Terminal) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Sanity check that replica with idx exists.
	ri, ok := i.replicas[t.n]
	if !ok {
		panic(fmt.Sprintf("pty with index %d does not exist", t.n))
	}

	// Drop the ref on replica inode taken during rootInode.allocateTerminal.
	ri.DecRef(ctx)
	delete(i.replicas, t.n)
}

// Open implements kernfs.Inode.Open.
func (i *rootInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), d, &i.OrderedChildren, &i.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndStaticEntries,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// Lookup implements kernfs.Inode.Lookup.
func (i *rootInode) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	// Check if a static entry was looked up.
	if d, err := i.OrderedChildren.Lookup(ctx, name); err == nil {
		return d, nil
	}

	// Not a static entry.
	idx, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if ri, ok := i.replicas[uint32(idx)]; ok {
		ri.IncRef() // This ref is passed to the dentry upon creation via Init.
		return ri, nil

	}
	return nil, syserror.ENOENT
}

// IterDirents implements kernfs.Inode.IterDirents.
func (i *rootInode) IterDirents(ctx context.Context, mnt *vfs.Mount, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.InodeAttrs.TouchAtime(ctx, mnt)
	ids := make([]int, 0, len(i.replicas))
	for id := range i.replicas {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids[relOffset:] {
		dirent := vfs.Dirent{
			Name:    strconv.FormatUint(uint64(id), 10),
			Type:    linux.DT_CHR,
			Ino:     i.replicas[uint32(id)].InodeAttrs.Ino(),
			NextOff: offset + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	return offset, nil
}

// DecRef implements kernfs.Inode.DecRef.
func (i *rootInode) DecRef(ctx context.Context) {
	i.rootInodeRefs.DecRef(func() { i.Destroy(ctx) })
}

// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.DEVPTS_SUPER_MAGIC), nil
}
