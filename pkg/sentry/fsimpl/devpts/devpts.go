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
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

var _ vfs.FilesystemType = (*FilesystemType)(nil)

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	// No data allowed.
	if opts.Data != "" {
		return nil, nil, syserror.EINVAL
	}

	fs, root, err := fstype.newFilesystem(vfsObj, creds)
	if err != nil {
		return nil, nil, err
	}
	return fs.Filesystem.VFSFilesystem(), root.VFSDentry(), nil
}

type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// newFilesystem creates a new devpts filesystem with root directory and ptmx
// master inode. It returns the filesystem and root Dentry.
func (fstype FilesystemType) newFilesystem(vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (*filesystem, *kernfs.Dentry, error) {
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
		slaves: make(map[uint32]*slaveInode),
	}
	root.InodeAttrs.Init(creds, linux.UNNAMED_MAJOR, devMinor, 1, linux.ModeDirectory|0555)
	root.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	root.dentry.Init(root)

	// Construct the pts master inode and dentry. Linux always uses inode
	// id 2 for ptmx. See fs/devpts/inode.c:mknod_ptmx.
	master := &masterInode{
		root: root,
	}
	master.InodeAttrs.Init(creds, linux.UNNAMED_MAJOR, devMinor, 2, linux.ModeCharacterDevice|0666)
	master.dentry.Init(master)

	// Add the master as a child of the root.
	links := root.OrderedChildren.Populate(&root.dentry, map[string]*kernfs.Dentry{
		"ptmx": &master.dentry,
	})
	root.IncLinks(links)

	return fs, &root.dentry, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release()
}

// rootInode is the root directory inode for the devpts mounts.
type rootInode struct {
	kernfs.AlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNotSymlink
	kernfs.OrderedChildren

	locks vfs.FileLocks

	// Keep a reference to this inode's dentry.
	dentry kernfs.Dentry

	// master is the master pty inode. Immutable.
	master *masterInode

	// root is the root directory inode for this filesystem. Immutable.
	root *rootInode

	// mu protects the fields below.
	mu sync.Mutex

	// slaves maps pty ids to slave inodes.
	slaves map[uint32]*slaveInode

	// nextIdx is the next pty index to use. Must be accessed atomically.
	//
	// TODO(b/29356795): reuse indices when ptys are closed.
	nextIdx uint32
}

var _ kernfs.Inode = (*rootInode)(nil)

// allocateTerminal creates a new Terminal and installs a pts node for it.
func (i *rootInode) allocateTerminal(creds *auth.Credentials) (*Terminal, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.nextIdx == math.MaxUint32 {
		return nil, syserror.ENOMEM
	}
	idx := i.nextIdx
	i.nextIdx++

	// Sanity check that slave with idx does not exist.
	if _, ok := i.slaves[idx]; ok {
		panic(fmt.Sprintf("pty index collision; index %d already exists", idx))
	}

	// Create the new terminal and slave.
	t := newTerminal(idx)
	slave := &slaveInode{
		root: i,
		t:    t,
	}
	// Linux always uses pty index + 3 as the inode id. See
	// fs/devpts/inode.c:devpts_pty_new().
	slave.InodeAttrs.Init(creds, i.InodeAttrs.DevMajor(), i.InodeAttrs.DevMinor(), uint64(idx+3), linux.ModeCharacterDevice|0600)
	slave.dentry.Init(slave)
	i.slaves[idx] = slave

	return t, nil
}

// masterClose is called when the master end of t is closed.
func (i *rootInode) masterClose(t *Terminal) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Sanity check that slave with idx exists.
	if _, ok := i.slaves[t.n]; !ok {
		panic(fmt.Sprintf("pty with index %d does not exist", t.n))
	}
	delete(i.slaves, t.n)
}

// Open implements kernfs.Inode.Open.
func (i *rootInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), vfsd, &i.OrderedChildren, &i.locks, &opts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// Lookup implements kernfs.Inode.Lookup.
func (i *rootInode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	idx, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if si, ok := i.slaves[uint32(idx)]; ok {
		si.dentry.IncRef()
		return si.dentry.VFSDentry(), nil

	}
	return nil, syserror.ENOENT
}

// IterDirents implements kernfs.Inode.IterDirents.
func (i *rootInode) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	ids := make([]int, 0, len(i.slaves))
	for id := range i.slaves {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids[relOffset:] {
		dirent := vfs.Dirent{
			Name:    strconv.FormatUint(uint64(id), 10),
			Type:    linux.DT_CHR,
			Ino:     i.slaves[uint32(id)].InodeAttrs.Ino(),
			NextOff: offset + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	return offset, nil
}
