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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// SeekEndConfig describes the SEEK_END behaviour for FDs.
//
// +stateify savable
type SeekEndConfig int

// Constants related to SEEK_END behaviour for FDs.
const (
	// Consider the end of the file to be after the final static entry. This is
	// the default option.
	SeekEndStaticEntries = iota
	// Consider the end of the file to be at offset 0.
	SeekEndZero
)

// GenericDirectoryFDOptions contains configuration for a GenericDirectoryFD.
//
// +stateify savable
type GenericDirectoryFDOptions struct {
	SeekEnd SeekEndConfig
}

// GenericDirectoryFD implements vfs.FileDescriptionImpl for a generic directory
// inode that uses OrderChildren to track child nodes.
//
// Note that GenericDirectoryFD holds a lock over OrderedChildren while calling
// IterDirents callback. The IterDirents callback therefore cannot hash or
// unhash children, or recursively call IterDirents on the same underlying
// inode.
//
// Must be initialize with Init before first use.
//
// Lock ordering: mu => children.mu.
//
// +stateify savable
type GenericDirectoryFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DirectoryFileDescriptionDefaultImpl
	vfs.LockFD

	// Immutable.
	seekEnd SeekEndConfig

	vfsfd    vfs.FileDescription
	children *OrderedChildren

	// mu protects the fields below.
	mu dirFDMutex `state:"nosave"`

	// off is the current directory offset. Protected by "mu".
	off int64
}

// NewGenericDirectoryFD creates a new GenericDirectoryFD and returns its
// dentry.
func NewGenericDirectoryFD(m *vfs.Mount, d *Dentry, children *OrderedChildren, locks *vfs.FileLocks, opts *vfs.OpenOptions, fdOpts GenericDirectoryFDOptions) (*GenericDirectoryFD, error) {
	fd := &GenericDirectoryFD{}
	if err := fd.Init(d, children, locks, opts, fdOpts); err != nil {
		return nil, err
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, m, d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return fd, nil
}

// Init initializes a GenericDirectoryFD. Use it when overriding
// GenericDirectoryFD. Caller must call fd.VFSFileDescription.Init() with the
// correct implementation.
func (fd *GenericDirectoryFD) Init(d *Dentry, children *OrderedChildren, locks *vfs.FileLocks, opts *vfs.OpenOptions, fdOpts GenericDirectoryFDOptions) error {
	fd.mu.AssignClass(d.fs.lockClassGenerator)
	if vfs.AccessTypesForOpenFlags(opts)&vfs.MayWrite != 0 {
		// Can't open directories for writing.
		return linuxerr.EISDIR
	}
	fd.LockFD.Init(locks)
	fd.seekEnd = fdOpts.SeekEnd
	fd.children = children
	return nil
}

// VFSFileDescription returns a pointer to the vfs.FileDescription representing
// this object.
func (fd *GenericDirectoryFD) VFSFileDescription() *vfs.FileDescription {
	return &fd.vfsfd
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *GenericDirectoryFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return fd.FileDescriptionDefaultImpl.ConfigureMMap(ctx, opts)
}

// Read implmenets vfs.FileDescriptionImpl.Read.
func (fd *GenericDirectoryFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.Read(ctx, dst, opts)
}

// PRead implmenets vfs.FileDescriptionImpl.PRead.
func (fd *GenericDirectoryFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.PRead(ctx, dst, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *GenericDirectoryFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.Write(ctx, src, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *GenericDirectoryFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.PWrite(ctx, src, offset, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *GenericDirectoryFD) Release(context.Context) {}

func (fd *GenericDirectoryFD) filesystem() *vfs.Filesystem {
	return fd.vfsfd.VirtualDentry().Mount().Filesystem()
}

func (fd *GenericDirectoryFD) dentry() *Dentry {
	return fd.vfsfd.Dentry().Impl().(*Dentry)
}

func (fd *GenericDirectoryFD) inode() Inode {
	return fd.dentry().inode
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents. IterDirents holds
// o.mu when calling cb.
func (fd *GenericDirectoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	opts := vfs.StatOptions{Mask: linux.STATX_INO}
	// Handle ".".
	if fd.off == 0 {
		stat, err := fd.inode().Stat(ctx, fd.filesystem(), opts)
		if err != nil {
			return err
		}
		dirent := vfs.Dirent{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     stat.Ino,
			NextOff: 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return err
		}
		fd.off++
	}

	// Handle "..".
	if fd.off == 1 {
		parentInode := genericParentOrSelf(fd.dentry()).inode
		stat, err := parentInode.Stat(ctx, fd.filesystem(), opts)
		if err != nil {
			return err
		}
		dirent := vfs.Dirent{
			Name:    "..",
			Type:    linux.FileMode(stat.Mode).DirentType(),
			Ino:     stat.Ino,
			NextOff: 2,
		}
		if err := cb.Handle(dirent); err != nil {
			return err
		}
		fd.off++
	}

	// Handle static children.
	fd.children.mu.RLock()
	defer fd.children.mu.RUnlock()
	// fd.off accounts for "." and "..", but fd.children do not track
	// these.
	childIdx := fd.off - 2
	for it := fd.children.nthLocked(childIdx); it != nil; it = it.Next() {
		stat, err := it.inode.Stat(ctx, fd.filesystem(), opts)
		if err != nil {
			return err
		}
		dirent := vfs.Dirent{
			Name:    it.name,
			Type:    linux.FileMode(stat.Mode).DirentType(),
			Ino:     stat.Ino,
			NextOff: fd.off + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return err
		}
		fd.off++
	}

	var err error
	relOffset := fd.off - int64(len(fd.children.set)) - 2
	fd.off, err = fd.inode().IterDirents(ctx, fd.vfsfd.Mount(), cb, fd.off, relOffset)
	return err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *GenericDirectoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	case linux.SEEK_END:
		switch fd.seekEnd {
		case SeekEndStaticEntries:
			fd.children.mu.RLock()
			offset += int64(len(fd.children.set))
			offset += 2 // '.' and '..' aren't tracked in children.
			fd.children.mu.RUnlock()
		case SeekEndZero:
			// No-op: offset += 0.
		default:
			panic(fmt.Sprintf("Invalid GenericDirectoryFD.seekEnd = %v", fd.seekEnd))
		}
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *GenericDirectoryFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.filesystem()
	inode := fd.inode()
	return inode.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *GenericDirectoryFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	return fd.inode().SetStat(ctx, fd.filesystem(), creds, opts)
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *GenericDirectoryFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return fd.DirectoryFileDescriptionDefaultImpl.Allocate(ctx, mode, offset, length)
}
