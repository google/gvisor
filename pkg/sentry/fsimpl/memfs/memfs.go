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

// Package memfs provides a filesystem implementation that behaves like tmpfs:
// the Dentry tree is the sole source of truth for the state of the filesystem.
//
// memfs is intended primarily to demonstrate filesystem implementation
// patterns. Real uses cases for an in-memory filesystem should use tmpfs
// instead.
//
// Lock order:
//
// Filesystem.mu
//   regularFileFD.offMu
//     regularFile.mu
//   Inode.mu
package memfs

import (
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// Filesystem implements vfs.FilesystemImpl.
type Filesystem struct {
	vfsfs vfs.Filesystem

	// mu serializes changes to the Dentry tree.
	mu sync.RWMutex

	nextInoMinusOne uint64 // accessed using atomic memory operations
}

// NewFilesystem implements vfs.FilesystemType.NewFilesystem.
func (fstype FilesystemType) NewFilesystem(ctx context.Context, creds *auth.Credentials, source string, opts vfs.NewFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	var fs Filesystem
	fs.vfsfs.Init(&fs)
	root := fs.newDentry(fs.newDirectory(creds, 01777))
	return &fs.vfsfs, &root.vfsd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *Filesystem) Release() {
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *Filesystem) Sync(ctx context.Context) error {
	// All filesystem state is in-memory.
	return nil
}

// Dentry implements vfs.DentryImpl.
type Dentry struct {
	vfsd vfs.Dentry

	// inode is the inode represented by this Dentry. Multiple Dentries may
	// share a single non-directory Inode (with hard links). inode is
	// immutable.
	inode *Inode

	// memfs doesn't count references on Dentries; because the Dentry tree is
	// the sole source of truth, it is by definition always consistent with the
	// state of the filesystem. However, it does count references on Inodes,
	// because Inode resources are released when all references are dropped.
	// (memfs doesn't really have resources to release, but we implement
	// reference counting because tmpfs regular files will.)

	// dentryEntry (ugh) links Dentries into their parent directory.childList.
	dentryEntry
}

func (fs *Filesystem) newDentry(inode *Inode) *Dentry {
	d := &Dentry{
		inode: inode,
	}
	d.vfsd.Init(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *Dentry) IncRef(vfsfs *vfs.Filesystem) {
	d.inode.incRef()
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *Dentry) TryIncRef(vfsfs *vfs.Filesystem) bool {
	return d.inode.tryIncRef()
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *Dentry) DecRef(vfsfs *vfs.Filesystem) {
	d.inode.decRef()
}

// Inode represents a filesystem object.
type Inode struct {
	// refs is a reference count. refs is accessed using atomic memory
	// operations.
	//
	// A reference is held on all Inodes that are reachable in the filesystem
	// tree. For non-directories (which may have multiple hard links), this
	// means that a reference is dropped when nlink reaches 0. For directories,
	// nlink never reaches 0 due to the "." entry; instead,
	// Filesystem.RmdirAt() drops the reference.
	refs int64

	// Inode metadata; protected by mu and accessed using atomic memory
	// operations unless otherwise specified.
	mu    sync.RWMutex
	mode  uint32 // excluding file type bits, which are based on impl
	nlink uint32 // protected by Filesystem.mu instead of Inode.mu
	uid   uint32 // auth.KUID, but stored as raw uint32 for sync/atomic
	gid   uint32 // auth.KGID, but ...
	ino   uint64 // immutable

	impl interface{} // immutable
}

func (i *Inode) init(impl interface{}, fs *Filesystem, creds *auth.Credentials, mode uint16) {
	i.refs = 1
	i.mode = uint32(mode)
	i.uid = uint32(creds.EffectiveKUID)
	i.gid = uint32(creds.EffectiveKGID)
	i.ino = atomic.AddUint64(&fs.nextInoMinusOne, 1)
	// i.nlink initialized by caller
	i.impl = impl
}

// Preconditions: Filesystem.mu must be locked for writing.
func (i *Inode) incLinksLocked() {
	if atomic.AddUint32(&i.nlink, 1) <= 1 {
		panic("memfs.Inode.incLinksLocked() called with no existing links")
	}
}

// Preconditions: Filesystem.mu must be locked for writing.
func (i *Inode) decLinksLocked() {
	if nlink := atomic.AddUint32(&i.nlink, ^uint32(0)); nlink == 0 {
		i.decRef()
	} else if nlink == ^uint32(0) { // negative overflow
		panic("memfs.Inode.decLinksLocked() called with no existing links")
	}
}

func (i *Inode) incRef() {
	if atomic.AddInt64(&i.refs, 1) <= 1 {
		panic("memfs.Inode.incRef() called without holding a reference")
	}
}

func (i *Inode) tryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&i.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&i.refs, refs, refs+1) {
			return true
		}
	}
}

func (i *Inode) decRef() {
	if refs := atomic.AddInt64(&i.refs, -1); refs == 0 {
		// This is unnecessary; it's mostly to simulate what tmpfs would do.
		if regfile, ok := i.impl.(*regularFile); ok {
			regfile.mu.Lock()
			regfile.data = nil
			atomic.StoreInt64(&regfile.dataLen, 0)
			regfile.mu.Unlock()
		}
	} else if refs < 0 {
		panic("memfs.Inode.decRef() called without holding a reference")
	}
}

func (i *Inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes, isDir bool) error {
	return vfs.GenericCheckPermissions(creds, ats, isDir, uint16(atomic.LoadUint32(&i.mode)), auth.KUID(atomic.LoadUint32(&i.uid)), auth.KGID(atomic.LoadUint32(&i.gid)))
}

// Go won't inline this function, and returning linux.Statx (which is quite
// big) means spending a lot of time in runtime.duffcopy(), so instead it's an
// output parameter.
func (i *Inode) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO
	stat.Blksize = 1 // usermem.PageSize in tmpfs
	stat.Nlink = atomic.LoadUint32(&i.nlink)
	stat.UID = atomic.LoadUint32(&i.uid)
	stat.GID = atomic.LoadUint32(&i.gid)
	stat.Mode = uint16(atomic.LoadUint32(&i.mode))
	stat.Ino = i.ino
	// TODO: device number
	switch impl := i.impl.(type) {
	case *regularFile:
		stat.Mode |= linux.S_IFREG
		stat.Mask |= linux.STATX_SIZE | linux.STATX_BLOCKS
		stat.Size = uint64(atomic.LoadInt64(&impl.dataLen))
		// In tmpfs, this will be FileRangeSet.Span() / 512 (but also cached in
		// a uint64 accessed using atomic memory operations to avoid taking
		// locks).
		stat.Blocks = allocatedBlocksForSize(stat.Size)
	case *directory:
		stat.Mode |= linux.S_IFDIR
	case *symlink:
		stat.Mode |= linux.S_IFLNK
		stat.Mask |= linux.STATX_SIZE | linux.STATX_BLOCKS
		stat.Size = uint64(len(impl.target))
		stat.Blocks = allocatedBlocksForSize(stat.Size)
	default:
		panic(fmt.Sprintf("unknown inode type: %T", i.impl))
	}
}

// allocatedBlocksForSize returns the number of 512B blocks needed to
// accommodate the given size in bytes, as appropriate for struct
// stat::st_blocks and struct statx::stx_blocks. (Note that this 512B block
// size is independent of the "preferred block size for I/O", struct
// stat::st_blksize and struct statx::stx_blksize.)
func allocatedBlocksForSize(size uint64) uint64 {
	return (size + 511) / 512
}

func (i *Inode) direntType() uint8 {
	switch i.impl.(type) {
	case *regularFile:
		return linux.DT_REG
	case *directory:
		return linux.DT_DIR
	case *symlink:
		return linux.DT_LNK
	default:
		panic(fmt.Sprintf("unknown inode type: %T", i.impl))
	}
}

// fileDescription is embedded by memfs implementations of
// vfs.FileDescriptionImpl.
type fileDescription struct {
	vfsfd vfs.FileDescription

	flags uint32 // status flags; immutable
}

func (fd *fileDescription) filesystem() *Filesystem {
	return fd.vfsfd.VirtualDentry().Mount().Filesystem().Impl().(*Filesystem)
}

func (fd *fileDescription) inode() *Inode {
	return fd.vfsfd.VirtualDentry().Dentry().Impl().(*Dentry).inode
}

// StatusFlags implements vfs.FileDescriptionImpl.StatusFlags.
func (fd *fileDescription) StatusFlags(ctx context.Context) (uint32, error) {
	return fd.flags, nil
}

// SetStatusFlags implements vfs.FileDescriptionImpl.SetStatusFlags.
func (fd *fileDescription) SetStatusFlags(ctx context.Context, flags uint32) error {
	// None of the flags settable by fcntl(F_SETFL) are supported, so this is a
	// no-op.
	return nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	fd.inode().statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	// TODO: implement Inode.setStat
	return syserror.EPERM
}
