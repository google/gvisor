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

// Package memdirfs is a filesystem implementation which provides a common set
// of operations for directories and read-only files for in-memory filesystems.
//
// Memdirfs is not a complete filesystem implementation. A concrete filesystem
// is expected to embed components from memdirfs and extend the default
// behaviour as required.
//
// Memdirfs is not intended for high-performance filesystems. It focuses on
// simplicity and convenience.
//
// Memdirfs re-introduces some classical filesystem concepts absent from VFS2:
//
// - Inodes. An inode represent a single filesystem object (file or
//   directory). An inode has no "name", an dentry points to an inode to give it
//   an identity within a mounted file system.
//
// - Multiple dentries can point to the same inode. A unique file or directory
//   on the filesystem has a unique inode representing it.
//
// - Client filesystems implement files by providing an InodeImpl implementation
//   to memdirfs.NewInode. For simple read-only files backed by
//   vfs.DynamicBytesSources, see DynamicBytesFileDefaultInodeImpl and
//   DynamicBytesFD.
//
// Memdirfs handles the implementation of directories. A directory may both have
// static, persistent children and dynamic children constructed on every path
// resolution. Memdirfs handles the vfs.FileDescription implementation of
// directories. See memdirfs.directoryFD.
//
// For a minimal concrete filesystem implementation using memdirfs, the
// following should be provided. For an example, see sysfs in
// pkg/sentry/fsimpl/sys.
//
// 1. Filesystem type
//
//    A type that embeds memdirfs.Filesystem.
//
// 2. Implementation the vfs.FilesystemType interface.
//
//    This is the filesystem constructor. The vfs.FilesytemType.NewFilesystem
//    implementation should construct and initialize an instance of the
//    filesystem type from #1. The initialization must call
//    memdirfs.Filesystem.Init(...).
//
//    The NewFilesystem implementation should also populate the filesystem with
//    any required nodes. Most filesystems will provide a root
//    directory. Filesystems such as sysfs may also provide nodes that are
//    always present.
//
// 3. Dentry type, an implementation of vfs.DentryImpl.
//
//    A dentry type representing a resolved filesystem node. Most filesystem
//    will simply use memdirfs.Dentry, which provides a complete implementation
//    of vfs.DentryImpl. Complex filesystems may embed memdirfs.Dentry instead
//    and overrides some of the provided behaviour.
//
// 4. Implementation of the memdirfs.InodeImpl interface.
//
//    This is the specific behaviour of inodes on the filesystem. An
//    implementation needs to be provided for each distinct node type, such as
//    regular files, sockets, pipes, etc.
//
//    Memdirfs provides the InodeImpls for directories.
//
//    For read-only regular files, implement vfs.DynamicBytesSource, and use
//    memdirfs.DynamicBytesFileDefaultInodeImpl.
//
// 5. Implementation the of vfs.FileDescription interface.
//
//    This is the specific behaviour of FDs for files on the filesystem. An
//    implementation needs to be provided for each distinct node type.
//
//    On memdirfs, FDs are constructed by calls to memdirfs.InodeImpl.Open. This
//    was provided in #4 above.
//
//    Memdirfs provides the implementations for directories.
//
//    For read-only regular files, use memdirfs.DynamicBytesFD.
package memdirfs

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

// Filesystem mostly implements vfs.FilesystemImpl for a generic in-memory
// filesystem. Concrete implementations are expected to embed this in their own
// Filesystem type.
type Filesystem struct {
	vfsfs vfs.Filesystem

	// Block size of the filesystem in bytes. Immutable.
	blksize uint32

	// Factory function for generating new empty regular file inodes on this
	// filesystem. Immutable.
	//
	// TODO: Figure out how to restore this after SR. However, similar problems
	// exist in VFS2.
	NewEmptyFileInodeImpl func() InodeImpl

	// mu serializes changes to the Dentry tree.
	mu sync.RWMutex

	nextInoMinusOne uint64 // Atomic ops.
}

// VFSFilesystem returns the generic vfs filesystem object.
func (fs *Filesystem) VFSFilesystem() *vfs.Filesystem {
	return &fs.vfsfs
}

// NewDirectory creates a new inode representing a directory, wraps it in a
// Dentry and then populates it with contents.
func (fs *Filesystem) NewDirectory(creds *auth.Credentials, mode linux.FileMode, contents map[string]*Dentry) *Dentry {
	d := fs.NewDirectoryInode(creds, mode).NewDentry()
	vfsD := d.VFSDentry()
	for name, de := range contents {
		vfsD.InsertChild(de.VFSDentry(), name)
	}
	return d
}

// NewFilesystem implements vfs.FilesystemType.NewFilesystem.
func (fstype FilesystemType) NewFilesystem(ctx context.Context, creds *auth.Credentials, source string, opts vfs.NewFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	var fs Filesystem
	fs.blksize = 1 // usermem.PageSize in tmpfs
	fs.vfsfs.Init(&fs)
	root := fs.NewDirectory(creds, 01777, nil)
	return &fs.vfsfs, &root.vfsd, nil
}

// NewFilesystemOptions specifics the filesystem options specific to memdirfs.
type NewFilesystemOptions struct {
	BlkSize               uint32
	NewEmptyFileInodeImpl func() InodeImpl
}

// Init initializes a memdirfs filesystem. This should be called from during
// vfs.FilesystemType.NewFilesystem for the concrete filesystem embedding
// memdirfs.
func (fs *Filesystem) Init(opts NewFilesystemOptions) {
	fs.blksize = opts.BlkSize
	fs.NewEmptyFileInodeImpl = opts.NewEmptyFileInodeImpl
	fs.vfsfs.Init(fs)
}

// Dentry implements vfs.DentryImpl.
type Dentry struct {
	vfsd vfs.Dentry

	inode *Inode

	// memdirfs doesn't count references on dentries; because the dentry tree is
	// the sole source of truth, it is by definition always consistent with the
	// state of the filesystem. However, it does count references on inodes,
	// because inode resources are released when all references are dropped.
	// (memdirfs doesn't really have resources to release, but we implement
	// reference counting because tmpfs regular files will.)

	// DentryEntry (ugh) links dentries into their parent directory.childList.
	DentryEntry
}

// VFSDentry returns the generic vfs dentry for this memdirfs dentry.
func (d *Dentry) VFSDentry() *vfs.Dentry {
	return &d.vfsd
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *Dentry) IncRef(vfsfs *vfs.Filesystem) {
	d.inode.IncRef()
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *Dentry) TryIncRef(vfsfs *vfs.Filesystem) bool {
	return d.inode.TryIncRef()
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *Dentry) DecRef(vfsfs *vfs.Filesystem) {
	d.inode.DecRef()
}

// Inode represents a concrete object on a filesystem. Inodes back files,
// special files and directories on memdirfs and have similar semantics to a
// traditional filesystem.
type Inode struct {
	refs int64

	ino uint64

	// mu Protects the fields below.
	mu sync.RWMutex
	// Only uses first 16 bits, but stored in a 32 bit int for atomic ops.
	mode  uint32
	nlink uint32 // protected by filesystem.mu instead of inode.mu
	uid   uint32
	gid   uint32

	isDirectory bool // Immutable.

	impl InodeImpl // Immutable.
}

// InodeImpl represents the set of inode-level operations to be provided by the
// concrete filesystem.
type InodeImpl interface {
	// Open creates a file description for the filesystem object represented by
	// this inode.
	//
	// Precondition: !rp.Done().
	Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error)

	// DynamicLookup gives the inode implementation an opportunity to provide
	// dynamic entries for a directory on every lookup. This is only called when
	// the inode is a directory. If the inode is not a directory, or if the
	// directory only contains a static set of children, the implementer can
	// unconditionally return an appropriate error (ENOTDIR and ENOENT
	// respectively).
	//
	// Precondition: !rp.Done().
	DynamicLookup(rp *vfs.ResolvingPath) (*vfs.Dentry, error)

	// Stat populates stat struct for this inode. Memdirfs will populate many
	// common fields prior to calling this function, see Inode.statTo.
	//
	// A minimal implementation should add the node type to the linux.Statx.Mode
	// field.
	Stat(stat *linux.Statx)
}

// InodeOpts contains the information requried to create a new inode.
type InodeOpts struct {
	Creds *auth.Credentials
	Mode  linux.FileMode
	Dir   bool
	Impl  InodeImpl
}

// NewInode creates a new inode.
func (fs *Filesystem) NewInode(opts InodeOpts) *Inode {
	i := &Inode{
		isDirectory: opts.Dir,
	}
	nlink := uint32(1)
	if opts.Dir {
		nlink = 2
	}

	i.refs = 1
	i.mode = uint32(opts.Mode)
	i.nlink = nlink
	i.uid = uint32(opts.Creds.EffectiveKUID)
	i.gid = uint32(opts.Creds.EffectiveKGID)
	i.ino = atomic.AddUint64(&fs.nextInoMinusOne, 1)
	i.impl = opts.Impl

	return i
}

// NewDentry wraps an inode in a Dentry.
func (i *Inode) NewDentry() *Dentry {
	d := &Dentry{
		inode: i,
	}
	d.vfsd.Init(d)
	return d
}

// Impl returns the InodeImpl for this inode.
func (i *Inode) Impl() InodeImpl {
	return i.impl
}

func (i *Inode) isDir() bool {
	return i.isDirectory
}

// IncLinksLocked increases the link count for this inode.
//
// Preconditions: filesystem.mu must be locked for writing.
func (i *Inode) IncLinksLocked() {
	if atomic.AddUint32(&i.nlink, 1) <= 1 {
		panic("memfs.inode.incLinksLocked() called with no existing links")
	}
}

// DecLinksLocked decreases the link count for this inode.
//
// Preconditions: inode must have at least one link, filesystem.mu must be
// locked for writing.
func (i *Inode) DecLinksLocked() {
	if nlink := atomic.AddUint32(&i.nlink, ^uint32(0)); nlink == 0 {
		i.DecRef()
	} else if nlink == ^uint32(0) { // negative overflow
		panic("memfs.inode.decLinksLocked() called with no existing links")
	}
}

// IncRef adds a reference to this inode.
//
// Precondition: inode must have at least one ref.
func (i *Inode) IncRef() {
	if refs := atomic.AddInt64(&i.refs, 1); refs <= 1 {
		panic(fmt.Sprintf("sys.inode.IncRef() at %v refs", refs-1))
	}
}

// TryIncRef attempts to add a reference to this inode. This succeeds iff the
// inode isn't at zero refs already.
func (i *Inode) TryIncRef() bool {
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

// DecRef drops a reference to this inode.
//
// Precondition: inode must have at least one ref.
func (i *Inode) DecRef() {
	if refs := atomic.AddInt64(&i.refs, -1); refs < 0 {
		panic(fmt.Sprintf("sys.inode.DecRef() at %v refs", refs+1))
	}
}

func (i *Inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes, isDir bool) error {
	return vfs.GenericCheckPermissions(
		creds,
		ats,
		isDir,
		uint16(atomic.LoadUint32(&i.mode)),
		auth.KUID(atomic.LoadUint32(&i.uid)),
		auth.KGID(atomic.LoadUint32(&i.gid)),
	)
}

func num512ByteBlocks(size uint64) uint64 {
	return (size + 511) / 512
}

func (i *Inode) statTo(fs *Filesystem, stat *linux.Statx) {
	// Fill in the common stat fields.
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO
	stat.Blksize = fs.blksize
	stat.Nlink = atomic.LoadUint32(&i.nlink)
	stat.UID = atomic.LoadUint32(&i.uid)
	stat.GID = atomic.LoadUint32(&i.gid)
	stat.Mode = uint16(atomic.LoadUint32(&i.mode))
	stat.Ino = i.ino
	// TODO: device number

	// Dispatch to implementation to fill in the rest.
	i.impl.Stat(stat)
}

func (i *Inode) direntType() uint8 {
	switch i.impl.(type) {
	case *Directory:
		return linux.DT_DIR
	case *symlink:
		return linux.DT_LNK
	default:
		// Fall back to slow path, extract node type from Stat interface.
		s := linux.Statx{}
		i.impl.Stat(&s)
		switch s.Mode & linux.S_IFMT {
		case linux.S_IFSOCK:
			return linux.DT_SOCK
		case linux.S_IFLNK:
			return linux.DT_LNK
		case linux.S_IFREG:
			return linux.DT_REG
		case linux.S_IFBLK:
			return linux.DT_BLK
		case linux.S_IFDIR:
			return linux.DT_DIR
		case linux.S_IFCHR:
			return linux.DT_CHR
		case linux.S_IFIFO:
		default:
			panic(fmt.Sprintf("Unknown mode %d", s.Mode&linux.S_IFMT))
		}
		panic("unreachable")
	}
}

type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

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
	fd.inode().statTo(fd.filesystem(), &stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	// TODO: implement inode.setStat
	return syserror.EPERM
}
