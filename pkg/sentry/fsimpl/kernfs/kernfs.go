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

// Package kernfs provides the tools to implement inode-based filesystems.
// Kernfs has two main features:
//
// 1. The Inode interface, which maps VFS2's path-based filesystem operations to
//    specific filesystem nodes. Kernfs uses the Inode interface to provide a
//    blanket implementation for the vfs.FilesystemImpl. Kernfs also serves as
//    the synchronization mechanism for all filesystem operations by holding a
//    filesystem-wide lock across all operations.
//
// 2. Various utility types which provide generic implementations for various
//    parts of the Inode and vfs.FileDescription interfaces. Client filesystems
//    based on kernfs can embed the appropriate set of these to avoid having to
//    reimplement common filesystem operations. See inode_impl_util.go and
//    fd_impl_util.go.
//
// Reference Model:
//
// Kernfs dentries represents named pointers to inodes. Dentries and inode have
// independent lifetimes and reference counts. A child dentry unconditionally
// holds a reference on its parent directory's dentry. A dentry also holds a
// reference on the inode it points to. Multiple dentries can point to the same
// inode (for example, in the case of hardlinks). File descriptors hold a
// reference to the dentry they're opened on.
//
// Dentries are guaranteed to exist while holding Filesystem.mu for
// reading. Dropping dentries require holding Filesystem.mu for writing. To
// queue dentries for destruction from a read critical section, see
// Filesystem.deferDecRef.
//
// Lock ordering:
//
// kernfs.Filesystem.mu
//   kernfs.Dentry.dirMu
//     vfs.VirtualFilesystem.mountMu
//       vfs.Dentry.mu
//   kernfs.Filesystem.droppedDentriesMu
//   (inode implementation locks, if any)
package kernfs

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Filesystem mostly implements vfs.FilesystemImpl for a generic in-memory
// filesystem. Concrete implementations are expected to embed this in their own
// Filesystem type.
type Filesystem struct {
	vfsfs vfs.Filesystem

	droppedDentriesMu sync.Mutex

	// droppedDentries is a list of dentries waiting to be DecRef()ed. This is
	// used to defer dentry destruction until mu can be acquired for
	// writing. Protected by droppedDentriesMu.
	droppedDentries []*vfs.Dentry

	// mu synchronizes the lifetime of Dentries on this filesystem. Holding it
	// for reading guarantees continued existence of any resolved dentries, but
	// the dentry tree may be modified.
	//
	// Kernfs dentries can only be DecRef()ed while holding mu for writing. For
	// example:
	//
	//   fs.mu.Lock()
	//   defer fs.mu.Unlock()
	//   ...
	//   dentry1.DecRef()
	//   defer dentry2.DecRef() // Ok, will run before Unlock.
	//
	// If discarding dentries in a read context, use Filesystem.deferDecRef. For
	// example:
	//
	//   fs.mu.RLock()
	//   fs.mu.processDeferredDecRefs()
	//   defer fs.mu.RUnlock()
	//   ...
	//   fs.deferDecRef(dentry)
	mu sync.RWMutex

	// nextInoMinusOne is used to to allocate inode numbers on this
	// filesystem. Must be accessed by atomic operations.
	nextInoMinusOne uint64
}

// deferDecRef defers dropping a dentry ref until the next call to
// processDeferredDecRefs{,Locked}. See comment on Filesystem.mu.
//
// Precondition: d must not already be pending destruction.
func (fs *Filesystem) deferDecRef(d *vfs.Dentry) {
	fs.droppedDentriesMu.Lock()
	fs.droppedDentries = append(fs.droppedDentries, d)
	fs.droppedDentriesMu.Unlock()
}

// processDeferredDecRefs calls vfs.Dentry.DecRef on all dentries in the
// droppedDentries list. See comment on Filesystem.mu.
func (fs *Filesystem) processDeferredDecRefs(ctx context.Context) {
	fs.mu.Lock()
	fs.processDeferredDecRefsLocked(ctx)
	fs.mu.Unlock()
}

// Precondition: fs.mu must be held for writing.
func (fs *Filesystem) processDeferredDecRefsLocked(ctx context.Context) {
	fs.droppedDentriesMu.Lock()
	for _, d := range fs.droppedDentries {
		d.DecRef(ctx)
	}
	fs.droppedDentries = fs.droppedDentries[:0] // Keep slice memory for reuse.
	fs.droppedDentriesMu.Unlock()
}

// VFSFilesystem returns the generic vfs filesystem object.
func (fs *Filesystem) VFSFilesystem() *vfs.Filesystem {
	return &fs.vfsfs
}

// NextIno allocates a new inode number on this filesystem.
func (fs *Filesystem) NextIno() uint64 {
	return atomic.AddUint64(&fs.nextInoMinusOne, 1)
}

// These consts are used in the Dentry.flags field.
const (
	// Dentry points to a directory inode.
	dflagsIsDir = 1 << iota

	// Dentry points to a symlink inode.
	dflagsIsSymlink
)

// Dentry implements vfs.DentryImpl.
//
// A kernfs dentry is similar to a dentry in a traditional filesystem: it's a
// named reference to an inode. A dentry generally lives as long as it's part of
// a mounted filesystem tree. Kernfs doesn't cache dentries once all references
// to them are removed. Dentries hold a single reference to the inode they point
// to, and child dentries hold a reference on their parent.
//
// Must be initialized by Init prior to first use.
type Dentry struct {
	DentryRefs

	vfsd vfs.Dentry

	// flags caches useful information about the dentry from the inode. See the
	// dflags* consts above. Must be accessed by atomic ops.
	flags uint32

	parent *Dentry
	name   string

	// dirMu protects children and the names of child Dentries.
	dirMu    sync.Mutex
	children map[string]*Dentry

	inode Inode
}

// Init initializes this dentry.
//
// Precondition: Caller must hold a reference on inode.
//
// Postcondition: Caller's reference on inode is transferred to the dentry.
func (d *Dentry) Init(inode Inode) {
	d.vfsd.Init(d)
	d.inode = inode
	ftype := inode.Mode().FileType()
	if ftype == linux.ModeDirectory {
		d.flags |= dflagsIsDir
	}
	if ftype == linux.ModeSymlink {
		d.flags |= dflagsIsSymlink
	}
	d.EnableLeakCheck()
}

// VFSDentry returns the generic vfs dentry for this kernfs dentry.
func (d *Dentry) VFSDentry() *vfs.Dentry {
	return &d.vfsd
}

// isDir checks whether the dentry points to a directory inode.
func (d *Dentry) isDir() bool {
	return atomic.LoadUint32(&d.flags)&dflagsIsDir != 0
}

// isSymlink checks whether the dentry points to a symlink inode.
func (d *Dentry) isSymlink() bool {
	return atomic.LoadUint32(&d.flags)&dflagsIsSymlink != 0
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *Dentry) DecRef(ctx context.Context) {
	// Before the destructor is called, Dentry must be removed from VFS' dentry cache.
	d.DentryRefs.DecRef(func() {
		d.inode.DecRef(ctx) // IncRef from Init.
		d.inode = nil
		if d.parent != nil {
			d.parent.DecRef(ctx) // IncRef from Dentry.InsertChild.
		}
	})
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
//
// Although Linux technically supports inotify on pseudo filesystems (inotify
// is implemented at the vfs layer), it is not particularly useful. It is left
// unimplemented until someone actually needs it.
func (d *Dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {}

// Watches implements vfs.DentryImpl.Watches.
func (d *Dentry) Watches() *vfs.Watches {
	return nil
}

// OnZeroWatches implements vfs.Dentry.OnZeroWatches.
func (d *Dentry) OnZeroWatches(context.Context) {}

// InsertChild inserts child into the vfs dentry cache with the given name under
// this dentry. This does not update the directory inode, so calling this on
// its own isn't sufficient to insert a child into a directory. InsertChild
// updates the link count on d if required.
//
// Precondition: d must represent a directory inode.
func (d *Dentry) InsertChild(name string, child *Dentry) {
	d.dirMu.Lock()
	d.InsertChildLocked(name, child)
	d.dirMu.Unlock()
}

// InsertChildLocked is equivalent to InsertChild, with additional
// preconditions.
//
// Precondition: d.dirMu must be locked.
func (d *Dentry) InsertChildLocked(name string, child *Dentry) {
	if !d.isDir() {
		panic(fmt.Sprintf("InsertChild called on non-directory Dentry: %+v.", d))
	}
	d.IncRef() // DecRef in child's Dentry.destroy.
	child.parent = d
	child.name = name
	if d.children == nil {
		d.children = make(map[string]*Dentry)
	}
	d.children[name] = child
}

// RemoveChild removes child from the vfs dentry cache. This does not update the
// directory inode or modify the inode to be unlinked. So calling this on its own
// isn't sufficient to remove a child from a directory.
//
// Precondition: d must represent a directory inode.
func (d *Dentry) RemoveChild(name string, child *vfs.Dentry) error {
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	return d.RemoveChildLocked(name, child)
}

// RemoveChildLocked is equivalent to RemoveChild, with additional
// preconditions.
//
// Precondition: d.dirMu must be locked.
func (d *Dentry) RemoveChildLocked(name string, child *vfs.Dentry) error {
	if !d.isDir() {
		panic(fmt.Sprintf("RemoveChild called on non-directory Dentry: %+v.", d))
	}
	c, ok := d.children[name]
	if !ok {
		return syserror.ENOENT
	}
	if &c.vfsd != child {
		panic(fmt.Sprintf("Dentry hashed into inode doesn't match what vfs thinks! Child: %+v, vfs: %+v", c, child))
	}
	delete(d.children, name)
	return nil
}

// Inode returns the dentry's inode.
func (d *Dentry) Inode() Inode {
	return d.inode
}

// The Inode interface maps filesystem-level operations that operate on paths to
// equivalent operations on specific filesystem nodes.
//
// The interface methods are groups into logical categories as sub interfaces
// below. Generally, an implementation for each sub interface can be provided by
// embedding an appropriate type from inode_impl_utils.go. The sub interfaces
// are purely organizational. Methods declared directly in the main interface
// have no generic implementations, and should be explicitly provided by the
// client filesystem.
//
// Generally, implementations are not responsible for tasks that are common to
// all filesystems. These include:
//
// - Checking that dentries passed to methods are of the appropriate file type.
// - Checking permissions.
// - Updating link and reference counts.
//
// Specific responsibilities of implementations are documented below.
type Inode interface {
	// Methods related to reference counting. A generic implementation is
	// provided by InodeNoopRefCount. These methods are generally called by the
	// equivalent Dentry methods.
	inodeRefs

	// Methods related to node metadata. A generic implementation is provided by
	// InodeAttrs.
	inodeMetadata

	// Method for inodes that represent symlink. InodeNotSymlink provides a
	// blanket implementation for all non-symlink inodes.
	inodeSymlink

	// Method for inodes that represent directories. InodeNotDirectory provides
	// a blanket implementation for all non-directory inodes.
	inodeDirectory

	// Method for inodes that represent dynamic directories and their
	// children. InodeNoDynamicLookup provides a blanket implementation for all
	// non-dynamic-directory inodes.
	inodeDynamicLookup

	// Open creates a file description for the filesystem object represented by
	// this inode. The returned file description should hold a reference on the
	// inode for its lifetime.
	//
	// Precondition: rp.Done(). vfsd.Impl() must be the kernfs Dentry containing
	// the inode on which Open() is being called.
	Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error)

	// StatFS returns filesystem statistics for the client filesystem. This
	// corresponds to vfs.FilesystemImpl.StatFSAt. If the client filesystem
	// doesn't support statfs(2), this should return ENOSYS.
	StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error)
}

type inodeRefs interface {
	IncRef()
	DecRef(ctx context.Context)
	TryIncRef() bool
}

type inodeMetadata interface {
	// CheckPermissions checks that creds may access this inode for the
	// requested access type, per the the rules of
	// fs/namei.c:generic_permission().
	CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error

	// Mode returns the (struct stat)::st_mode value for this inode. This is
	// separated from Stat for performance.
	Mode() linux.FileMode

	// Stat returns the metadata for this inode. This corresponds to
	// vfs.FilesystemImpl.StatAt.
	Stat(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error)

	// SetStat updates the metadata for this inode. This corresponds to
	// vfs.FilesystemImpl.SetStatAt. Implementations are responsible for checking
	// if the operation can be performed (see vfs.CheckSetStat() for common
	// checks).
	SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error
}

// Precondition: All methods in this interface may only be called on directory
// inodes.
type inodeDirectory interface {
	// The New{File,Dir,Node,Symlink} methods below should return a new inode
	// hashed into this inode.
	//
	// These inode constructors are inode-level operations rather than
	// filesystem-level operations to allow client filesystems to mix different
	// implementations based on the new node's location in the
	// filesystem.

	// HasChildren returns true if the directory inode has any children.
	HasChildren() bool

	// NewFile creates a new regular file inode.
	NewFile(ctx context.Context, name string, opts vfs.OpenOptions) (*vfs.Dentry, error)

	// NewDir creates a new directory inode.
	NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (*vfs.Dentry, error)

	// NewLink creates a new hardlink to a specified inode in this
	// directory. Implementations should create a new kernfs Dentry pointing to
	// target, and update target's link count.
	NewLink(ctx context.Context, name string, target Inode) (*vfs.Dentry, error)

	// NewSymlink creates a new symbolic link inode.
	NewSymlink(ctx context.Context, name, target string) (*vfs.Dentry, error)

	// NewNode creates a new filesystem node for a mknod syscall.
	NewNode(ctx context.Context, name string, opts vfs.MknodOptions) (*vfs.Dentry, error)

	// Unlink removes a child dentry from this directory inode.
	Unlink(ctx context.Context, name string, child *vfs.Dentry) error

	// RmDir removes an empty child directory from this directory
	// inode. Implementations must update the parent directory's link count,
	// if required. Implementations are not responsible for checking that child
	// is a directory, checking for an empty directory.
	RmDir(ctx context.Context, name string, child *vfs.Dentry) error

	// Rename is called on the source directory containing an inode being
	// renamed. child should point to the resolved child in the source
	// directory. If Rename replaces a dentry in the destination directory, it
	// should return the replaced dentry or nil otherwise.
	//
	// Precondition: Caller must serialize concurrent calls to Rename.
	Rename(ctx context.Context, oldname, newname string, child, dstDir *vfs.Dentry) (replaced *vfs.Dentry, err error)
}

type inodeDynamicLookup interface {
	// Lookup should return an appropriate dentry if name should resolve to a
	// child of this dynamic directory inode. This gives the directory an
	// opportunity on every lookup to resolve additional entries that aren't
	// hashed into the directory. This is only called when the inode is a
	// directory. If the inode is not a directory, or if the directory only
	// contains a static set of children, the implementer can unconditionally
	// return an appropriate error (ENOTDIR and ENOENT respectively).
	//
	// The child returned by Lookup will be hashed into the VFS dentry tree. Its
	// lifetime can be controlled by the filesystem implementation with an
	// appropriate implementation of Valid.
	//
	// Lookup returns the child with an extra reference and the caller owns this
	// reference.
	Lookup(ctx context.Context, name string) (*vfs.Dentry, error)

	// Valid should return true if this inode is still valid, or needs to
	// be resolved again by a call to Lookup.
	Valid(ctx context.Context) bool

	// IterDirents is used to iterate over dynamically created entries. It invokes
	// cb on each entry in the directory represented by the Inode.
	// 'offset' is the offset for the entire IterDirents call, which may include
	// results from the caller (e.g. "." and ".."). 'relOffset' is the offset
	// inside the entries returned by this IterDirents invocation. In other words,
	// 'offset' should be used to calculate each vfs.Dirent.NextOff as well as
	// the return value, while 'relOffset' is the place to start iteration.
	IterDirents(ctx context.Context, callback vfs.IterDirentsCallback, offset, relOffset int64) (newOffset int64, err error)
}

type inodeSymlink interface {
	// Readlink returns the target of a symbolic link. If an inode is not a
	// symlink, the implementation should return EINVAL.
	Readlink(ctx context.Context, mnt *vfs.Mount) (string, error)

	// Getlink returns the target of a symbolic link, as used by path
	// resolution:
	//
	// - If the inode is a "magic link" (a link whose target is most accurately
	// represented as a VirtualDentry), Getlink returns (ok VirtualDentry, "",
	// nil). A reference is taken on the returned VirtualDentry.
	//
	// - If the inode is an ordinary symlink, Getlink returns (zero-value
	// VirtualDentry, symlink target, nil).
	//
	// - If the inode is not a symlink, Getlink returns (zero-value
	// VirtualDentry, "", EINVAL).
	Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error)
}
