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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// InodeNoopRefCount partially implements the Inode interface, specifically the
// inodeRefs sub interface. InodeNoopRefCount implements a simple reference
// count for inodes, performing no extra actions when references are obtained or
// released. This is suitable for simple file inodes that don't reference any
// resources.
type InodeNoopRefCount struct {
}

// IncRef implements Inode.IncRef.
func (InodeNoopRefCount) IncRef() {
}

// DecRef implements Inode.DecRef.
func (InodeNoopRefCount) DecRef(context.Context) {
}

// TryIncRef implements Inode.TryIncRef.
func (InodeNoopRefCount) TryIncRef() bool {
	return true
}

// InodeDirectoryNoNewChildren partially implements the Inode interface.
// InodeDirectoryNoNewChildren represents a directory inode which does not
// support creation of new children.
type InodeDirectoryNoNewChildren struct{}

// NewFile implements Inode.NewFile.
func (InodeDirectoryNoNewChildren) NewFile(context.Context, string, vfs.OpenOptions) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewDir implements Inode.NewDir.
func (InodeDirectoryNoNewChildren) NewDir(context.Context, string, vfs.MkdirOptions) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewLink implements Inode.NewLink.
func (InodeDirectoryNoNewChildren) NewLink(context.Context, string, Inode) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewSymlink implements Inode.NewSymlink.
func (InodeDirectoryNoNewChildren) NewSymlink(context.Context, string, string) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// NewNode implements Inode.NewNode.
func (InodeDirectoryNoNewChildren) NewNode(context.Context, string, vfs.MknodOptions) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

// InodeNotDirectory partially implements the Inode interface, specifically the
// inodeDirectory and inodeDynamicDirectory sub interfaces. Inodes that do not
// represent directories can embed this to provide no-op implementations for
// directory-related functions.
type InodeNotDirectory struct {
}

// HasChildren implements Inode.HasChildren.
func (InodeNotDirectory) HasChildren() bool {
	return false
}

// NewFile implements Inode.NewFile.
func (InodeNotDirectory) NewFile(context.Context, string, vfs.OpenOptions) (*vfs.Dentry, error) {
	panic("NewFile called on non-directory inode")
}

// NewDir implements Inode.NewDir.
func (InodeNotDirectory) NewDir(context.Context, string, vfs.MkdirOptions) (*vfs.Dentry, error) {
	panic("NewDir called on non-directory inode")
}

// NewLink implements Inode.NewLinkink.
func (InodeNotDirectory) NewLink(context.Context, string, Inode) (*vfs.Dentry, error) {
	panic("NewLink called on non-directory inode")
}

// NewSymlink implements Inode.NewSymlink.
func (InodeNotDirectory) NewSymlink(context.Context, string, string) (*vfs.Dentry, error) {
	panic("NewSymlink called on non-directory inode")
}

// NewNode implements Inode.NewNode.
func (InodeNotDirectory) NewNode(context.Context, string, vfs.MknodOptions) (*vfs.Dentry, error) {
	panic("NewNode called on non-directory inode")
}

// Unlink implements Inode.Unlink.
func (InodeNotDirectory) Unlink(context.Context, string, *vfs.Dentry) error {
	panic("Unlink called on non-directory inode")
}

// RmDir implements Inode.RmDir.
func (InodeNotDirectory) RmDir(context.Context, string, *vfs.Dentry) error {
	panic("RmDir called on non-directory inode")
}

// Rename implements Inode.Rename.
func (InodeNotDirectory) Rename(context.Context, string, string, *vfs.Dentry, *vfs.Dentry) (*vfs.Dentry, error) {
	panic("Rename called on non-directory inode")
}

// Lookup implements Inode.Lookup.
func (InodeNotDirectory) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	panic("Lookup called on non-directory inode")
}

// IterDirents implements Inode.IterDirents.
func (InodeNotDirectory) IterDirents(ctx context.Context, callback vfs.IterDirentsCallback, offset, relOffset int64) (newOffset int64, err error) {
	panic("IterDirents called on non-directory inode")
}

// Valid implements Inode.Valid.
func (InodeNotDirectory) Valid(context.Context) bool {
	return true
}

// InodeNoDynamicLookup partially implements the Inode interface, specifically
// the inodeDynamicLookup sub interface. Directory inodes that do not support
// dymanic entries (i.e. entries that are not "hashed" into the
// vfs.Dentry.children) can embed this to provide no-op implementations for
// functions related to dynamic entries.
type InodeNoDynamicLookup struct{}

// Lookup implements Inode.Lookup.
func (InodeNoDynamicLookup) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	return nil, syserror.ENOENT
}

// IterDirents implements Inode.IterDirents.
func (InodeNoDynamicLookup) IterDirents(ctx context.Context, callback vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	return offset, nil
}

// Valid implements Inode.Valid.
func (InodeNoDynamicLookup) Valid(ctx context.Context) bool {
	return true
}

// InodeNotSymlink partially implements the Inode interface, specifically the
// inodeSymlink sub interface. All inodes that are not symlinks may embed this
// to return the appropriate errors from symlink-related functions.
type InodeNotSymlink struct{}

// Readlink implements Inode.Readlink.
func (InodeNotSymlink) Readlink(context.Context, *vfs.Mount) (string, error) {
	return "", syserror.EINVAL
}

// Getlink implements Inode.Getlink.
func (InodeNotSymlink) Getlink(context.Context, *vfs.Mount) (vfs.VirtualDentry, string, error) {
	return vfs.VirtualDentry{}, "", syserror.EINVAL
}

// InodeAttrs partially implements the Inode interface, specifically the
// inodeMetadata sub interface. InodeAttrs provides functionality related to
// inode attributes.
//
// Must be initialized by Init prior to first use.
type InodeAttrs struct {
	devMajor uint32
	devMinor uint32
	ino      uint64
	mode     uint32
	uid      uint32
	gid      uint32
	nlink    uint32
}

// Init initializes this InodeAttrs.
func (a *InodeAttrs) Init(creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, mode linux.FileMode) {
	if mode.FileType() == 0 {
		panic(fmt.Sprintf("No file type specified in 'mode' for InodeAttrs.Init(): mode=0%o", mode))
	}

	nlink := uint32(1)
	if mode.FileType() == linux.ModeDirectory {
		nlink = 2
	}
	a.devMajor = devMajor
	a.devMinor = devMinor
	atomic.StoreUint64(&a.ino, ino)
	atomic.StoreUint32(&a.mode, uint32(mode))
	atomic.StoreUint32(&a.uid, uint32(creds.EffectiveKUID))
	atomic.StoreUint32(&a.gid, uint32(creds.EffectiveKGID))
	atomic.StoreUint32(&a.nlink, nlink)
}

// DevMajor returns the device major number.
func (a *InodeAttrs) DevMajor() uint32 {
	return a.devMajor
}

// DevMinor returns the device minor number.
func (a *InodeAttrs) DevMinor() uint32 {
	return a.devMinor
}

// Ino returns the inode id.
func (a *InodeAttrs) Ino() uint64 {
	return atomic.LoadUint64(&a.ino)
}

// Mode implements Inode.Mode.
func (a *InodeAttrs) Mode() linux.FileMode {
	return linux.FileMode(atomic.LoadUint32(&a.mode))
}

// Stat partially implements Inode.Stat. Note that this function doesn't provide
// all the stat fields, and the embedder should consider extending the result
// with filesystem-specific fields.
func (a *InodeAttrs) Stat(context.Context, *vfs.Filesystem, vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_NLINK
	stat.DevMajor = a.devMajor
	stat.DevMinor = a.devMinor
	stat.Ino = atomic.LoadUint64(&a.ino)
	stat.Mode = uint16(a.Mode())
	stat.UID = atomic.LoadUint32(&a.uid)
	stat.GID = atomic.LoadUint32(&a.gid)
	stat.Nlink = atomic.LoadUint32(&a.nlink)

	// TODO(gvisor.dev/issue/1193): Implement other stat fields like timestamps.

	return stat, nil
}

// SetStat implements Inode.SetStat.
func (a *InodeAttrs) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return a.SetInodeStat(ctx, fs, creds, opts)
}

// SetInodeStat sets the corresponding attributes from opts to InodeAttrs.
// This function can be used by other kernfs-based filesystem implementation to
// sets the unexported attributes into kernfs.InodeAttrs.
func (a *InodeAttrs) SetInodeStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	if opts.Stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID) != 0 {
		return syserror.EPERM
	}
	if err := vfs.CheckSetStat(ctx, creds, &opts, a.Mode(), auth.KUID(atomic.LoadUint32(&a.uid)), auth.KGID(atomic.LoadUint32(&a.gid))); err != nil {
		return err
	}

	stat := opts.Stat
	if stat.Mask&linux.STATX_MODE != 0 {
		for {
			old := atomic.LoadUint32(&a.mode)
			new := old | uint32(stat.Mode & ^uint16(linux.S_IFMT))
			if swapped := atomic.CompareAndSwapUint32(&a.mode, old, new); swapped {
				break
			}
		}
	}

	if stat.Mask&linux.STATX_UID != 0 {
		atomic.StoreUint32(&a.uid, stat.UID)
	}
	if stat.Mask&linux.STATX_GID != 0 {
		atomic.StoreUint32(&a.gid, stat.GID)
	}

	// Note that not all fields are modifiable. For example, the file type and
	// inode numbers are immutable after node creation.

	// TODO(gvisor.dev/issue/1193): Implement other stat fields like timestamps.
	// Also, STATX_SIZE will need some special handling, because read-only static
	// files should return EIO for truncate operations.

	return nil
}

// CheckPermissions implements Inode.CheckPermissions.
func (a *InodeAttrs) CheckPermissions(_ context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(
		creds,
		ats,
		a.Mode(),
		auth.KUID(atomic.LoadUint32(&a.uid)),
		auth.KGID(atomic.LoadUint32(&a.gid)),
	)
}

// IncLinks implements Inode.IncLinks.
func (a *InodeAttrs) IncLinks(n uint32) {
	if atomic.AddUint32(&a.nlink, n) <= n {
		panic("InodeLink.IncLinks called with no existing links")
	}
}

// DecLinks implements Inode.DecLinks.
func (a *InodeAttrs) DecLinks() {
	if nlink := atomic.AddUint32(&a.nlink, ^uint32(0)); nlink == ^uint32(0) {
		// Negative overflow
		panic("Inode.DecLinks called at 0 links")
	}
}

type slot struct {
	Name   string
	Dentry *vfs.Dentry
	slotEntry
}

// OrderedChildrenOptions contains initialization options for OrderedChildren.
type OrderedChildrenOptions struct {
	// Writable indicates whether vfs.FilesystemImpl methods implemented by
	// OrderedChildren may modify the tracked children. This applies to
	// operations related to rename, unlink and rmdir. If an OrderedChildren is
	// not writable, these operations all fail with EPERM.
	Writable bool
}

// OrderedChildren partially implements the Inode interface. OrderedChildren can
// be embedded in directory inodes to keep track of the children in the
// directory, and can then be used to implement a generic directory FD -- see
// GenericDirectoryFD. OrderedChildren is not compatible with dynamic
// directories.
//
// Must be initialize with Init before first use.
type OrderedChildren struct {
	// Can children be modified by user syscalls? It set to false, interface
	// methods that would modify the children return EPERM. Immutable.
	writable bool

	mu    sync.RWMutex
	order slotList
	set   map[string]*slot
}

// Init initializes an OrderedChildren.
func (o *OrderedChildren) Init(opts OrderedChildrenOptions) {
	o.writable = opts.Writable
	o.set = make(map[string]*slot)
}

// Destroy clears the children stored in o. It should be called by structs
// embedding OrderedChildren upon destruction, i.e. when their reference count
// reaches zero.
func (o *OrderedChildren) Destroy() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.order.Reset()
	o.set = nil
}

// Populate inserts children into this OrderedChildren, and d's dentry
// cache. Populate returns the number of directories inserted, which the caller
// may use to update the link count for the parent directory.
//
// Precondition: d must represent a directory inode. children must not contain
// any conflicting entries already in o.
func (o *OrderedChildren) Populate(d *Dentry, children map[string]*Dentry) uint32 {
	var links uint32
	for name, child := range children {
		if child.isDir() {
			links++
		}
		if err := o.Insert(name, child.VFSDentry()); err != nil {
			panic(fmt.Sprintf("Collision when attempting to insert child %q (%+v) into %+v", name, child, d))
		}
		d.InsertChild(name, child)
	}
	return links
}

// HasChildren implements Inode.HasChildren.
func (o *OrderedChildren) HasChildren() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.set) > 0
}

// Insert inserts child into o. This ignores the writability of o, as this is
// not part of the vfs.FilesystemImpl interface, and is a lower-level operation.
func (o *OrderedChildren) Insert(name string, child *vfs.Dentry) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.set[name]; ok {
		return syserror.EEXIST
	}
	s := &slot{
		Name:   name,
		Dentry: child,
	}
	o.order.PushBack(s)
	o.set[name] = s
	return nil
}

// Precondition: caller must hold o.mu for writing.
func (o *OrderedChildren) removeLocked(name string) {
	if s, ok := o.set[name]; ok {
		delete(o.set, name)
		o.order.Remove(s)
	}
}

// Precondition: caller must hold o.mu for writing.
func (o *OrderedChildren) replaceChildLocked(name string, new *vfs.Dentry) *vfs.Dentry {
	if s, ok := o.set[name]; ok {
		// Existing slot with given name, simply replace the dentry.
		var old *vfs.Dentry
		old, s.Dentry = s.Dentry, new
		return old
	}

	// No existing slot with given name, create and hash new slot.
	s := &slot{
		Name:   name,
		Dentry: new,
	}
	o.order.PushBack(s)
	o.set[name] = s
	return nil
}

// Precondition: caller must hold o.mu for reading or writing.
func (o *OrderedChildren) checkExistingLocked(name string, child *vfs.Dentry) error {
	s, ok := o.set[name]
	if !ok {
		return syserror.ENOENT
	}
	if s.Dentry != child {
		panic(fmt.Sprintf("Dentry hashed into inode doesn't match what vfs thinks! OrderedChild: %+v, vfs: %+v", s.Dentry, child))
	}
	return nil
}

// Unlink implements Inode.Unlink.
func (o *OrderedChildren) Unlink(ctx context.Context, name string, child *vfs.Dentry) error {
	if !o.writable {
		return syserror.EPERM
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkExistingLocked(name, child); err != nil {
		return err
	}

	// TODO(gvisor.dev/issue/3027): Check sticky bit before removing.
	o.removeLocked(name)
	return nil
}

// Rmdir implements Inode.Rmdir.
func (o *OrderedChildren) RmDir(ctx context.Context, name string, child *vfs.Dentry) error {
	// We're not responsible for checking that child is a directory, that it's
	// empty, or updating any link counts; so this is the same as unlink.
	return o.Unlink(ctx, name, child)
}

type renameAcrossDifferentImplementationsError struct{}

func (renameAcrossDifferentImplementationsError) Error() string {
	return "rename across inodes with different implementations"
}

// Rename implements Inode.Rename.
//
// Precondition: Rename may only be called across two directory inodes with
// identical implementations of Rename. Practically, this means filesystems that
// implement Rename by embedding OrderedChildren for any directory
// implementation must use OrderedChildren for all directory implementations
// that will support Rename.
//
// Postcondition: reference on any replaced dentry transferred to caller.
func (o *OrderedChildren) Rename(ctx context.Context, oldname, newname string, child, dstDir *vfs.Dentry) (*vfs.Dentry, error) {
	dst, ok := dstDir.Impl().(*Dentry).inode.(interface{}).(*OrderedChildren)
	if !ok {
		return nil, renameAcrossDifferentImplementationsError{}
	}
	if !o.writable || !dst.writable {
		return nil, syserror.EPERM
	}
	// Note: There's a potential deadlock below if concurrent calls to Rename
	// refer to the same src and dst directories in reverse. We avoid any
	// ordering issues because the caller is required to serialize concurrent
	// calls to Rename in accordance with the interface declaration.
	o.mu.Lock()
	defer o.mu.Unlock()
	if dst != o {
		dst.mu.Lock()
		defer dst.mu.Unlock()
	}
	if err := o.checkExistingLocked(oldname, child); err != nil {
		return nil, err
	}

	// TODO(gvisor.dev/issue/3027): Check sticky bit before removing.
	replaced := dst.replaceChildLocked(newname, child)
	return replaced, nil
}

// nthLocked returns an iterator to the nth child tracked by this object. The
// iterator is valid until the caller releases o.mu. Returns nil if the
// requested index falls out of bounds.
//
// Preconditon: Caller must hold o.mu for reading.
func (o *OrderedChildren) nthLocked(i int64) *slot {
	for it := o.order.Front(); it != nil && i >= 0; it = it.Next() {
		if i == 0 {
			return it
		}
		i--
	}
	return nil
}

// InodeSymlink partially implements Inode interface for symlinks.
type InodeSymlink struct {
	InodeNotDirectory
}

// Open implements Inode.Open.
func (InodeSymlink) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, syserror.ELOOP
}

// StaticDirectory is a standard implementation of a directory with static
// contents.
//
// +stateify savable
type StaticDirectory struct {
	InodeAttrs
	InodeDirectoryNoNewChildren
	InodeNoDynamicLookup
	InodeNoStatFS
	InodeNotSymlink
	OrderedChildren
	StaticDirectoryRefs

	locks  vfs.FileLocks
	fdOpts GenericDirectoryFDOptions
}

var _ Inode = (*StaticDirectory)(nil)

// NewStaticDir creates a new static directory and returns its dentry.
func NewStaticDir(creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode, children map[string]*Dentry, fdOpts GenericDirectoryFDOptions) *Dentry {
	inode := &StaticDirectory{}
	inode.Init(creds, devMajor, devMinor, ino, perm, fdOpts)

	dentry := &Dentry{}
	dentry.Init(inode)

	inode.OrderedChildren.Init(OrderedChildrenOptions{})
	links := inode.OrderedChildren.Populate(dentry, children)
	inode.IncLinks(links)

	return dentry
}

// Init initializes StaticDirectory.
func (s *StaticDirectory) Init(creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode, fdOpts GenericDirectoryFDOptions) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("Only permission mask must be set: %x", perm&linux.PermissionsMask))
	}
	s.fdOpts = fdOpts
	s.InodeAttrs.Init(creds, devMajor, devMinor, ino, linux.ModeDirectory|perm)
}

// Open implements kernfs.Inode.
func (s *StaticDirectory) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := NewGenericDirectoryFD(rp.Mount(), vfsd, &s.OrderedChildren, &s.locks, &opts, s.fdOpts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// SetStat implements kernfs.Inode.SetStat not allowing inode attributes to be changed.
func (*StaticDirectory) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return syserror.EPERM
}

// DecRef implements kernfs.Inode.
func (s *StaticDirectory) DecRef(context.Context) {
	s.StaticDirectoryRefs.DecRef(s.Destroy)
}

// AlwaysValid partially implements kernfs.inodeDynamicLookup.
type AlwaysValid struct{}

// Valid implements kernfs.inodeDynamicLookup.
func (*AlwaysValid) Valid(context.Context) bool {
	return true
}

// InodeNoStatFS partially implements the Inode interface, where the client
// filesystem doesn't support statfs(2).
type InodeNoStatFS struct{}

// StatFS implements Inode.StatFS.
func (*InodeNoStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return linux.Statfs{}, syserror.ENOSYS
}
