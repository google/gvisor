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
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// InodeNoopRefCount partially implements the Inode interface, specifically the
// inodeRefs sub interface. InodeNoopRefCount implements a simple reference
// count for inodes, performing no extra actions when references are obtained or
// released. This is suitable for simple file inodes that don't reference any
// resources.
//
// +stateify savable
type InodeNoopRefCount struct {
	InodeTemporary
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
//
// +stateify savable
type InodeDirectoryNoNewChildren struct{}

// NewFile implements Inode.NewFile.
func (InodeDirectoryNoNewChildren) NewFile(context.Context, string, vfs.OpenOptions) (Inode, error) {
	return nil, linuxerr.EPERM
}

// NewDir implements Inode.NewDir.
func (InodeDirectoryNoNewChildren) NewDir(context.Context, string, vfs.MkdirOptions) (Inode, error) {
	return nil, linuxerr.EPERM
}

// NewLink implements Inode.NewLink.
func (InodeDirectoryNoNewChildren) NewLink(context.Context, string, Inode) (Inode, error) {
	return nil, linuxerr.EPERM
}

// NewSymlink implements Inode.NewSymlink.
func (InodeDirectoryNoNewChildren) NewSymlink(context.Context, string, string) (Inode, error) {
	return nil, linuxerr.EPERM
}

// NewNode implements Inode.NewNode.
func (InodeDirectoryNoNewChildren) NewNode(context.Context, string, vfs.MknodOptions) (Inode, error) {
	return nil, linuxerr.EPERM
}

// InodeNotDirectory partially implements the Inode interface, specifically the
// inodeDirectory and inodeDynamicDirectory sub interfaces. Inodes that do not
// represent directories can embed this to provide no-op implementations for
// directory-related functions.
//
// +stateify savable
type InodeNotDirectory struct {
	InodeAlwaysValid
}

// HasChildren implements Inode.HasChildren.
func (InodeNotDirectory) HasChildren() bool {
	return false
}

// NewFile implements Inode.NewFile.
func (InodeNotDirectory) NewFile(context.Context, string, vfs.OpenOptions) (Inode, error) {
	panic("NewFile called on non-directory inode")
}

// NewDir implements Inode.NewDir.
func (InodeNotDirectory) NewDir(context.Context, string, vfs.MkdirOptions) (Inode, error) {
	panic("NewDir called on non-directory inode")
}

// NewLink implements Inode.NewLinkink.
func (InodeNotDirectory) NewLink(context.Context, string, Inode) (Inode, error) {
	panic("NewLink called on non-directory inode")
}

// NewSymlink implements Inode.NewSymlink.
func (InodeNotDirectory) NewSymlink(context.Context, string, string) (Inode, error) {
	panic("NewSymlink called on non-directory inode")
}

// NewNode implements Inode.NewNode.
func (InodeNotDirectory) NewNode(context.Context, string, vfs.MknodOptions) (Inode, error) {
	panic("NewNode called on non-directory inode")
}

// Unlink implements Inode.Unlink.
func (InodeNotDirectory) Unlink(context.Context, string, Inode) error {
	panic("Unlink called on non-directory inode")
}

// RmDir implements Inode.RmDir.
func (InodeNotDirectory) RmDir(context.Context, string, Inode) error {
	panic("RmDir called on non-directory inode")
}

// Rename implements Inode.Rename.
func (InodeNotDirectory) Rename(context.Context, string, string, Inode, Inode) error {
	panic("Rename called on non-directory inode")
}

// Lookup implements Inode.Lookup.
func (InodeNotDirectory) Lookup(ctx context.Context, name string) (Inode, error) {
	panic("Lookup called on non-directory inode")
}

// IterDirents implements Inode.IterDirents.
func (InodeNotDirectory) IterDirents(ctx context.Context, mnt *vfs.Mount, callback vfs.IterDirentsCallback, offset, relOffset int64) (newOffset int64, err error) {
	panic("IterDirents called on non-directory inode")
}

// InodeNotSymlink partially implements the Inode interface, specifically the
// inodeSymlink sub interface. All inodes that are not symlinks may embed this
// to return the appropriate errors from symlink-related functions.
//
// +stateify savable
type InodeNotSymlink struct{}

// Readlink implements Inode.Readlink.
func (InodeNotSymlink) Readlink(context.Context, *vfs.Mount) (string, error) {
	return "", linuxerr.EINVAL
}

// Getlink implements Inode.Getlink.
func (InodeNotSymlink) Getlink(context.Context, *vfs.Mount) (vfs.VirtualDentry, string, error) {
	return vfs.VirtualDentry{}, "", linuxerr.EINVAL
}

// InodeAttrs partially implements the Inode interface, specifically the
// inodeMetadata sub interface. InodeAttrs provides functionality related to
// inode attributes.
//
// Must be initialized by Init prior to first use.
//
// +stateify savable
type InodeAttrs struct {
	devMajor  uint32
	devMinor  uint32
	ino       atomicbitops.Uint64
	mode      atomicbitops.Uint32
	uid       atomicbitops.Uint32
	gid       atomicbitops.Uint32
	nlink     atomicbitops.Uint32
	blockSize atomicbitops.Uint32

	// Timestamps, all nsecs from the Unix epoch.
	atime atomicbitops.Int64
	mtime atomicbitops.Int64
	ctime atomicbitops.Int64
}

// Init initializes this InodeAttrs.
func (a *InodeAttrs) Init(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, mode linux.FileMode) {
	if mode.FileType() == 0 {
		panic(fmt.Sprintf("No file type specified in 'mode' for InodeAttrs.Init(): mode=0%o", mode))
	}

	nlink := uint32(1)
	if mode.FileType() == linux.ModeDirectory {
		nlink = 2
	}
	a.devMajor = devMajor
	a.devMinor = devMinor
	a.ino.Store(ino)
	a.mode.Store(uint32(mode))
	a.uid.Store(uint32(creds.EffectiveKUID))
	a.gid.Store(uint32(creds.EffectiveKGID))
	a.nlink.Store(nlink)
	a.blockSize.Store(hostarch.PageSize)
	now := ktime.NowFromContext(ctx).Nanoseconds()
	a.atime.Store(now)
	a.mtime.Store(now)
	a.ctime.Store(now)
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
	return a.ino.Load()
}

// Mode implements Inode.Mode.
func (a *InodeAttrs) Mode() linux.FileMode {
	return linux.FileMode(a.mode.Load())
}

// Links returns the link count.
func (a *InodeAttrs) Links() uint32 {
	return a.nlink.Load()
}

// TouchAtime updates a.atime to the current time.
func (a *InodeAttrs) TouchAtime(ctx context.Context, mnt *vfs.Mount) {
	if mnt.Flags.NoATime || mnt.ReadOnly() {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	a.atime.Store(ktime.NowFromContext(ctx).Nanoseconds())
	mnt.EndWrite()
}

// TouchCMtime updates a.{c/m}time to the current time. The caller should
// synchronize calls to this so that ctime and mtime are updated to the same
// value.
func (a *InodeAttrs) TouchCMtime(ctx context.Context) {
	now := ktime.NowFromContext(ctx).Nanoseconds()
	a.mtime.Store(now)
	a.ctime.Store(now)
}

// Stat partially implements Inode.Stat. Note that this function doesn't provide
// all the stat fields, and the embedder should consider extending the result
// with filesystem-specific fields.
func (a *InodeAttrs) Stat(context.Context, *vfs.Filesystem, vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_NLINK | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME
	stat.DevMajor = a.devMajor
	stat.DevMinor = a.devMinor
	stat.Ino = a.ino.Load()
	stat.Mode = uint16(a.Mode())
	stat.UID = a.uid.Load()
	stat.GID = a.gid.Load()
	stat.Nlink = a.nlink.Load()
	stat.Blksize = a.blockSize.Load()
	stat.Atime = linux.NsecToStatxTimestamp(a.atime.Load())
	stat.Mtime = linux.NsecToStatxTimestamp(a.mtime.Load())
	stat.Ctime = linux.NsecToStatxTimestamp(a.ctime.Load())
	return stat, nil
}

// SetStat implements Inode.SetStat.
func (a *InodeAttrs) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}

	// Note that not all fields are modifiable. For example, the file type and
	// inode numbers are immutable after node creation. Setting the size is often
	// allowed by kernfs files but does not do anything. If some other behavior is
	// needed, the embedder should consider extending SetStat.
	if opts.Stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_SIZE) != 0 {
		return linuxerr.EPERM
	}
	if opts.Stat.Mask&linux.STATX_SIZE != 0 && a.Mode().IsDir() {
		return linuxerr.EISDIR
	}
	if err := vfs.CheckSetStat(ctx, creds, &opts, a.Mode(), auth.KUID(a.uid.Load()), auth.KGID(a.gid.Load())); err != nil {
		return err
	}

	clearSID := false
	stat := opts.Stat
	if stat.Mask&linux.STATX_UID != 0 {
		a.uid.Store(stat.UID)
		clearSID = true
	}
	if stat.Mask&linux.STATX_GID != 0 {
		a.gid.Store(stat.GID)
		clearSID = true
	}
	if stat.Mask&linux.STATX_MODE != 0 {
		for {
			old := a.mode.Load()
			ft := old & linux.S_IFMT
			newMode := ft | uint32(stat.Mode & ^uint16(linux.S_IFMT))
			if clearSID {
				newMode = vfs.ClearSUIDAndSGID(newMode)
			}
			if swapped := a.mode.CompareAndSwap(old, newMode); swapped {
				clearSID = false
				break
			}
		}
	}

	// We may have to clear the SUID/SGID bits, but didn't do so as part of
	// STATX_MODE.
	if clearSID {
		for {
			old := a.mode.Load()
			newMode := vfs.ClearSUIDAndSGID(old)
			if swapped := a.mode.CompareAndSwap(old, newMode); swapped {
				break
			}
		}
	}

	now := ktime.NowFromContext(ctx).Nanoseconds()
	if stat.Mask&linux.STATX_ATIME != 0 {
		if stat.Atime.Nsec == linux.UTIME_NOW {
			stat.Atime = linux.NsecToStatxTimestamp(now)
		}
		a.atime.Store(stat.Atime.ToNsec())
	}
	if stat.Mask&linux.STATX_MTIME != 0 {
		if stat.Mtime.Nsec == linux.UTIME_NOW {
			stat.Mtime = linux.NsecToStatxTimestamp(now)
		}
		a.mtime.Store(stat.Mtime.ToNsec())
	}

	return nil
}

// CheckPermissions implements Inode.CheckPermissions.
func (a *InodeAttrs) CheckPermissions(_ context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(
		creds,
		ats,
		a.Mode(),
		auth.KUID(a.uid.Load()),
		auth.KGID(a.gid.Load()),
	)
}

// IncLinks implements Inode.IncLinks.
func (a *InodeAttrs) IncLinks(n uint32) {
	if a.nlink.Add(n) <= n {
		panic("InodeLink.IncLinks called with no existing links")
	}
}

// DecLinks implements Inode.DecLinks.
func (a *InodeAttrs) DecLinks() {
	if nlink := a.nlink.Add(^uint32(0)); nlink == ^uint32(0) {
		// Negative overflow
		panic("Inode.DecLinks called at 0 links")
	}
}

// +stateify savable
type slot struct {
	name   string
	inode  Inode
	static bool
	slotEntry
}

// OrderedChildrenOptions contains initialization options for OrderedChildren.
//
// +stateify savable
type OrderedChildrenOptions struct {
	// Writable indicates whether vfs.FilesystemImpl methods implemented by
	// OrderedChildren may modify the tracked children. This applies to
	// operations related to rename, unlink and rmdir. If an OrderedChildren is
	// not writable, these operations all fail with EPERM.
	//
	// Note that writable users must implement the sticky bit (I_SVTX).
	Writable bool
}

// inodeWithOrderedChildren allows extraction of an OrderedChildren from an
// Inode implementation. A concrete type that both implements the Inode
// interface and embeds OrderedChildren will be castable to this interface, and
// we can get to the embedded OrderedChildren through the orderedChildren
// method.
type inodeWithOrderedChildren interface {
	Inode
	orderedChildren() *OrderedChildren
}

// OrderedChildren partially implements the Inode interface. OrderedChildren can
// be embedded in directory inodes to keep track of children in the
// directory, and can then be used to implement a generic directory FD -- see
// GenericDirectoryFD.
//
// OrderedChildren can represent a node in an Inode tree. The children inodes
// might be directories themselves using OrderedChildren; hence extending the
// tree. The parent inode (OrderedChildren user) holds a ref on all its static
// children. This lets the static inodes outlive their associated dentry.
// While the dentry might have to be regenerated via a Lookup() call, we can
// keep reusing the same static inode. These static children inodes are finally
// DecRef'd when this directory inode is being destroyed. This makes
// OrderedChildren suitable for static directory entries as well.
//
// Must be initialize with Init before first use.
//
// +stateify savable
type OrderedChildren struct {
	// Can children be modified by user syscalls? It set to false, interface
	// methods that would modify the children return EPERM. Immutable.
	writable bool

	mu    sync.RWMutex `state:"nosave"`
	order slotList
	set   map[string]*slot
}

// orderedChildren implements inodeWithOrderedChildren.orderedChildren.
func (o *OrderedChildren) orderedChildren() *OrderedChildren {
	return o
}

// Init initializes an OrderedChildren.
func (o *OrderedChildren) Init(opts OrderedChildrenOptions) {
	o.writable = opts.Writable
	o.set = make(map[string]*slot)
}

// Destroy clears the children stored in o. It should be called by structs
// embedding OrderedChildren upon destruction, i.e. when their reference count
// reaches zero.
func (o *OrderedChildren) Destroy(ctx context.Context) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// Drop the ref that o owns on the static inodes it holds.
	for _, s := range o.set {
		if s.static {
			s.inode.DecRef(ctx)
		}
	}
	o.order.Reset()
	o.set = nil
}

// Populate inserts static children into this OrderedChildren.
// Populate returns the number of directories inserted, which the caller
// may use to update the link count for the parent directory.
//
// Precondition:
//   - d must represent a directory inode.
//   - children must not contain any conflicting entries already in o.
//   - Caller must hold a reference on all inodes passed.
//
// Postcondition: Caller's references on inodes are transferred to o.
func (o *OrderedChildren) Populate(children map[string]Inode) uint32 {
	var links uint32
	for name, child := range children {
		if child.Mode().IsDir() {
			links++
		}
		if err := o.insert(name, child, true); err != nil {
			panic(fmt.Sprintf("Collision when attempting to insert child %q (%+v)", name, child))
		}
	}
	return links
}

// Lookup implements Inode.Lookup.
func (o *OrderedChildren) Lookup(ctx context.Context, name string) (Inode, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	s, ok := o.set[name]
	if !ok {
		return nil, linuxerr.ENOENT
	}

	s.inode.IncRef() // This ref is passed to the dentry upon creation via Init.
	return s.inode, nil
}

// ForEachChild calls fn on all childrens tracked by this ordered children.
func (o *OrderedChildren) ForEachChild(fn func(string, Inode)) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	for name, slot := range o.set {
		fn(name, slot.inode)
	}
}

// IterDirents implements Inode.IterDirents.
func (o *OrderedChildren) IterDirents(ctx context.Context, mnt *vfs.Mount, cb vfs.IterDirentsCallback, offset, relOffset int64) (newOffset int64, err error) {
	// All entries from OrderedChildren have already been handled in
	// GenericDirectoryFD.IterDirents.
	return offset, nil
}

// HasChildren implements Inode.HasChildren.
func (o *OrderedChildren) HasChildren() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.set) > 0
}

// Insert inserts a dynamic child into o. This ignores the writability of o, as
// this is not part of the vfs.FilesystemImpl interface, and is a lower-level operation.
func (o *OrderedChildren) Insert(name string, child Inode) error {
	return o.insert(name, child, false)
}

// Inserter is like Insert, but obtains the child to insert by calling
// makeChild. makeChild is only called if the insert will succeed. This allows
// the caller to atomically check and insert a child without having to
// clean up the child on failure.
func (o *OrderedChildren) Inserter(name string, makeChild func() Inode) (Inode, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.set[name]; ok {
		return nil, linuxerr.EEXIST
	}

	// Note: We must not fail after we call makeChild().

	child := makeChild()
	s := &slot{
		name:   name,
		inode:  child,
		static: false,
	}
	o.order.PushBack(s)
	o.set[name] = s
	return child, nil
}

// insert inserts child into o.
//
// Precondition: Caller must be holding a ref on child if static is true.
//
// Postcondition: Caller's ref on child is transferred to o if static is true.
func (o *OrderedChildren) insert(name string, child Inode, static bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.set[name]; ok {
		return linuxerr.EEXIST
	}
	s := &slot{
		name:   name,
		inode:  child,
		static: static,
	}
	o.order.PushBack(s)
	o.set[name] = s
	return nil
}

// Precondition: caller must hold o.mu for writing.
func (o *OrderedChildren) removeLocked(name string) {
	if s, ok := o.set[name]; ok {
		if s.static {
			panic(fmt.Sprintf("removeLocked called on a static inode: %v", s.inode))
		}
		delete(o.set, name)
		o.order.Remove(s)
	}
}

// Precondition: caller must hold o.mu for reading or writing.
func (o *OrderedChildren) checkExistingLocked(name string, child Inode) error {
	s, ok := o.set[name]
	if !ok {
		return linuxerr.ENOENT
	}
	if s.inode != child {
		panic(fmt.Sprintf("Inode doesn't match what kernfs thinks! Name: %q, OrderedChild: %p, kernfs: %p", name, s.inode, child))
	}
	return nil
}

// Unlink implements Inode.Unlink.
func (o *OrderedChildren) Unlink(ctx context.Context, name string, child Inode) error {
	if !o.writable {
		return linuxerr.EPERM
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkExistingLocked(name, child); err != nil {
		return err
	}

	o.removeLocked(name)
	return nil
}

// RmDir implements Inode.RmDir.
func (o *OrderedChildren) RmDir(ctx context.Context, name string, child Inode) error {
	// We're not responsible for checking that child is a directory, that it's
	// empty, or updating any link counts; so this is the same as unlink.
	return o.Unlink(ctx, name, child)
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
func (o *OrderedChildren) Rename(ctx context.Context, oldname, newname string, child, dstDir Inode) error {
	if !o.writable {
		return linuxerr.EPERM
	}
	dstIOC, ok := dstDir.(inodeWithOrderedChildren)
	if !ok {
		return linuxerr.EXDEV
	}
	dst := dstIOC.orderedChildren()
	if !dst.writable {
		return linuxerr.EPERM
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

	// Ensure target inode exists in src.
	if err := o.checkExistingLocked(oldname, child); err != nil {
		return err
	}

	// Ensure no name collision in dst.
	if _, ok := dst.set[newname]; ok {
		return linuxerr.EEXIST
	}

	// Remove from src.
	o.removeLocked(oldname)

	// Add to dst.
	s := &slot{
		name:  newname,
		inode: child,
	}
	dst.order.PushBack(s)
	dst.set[newname] = s

	return nil
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
//
// +stateify savable
type InodeSymlink struct {
	InodeNotDirectory
}

// Open implements Inode.Open.
func (InodeSymlink) Open(ctx context.Context, rp *vfs.ResolvingPath, d *Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, linuxerr.ELOOP
}

// StaticDirectory is a standard implementation of a directory with static
// contents.
//
// +stateify savable
type StaticDirectory struct {
	InodeAlwaysValid
	InodeAttrs
	InodeDirectoryNoNewChildren
	InodeNoStatFS
	InodeNotSymlink
	InodeTemporary
	InodeWatches
	OrderedChildren
	StaticDirectoryRefs

	locks  vfs.FileLocks
	fdOpts GenericDirectoryFDOptions
}

var _ Inode = (*StaticDirectory)(nil)

// NewStaticDir creates a new static directory and returns its dentry.
func NewStaticDir(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode, children map[string]Inode, fdOpts GenericDirectoryFDOptions) Inode {
	inode := &StaticDirectory{}
	inode.Init(ctx, creds, devMajor, devMinor, ino, perm, fdOpts)
	inode.InitRefs()

	inode.OrderedChildren.Init(OrderedChildrenOptions{})
	links := inode.OrderedChildren.Populate(children)
	inode.IncLinks(links)

	return inode
}

// Init initializes StaticDirectory.
func (s *StaticDirectory) Init(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode, fdOpts GenericDirectoryFDOptions) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("Only permission mask must be set: %x", perm&linux.PermissionsMask))
	}
	s.fdOpts = fdOpts
	s.InodeAttrs.Init(ctx, creds, devMajor, devMinor, ino, linux.ModeDirectory|perm)
}

// Open implements Inode.Open.
func (s *StaticDirectory) Open(ctx context.Context, rp *vfs.ResolvingPath, d *Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := NewGenericDirectoryFD(rp.Mount(), d, &s.OrderedChildren, &s.locks, &opts, s.fdOpts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// SetStat implements Inode.SetStat not allowing inode attributes to be changed.
func (*StaticDirectory) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// DecRef implements Inode.DecRef.
func (s *StaticDirectory) DecRef(ctx context.Context) {
	s.StaticDirectoryRefs.DecRef(func() { s.Destroy(ctx) })
}

// InodeAlwaysValid partially implements Inode.
//
// +stateify savable
type InodeAlwaysValid struct{}

// Valid implements Inode.Valid.
func (*InodeAlwaysValid) Valid(context.Context) bool {
	return true
}

// InodeTemporary partially implements Inode.
//
// +stateify savable
type InodeTemporary struct{}

// Keep implements Inode.Keep.
func (*InodeTemporary) Keep() bool {
	return false
}

// InodeNoStatFS partially implements the Inode interface, where the client
// filesystem doesn't support statfs(2).
//
// +stateify savable
type InodeNoStatFS struct{}

// StatFS implements Inode.StatFS.
func (*InodeNoStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return linux.Statfs{}, linuxerr.ENOSYS
}

// InodeWatches partially implements Inode.
//
// +stateify savable
type InodeWatches struct {
	watches vfs.Watches
}

// Watches implements Inode.Watches.
func (i *InodeWatches) Watches() *vfs.Watches {
	return &i.watches
}
