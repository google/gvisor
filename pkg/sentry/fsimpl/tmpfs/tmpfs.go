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

// Package tmpfs provides an in-memory filesystem whose contents are
// application-mutable, consistent with Linux's tmpfs.
//
// Lock order:
//
//	filesystem.mu
//		inode.mu
//		  regularFileFD.offMu
//		    *** "memmap.Mappable locks" below this point
//		    regularFile.mapsMu
//		      *** "memmap.Mappable locks taken by Translate" below this point
//		      regularFile.dataMu
//		        fs.pagesUsedMu
//		  directory.iterMu
package tmpfs

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs/memxattr"
)

// Name is the default filesystem name.
const Name = "tmpfs"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	vfsfs vfs.Filesystem

	// mfp is used to allocate memory that stores regular file contents. mfp is
	// immutable.
	mfp pgalloc.MemoryFileProvider

	// clock is a realtime clock used to set timestamps in file operations.
	clock time.Clock

	// devMinor is the filesystem's minor device number. devMinor is immutable.
	devMinor uint32

	// mopts contains the tmpfs-specific mount options passed to this
	// filesystem. Immutable.
	mopts string

	// usage is the memory accounting category under which pages backing
	// files in this filesystem are accounted.
	usage usage.MemoryKind

	// mu serializes changes to the Dentry tree.
	mu filesystemRWMutex `state:"nosave"`

	nextInoMinusOne atomicbitops.Uint64 // accessed using atomic memory operations

	root *dentry

	maxFilenameLen int

	// maxSizeInPages is the maximum permissible size for the tmpfs in terms of pages.
	// This field is immutable.
	maxSizeInPages uint64

	// pagesUsed is the number of pages used by this filesystem.
	pagesUsed atomicbitops.Uint64
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// FilesystemOpts is used to pass configuration data to tmpfs.
//
// +stateify savable
type FilesystemOpts struct {
	// RootFileType is the FileType of the filesystem root. Valid values
	// are: S_IFDIR, S_IFREG, and S_IFLNK. Defaults to S_IFDIR.
	RootFileType uint16

	// RootSymlinkTarget is the target of the root symlink. Only valid if
	// RootFileType == S_IFLNK.
	RootSymlinkTarget string

	// FilesystemType allows setting a different FilesystemType for this
	// tmpfs filesystem. This allows tmpfs to "impersonate" other
	// filesystems, like ramdiskfs and cgroupfs.
	FilesystemType vfs.FilesystemType

	// Usage is the memory accounting category under which pages backing files in
	// the filesystem are accounted.
	Usage *usage.MemoryKind

	// MaxFilenameLen is the maximum filename length allowed by the tmpfs.
	MaxFilenameLen int

	// Filestore is the MemoryFile that will be used to store file data. If this
	// is nil, then MemoryFileProviderFromContext() is used.
	Filestore *pgalloc.MemoryFile
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, _ string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic("MemoryFileProviderFromContext returned nil")
	}

	rootFileType := uint16(linux.S_IFDIR)
	newFSType := vfs.FilesystemType(&fstype)
	tmpfsOpts, tmpfsOptsOk := opts.InternalData.(FilesystemOpts)
	if tmpfsOptsOk {
		if tmpfsOpts.RootFileType != 0 {
			rootFileType = tmpfsOpts.RootFileType
		}
		if tmpfsOpts.FilesystemType != nil {
			newFSType = tmpfsOpts.FilesystemType
		}
		if tmpfsOpts.Filestore != nil {
			mfp = tmpfsOpts.Filestore
		}
	}

	mopts := vfs.GenericParseMountOptions(opts.Data)
	rootMode := linux.FileMode(0777)
	if rootFileType == linux.S_IFDIR {
		rootMode = 01777
	}
	modeStr, ok := mopts["mode"]
	if ok {
		delete(mopts, "mode")
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: invalid mode: %q", modeStr)
			return nil, nil, linuxerr.EINVAL
		}
		rootMode = linux.FileMode(mode & 07777)
	}
	rootKUID := creds.EffectiveKUID
	uidStr, ok := mopts["uid"]
	if ok {
		delete(mopts, "uid")
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: invalid uid: %q", uidStr)
			return nil, nil, linuxerr.EINVAL
		}
		kuid := creds.UserNamespace.MapToKUID(auth.UID(uid))
		if !kuid.Ok() {
			ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: unmapped uid: %d", uid)
			return nil, nil, linuxerr.EINVAL
		}
		rootKUID = kuid
	}
	rootKGID := creds.EffectiveKGID
	gidStr, ok := mopts["gid"]
	if ok {
		delete(mopts, "gid")
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: invalid gid: %q", gidStr)
			return nil, nil, linuxerr.EINVAL
		}
		kgid := creds.UserNamespace.MapToKGID(auth.GID(gid))
		if !kgid.Ok() {
			ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: unmapped gid: %d", gid)
			return nil, nil, linuxerr.EINVAL
		}
		rootKGID = kgid
	}
	// In Linux, the default size limit is set to 50% of physical RAM. Such a
	// default is not suitable in gVisor, because we don't want to reveal the
	// host's RAM size. If Linux tmpfs is mounted with no size option, then
	// statfs(2) returns f_blocks == f_bfree == f_bavail == 0.
	// However, many applications treat this as having a size limit
	// of 0. To work around these, set a very large but non-zero default size
	// limit, chosen to ensure that BlockSize * Blocks does not overflow int64
	// (which applications may also handle incorrectly).
	maxSizeInPages := uint64(math.MaxInt64 / hostarch.PageSize)
	maxSizeStr, ok := mopts["size"]
	if ok {
		delete(mopts, "size")
		maxSizeInBytes, err := parseSize(maxSizeStr)
		if err != nil {
			ctx.Debugf("tmpfs.FilesystemType.GetFilesystem: parseSize() failed: %v", err)
			return nil, nil, linuxerr.EINVAL
		}
		// Convert size in bytes to nearest Page Size bytes
		// as Linux allocates memory in terms of Page size.
		maxSizeInPages, ok = hostarch.ToPages(maxSizeInBytes)
		if !ok {
			ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: Pages RoundUp Overflow error: %q", ok)
			return nil, nil, linuxerr.EINVAL
		}
	}

	if len(mopts) != 0 {
		ctx.Warningf("tmpfs.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, linuxerr.EINVAL
	}

	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	clock := time.RealtimeClockFromContext(ctx)
	memUsage := usage.Tmpfs
	if tmpfsOpts.Usage != nil {
		memUsage = *tmpfsOpts.Usage
	}
	fs := filesystem{
		mfp:            mfp,
		clock:          clock,
		devMinor:       devMinor,
		mopts:          opts.Data,
		usage:          memUsage,
		maxFilenameLen: linux.NAME_MAX,
		maxSizeInPages: maxSizeInPages,
	}
	fs.vfsfs.Init(vfsObj, newFSType, &fs)
	if tmpfsOptsOk && tmpfsOpts.MaxFilenameLen > 0 {
		fs.maxFilenameLen = tmpfsOpts.MaxFilenameLen
	}

	var root *dentry
	switch rootFileType {
	case linux.S_IFREG:
		root = fs.newDentry(fs.newRegularFile(rootKUID, rootKGID, rootMode, nil /* parentDir */))
	case linux.S_IFLNK:
		root = fs.newDentry(fs.newSymlink(rootKUID, rootKGID, rootMode, tmpfsOpts.RootSymlinkTarget, nil /* parentDir */))
	case linux.S_IFDIR:
		root = &fs.newDirectory(rootKUID, rootKGID, rootMode, nil /* parentDir */).dentry
	default:
		fs.vfsfs.DecRef(ctx)
		return nil, nil, fmt.Errorf("invalid tmpfs root file type: %#o", rootFileType)
	}
	fs.root = root
	return &fs.vfsfs, &root.vfsd, nil
}

// NewFilesystem returns a new tmpfs filesystem.
func NewFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (*vfs.Filesystem, *vfs.Dentry, error) {
	return FilesystemType{}.GetFilesystem(ctx, vfsObj, creds, "", vfs.GetFilesystemOptions{})
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.mu.Lock()
	if fs.root.inode.isDir() {
		fs.root.releaseChildrenLocked(ctx)
	}
	fs.mu.Unlock()
}

// releaseChildrenLocked is called on the mount point by filesystem.Release() to
// destroy all objects in the mount. It performs a depth-first walk of the
// filesystem and "unlinks" everything by decrementing link counts
// appropriately. There should be no open file descriptors when this is called,
// so each inode should only have one outstanding reference that is removed once
// its link count hits zero.
//
// Note that we do not update filesystem state precisely while tearing down (for
// instance, the child maps are ignored)--we only care to remove all remaining
// references so that every filesystem object gets destroyed. Also note that we
// do not need to trigger DecRef on the mount point itself or any child mount;
// these are taken care of by the destructor of the enclosing MountNamespace.
//
// Precondition: filesystem.mu is held.
func (d *dentry) releaseChildrenLocked(ctx context.Context) {
	dir := d.inode.impl.(*directory)
	for _, child := range dir.childMap {
		if child.inode.isDir() {
			child.releaseChildrenLocked(ctx)
			child.inode.decLinksLocked(ctx) // link for child/.
			dir.inode.decLinksLocked(ctx)   // link for child/..
		}
		child.inode.decLinksLocked(ctx) // link for child
	}
}

func (fs *filesystem) statFS() linux.Statfs {
	st := linux.Statfs{
		Type:         linux.TMPFS_MAGIC,
		BlockSize:    hostarch.PageSize,
		FragmentSize: hostarch.PageSize,
		NameLength:   linux.NAME_MAX,
	}

	// If size is set for tmpfs return set values.
	st.Blocks = fs.maxSizeInPages
	pagesUsed := fs.pagesUsed.Load()
	st.BlocksFree = fs.maxSizeInPages - pagesUsed
	st.BlocksAvailable = fs.maxSizeInPages - pagesUsed
	return st
}

// dentry implements vfs.DentryImpl.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	// parent is this dentry's parent directory. Each referenced dentry holds a
	// reference on parent.dentry. If this dentry is a filesystem root, parent
	// is nil. parent is protected by filesystem.mu.
	parent *dentry

	// name is the name of this dentry in its parent. If this dentry is a
	// filesystem root, name is the empty string. name is protected by
	// filesystem.mu.
	name string

	// dentryEntry (ugh) links dentries into their parent directory.childList.
	dentryEntry

	// inode is the inode represented by this dentry. Multiple Dentries may
	// share a single non-directory inode (with hard links). inode is
	// immutable.
	//
	// tmpfs doesn't count references on dentries; because the dentry tree is
	// the sole source of truth, it is by definition always consistent with the
	// state of the filesystem. However, it does count references on inodes,
	// because inode resources are released when all references are dropped.
	// dentry therefore forwards reference counting directly to inode.
	inode *inode
}

func (fs *filesystem) newDentry(inode *inode) *dentry {
	d := &dentry{
		inode: inode,
	}
	d.vfsd.Init(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	d.inode.incRef()
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	return d.inode.tryIncRef()
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(ctx context.Context) {
	d.inode.decRef(ctx)
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if d.inode.isDir() {
		events |= linux.IN_ISDIR
	}

	// tmpfs never calls VFS.InvalidateDentry(), so d.vfsd.IsDead() indicates
	// that d was deleted.
	deleted := d.vfsd.IsDead()

	d.inode.fs.mu.RLock()
	// The ordering below is important, Linux always notifies the parent first.
	if d.parent != nil {
		d.parent.inode.watches.Notify(ctx, d.name, events, cookie, et, deleted)
	}
	d.inode.watches.Notify(ctx, "", events, cookie, et, deleted)
	d.inode.fs.mu.RUnlock()
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.inode.watches
}

// OnZeroWatches implements vfs.Dentry.OnZeroWatches.
func (d *dentry) OnZeroWatches(context.Context) {}

// inode represents a filesystem object.
//
// +stateify savable
type inode struct {
	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// A reference is held on all inodes as long as they are reachable in the
	// filesystem tree, i.e. nlink is nonzero. This reference is dropped when
	// nlink reaches 0.
	refs inodeRefs

	// xattrs implements extended attributes.
	//
	// TODO(b/148380782): Support xattrs other than user.*
	xattrs memxattr.SimpleExtendedAttributes

	// Inode metadata. Writing multiple fields atomically requires holding
	// mu, othewise atomic operations can be used.
	mu    inodeMutex          `state:"nosave"`
	mode  atomicbitops.Uint32 // file type and mode
	nlink atomicbitops.Uint32 // protected by filesystem.mu instead of inode.mu
	uid   atomicbitops.Uint32 // auth.KUID, but stored as raw uint32 for sync/atomic
	gid   atomicbitops.Uint32 // auth.KGID, but ...
	ino   uint64              // immutable

	// Linux's tmpfs has no concept of btime.
	atime atomicbitops.Int64 // nanoseconds
	ctime atomicbitops.Int64 // nanoseconds
	mtime atomicbitops.Int64 // nanoseconds

	locks vfs.FileLocks

	// Inotify watches for this inode.
	watches vfs.Watches

	impl any // immutable
}

const maxLinks = math.MaxUint32

func (i *inode) init(impl any, fs *filesystem, kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, parentDir *directory) {
	if mode.FileType() == 0 {
		panic("file type is required in FileMode")
	}

	// Inherit the group and setgid bit as in fs/inode.c:inode_init_owner().
	if parentDir != nil && parentDir.inode.mode.Load()&linux.S_ISGID == linux.S_ISGID {
		kgid = auth.KGID(parentDir.inode.gid.Load())
		if mode&linux.S_IFDIR == linux.S_IFDIR {
			mode |= linux.S_ISGID
		}
	}

	i.fs = fs
	i.mode = atomicbitops.FromUint32(uint32(mode))
	i.uid = atomicbitops.FromUint32(uint32(kuid))
	i.gid = atomicbitops.FromUint32(uint32(kgid))
	i.ino = fs.nextInoMinusOne.Add(1)
	// Tmpfs creation sets atime, ctime, and mtime to current time.
	now := fs.clock.Now().Nanoseconds()
	i.atime = atomicbitops.FromInt64(now)
	i.ctime = atomicbitops.FromInt64(now)
	i.mtime = atomicbitops.FromInt64(now)
	// i.nlink initialized by caller
	i.impl = impl
	i.refs.InitRefs()
}

// incLinksLocked increments i's link count.
//
// Preconditions:
//   - filesystem.mu must be locked for writing.
//   - i.mu must be lcoked.
//   - i.nlink != 0.
//   - i.nlink < maxLinks.
func (i *inode) incLinksLocked() {
	if i.nlink.RacyLoad() == 0 {
		panic("tmpfs.inode.incLinksLocked() called with no existing links")
	}
	if i.nlink.RacyLoad() == maxLinks {
		panic("tmpfs.inode.incLinksLocked() called with maximum link count")
	}
	i.nlink.Add(1)
}

// decLinksLocked decrements i's link count. If the link count reaches 0, we
// remove a reference on i as well.
//
// Preconditions:
//   - filesystem.mu must be locked for writing.
//   - i.mu must be lcoked.
//   - i.nlink != 0.
func (i *inode) decLinksLocked(ctx context.Context) {
	if i.nlink.RacyLoad() == 0 {
		panic("tmpfs.inode.decLinksLocked() called with no existing links")
	}
	if i.nlink.Add(^uint32(0)) == 0 {
		i.decRef(ctx)
	}
}

func (i *inode) incRef() {
	i.refs.IncRef()
}

func (i *inode) tryIncRef() bool {
	return i.refs.TryIncRef()
}

func (i *inode) decRef(ctx context.Context) {
	i.refs.DecRef(func() {
		i.watches.HandleDeletion(ctx)
		// Remove pages used if child being removed is a SymLink or Regular File.
		switch impl := i.impl.(type) {
		case *symlink:
			if len(impl.target) >= shortSymlinkLen {
				impl.inode.fs.unaccountPages(1)
			}
		case *regularFile:
			// Release memory used by regFile to store data. Since regFile is
			// no longer usable, we don't need to grab any locks or update any
			// metadata.
			pagesDec := impl.data.DropAll(impl.memFile)
			impl.inode.fs.unaccountPages(pagesDec)
		}

	})
}

func (i *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	mode := linux.FileMode(i.mode.Load())
	return vfs.GenericCheckPermissions(creds, ats, mode, auth.KUID(i.uid.Load()), auth.KGID(i.gid.Load()))
}

// Go won't inline this function, and returning linux.Statx (which is quite
// big) means spending a lot of time in runtime.duffcopy(), so instead it's an
// output parameter.
//
// Note that Linux does not guarantee to return consistent data (in the case of
// a concurrent modification), so we do not require holding inode.mu.
func (i *inode) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK |
		linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_SIZE |
		linux.STATX_BLOCKS | linux.STATX_ATIME | linux.STATX_CTIME |
		linux.STATX_MTIME
	stat.Blksize = hostarch.PageSize
	stat.Nlink = i.nlink.Load()
	stat.UID = i.uid.Load()
	stat.GID = i.gid.Load()
	stat.Mode = uint16(i.mode.Load())
	stat.Ino = i.ino
	stat.Atime = linux.NsecToStatxTimestamp(i.atime.Load())
	stat.Ctime = linux.NsecToStatxTimestamp(i.ctime.Load())
	stat.Mtime = linux.NsecToStatxTimestamp(i.mtime.Load())
	stat.DevMajor = linux.UNNAMED_MAJOR
	stat.DevMinor = i.fs.devMinor
	switch impl := i.impl.(type) {
	case *regularFile:
		stat.Mask |= linux.STATX_SIZE | linux.STATX_BLOCKS
		stat.Size = uint64(impl.size.Load())
		// TODO(jamieliu): This should be impl.data.Span() / 512, but this is
		// too expensive to compute here. Cache it in regularFile.
		stat.Blocks = allocatedBlocksForSize(stat.Size)
	case *directory:
		stat.Size = direntSize * (2 + uint64(impl.numChildren.Load()))
		// stat.Blocks is 0.
	case *symlink:
		stat.Size = uint64(len(impl.target))
		// stat.Blocks is 0.
	case *namedPipe, *socketFile:
		// stat.Size and stat.Blocks are 0.
	case *deviceFile:
		// stat.Size and stat.Blocks are 0.
		stat.RdevMajor = impl.major
		stat.RdevMinor = impl.minor
	default:
		panic(fmt.Sprintf("unknown inode type: %T", i.impl))
	}
}

func (i *inode) setStat(ctx context.Context, creds *auth.Credentials, opts *vfs.SetStatOptions) error {
	stat := &opts.Stat
	if stat.Mask == 0 {
		return nil
	}
	if stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_CTIME|linux.STATX_SIZE) != 0 {
		return linuxerr.EPERM
	}
	mode := linux.FileMode(i.mode.Load())
	if err := vfs.CheckSetStat(ctx, creds, opts, mode, auth.KUID(i.uid.Load()), auth.KGID(i.gid.Load())); err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	var (
		needsMtimeBump bool
		needsCtimeBump bool
	)
	clearSID := false
	mask := stat.Mask
	if mask&linux.STATX_SIZE != 0 {
		switch impl := i.impl.(type) {
		case *regularFile:
			updated, err := impl.truncateLocked(stat.Size)
			if err != nil {
				return err
			}
			if updated {
				clearSID = true
				needsMtimeBump = true
				needsCtimeBump = true
			}
		case *directory:
			return linuxerr.EISDIR
		default:
			return linuxerr.EINVAL
		}
	}
	if mask&linux.STATX_UID != 0 {
		i.uid.Store(stat.UID)
		needsCtimeBump = true
		clearSID = true
	}
	if mask&linux.STATX_GID != 0 {
		i.gid.Store(stat.GID)
		needsCtimeBump = true
		clearSID = true
	}
	if mask&linux.STATX_MODE != 0 {
		for {
			old := i.mode.Load()
			ft := old & linux.S_IFMT
			newMode := ft | uint32(stat.Mode & ^uint16(linux.S_IFMT))
			if clearSID {
				newMode = vfs.ClearSUIDAndSGID(newMode)
			}
			if swapped := i.mode.CompareAndSwap(old, newMode); swapped {
				clearSID = false
				break
			}
		}
		needsCtimeBump = true
	}
	now := i.fs.clock.Now().Nanoseconds()
	if mask&linux.STATX_ATIME != 0 {
		if stat.Atime.Nsec == linux.UTIME_NOW {
			i.atime.Store(now)
		} else {
			i.atime.Store(stat.Atime.ToNsecCapped())
		}
		needsCtimeBump = true
	}
	if mask&linux.STATX_MTIME != 0 {
		if stat.Mtime.Nsec == linux.UTIME_NOW {
			i.mtime.Store(now)
		} else {
			i.mtime.Store(stat.Mtime.ToNsecCapped())
		}
		needsCtimeBump = true
		// Ignore the mtime bump, since we just set it ourselves.
		needsMtimeBump = false
	}
	if mask&linux.STATX_CTIME != 0 {
		if stat.Ctime.Nsec == linux.UTIME_NOW {
			i.ctime.Store(now)
		} else {
			i.ctime.Store(stat.Ctime.ToNsecCapped())
		}
		// Ignore the ctime bump, since we just set it ourselves.
		needsCtimeBump = false
	}

	// We may have to clear the SUID/SGID bits, but didn't do so as part of
	// STATX_MODE.
	if clearSID {
		for {
			old := i.mode.Load()
			newMode := vfs.ClearSUIDAndSGID(old)
			if swapped := i.mode.CompareAndSwap(old, newMode); swapped {
				break
			}
		}
		needsCtimeBump = true
	}

	if needsMtimeBump {
		i.mtime.Store(now)
	}
	if needsCtimeBump {
		i.ctime.Store(now)
	}

	return nil
}

// allocatedBlocksForSize returns the number of 512B blocks needed to
// accommodate the given size in bytes, as appropriate for struct
// stat::st_blocks and struct statx::stx_blocks. (Note that this 512B block
// size is independent of the "preferred block size for I/O", struct
// stat::st_blksize and struct statx::stx_blksize.)
func allocatedBlocksForSize(size uint64) uint64 {
	return (size + 511) / 512
}

func (i *inode) direntType() uint8 {
	switch impl := i.impl.(type) {
	case *regularFile:
		return linux.DT_REG
	case *directory:
		return linux.DT_DIR
	case *symlink:
		return linux.DT_LNK
	case *socketFile:
		return linux.DT_SOCK
	case *namedPipe:
		return linux.DT_FIFO
	case *deviceFile:
		switch impl.kind {
		case vfs.BlockDevice:
			return linux.DT_BLK
		case vfs.CharDevice:
			return linux.DT_CHR
		default:
			panic(fmt.Sprintf("unknown vfs.DeviceKind: %v", impl.kind))
		}
	default:
		panic(fmt.Sprintf("unknown inode type: %T", i.impl))
	}
}

func (i *inode) isDir() bool {
	mode := linux.FileMode(i.mode.Load())
	return mode.FileType() == linux.S_IFDIR
}

func (i *inode) touchAtime(mnt *vfs.Mount) {
	if mnt.Flags.NoATime {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	now := i.fs.clock.Now().Nanoseconds()
	i.mu.Lock()
	i.atime.Store(now)
	i.mu.Unlock()
	mnt.EndWrite()
}

// Preconditions: The caller has called vfs.Mount.CheckBeginWrite().
func (i *inode) touchCtime() {
	now := i.fs.clock.Now().Nanoseconds()
	i.mu.Lock()
	i.ctime.Store(now)
	i.mu.Unlock()
}

// Preconditions: The caller has called vfs.Mount.CheckBeginWrite().
func (i *inode) touchCMtime() {
	now := i.fs.clock.Now().Nanoseconds()
	i.mu.Lock()
	i.mtime.Store(now)
	i.ctime.Store(now)
	i.mu.Unlock()
}

// Preconditions:
//   - The caller has called vfs.Mount.CheckBeginWrite().
//   - inode.mu must be locked.
func (i *inode) touchCMtimeLocked() {
	now := i.fs.clock.Now().Nanoseconds()
	i.mtime.Store(now)
	i.ctime.Store(now)
}

func checkXattrName(name string) error {
	// Linux's tmpfs supports "security" and "trusted" xattr namespaces, and
	// (depending on build configuration) POSIX ACL xattr namespaces
	// ("system.posix_acl_access" and "system.posix_acl_default"). We don't
	// support POSIX ACLs or the "security" namespace (b/148380782).
	if strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
		return nil
	}
	// We support the "user" namespace because we have tests that depend on
	// this feature.
	if strings.HasPrefix(name, linux.XATTR_USER_PREFIX) {
		return nil
	}
	return linuxerr.EOPNOTSUPP
}

func (i *inode) listXattr(creds *auth.Credentials, size uint64) ([]string, error) {
	return i.xattrs.ListXattr(creds, size)
}

func (i *inode) getXattr(creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	if err := checkXattrName(opts.Name); err != nil {
		return "", err
	}
	mode := linux.FileMode(i.mode.Load())
	kuid := auth.KUID(i.uid.Load())
	kgid := auth.KGID(i.gid.Load())
	if err := vfs.GenericCheckPermissions(creds, vfs.MayRead, mode, kuid, kgid); err != nil {
		return "", err
	}
	return i.xattrs.GetXattr(creds, mode, kuid, opts)
}

func (i *inode) setXattr(creds *auth.Credentials, opts *vfs.SetXattrOptions) error {
	if err := checkXattrName(opts.Name); err != nil {
		return err
	}
	mode := linux.FileMode(i.mode.Load())
	kuid := auth.KUID(i.uid.Load())
	kgid := auth.KGID(i.gid.Load())
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, kuid, kgid); err != nil {
		return err
	}
	return i.xattrs.SetXattr(creds, mode, kuid, opts)
}

func (i *inode) removeXattr(creds *auth.Credentials, name string) error {
	if err := checkXattrName(name); err != nil {
		return err
	}
	mode := linux.FileMode(i.mode.Load())
	kuid := auth.KUID(i.uid.Load())
	kgid := auth.KGID(i.gid.Load())
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, kuid, kgid); err != nil {
		return err
	}
	return i.xattrs.RemoveXattr(creds, mode, kuid, name)
}

// fileDescription is embedded by tmpfs implementations of
// vfs.FileDescriptionImpl.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD
}

func (fd *fileDescription) filesystem() *filesystem {
	return fd.vfsfd.Mount().Filesystem().Impl().(*filesystem)
}

func (fd *fileDescription) dentry() *dentry {
	return fd.vfsfd.Dentry().Impl().(*dentry)
}

func (fd *fileDescription) inode() *inode {
	return fd.dentry().inode
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	fd.inode().statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	return fd.dentry().inode.setStat(ctx, auth.CredentialsFromContext(ctx), &opts)
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.filesystem().statFS(), nil
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *fileDescription) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.inode().listXattr(auth.CredentialsFromContext(ctx), size)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *fileDescription) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.inode().getXattr(auth.CredentialsFromContext(ctx), &opts)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *fileDescription) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	return fd.dentry().inode.setXattr(auth.CredentialsFromContext(ctx), &opts)
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *fileDescription) RemoveXattr(ctx context.Context, name string) error {
	return fd.dentry().inode.removeXattr(auth.CredentialsFromContext(ctx), name)
}

// Sync implements vfs.FileDescriptionImpl.Sync. It does nothing because all
// filesystem state is in-memory.
func (*fileDescription) Sync(context.Context) error {
	return nil
}

// parseSize converts size in string to an integer bytes.
// Supported suffixes in string are:K, M, G, T, P, E.
func parseSize(s string) (uint64, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("size parameter empty")
	}
	suffix := s[len(s)-1]
	count := 1
	switch suffix {
	case 'e', 'E':
		count = count << 10
		fallthrough
	case 'p', 'P':
		count = count << 10
		fallthrough
	case 't', 'T':
		count = count << 10
		fallthrough
	case 'g', 'G':
		count = count << 10
		fallthrough
	case 'm', 'M':
		count = count << 10
		fallthrough
	case 'k', 'K':
		count = count << 10
		s = s[:len(s)-1]
	}
	byteTmp, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	// Check for overflow.
	bytes := byteTmp * uint64(count)
	if byteTmp != 0 && bytes/byteTmp != uint64(count) {
		return 0, fmt.Errorf("size overflow")
	}
	return bytes, err
}
