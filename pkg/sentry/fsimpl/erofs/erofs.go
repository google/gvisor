// Copyright 2023 The gVisor Authors.
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

// Package erofs implements erofs.
//
// Lock order:
//
//	dentry.cachingMu
//	  dentry.dirMu
//	    inode.dirMu
//	    inodeBucket.mu
//	    filesystem.cacheMu
package erofs

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Name is the filesystem name. It is part of the interface used by users,
// e.g. via annotations, and shouldn't change.
const Name = "erofs"

// Mount option names for EROFS.
const (
	moptImageFD = "ifd"
)

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

const defaultMaxCachedDentries = 1000

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	vfsfs vfs.Filesystem

	// Immutable options.
	mopts string
	iopts InternalFilesystemOptions

	// devMinor is the filesystem's minor device number. devMinor is immutable.
	devMinor uint32

	// root is the root dentry. root is immutable.
	root *dentry

	// image is the EROFS image. image is immutable.
	image *erofs.Image

	// mf implements memmap.File for this image.
	mf imageMemmapFile

	// useReadForIO indicates that file I/O should be driven by read syscalls
	// from the image file descriptor instead of the image mapping.
	// useReadForIO is immutable.
	useReadForIO bool

	// inodeBuckets contains the inodes in use. Multiple buckets are used to
	// reduce the lock contention. Bucket is chosen based on the hash calculation
	// on nid in filesystem.inodeBucket.
	inodeBuckets []inodeBucket

	// ancestryMu is required by genericfstree.
	ancestryMu sync.RWMutex `state:"nosave"`

	// cacheMu protects the dentry cache LRU list.
	cacheMu sync.Mutex `state:"nosave"`
	// +checklocks:cacheMu
	cachedDentries dentryList
	// +checklocks:cacheMu
	cachedDentriesLen uint64
	maxCachedDentries uint64

	// released is nonzero once filesystem.Release has been called.
	released atomicbitops.Uint32
}

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
//
// +stateify savable
type InternalFilesystemOptions struct {
	// If UniqueID is non-empty, it is used to reassociate the filesystem with
	// a new image FD during restoration from checkpoint.
	UniqueID checkpoint.ResourceID
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mopts := vfs.GenericParseMountOptions(opts.Data)

	var cu cleanup.Cleanup
	defer cu.Clean()

	fd, err := getFDFromMountOptionsMap(ctx, mopts)
	if err != nil {
		return nil, nil, err
	}

	f := os.NewFile(uintptr(fd), "EROFS image file")
	image, err := erofs.OpenImage(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	cu.Add(func() { image.Close() })

	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if opts.InternalData != nil && !ok {
		ctx.Warningf("erofs.FilesystemType.GetFilesystem: GetFilesystemOptions.InternalData has type %T, wanted erofs.InternalFilesystemOptions", opts.InternalData)
		return nil, nil, linuxerr.EINVAL
	}

	useReadForIO, err := shouldUseReadForIO(ctx, fd)
	if err != nil {
		return nil, nil, err
	}

	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	fs := &filesystem{
		mopts:             opts.Data,
		iopts:             iopts,
		image:             image,
		devMinor:          devMinor,
		useReadForIO:      useReadForIO,
		mf:                imageMemmapFile{image: image},
		maxCachedDentries: defaultMaxCachedDentries,
	}
	fs.vfsfs.Init(vfsObj, &fstype, fs)
	cu.Add(func() { fs.vfsfs.DecRef(ctx) })

	fs.inodeBuckets = make([]inodeBucket, runtime.GOMAXPROCS(0))
	for i := range fs.inodeBuckets {
		fs.inodeBuckets[i].init()
	}

	root, err := fs.newDentry(image.RootNid())
	if err != nil {
		return nil, nil, err
	}

	// Increase the root's reference count to 2. One reference is returned to
	// the caller, and the other is held by fs.
	root.IncRef()
	fs.root = root

	cu.Release()
	return &fs.vfsfs, &root.vfsd, nil
}

func getFDFromMountOptionsMap(ctx context.Context, mopts map[string]string) (int, error) {
	ifdstr, ok := mopts[moptImageFD]
	if !ok {
		ctx.Warningf("erofs.getFDFromMountOptionsMap: image FD must be specified as '%s=<file descriptor>'", moptImageFD)
		return -1, linuxerr.EINVAL
	}
	delete(mopts, moptImageFD)

	ifd, err := strconv.Atoi(ifdstr)
	if err != nil {
		ctx.Warningf("erofs.getFDFromMountOptionsMap: invalid image FD: %s=%s", moptImageFD, ifdstr)
		return -1, linuxerr.EINVAL
	}

	return ifd, nil
}

func shouldUseReadForIO(ctx context.Context, imageFD int) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(imageFD, &st); err != nil {
		// Detection is best-effort; fall back to reading via the mapping.
		ctx.Warningf("erofs.shouldUseReadForIO: fstatfs failed, defaulting to using mmap for reads: %v", err)
		return false, nil
	}
	// Use read syscalls when the EROFS image file lives on FUSE filesystem.
	// This avoids faulting the mapping in page by page and turning a large
	// read into many small, largely serialized requests to the FUSE server.
	return st.Type == linux.FUSE_SUPER_MAGIC, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.released.Store(1)
	fs.evictAllCachedDentries(ctx)
	// An extra reference was held by the filesystem on the root.
	if fs.root != nil {
		fs.root.DecRef(ctx)
	}
	fs.image.Close()
	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
}

func (fs *filesystem) statFS() linux.Statfs {
	blockSize := int64(fs.image.BlockSize())
	return linux.Statfs{
		Type:         erofs.SuperBlockMagicV1,
		NameLength:   erofs.MaxNameLen,
		BlockSize:    blockSize,
		FragmentSize: blockSize,
		Blocks:       uint64(fs.image.Blocks()),
	}
}

// +stateify savable
type inodeBucket struct {
	// mu protects inodeMap.
	mu sync.RWMutex `state:"nosave"`

	// inodeMap contains the inodes indexed by nid.
	// +checklocks:mu
	inodeMap map[uint64]*inode
}

func (ib *inodeBucket) init() {
	ib.inodeMap = make(map[uint64]*inode) // +checklocksignore
}

// getInode returns the inode identified by nid. A reference on inode is also
// returned to caller.
func (ib *inodeBucket) getInode(nid uint64) *inode {
	ib.mu.RLock()
	defer ib.mu.RUnlock()
	i := ib.inodeMap[nid]
	if i != nil {
		i.IncRef()
	}
	return i
}

// addInode adds the inode identified by nid into the bucket. It will first check
// whether the old inode exists. If not, it will call newInode() to get the new inode.
// The inode eventually saved in the bucket will be returned with a reference for caller.
func (ib *inodeBucket) addInode(nid uint64, newInode func() *inode) *inode {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	if i, ok := ib.inodeMap[nid]; ok {
		i.IncRef()
		return i
	}
	i := newInode()
	ib.inodeMap[nid] = i
	return i
}

// removeInodeLocked removes the inode identified by nid.
// +checklocks:ib.mu
func (ib *inodeBucket) removeInodeLocked(nid uint64) {
	delete(ib.inodeMap, nid)
}

func (fs *filesystem) inodeBucket(nid uint64) *inodeBucket {
	bucket := nid % uint64(len(fs.inodeBuckets))
	return &fs.inodeBuckets[bucket]
}

// inode represents a filesystem object.
//
// Each dentry holds a reference on the inode it represents. An inode will
// be dropped once its reference count reaches zero. We do not cache inodes
// directly. The caching policy is implemented on top of dentries.
//
// +stateify savable
type inode struct {
	erofs.Inode

	// inodeRefs is the reference count.
	inodeRefs

	// fs is the owning filesystem.
	fs *filesystem

	// dirMu protects dirents. dirents is immutable after creation.
	dirMu sync.RWMutex `state:"nosave"`
	// +checklocks:dirMu
	dirents []vfs.Dirent `state:"nosave"`

	// TODO: Since EROFS is read-only, files can't be truncated or
	// hole-punched, so mapsMu and mappings are only used by
	// inode.InvalidateUnsavable. However, AFAIU inode.Translate will return
	// the same File and offset after save/restore, so this is unnecessary, and
	// we can use memmap.MappableNoTrackMappings instead.

	// mapsMu protects mappings.
	mapsMu sync.Mutex `state:"nosave"`

	// mappings tracks the mappings of the file into memmap.MappingSpaces
	// if this inode represents a regular file.
	// +checklocks:mapsMu
	mappings memmap.MappingSet

	// locks supports POSIX and BSD style locks.
	locks vfs.FileLocks

	// Inotify watches for this inode.
	watches vfs.Watches
}

// getInode returns the inode identified by nid. A reference on inode is also
// returned to caller.
func (fs *filesystem) getInode(nid uint64) (*inode, error) {
	bucket := fs.inodeBucket(nid)

	// Fast path, inode already exists.
	if i := bucket.getInode(nid); i != nil {
		return i, nil
	}

	// Slow path, create a new inode.
	//
	// Construct the underlying inode object from the image without taking
	// the bucket lock first to reduce the contention.
	ino, err := fs.image.Inode(nid)
	if err != nil {
		return nil, err
	}
	return bucket.addInode(nid, func() *inode {
		i := &inode{
			Inode: ino,
			fs:    fs,
		}
		i.InitRefs()
		return i
	}), nil

}

// DecRef should be called when you're finished with an inode.
func (i *inode) DecRef(ctx context.Context) {
	nid := i.Nid()
	ib := i.fs.inodeBucket(nid)
	ib.mu.Lock()
	defer ib.mu.Unlock()
	i.inodeRefs.DecRef(func() {
		ib.removeInodeLocked(nid) // +checklocksforce: ib.mu is locked above.
	})
}

func (i *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(i.Mode()), nil, auth.KUID(i.UID()), auth.KGID(i.GID()))
}

func (i *inode) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK |
		linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_SIZE |
		linux.STATX_BLOCKS | linux.STATX_ATIME | linux.STATX_CTIME |
		linux.STATX_MTIME
	stat.Blksize = i.fs.image.BlockSize()
	stat.Nlink = i.Nlink()
	stat.UID = i.UID()
	stat.GID = i.GID()
	stat.Mode = i.Mode()
	stat.Ino = i.Nid()
	stat.Size = i.Size()
	stat.Blocks = (stat.Size + 511) / 512
	stat.Mtime = linux.StatxTimestamp{
		Sec:  int64(i.Mtime()),
		Nsec: i.MtimeNsec(),
	}
	stat.Atime = stat.Mtime
	stat.Ctime = stat.Mtime
	stat.DevMajor = linux.UNNAMED_MAJOR
	stat.DevMinor = i.fs.devMinor
}

func (i *inode) fileType() uint16 {
	return i.Mode() & linux.S_IFMT
}

// dentry implements vfs.DentryImpl.
//
// Reference model:
//
//   - Each dentry holds one reference on its parent. The ref is acquired when
//     the child is inserted into the parent's childMap and dropped when the
//     child is destroyed.
//   - Each dentry holds one reference on its inode. The ref is acquired when
//     the dentry is created and dropped when the dentry is destroyed.
//   - refs == 0 means that the dentry is cache-eligible and can be added to
//     filesystem's LRU dentry cache via checkCaching(). A cached child still
//     holds its parent's ref, so a parent can only become cache-eligible once
//     all its children have been destroyed.
//   - refs == -1 means destroyed.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	// refs is the reference count.
	refs atomicbitops.Int64

	// parent is this dentry's parent directory. If this dentry is
	// a file system root, parent is nil.
	parent atomic.Pointer[dentry] `state:".(*dentry)"`

	// name is this dentry's name in its parent. If this dentry is
	// a file system root, name is the empty string.
	name string

	// inode is the inode represented by this dentry.
	inode *inode

	// dirMu serializes changes to the dentry tree.
	dirMu sync.RWMutex `state:"nosave"`

	// childMap contains the mappings of child names to dentries if this
	// dentry represents a directory.
	// +checklocks:dirMu
	childMap map[string]*dentry

	// cachingMu serializes this dentry's caching and eviction decisions.
	cachingMu sync.Mutex `state:"nosave"`

	// cached indicates whether this dentry is on fs.cachedDentries. It is
	// protected by cachingMu.
	cached bool

	dentryEntry
}

// newDentry returns a dentry with refs == 1 (held by the caller). The caller
// is responsible for inserting it into the dentry tree.
func (fs *filesystem) newDentry(nid uint64) (*dentry, error) {
	i, err := fs.getInode(nid)
	if err != nil {
		return nil, err
	}
	d := &dentry{
		inode: i,
	}
	d.refs.Store(1)
	d.vfsd.Init(d)
	refs.Register(d)
	return d, nil
}

// IncRef implements vfs.DentryImpl.IncRef.
//
// Preconditions: the caller must hold either an existing reference on d, or
// d.parent.dirMu. The latter case covers reviving a cached dentry (d.refs
// going from 0 to 1): dentry eviction acquires parent.dirMu before destroying
// d, so any dentry found in parent.childMap under that lock is guaranteed not
// to be destroyed (d.refs >= 0).
func (d *dentry) IncRef() {
	r := d.refs.Add(1)
	if d.LogRefs() {
		refs.LogIncRef(d, r)
	}
	if r <= 0 {
		panic("erofs.dentry.IncRef() on destroyed dentry")
	}
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		r := d.refs.Load()
		if r <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(r, r+1) {
			if d.LogRefs() {
				refs.LogTryIncRef(d, r+1)
			}
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(ctx context.Context) {
	r := d.refs.Add(-1)
	if d.LogRefs() {
		refs.LogDecRef(d, r)
	}
	if r < 0 {
		panic("erofs.dentry.DecRef() called without holding a reference")
	}
	if r == 0 {
		d.checkCaching(ctx)
	}
}

// RefType implements refs.CheckedObject.RefType.
func (d *dentry) RefType() string { return "erofs.dentry" }

// LeakMessage implements refs.CheckedObject.LeakMessage.
func (d *dentry) LeakMessage() string {
	return fmt.Sprintf("[erofs.dentry %p] reference count of %d instead of -1", d, d.refs.Load())
}

// LogRefs implements refs.CheckedObject.LogRefs.
//
// This should only be set to true for debugging purposes, as it can generate
// an extremely large amount of output and drastically degrade performance.
func (d *dentry) LogRefs() bool { return false }

// checkCaching reconciles d's caching state with its current refcount: place
// on or move to the MRU end of the LRU if refs == 0, or remove from the LRU
// if refs > 0.
//
// Safe to call after either a DecRef or an IncRef; the latter is a hygiene
// pass that yanks revived dentries off the LRU.
//
// Preconditions: the caller holds neither d.cachingMu nor fs.cacheMu.
func (d *dentry) checkCaching(ctx context.Context) {
	d.cachingMu.Lock()

	r := d.refs.Load()
	if r < 0 {
		d.cachingMu.Unlock()
		return
	}
	// If d still has inotify watches, it can't be evicted. Otherwise, we will
	// lose its watches, even if a new dentry is created for the same file in
	// the future. Note that the size of d.inode.watches cannot concurrently
	// transition from zero to non-zero, because adding a watch requires
	// holding a reference on d.
	if r > 0 || d.inode.watches.Size() > 0 {
		d.removeFromCache()
		d.cachingMu.Unlock()
		return
	}
	if d.vfsd.IsEvictable() {
		d.evictAndUnlockCachingMu(ctx)
		return
	}

	fs := d.inode.fs

	// Filesystem teardown: destroy immediately instead of caching. Reached
	// by (a) the cascade up the tree when leaf eviction drops parent refs
	// to zero, and (b) the final root.DecRef in fs.Release.
	if fs.released.Load() != 0 {
		// Root is never cached and has no parent to unlink (evict would panic);
		// others go via evict.
		if d.parent.Load() == nil {
			d.refs.Store(-1)
			// Release cachingMu before destroy(); see evictAndUnlockCachingMu.
			d.cachingMu.Unlock()
			d.destroy(ctx)
		} else {
			d.evictAndUnlockCachingMu(ctx)
		}
		return
	}

	if d.cached {
		// If d is already cached, just move it to the front of the LRU.
		fs.cacheMu.Lock()
		fs.cachedDentries.Remove(d)
		fs.cachedDentries.PushFront(d)
		fs.cacheMu.Unlock()
		d.cachingMu.Unlock()
		return
	}
	// Cache the dentry, then evict the least recently used cached dentry if
	// the cache becomes over-full.
	fs.cacheMu.Lock()
	fs.cachedDentries.PushFront(d)
	fs.cachedDentriesLen++
	shouldEvict := fs.cachedDentriesLen > fs.maxCachedDentries
	fs.cacheMu.Unlock()
	d.cached = true
	d.cachingMu.Unlock()

	if shouldEvict {
		fs.evictCachedDentry(ctx)
	}
}

// removeFromCache ensures d is not on fs.cachedDentries. It is idempotent.
//
// +checklocks:d.cachingMu
func (d *dentry) removeFromCache() {
	if !d.cached {
		return
	}
	d.inode.fs.cacheMu.Lock()
	d.inode.fs.cachedDentries.Remove(d)
	d.inode.fs.cachedDentriesLen--
	d.inode.fs.cacheMu.Unlock()
	d.cached = false
}

// evictCachedDentry removes the least-recently-used dentry from cachedDentries
// and evicts it. Returns true if a dentry was evicted.
func (fs *filesystem) evictCachedDentry(ctx context.Context) bool {
	for {
		fs.cacheMu.Lock()
		victim := fs.cachedDentries.Back()
		fs.cacheMu.Unlock()
		if victim == nil {
			return false
		}
		victim.cachingMu.Lock()
		// victim may have been removed from the cache by a racing checkCaching
		// or eviction, so recheck cached under cachingMu.
		if !victim.cached {
			victim.cachingMu.Unlock()
			continue
		}
		victim.evictAndUnlockCachingMu(ctx)
		return true
	}
}

// evictAllCachedDentries drains the LRU. Used during filesystem release;
// the fs.released flag ensures the cascade doesn't re-populate the LRU.
func (fs *filesystem) evictAllCachedDentries(ctx context.Context) {
	for fs.evictCachedDentry(ctx) {
	}
}

// evictAndUnlockCachingMu tears d off the LRU and destroys it, unless a racing lookup revived d
// or a racing evictor already claimed it.
//
// Postconditions: d.cachingMu will be unlocked.
// +checklocksrelease:d.cachingMu
func (d *dentry) evictAndUnlockCachingMu(ctx context.Context) {
	d.removeFromCache()

	parent := d.parent.Load()
	if parent == nil {
		// The root should never enter the LRU: checkCaching routes
		// parent-nil dentries to destroy via the fs.released branch,
		// which is set before fs.root.DecRef in fs.Release.
		panic("erofs.dentry.evictAndUnlockCachingMu() called on the root")
	}

	parent.dirMu.Lock()

	// Recheck under parent.dirMu, which serializes against lookup: bail if a
	// lookup revived d (refs != 0) or a racing evictor claimed it (refs == -1).
	if d.refs.Load() != 0 || d.inode.watches.Size() != 0 {
		parent.dirMu.Unlock()
		d.cachingMu.Unlock()
		return
	}

	delete(parent.childMap, d.name)

	// Claim d so a racing evictor bails at the recheck above.
	d.refs.Store(-1)

	parent.dirMu.Unlock()

	// destroy() may cascade into evicting an unrelated dentry and lock its
	// cachingMu; release d.cachingMu first so no goroutine ever holds two
	// dentries' cachingMu at once.
	d.cachingMu.Unlock()

	d.destroy(ctx)
}

// destroy tears down a dentry the caller has claimed by setting refs to -1.
// Drops the inode ref and the parent ref, cascading checkCaching up the tree.
//
// Preconditions:
//   - d.refs == -1
//   - d is no longer reachable via parent.childMap
//   - the caller holds no locks (destroy may cascade into parent.checkCaching)
func (d *dentry) destroy(ctx context.Context) {
	if d.refs.Load() != -1 {
		panic("erofs.dentry.destroy() on an unclaimed dentry")
	}

	refs.Unregister(d)

	d.inode.DecRef(ctx)

	// Drop the parent ref, which may cascade into parent.checkCaching.
	if parent := d.parent.Load(); parent != nil {
		parent.DecRef(ctx)
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if d.inode.IsDir() {
		events |= linux.IN_ISDIR
	}
	// The ordering below is important, Linux always notifies the parent first.
	if parent := d.parent.Load(); parent != nil {
		parent.inode.watches.Notify(ctx, d.name, events, cookie, et, false)
	}
	d.inode.watches.Notify(ctx, "", events, cookie, et, false)
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.inode.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches(ctx context.Context) {
	// If no watches are left on this dentry, try caching it.
	d.checkCaching(ctx)
}

func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.inode.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}

	switch d.inode.fileType() {
	case linux.S_IFREG:
		if ats&vfs.MayWrite != 0 {
			return nil, linuxerr.EROFS
		}
		var fd regularFileFD
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Credentials(), rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil

	case linux.S_IFDIR:
		// Can't open directories with O_CREAT.
		if opts.Flags&linux.O_CREAT != 0 {
			return nil, linuxerr.EISDIR
		}
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, linuxerr.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, linuxerr.EINVAL
		}
		var fd directoryFD
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Credentials(), rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil

	case linux.S_IFLNK:
		// Can't open symlinks without O_PATH, which is handled at the VFS layer.
		return nil, linuxerr.ELOOP

	default:
		return nil, linuxerr.ENXIO
	}
}

// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	lockLogging sync.Once `state:"nosave"`
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
	return linuxerr.EROFS
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.filesystem().statFS(), nil
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *fileDescription) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return nil, linuxerr.ENOTSUP
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *fileDescription) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return "", linuxerr.ENOTSUP
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *fileDescription) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	return linuxerr.EROFS
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *fileDescription) RemoveXattr(ctx context.Context, name string) error {
	return linuxerr.EROFS
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (*fileDescription) Sync(context.Context, vfs.SyncOptions) error {
	return nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (*fileDescription) Release(ctx context.Context) {}
