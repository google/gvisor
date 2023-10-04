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
package erofs

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const Name = "erofs"

// Mount option names for EROFS.
const (
	moptImageFD = "ifd"
)

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

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

	// inodeBuckets contains the inodes in use. Multiple buckets are used to
	// reduce the lock contention. Bucket is chosen based on the hash calculation
	// on nid in filesystem.inodeBucket.
	inodeBuckets []inodeBucket
}

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
//
// +stateify savable
type InternalFilesystemOptions struct {
	// If UniqueID is non-empty, it is an opaque string used to reassociate the
	// filesystem with a new image FD during restoration from checkpoint.
	UniqueID string
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

	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	fs := &filesystem{
		mopts:    opts.Data,
		iopts:    iopts,
		image:    image,
		devMinor: devMinor,
		mf:       imageMemmapFile{image: image},
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

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
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

// removeInode removes the inode identified by nid.
func (ib *inodeBucket) removeInode(nid uint64) {
	ib.mu.Lock()
	delete(ib.inodeMap, nid)
	ib.mu.Unlock()
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
	i.inodeRefs.DecRef(func() {
		nid := i.Nid()
		i.fs.inodeBucket(nid).removeInode(nid)
	})
}

func (i *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(i.Mode()), auth.KUID(i.UID()), auth.KGID(i.GID()))
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
// The filesystem is read-only and currently we never drop the cached dentries
// until the filesystem is unmounted. The reference model works like this:
//
//   - The initial reference count of each dentry is one, which is the reference
//     held by the parent (so when the reference count is one, it also means that
//     this is a cached dentry, i.e. not in use).
//
//   - When a dentry is used (e.g. opened by someone), its reference count will
//     be increased and the new reference is held by caller.
//
//   - The reference count of root dentry is two. One reference is returned to
//     the caller of `GetFilesystem()`, and the other is held by `fs`.
//
// TODO: This can lead to unbounded memory growth in sentry due to the ever-growing
// dentry tree. We should have a dentry LRU cache, similar to what fsimpl/gofer does.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	// dentryRefs is the reference count.
	dentryRefs

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
}

// The caller is expected to handle dentry insertion into dentry tree.
func (fs *filesystem) newDentry(nid uint64) (*dentry, error) {
	i, err := fs.getInode(nid)
	if err != nil {
		return nil, err
	}
	d := &dentry{
		inode: i,
	}
	d.InitRefs()
	d.vfsd.Init(d)
	return d, nil
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(ctx context.Context) {
	d.dentryRefs.DecRef(func() {
		d.dirMu.Lock()
		for _, c := range d.childMap {
			c.DecRef(ctx)
		}
		d.childMap = nil
		d.dirMu.Unlock()
		d.inode.DecRef(ctx)
	})
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
func (d *dentry) OnZeroWatches(ctx context.Context) {}

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
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
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
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
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
func (*fileDescription) Sync(context.Context) error {
	return nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (*fileDescription) Release(ctx context.Context) {}
