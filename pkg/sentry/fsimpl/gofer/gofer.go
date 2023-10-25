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

// Package gofer provides a filesystem implementation that is backed by a 9p
// server, interchangeably referred to as "gofers" throughout this package.
//
// Lock order:
//
//	regularFileFD/directoryFD.mu
//	  filesystem.renameMu
//	    dentry.cachingMu
//	      dentryCache.mu
//	      dentry.opMu
//	        dentry.childrenMu
//	        filesystem.syncMu
//	        dentry.metadataMu
//	          *** "memmap.Mappable locks" below this point
//	          dentry.mapsMu
//	            *** "memmap.Mappable locks taken by Translate" below this point
//	            dentry.handleMu
//	              dentry.dataMu
//	          filesystem.inoMu
//	specialFileFD.mu
//	  specialFileFD.bufMu
//
// Locking dentry.opMu and dentry.metadataMu in multiple dentries requires that
// either ancestor dentries are locked before descendant dentries, or that
// filesystem.renameMu is locked for writing.
package gofer

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	fslock "gvisor.dev/gvisor/pkg/sentry/fsimpl/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Name is the default filesystem name.
const Name = "9p"

// Mount option names for goferfs.
const (
	moptTransport                = "trans"
	moptReadFD                   = "rfdno"
	moptWriteFD                  = "wfdno"
	moptAname                    = "aname"
	moptDfltUID                  = "dfltuid"
	moptDfltGID                  = "dfltgid"
	moptCache                    = "cache"
	moptForcePageCache           = "force_page_cache"
	moptLimitHostFDTranslation   = "limit_host_fd_translation"
	moptOverlayfsStaleRead       = "overlayfs_stale_read"
	moptDisableFileHandleSharing = "disable_file_handle_sharing"
	moptDisableFifoOpen          = "disable_fifo_open"

	// Directfs options.
	moptDirectfs = "directfs"
)

// Valid values for the "cache" mount option.
const (
	cacheFSCache             = "fscache"
	cacheFSCacheWritethrough = "fscache_writethrough"
	cacheRemoteRevalidating  = "remote_revalidating"
)

const (
	defaultMaxCachedDentries  = 1000
	maxCachedNegativeChildren = 1000
)

// stringFixedCache is a fixed sized cache, once initialized,
// its size never changes.
//
// +stateify savable
type stringFixedCache struct {
	// namesList stores negative names with fifo list.
	// name stored in namesList only means it used to be negative
	// at the moment you pushed it to the list.
	namesList stringList
	size      uint64
}

func (cache *stringFixedCache) isInited() bool {
	return cache.size != 0
}

func (cache *stringFixedCache) init(size uint64) {
	elements := make([]stringListElem, size)
	for i := uint64(0); i < size; i++ {
		cache.namesList.PushFront(&elements[i])
	}
	cache.size = size
}

// Update will push name to the front of the list,
// and pop the tail value.
func (cache *stringFixedCache) add(name string) string {
	tail := cache.namesList.Back()
	victimName := tail.str
	tail.str = name
	cache.namesList.Remove(tail)
	cache.namesList.PushFront(tail)
	return victimName
}

// +stateify savable
type dentryCache struct {
	// mu protects the below fields.
	mu sync.Mutex `state:"nosave"`
	// dentries contains all dentries with 0 references. Due to race conditions,
	// it may also contain dentries with non-zero references.
	dentries dentryList
	// dentriesLen is the number of dentries in dentries.
	dentriesLen uint64
	// maxCachedDentries is the maximum number of cacheable dentries.
	maxCachedDentries uint64
}

// SetDentryCacheSize sets the size of the global gofer dentry cache.
func SetDentryCacheSize(size int) {
	if size < 0 {
		return
	}
	if globalDentryCache != nil {
		log.Warningf("Global dentry cache has already been initialized. Ignoring subsequent attempt.")
		return
	}
	globalDentryCache = &dentryCache{maxCachedDentries: uint64(size)}
}

// globalDentryCache is a global cache of dentries across all gofers.
var globalDentryCache *dentryCache

// Valid values for "trans" mount option.
const transportModeFD = "fd"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	vfsfs vfs.Filesystem

	// mfp is used to allocate memory that caches regular file contents. mfp is
	// immutable.
	mfp pgalloc.MemoryFileProvider

	// Immutable options.
	opts  filesystemOptions
	iopts InternalFilesystemOptions

	// client is the LISAFS client used for communicating with the server. client
	// is immutable.
	client *lisafs.Client `state:"nosave"`

	// clock is a realtime clock used to set timestamps in file operations.
	clock ktime.Clock

	// devMinor is the filesystem's minor device number. devMinor is immutable.
	devMinor uint32

	// root is the root dentry. root is immutable.
	root *dentry

	// renameMu serves two purposes:
	//
	//	- It synchronizes path resolution with renaming initiated by this
	//		client.
	//
	//	- It is held by path resolution to ensure that reachable dentries remain
	//		valid. A dentry is reachable by path resolution if it has a non-zero
	//		reference count (such that it is usable as vfs.ResolvingPath.Start() or
	//		is reachable from its children), or if it is a child dentry (such that
	//		it is reachable from its parent).
	renameMu sync.RWMutex `state:"nosave"`

	dentryCache *dentryCache

	// syncableDentries contains all non-synthetic dentries. specialFileFDs
	// contains all open specialFileFDs. These fields are protected by syncMu.
	syncMu           sync.Mutex `state:"nosave"`
	syncableDentries dentryList
	specialFileFDs   specialFDList

	// inoByKey maps previously-observed device ID and host inode numbers to
	// internal inode numbers assigned to those files. inoByKey is not preserved
	// across checkpoint/restore because inode numbers may be reused between
	// different gofer processes, so inode numbers may be repeated for different
	// files across checkpoint/restore. inoByKey is protected by inoMu.
	inoMu    sync.Mutex        `state:"nosave"`
	inoByKey map[inoKey]uint64 `state:"nosave"`

	// lastIno is the last inode number assigned to a file. lastIno is accessed
	// using atomic memory operations.
	lastIno atomicbitops.Uint64

	// savedDentryRW records open read/write handles during save/restore.
	savedDentryRW map[*dentry]savedDentryRW

	// released is nonzero once filesystem.Release has been called.
	released atomicbitops.Int32
}

// +stateify savable
type filesystemOptions struct {
	fd      int
	aname   string
	interop InteropMode // derived from the "cache" mount option
	dfltuid auth.KUID
	dfltgid auth.KGID

	// If forcePageCache is true, host FDs may not be used for application
	// memory mappings even if available; instead, the client must perform its
	// own caching of regular file pages. This is primarily useful for testing.
	forcePageCache bool

	// If limitHostFDTranslation is true, apply maxFillRange() constraints to
	// host FD mappings returned by dentry.(memmap.Mappable).Translate(). This
	// makes memory accounting behavior more consistent between cases where
	// host FDs are / are not available, but may increase the frequency of
	// sentry-handled page faults on files for which a host FD is available.
	limitHostFDTranslation bool

	// If overlayfsStaleRead is true, O_RDONLY host FDs provided by the remote
	// filesystem may not be coherent with writable host FDs opened later, so
	// all uses of the former must be replaced by uses of the latter. This is
	// usually only the case when the remote filesystem is a Linux overlayfs
	// mount. (Prior to Linux 4.18, patch series centered on commit
	// d1d04ef8572b "ovl: stack file ops", both I/O and memory mappings were
	// incoherent between pre-copy-up and post-copy-up FDs; after that patch
	// series, only memory mappings are incoherent.)
	overlayfsStaleRead bool

	// If regularFilesUseSpecialFileFD is true, application FDs representing
	// regular files will use distinct file handles for each FD, in the same
	// way that application FDs representing "special files" such as sockets
	// do. Note that this disables client caching for regular files. This option
	// may regress performance due to excessive Open RPCs. This option is not
	// supported with overlayfsStaleRead for now.
	regularFilesUseSpecialFileFD bool

	// If disableFifoOpen is true, application attempts to open(2) a host FIFO
	// are disallowed.
	disableFifoOpen bool

	// directfs holds options for directfs mode.
	directfs directfsOpts
}

// +stateify savable
type directfsOpts struct {
	// If directfs is enabled, the gofer client does not make RPCs to the gofer
	// process. Instead, it makes host syscalls to perform file operations.
	enabled bool
}

// InteropMode controls the client's interaction with other remote filesystem
// users.
//
// +stateify savable
type InteropMode uint32

const (
	// InteropModeExclusive is appropriate when the filesystem client is the
	// only user of the remote filesystem.
	//
	//	- The client may cache arbitrary filesystem state (file data, metadata,
	//		filesystem structure, etc.).
	//
	//	- Client changes to filesystem state may be sent to the remote
	//		filesystem asynchronously, except when server permission checks are
	//		necessary.
	//
	//	- File timestamps are based on client clocks. This ensures that users of
	//		the client observe timestamps that are coherent with their own clocks
	//		and consistent with Linux's semantics (in particular, it is not always
	//		possible for clients to set arbitrary atimes and mtimes depending on the
	//		remote filesystem implementation, and never possible for clients to set
	//		arbitrary ctimes.)
	InteropModeExclusive InteropMode = iota

	// InteropModeWritethrough is appropriate when there are read-only users of
	// the remote filesystem that expect to observe changes made by the
	// filesystem client.
	//
	//	- The client may cache arbitrary filesystem state.
	//
	//	- Client changes to filesystem state must be sent to the remote
	//		filesystem synchronously.
	//
	//	- File timestamps are based on client clocks. As a corollary, access
	//		timestamp changes from other remote filesystem users will not be visible
	//		to the client.
	InteropModeWritethrough

	// InteropModeShared is appropriate when there are users of the remote
	// filesystem that may mutate its state other than the client.
	//
	//	- The client must verify ("revalidate") cached filesystem state before
	//		using it.
	//
	//	- Client changes to filesystem state must be sent to the remote
	//		filesystem synchronously.
	//
	//	- File timestamps are based on server clocks. This is necessary to
	//		ensure that timestamp changes are synchronized between remote filesystem
	//		users.
	//
	// Note that the correctness of InteropModeShared depends on the server
	// correctly implementing 9P fids (i.e. each fid immutably represents a
	// single filesystem object), even in the presence of remote filesystem
	// mutations from other users. If this is violated, the behavior of the
	// client is undefined.
	InteropModeShared
)

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
//
// +stateify savable
type InternalFilesystemOptions struct {
	// If UniqueID is non-empty, it is an opaque string used to reassociate the
	// filesystem with a new server FD during restoration from checkpoint.
	UniqueID string

	// If LeakConnection is true, do not close the connection to the server
	// when the Filesystem is released. This is necessary for deployments in
	// which servers can handle only a single client and report failure if that
	// client disconnects.
	LeakConnection bool

	// If OpenSocketsByConnecting is true, silently translate attempts to open
	// files identifying as sockets to connect RPCs.
	OpenSocketsByConnecting bool
}

// _V9FS_DEFUID and _V9FS_DEFGID (from Linux's fs/9p/v9fs.h) are the default
// UIDs and GIDs used for files that do not provide a specific owner or group
// respectively.
const (
	// uint32(-2) doesn't work in Go.
	_V9FS_DEFUID = auth.KUID(4294967294)
	_V9FS_DEFGID = auth.KGID(4294967294)
)

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: context does not provide a pgalloc.MemoryFileProvider")
		return nil, nil, linuxerr.EINVAL
	}

	mopts := vfs.GenericParseMountOptions(opts.Data)
	var fsopts filesystemOptions

	fd, err := getFDFromMountOptionsMap(ctx, mopts)
	if err != nil {
		return nil, nil, err
	}
	fsopts.fd = fd

	// Get the attach name.
	fsopts.aname = "/"
	if aname, ok := mopts[moptAname]; ok {
		delete(mopts, moptAname)
		if !path.IsAbs(aname) {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: aname is not absolute: %s=%s", moptAname, aname)
			return nil, nil, linuxerr.EINVAL
		}
		fsopts.aname = path.Clean(aname)
	}

	// Parse the cache policy. For historical reasons, this defaults to the
	// least generally-applicable option, InteropModeExclusive.
	fsopts.interop = InteropModeExclusive
	if cache, ok := mopts[moptCache]; ok {
		delete(mopts, moptCache)
		switch cache {
		case cacheFSCache:
			fsopts.interop = InteropModeExclusive
		case cacheFSCacheWritethrough:
			fsopts.interop = InteropModeWritethrough
		case cacheRemoteRevalidating:
			fsopts.interop = InteropModeShared
		default:
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid cache policy: %s=%s", moptCache, cache)
			return nil, nil, linuxerr.EINVAL
		}
	}

	// Parse the default UID and GID.
	fsopts.dfltuid = _V9FS_DEFUID
	if dfltuidstr, ok := mopts[moptDfltUID]; ok {
		delete(mopts, moptDfltUID)
		dfltuid, err := strconv.ParseUint(dfltuidstr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid default UID: %s=%s", moptDfltUID, dfltuidstr)
			return nil, nil, linuxerr.EINVAL
		}
		// In Linux, dfltuid is interpreted as a UID and is converted to a KUID
		// in the caller's user namespace, but goferfs isn't
		// application-mountable.
		fsopts.dfltuid = auth.KUID(dfltuid)
	}
	fsopts.dfltgid = _V9FS_DEFGID
	if dfltgidstr, ok := mopts[moptDfltGID]; ok {
		delete(mopts, moptDfltGID)
		dfltgid, err := strconv.ParseUint(dfltgidstr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid default UID: %s=%s", moptDfltGID, dfltgidstr)
			return nil, nil, linuxerr.EINVAL
		}
		fsopts.dfltgid = auth.KGID(dfltgid)
	}

	// Handle simple flags.
	if _, ok := mopts[moptDisableFileHandleSharing]; ok {
		delete(mopts, moptDisableFileHandleSharing)
		fsopts.regularFilesUseSpecialFileFD = true
	}
	if _, ok := mopts[moptDisableFifoOpen]; ok {
		delete(mopts, moptDisableFifoOpen)
		fsopts.disableFifoOpen = true
	}
	if _, ok := mopts[moptForcePageCache]; ok {
		delete(mopts, moptForcePageCache)
		fsopts.forcePageCache = true
	}
	if _, ok := mopts[moptLimitHostFDTranslation]; ok {
		delete(mopts, moptLimitHostFDTranslation)
		fsopts.limitHostFDTranslation = true
	}
	if _, ok := mopts[moptOverlayfsStaleRead]; ok {
		delete(mopts, moptOverlayfsStaleRead)
		fsopts.overlayfsStaleRead = true
	}
	if _, ok := mopts[moptDirectfs]; ok {
		delete(mopts, moptDirectfs)
		fsopts.directfs.enabled = true
	}
	// fsopts.regularFilesUseSpecialFileFD can only be enabled by specifying
	// "cache=none".

	// Check for unparsed options.
	if len(mopts) != 0 {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, linuxerr.EINVAL
	}

	// Validation.
	if fsopts.regularFilesUseSpecialFileFD && fsopts.overlayfsStaleRead {
		// These options are not supported together. To support this, when a dentry
		// is opened writably for the first time, we need to iterate over all the
		// specialFileFDs of that dentry that represent a regular file and call
		// fd.hostFileMapper.RegenerateMappings(writable_fd).
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: regularFilesUseSpecialFileFD and overlayfsStaleRead options are not supported together.")
		return nil, nil, linuxerr.EINVAL
	}

	// Handle internal options.
	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if opts.InternalData != nil && !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: GetFilesystemOptions.InternalData has type %T, wanted gofer.InternalFilesystemOptions", opts.InternalData)
		return nil, nil, linuxerr.EINVAL
	}
	// If !ok, iopts being the zero value is correct.

	// Construct the filesystem object.
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	fs := &filesystem{
		mfp:      mfp,
		opts:     fsopts,
		iopts:    iopts,
		clock:    ktime.RealtimeClockFromContext(ctx),
		devMinor: devMinor,
		inoByKey: make(map[inoKey]uint64),
	}

	// Did the user configure a global dentry cache?
	if globalDentryCache != nil {
		fs.dentryCache = globalDentryCache
	} else {
		fs.dentryCache = &dentryCache{maxCachedDentries: defaultMaxCachedDentries}
	}

	fs.vfsfs.Init(vfsObj, &fstype, fs)

	rootInode, rootHostFD, err := fs.initClientAndGetRoot(ctx)
	if err != nil {
		fs.vfsfs.DecRef(ctx)
		return nil, nil, err
	}
	if fs.opts.directfs.enabled {
		fs.root, err = fs.getDirectfsRootDentry(ctx, rootHostFD, fs.client.NewFD(rootInode.ControlFD))
	} else {
		fs.root, err = fs.newLisafsDentry(ctx, &rootInode)
	}
	if err != nil {
		fs.vfsfs.DecRef(ctx)
		return nil, nil, err
	}
	// Set the root's reference count to 2. One reference is returned to the
	// caller, and the other is held by fs to prevent the root from being "cached"
	// and subsequently evicted.
	fs.root.refs = atomicbitops.FromInt64(2)
	return &fs.vfsfs, &fs.root.vfsd, nil
}

// initClientAndGetRoot initializes fs.client and returns the root inode for
// this mount point. It handles the attach point (fs.opts.aname) resolution.
func (fs *filesystem) initClientAndGetRoot(ctx context.Context) (lisafs.Inode, int, error) {
	sock, err := unet.NewSocket(fs.opts.fd)
	if err != nil {
		return lisafs.Inode{}, -1, err
	}

	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	var (
		rootInode  lisafs.Inode
		rootHostFD int
	)
	fs.client, rootInode, rootHostFD, err = lisafs.NewClient(sock)
	if err != nil {
		return lisafs.Inode{}, -1, err
	}

	cu := cleanup.Make(func() {
		if rootHostFD >= 0 {
			_ = unix.Close(rootHostFD)
		}
		rootControlFD := fs.client.NewFD(rootInode.ControlFD)
		rootControlFD.Close(ctx, false /* flush */)
	})
	defer cu.Clean()

	if fs.opts.directfs.enabled {
		if fs.opts.aname != "/" {
			log.Warningf("directfs does not support aname filesystem option: aname=%q", fs.opts.aname)
			return lisafs.Inode{}, -1, unix.EINVAL
		}
		if rootHostFD < 0 {
			log.Warningf("Mount RPC did not return host FD to mount point with directfs enabled")
			return lisafs.Inode{}, -1, unix.EINVAL
		}
	} else {
		if rootHostFD >= 0 {
			log.Warningf("Mount RPC returned a host FD to mount point without directfs, we didn't ask for it")
			_ = unix.Close(rootHostFD)
			rootHostFD = -1
		}
		// Use flipcall channels with lisafs because it makes a lot of RPCs.
		if err := fs.client.StartChannels(); err != nil {
			return lisafs.Inode{}, -1, err
		}
		rootInode, err = fs.handleAnameLisafs(ctx, rootInode)
		if err != nil {
			return lisafs.Inode{}, -1, err
		}
	}
	cu.Release()
	return rootInode, rootHostFD, nil
}

func getFDFromMountOptionsMap(ctx context.Context, mopts map[string]string) (int, error) {
	// Check that the transport is "fd".
	trans, ok := mopts[moptTransport]
	if !ok || trans != transportModeFD {
		ctx.Warningf("gofer.getFDFromMountOptionsMap: transport must be specified as '%s=%s'", moptTransport, transportModeFD)
		return -1, linuxerr.EINVAL
	}
	delete(mopts, moptTransport)

	// Check that read and write FDs are provided and identical.
	rfdstr, ok := mopts[moptReadFD]
	if !ok {
		ctx.Warningf("gofer.getFDFromMountOptionsMap: read FD must be specified as '%s=<file descriptor>'", moptReadFD)
		return -1, linuxerr.EINVAL
	}
	delete(mopts, moptReadFD)
	rfd, err := strconv.Atoi(rfdstr)
	if err != nil {
		ctx.Warningf("gofer.getFDFromMountOptionsMap: invalid read FD: %s=%s", moptReadFD, rfdstr)
		return -1, linuxerr.EINVAL
	}
	wfdstr, ok := mopts[moptWriteFD]
	if !ok {
		ctx.Warningf("gofer.getFDFromMountOptionsMap: write FD must be specified as '%s=<file descriptor>'", moptWriteFD)
		return -1, linuxerr.EINVAL
	}
	delete(mopts, moptWriteFD)
	wfd, err := strconv.Atoi(wfdstr)
	if err != nil {
		ctx.Warningf("gofer.getFDFromMountOptionsMap: invalid write FD: %s=%s", moptWriteFD, wfdstr)
		return -1, linuxerr.EINVAL
	}
	if rfd != wfd {
		ctx.Warningf("gofer.getFDFromMountOptionsMap: read FD (%d) and write FD (%d) must be equal", rfd, wfd)
		return -1, linuxerr.EINVAL
	}
	return rfd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.released.Store(1)

	mf := fs.mfp.MemoryFile()
	fs.syncMu.Lock()
	for elem := fs.syncableDentries.Front(); elem != nil; elem = elem.Next() {
		d := elem.d
		d.handleMu.Lock()
		d.dataMu.Lock()
		if d.isWriteHandleOk() {
			// Write dirty cached data to the remote file.
			h := d.writeHandle()
			if err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size.Load(), mf, h.writeFromBlocksAt); err != nil {
				log.Warningf("gofer.filesystem.Release: failed to flush dentry: %v", err)
			}
			// TODO(jamieliu): Do we need to flushf/fsync d?
		}
		// Discard cached pages.
		d.cache.DropAll(mf)
		d.dirty.RemoveAll()
		d.dataMu.Unlock()
		// Close host FDs if they exist. We can use RacyLoad() because d.handleMu
		// is locked.
		if d.readFD.RacyLoad() >= 0 {
			_ = unix.Close(int(d.readFD.RacyLoad()))
		}
		if d.writeFD.RacyLoad() >= 0 && d.readFD.RacyLoad() != d.writeFD.RacyLoad() {
			_ = unix.Close(int(d.writeFD.RacyLoad()))
		}
		d.readFD = atomicbitops.FromInt32(-1)
		d.writeFD = atomicbitops.FromInt32(-1)
		d.mmapFD = atomicbitops.FromInt32(-1)
		d.handleMu.Unlock()
	}
	// There can't be any specialFileFDs still using fs, since each such
	// FileDescription would hold a reference on a Mount holding a reference on
	// fs.
	fs.syncMu.Unlock()

	// If leak checking is enabled, release all outstanding references in the
	// filesystem. We deliberately avoid doing this outside of leak checking; we
	// have released all external resources above rather than relying on dentry
	// destructors. fs.root may be nil if creating the client or initializing the
	// root dentry failed in GetFilesystem.
	if refs.GetLeakMode() != refs.NoLeakChecking && fs.root != nil {
		fs.renameMu.Lock()
		fs.root.releaseSyntheticRecursiveLocked(ctx)
		fs.evictAllCachedDentriesLocked(ctx)
		fs.renameMu.Unlock()

		// An extra reference was held by the filesystem on the root to prevent it from
		// being cached/evicted.
		fs.root.DecRef(ctx)
	}

	if !fs.iopts.LeakConnection {
		// Close the connection to the server. This implicitly closes all FDs.
		if fs.client != nil {
			fs.client.Close()
		}
	}

	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
}

// releaseSyntheticRecursiveLocked traverses the tree with root d and decrements
// the reference count on every synthetic dentry. Synthetic dentries have one
// reference for existence that should be dropped during filesystem.Release.
//
// Precondition: d.fs.renameMu is locked for writing.
func (d *dentry) releaseSyntheticRecursiveLocked(ctx context.Context) {
	if d.isSynthetic() {
		d.decRefNoCaching()
		d.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	}
	if d.isDir() {
		var children []*dentry
		d.childrenMu.Lock()
		for _, child := range d.children {
			children = append(children, child)
		}
		d.childrenMu.Unlock()
		for _, child := range children {
			if child != nil {
				child.releaseSyntheticRecursiveLocked(ctx)
			}
		}
	}
}

// inoKey is the key used to identify the inode backed by this dentry.
//
// +stateify savable
type inoKey struct {
	ino      uint64
	devMinor uint32
	devMajor uint32
}

func inoKeyFromStatx(stat *linux.Statx) inoKey {
	return inoKey{
		ino:      stat.Ino,
		devMinor: stat.DevMinor,
		devMajor: stat.DevMajor,
	}
}

func inoKeyFromStat(stat *unix.Stat_t) inoKey {
	return inoKey{
		ino:      stat.Ino,
		devMinor: unix.Minor(stat.Dev),
		devMajor: unix.Major(stat.Dev),
	}
}

// dentry implements vfs.DentryImpl.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	// refs is the reference count. Each dentry holds a reference on its
	// parent, even if disowned. An additional reference is held on all
	// synthetic dentries until they are unlinked or invalidated. When refs
	// reaches 0, the dentry may be added to the cache or destroyed. If refs ==
	// -1, the dentry has already been destroyed. refs is accessed using atomic
	// memory operations.
	refs atomicbitops.Int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// parent is this dentry's parent directory. Each dentry holds a reference
	// on its parent. If this dentry is a filesystem root, parent is nil.
	// parent is protected by filesystem.renameMu.
	parent atomic.Pointer[dentry] `state:".(*dentry)"`

	// name is the name of this dentry in its parent. If this dentry is a
	// filesystem root, name is the empty string. name is protected by
	// filesystem.renameMu.
	name string

	// inoKey is used to identify this dentry's inode.
	inoKey inoKey

	// If deleted is non-zero, the file represented by this dentry has been
	// deleted is accessed using atomic memory operations.
	deleted atomicbitops.Uint32

	// cachingMu is used to synchronize concurrent dentry caching attempts on
	// this dentry.
	cachingMu sync.Mutex `state:"nosave"`

	// If cached is true, this dentry is part of filesystem.dentryCache. cached
	// is protected by cachingMu.
	cached bool

	// cacheEntry links dentry into filesystem.dentryCache.dentries. It is
	// protected by filesystem.dentryCache.mu.
	cacheEntry dentryListElem

	// syncableListEntry links dentry into filesystem.syncableDentries. It is
	// protected by filesystem.syncMu.
	syncableListEntry dentryListElem

	// opMu synchronizes operations on this dentry. Operations that mutate
	// the dentry tree must hold this lock for writing. Operations that
	// only read the tree must hold for reading.
	opMu sync.RWMutex `state:"nosave"`

	// childrenMu protects the cached children data for this dentry.
	childrenMu sync.Mutex `state:"nosave"`

	// If this dentry represents a directory, children contains:
	//
	//	- Mappings of child filenames to dentries representing those children.
	//
	//	- Mappings of child filenames that are known not to exist to nil
	//		dentries (only if InteropModeShared is not in effect and the directory
	//		is not synthetic).
	//
	// +checklocks:childrenMu
	children map[string]*dentry

	// If this dentry represents a directory, negativeChildrenCache cache
	// names of negative children.
	//
	// +checklocks:childrenMu
	negativeChildrenCache stringFixedCache
	// If this dentry represents a directory, negativeChildren is the number
	// of negative children cached in dentry.children
	//
	// +checklocks:childrenMu
	negativeChildren int

	// If this dentry represents a directory, syntheticChildren is the number
	// of child dentries for which dentry.isSynthetic() == true.
	//
	// +checklocks:childrenMu
	syntheticChildren int

	// If this dentry represents a directory,
	// dentry.cachedMetadataAuthoritative() == true, and dirents is not
	// nil, then dirents is a cache of all entries in the directory, in the
	// order they were returned by the server. childrenSet just stores the
	// `Name` field of all dirents in a set for fast query. dirents and
	// childrenSet share the same lifecycle.
	//
	// +checklocks:childrenMu
	dirents []vfs.Dirent
	// +checklocks:childrenMu
	childrenSet map[string]struct{}

	// Cached metadata; protected by metadataMu.
	// To access:
	//   - In situations where consistency is not required (like stat), these
	//     can be accessed using atomic operations only (without locking).
	//   - Lock metadataMu and can access without atomic operations.
	// To mutate:
	//   - Lock metadataMu and use atomic operations to update because we might
	//     have atomic readers that don't hold the lock.
	metadataMu sync.Mutex          `state:"nosave"`
	ino        uint64              // immutable
	mode       atomicbitops.Uint32 // type is immutable, perms are mutable
	uid        atomicbitops.Uint32 // auth.KUID, but stored as raw uint32 for sync/atomic
	gid        atomicbitops.Uint32 // auth.KGID, but ...
	blockSize  atomicbitops.Uint32 // 0 if unknown
	// Timestamps, all nsecs from the Unix epoch.
	atime atomicbitops.Int64
	mtime atomicbitops.Int64
	ctime atomicbitops.Int64
	btime atomicbitops.Int64
	// File size, which differs from other metadata in two ways:
	//
	//	- We make a best-effort attempt to keep it up to date even if
	//		!dentry.cachedMetadataAuthoritative() for the sake of O_APPEND writes.
	//
	//	- size is protected by both metadataMu and dataMu (i.e. both must be
	//		locked to mutate it; locking either is sufficient to access it).
	size atomicbitops.Uint64
	// If this dentry does not represent a synthetic file, deleted is 0, and
	// atimeDirty/mtimeDirty are non-zero, atime/mtime may have diverged from the
	// remote file's timestamps, which should be updated when this dentry is
	// evicted.
	atimeDirty atomicbitops.Uint32
	mtimeDirty atomicbitops.Uint32

	// nlink counts the number of hard links to this dentry. It's updated and
	// accessed using atomic operations. It's not protected by metadataMu like the
	// other metadata fields.
	nlink atomicbitops.Uint32

	mapsMu sync.Mutex `state:"nosave"`

	// If this dentry represents a regular file, mappings tracks mappings of
	// the file into memmap.MappingSpaces. mappings is protected by mapsMu.
	mappings memmap.MappingSet

	//	- If this dentry represents a regular file or directory, readFD (if not
	//    -1) is a host FD used for reads by all regularFileFDs/directoryFDs
	//    representing this dentry.
	//
	//	- If this dentry represents a regular file, writeFD (if not -1) is a host
	//    FD used for writes by all regularFileFDs representing this dentry.
	//
	//	- If this dentry represents a regular file, mmapFD is the host FD used
	//		for memory mappings. If mmapFD is -1, no such FD is available, and the
	//		internal page cache implementation is used for memory mappings instead.
	//
	// These fields are protected by handleMu. readFD, writeFD, and mmapFD are
	// additionally written using atomic memory operations, allowing them to be
	// read (albeit racily) with atomic.LoadInt32() without locking handleMu.
	//
	// readFD and writeFD may or may not be the same file descriptor. Once either
	// transitions from closed (-1) to open, it may be mutated with handleMu
	// locked, but cannot be closed until the dentry is destroyed.
	//
	// readFD and writeFD may or may not be the same file descriptor. mmapFD is
	// always either -1 or equal to readFD; if the file has been opened for
	// writing, it is additionally either -1 or equal to writeFD.
	handleMu sync.RWMutex       `state:"nosave"`
	readFD   atomicbitops.Int32 `state:"nosave"`
	writeFD  atomicbitops.Int32 `state:"nosave"`
	mmapFD   atomicbitops.Int32 `state:"nosave"`

	dataMu sync.RWMutex `state:"nosave"`

	// If this dentry represents a regular file that is client-cached, cache
	// maps offsets into the cached file to offsets into
	// filesystem.mfp.MemoryFile() that store the file's data. cache is
	// protected by dataMu.
	cache fsutil.FileRangeSet

	// If this dentry represents a regular file that is client-cached, dirty
	// tracks dirty segments in cache. dirty is protected by dataMu.
	dirty fsutil.DirtySet

	// pf implements memmap.File for mappings of hostFD.
	pf dentryPlatformFile

	// If this dentry represents a symbolic link, InteropModeShared is not in
	// effect, and haveTarget is true, target is the symlink target. haveTarget
	// and target are protected by dataMu.
	haveTarget bool
	target     string

	// If this dentry represents a synthetic socket file, endpoint is the
	// transport endpoint bound to this file.
	endpoint transport.BoundEndpoint

	// If this dentry represents a synthetic named pipe, pipe is the pipe
	// endpoint bound to this file.
	pipe *pipe.VFSPipe

	locks vfs.FileLocks

	// Inotify watches for this dentry.
	//
	// Note that inotify may behave unexpectedly in the presence of hard links,
	// because dentries corresponding to the same file have separate inotify
	// watches when they should share the same set. This is the case because it is
	// impossible for us to know for sure whether two dentries correspond to the
	// same underlying file (see the gofer filesystem section fo vfs/inotify.md for
	// a more in-depth discussion on this matter).
	watches vfs.Watches

	// impl is the specific dentry implementation for non-synthetic dentries.
	// impl is immutable.
	//
	// If impl is nil, this dentry represents a synthetic file, i.e. a
	// file that does not exist on the host filesystem. As of this writing, the
	// only files that can be synthetic are sockets, pipes, and directories.
	impl any
}

// +stateify savable
type stringListElem struct {
	// str is the string that this elem represents.
	str string
	stringEntry
}

// +stateify savable
type dentryListElem struct {
	// d is the dentry that this elem represents.
	d *dentry
	dentryEntry
}

func (fs *filesystem) inoFromKey(key inoKey) uint64 {
	fs.inoMu.Lock()
	defer fs.inoMu.Unlock()

	if ino, ok := fs.inoByKey[key]; ok {
		return ino
	}
	ino := fs.nextIno()
	fs.inoByKey[key] = ino
	return ino
}

func (fs *filesystem) nextIno() uint64 {
	return fs.lastIno.Add(1)
}

// init must be called before first use of d.
func (d *dentry) init(impl any) {
	d.pf.dentry = d
	d.cacheEntry.d = d
	d.syncableListEntry.d = d
	// Nested impl-inheritance pattern. In memory it looks like:
	// [[[ vfs.Dentry ] dentry ] dentryImpl ]
	// All 3 abstractions are allocated in one allocation. We achieve this by
	// making each outer dentry implementation hold the inner dentry by value.
	// Then the outer most dentry is allocated and we initialize fields inward.
	// Each inner dentry has a pointer to the next level of implementation.
	d.impl = impl
	d.vfsd.Init(d)
	refs.Register(d)
}

func (d *dentry) isSynthetic() bool {
	return d.impl == nil
}

func (d *dentry) cachedMetadataAuthoritative() bool {
	return d.fs.opts.interop != InteropModeShared || d.isSynthetic()
}

// updateMetadataFromStatxLocked is called to update d's metadata after an update
// from the remote filesystem.
// Precondition: d.metadataMu must be locked.
// +checklocks:d.metadataMu
func (d *lisafsDentry) updateMetadataFromStatxLocked(stat *linux.Statx) {
	if stat.Mask&linux.STATX_TYPE != 0 {
		if got, want := stat.Mode&linux.FileTypeMask, d.fileType(); uint32(got) != want {
			panic(fmt.Sprintf("gofer.dentry file type changed from %#o to %#o", want, got))
		}
	}
	if stat.Mask&linux.STATX_MODE != 0 {
		d.mode.Store(uint32(stat.Mode))
	}
	if stat.Mask&linux.STATX_UID != 0 {
		d.uid.Store(dentryUID(lisafs.UID(stat.UID)))
	}
	if stat.Mask&linux.STATX_GID != 0 {
		d.gid.Store(dentryGID(lisafs.GID(stat.GID)))
	}
	if stat.Blksize != 0 {
		d.blockSize.Store(stat.Blksize)
	}
	// Don't override newer client-defined timestamps with old server-defined
	// ones.
	if stat.Mask&linux.STATX_ATIME != 0 && d.atimeDirty.Load() == 0 {
		d.atime.Store(dentryTimestamp(stat.Atime))
	}
	if stat.Mask&linux.STATX_MTIME != 0 && d.mtimeDirty.Load() == 0 {
		d.mtime.Store(dentryTimestamp(stat.Mtime))
	}
	if stat.Mask&linux.STATX_CTIME != 0 {
		d.ctime.Store(dentryTimestamp(stat.Ctime))
	}
	if stat.Mask&linux.STATX_BTIME != 0 {
		d.btime.Store(dentryTimestamp(stat.Btime))
	}
	if stat.Mask&linux.STATX_NLINK != 0 {
		d.nlink.Store(stat.Nlink)
	}
	if stat.Mask&linux.STATX_SIZE != 0 {
		d.updateSizeLocked(stat.Size)
	}
}

// updateMetadataFromStatLocked is similar to updateMetadataFromStatxLocked,
// except that it takes a unix.Stat_t argument.
// Precondition: d.metadataMu must be locked.
// +checklocks:d.metadataMu
func (d *directfsDentry) updateMetadataFromStatLocked(stat *unix.Stat_t) error {
	if got, want := stat.Mode&unix.S_IFMT, d.fileType(); got != want {
		panic(fmt.Sprintf("direct.dentry file type changed from %#o to %#o", want, got))
	}
	d.mode.Store(stat.Mode)
	d.uid.Store(stat.Uid)
	d.gid.Store(stat.Gid)
	d.blockSize.Store(uint32(stat.Blksize))
	// Don't override newer client-defined timestamps with old host-defined
	// ones.
	if d.atimeDirty.Load() == 0 {
		d.atime.Store(dentryTimestampFromUnix(stat.Atim))
	}
	if d.mtimeDirty.Load() == 0 {
		d.mtime.Store(dentryTimestampFromUnix(stat.Mtim))
	}
	d.ctime.Store(dentryTimestampFromUnix(stat.Ctim))
	d.nlink.Store(uint32(stat.Nlink))
	d.updateSizeLocked(uint64(stat.Size))
	return nil
}

// Preconditions: !d.isSynthetic().
// Preconditions: d.metadataMu is locked.
// +checklocks:d.metadataMu
func (d *dentry) refreshSizeLocked(ctx context.Context) error {
	d.handleMu.RLock()

	// Can use RacyLoad() because handleMu is locked.
	if d.writeFD.RacyLoad() < 0 {
		d.handleMu.RUnlock()
		// Use a suitable FD if we don't have a writable host FD.
		return d.updateMetadataLocked(ctx, noHandle)
	}

	// Using statx(2) with a minimal mask is faster than fstat(2).
	var stat unix.Statx_t
	// Can use RacyLoad() because handleMu is locked.
	err := unix.Statx(int(d.writeFD.RacyLoad()), "", unix.AT_EMPTY_PATH, unix.STATX_SIZE, &stat)
	d.handleMu.RUnlock() // must be released before updateSizeLocked()
	if err != nil {
		return err
	}
	d.updateSizeLocked(stat.Size)
	return nil
}

// Preconditions: !d.isSynthetic().
func (d *dentry) updateMetadata(ctx context.Context) error {
	// d.metadataMu must be locked *before* we stat so that we do not end up
	// updating stale attributes in d.updateMetadataFromStatLocked().
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	return d.updateMetadataLocked(ctx, noHandle)
}

func (d *dentry) fileType() uint32 {
	return d.mode.Load() & linux.S_IFMT
}

func (d *dentry) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS | linux.STATX_BTIME
	stat.Blksize = d.blockSize.Load()
	stat.Nlink = d.nlink.Load()
	if stat.Nlink == 0 {
		// The remote filesystem doesn't support link count; just make
		// something up. This is consistent with Linux, where
		// fs/inode.c:inode_init_always() initializes link count to 1, and
		// fs/9p/vfs_inode_dotl.c:v9fs_stat2inode_dotl() doesn't touch it if
		// it's not provided by the remote filesystem.
		stat.Nlink = 1
	}
	stat.UID = d.uid.Load()
	stat.GID = d.gid.Load()
	stat.Mode = uint16(d.mode.Load())
	stat.Ino = uint64(d.ino)
	stat.Size = d.size.Load()
	// This is consistent with regularFileFD.Seek(), which treats regular files
	// as having no holes.
	stat.Blocks = (stat.Size + 511) / 512
	stat.Atime = linux.NsecToStatxTimestamp(d.atime.Load())
	stat.Btime = linux.NsecToStatxTimestamp(d.btime.Load())
	stat.Ctime = linux.NsecToStatxTimestamp(d.ctime.Load())
	stat.Mtime = linux.NsecToStatxTimestamp(d.mtime.Load())
	stat.DevMajor = linux.UNNAMED_MAJOR
	stat.DevMinor = d.fs.devMinor
}

// Precondition: fs.renameMu is locked.
func (d *dentry) setStat(ctx context.Context, creds *auth.Credentials, opts *vfs.SetStatOptions, mnt *vfs.Mount) error {
	stat := &opts.Stat
	if stat.Mask == 0 {
		return nil
	}
	if stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_SIZE) != 0 {
		return linuxerr.EPERM
	}
	mode := linux.FileMode(d.mode.Load())
	if err := vfs.CheckSetStat(ctx, creds, opts, mode, auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load())); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	if stat.Mask&linux.STATX_SIZE != 0 {
		// Reject attempts to truncate files other than regular files, since
		// filesystem implementations may return the wrong errno.
		switch mode.FileType() {
		case linux.S_IFREG:
			// ok
		case linux.S_IFDIR:
			return linuxerr.EISDIR
		default:
			return linuxerr.EINVAL
		}
	}

	var now int64
	if d.cachedMetadataAuthoritative() {
		// Truncate updates mtime.
		if stat.Mask&(linux.STATX_SIZE|linux.STATX_MTIME) == linux.STATX_SIZE {
			stat.Mask |= linux.STATX_MTIME
			stat.Mtime = linux.StatxTimestamp{
				Nsec: linux.UTIME_NOW,
			}
		}

		// Use client clocks for timestamps.
		now = d.fs.clock.Now().Nanoseconds()
		if stat.Mask&linux.STATX_ATIME != 0 && stat.Atime.Nsec == linux.UTIME_NOW {
			stat.Atime = linux.NsecToStatxTimestamp(now)
		}
		if stat.Mask&linux.STATX_MTIME != 0 && stat.Mtime.Nsec == linux.UTIME_NOW {
			stat.Mtime = linux.NsecToStatxTimestamp(now)
		}
	}

	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	// As with Linux, if the UID, GID, or file size is changing, we have to
	// clear permission bits. Note that when set, clearSGID may cause
	// permissions to be updated.
	clearSGID := (stat.Mask&linux.STATX_UID != 0 && stat.UID != d.uid.Load()) ||
		(stat.Mask&linux.STATX_GID != 0 && stat.GID != d.gid.Load()) ||
		stat.Mask&linux.STATX_SIZE != 0
	if clearSGID {
		if stat.Mask&linux.STATX_MODE != 0 {
			stat.Mode = uint16(vfs.ClearSUIDAndSGID(uint32(stat.Mode)))
		} else {
			oldMode := d.mode.Load()
			if updatedMode := vfs.ClearSUIDAndSGID(oldMode); updatedMode != oldMode {
				stat.Mode = uint16(updatedMode)
				stat.Mask |= linux.STATX_MODE
			}
		}
	}

	// failureMask indicates which attributes could not be set on the remote
	// filesystem. p9 returns an error if any of the attributes could not be set
	// but that leads to inconsistency as the server could have set a few
	// attributes successfully but a later failure will cause the successful ones
	// to not be updated in the dentry cache.
	var failureMask uint32
	var failureErr error
	if !d.isSynthetic() {
		if stat.Mask != 0 {
			if err := d.prepareSetStat(ctx, stat); err != nil {
				return err
			}
			d.handleMu.RLock()
			if stat.Mask&linux.STATX_SIZE != 0 {
				// d.dataMu must be held around the update to both the remote
				// file's size and d.size to serialize with writeback (which
				// might otherwise write data back up to the old d.size after
				// the remote file has been truncated).
				d.dataMu.Lock()
			}
			var err error
			failureMask, failureErr, err = d.setStatLocked(ctx, stat)
			d.handleMu.RUnlock()
			if err != nil {
				if stat.Mask&linux.STATX_SIZE != 0 {
					d.dataMu.Unlock() // +checklocksforce: locked conditionally above
				}
				return err
			}
			if stat.Mask&linux.STATX_SIZE != 0 {
				if failureMask&linux.STATX_SIZE == 0 {
					// d.size should be kept up to date, and privatized
					// copy-on-write mappings of truncated pages need to be
					// invalidated, even if InteropModeShared is in effect.
					d.updateSizeAndUnlockDataMuLocked(stat.Size) // +checklocksforce: locked conditionally above
				} else {
					d.dataMu.Unlock() // +checklocksforce: locked conditionally above
				}
			}
		}
		if d.fs.opts.interop == InteropModeShared {
			// There's no point to updating d's metadata in this case since
			// it'll be overwritten by revalidation before the next time it's
			// used anyway. (InteropModeShared inhibits client caching of
			// regular file data, so there's no cache to truncate either.)
			return nil
		}
	}
	if stat.Mask&linux.STATX_MODE != 0 && failureMask&linux.STATX_MODE == 0 {
		d.mode.Store(d.fileType() | uint32(stat.Mode))
	}
	if stat.Mask&linux.STATX_UID != 0 && failureMask&linux.STATX_UID == 0 {
		d.uid.Store(stat.UID)
	}
	if stat.Mask&linux.STATX_GID != 0 && failureMask&linux.STATX_GID == 0 {
		d.gid.Store(stat.GID)
	}
	// Note that stat.Atime.Nsec and stat.Mtime.Nsec can't be UTIME_NOW because
	// if d.cachedMetadataAuthoritative() then we converted stat.Atime and
	// stat.Mtime to client-local timestamps above, and if
	// !d.cachedMetadataAuthoritative() then we returned after calling
	// d.file.setAttr(). For the same reason, now must have been initialized.
	if stat.Mask&linux.STATX_ATIME != 0 && failureMask&linux.STATX_ATIME == 0 {
		d.atime.Store(stat.Atime.ToNsec())
		d.atimeDirty.Store(0)
	}
	if stat.Mask&linux.STATX_MTIME != 0 && failureMask&linux.STATX_MTIME == 0 {
		d.mtime.Store(stat.Mtime.ToNsec())
		d.mtimeDirty.Store(0)
	}
	d.ctime.Store(now)
	if failureMask != 0 {
		// Setting some attribute failed on the remote filesystem.
		return failureErr
	}
	return nil
}

// doAllocate performs an allocate operation on d. Note that d.metadataMu will
// be held when allocate is called.
func (d *dentry) doAllocate(ctx context.Context, offset, length uint64, allocate func() error) error {
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	// Allocating a smaller size is a noop.
	size := offset + length
	if d.cachedMetadataAuthoritative() && size <= d.size.RacyLoad() {
		return nil
	}

	err := allocate()
	if err != nil {
		return err
	}
	d.updateSizeLocked(size)
	if d.cachedMetadataAuthoritative() {
		d.touchCMtimeLocked()
	}
	return nil
}

// Preconditions: d.metadataMu must be locked.
func (d *dentry) updateSizeLocked(newSize uint64) {
	d.dataMu.Lock()
	d.updateSizeAndUnlockDataMuLocked(newSize)
}

// Preconditions: d.metadataMu and d.dataMu must be locked.
//
// Postconditions: d.dataMu is unlocked.
// +checklocksrelease:d.dataMu
func (d *dentry) updateSizeAndUnlockDataMuLocked(newSize uint64) {
	oldSize := d.size.RacyLoad()
	d.size.Store(newSize)
	// d.dataMu must be unlocked to lock d.mapsMu and invalidate mappings
	// below. This allows concurrent calls to Read/Translate/etc. These
	// functions synchronize with truncation by refusing to use cache
	// contents beyond the new d.size. (We are still holding d.metadataMu,
	// so we can't race with Write or another truncate.)
	d.dataMu.Unlock()
	if newSize < oldSize {
		oldpgend, _ := hostarch.PageRoundUp(oldSize)
		newpgend, _ := hostarch.PageRoundUp(newSize)
		if oldpgend != newpgend {
			d.mapsMu.Lock()
			d.mappings.Invalidate(memmap.MappableRange{newpgend, oldpgend}, memmap.InvalidateOpts{
				// Compare Linux's mm/truncate.c:truncate_setsize() =>
				// truncate_pagecache() =>
				// mm/memory.c:unmap_mapping_range(evencows=1).
				InvalidatePrivate: true,
			})
			d.mapsMu.Unlock()
		}
		// We are now guaranteed that there are no translations of
		// truncated pages, and can remove them from the cache. Since
		// truncated pages have been removed from the remote file, they
		// should be dropped without being written back.
		d.dataMu.Lock()
		d.cache.Truncate(newSize, d.fs.mfp.MemoryFile())
		d.dirty.KeepClean(memmap.MappableRange{newSize, oldpgend})
		d.dataMu.Unlock()
	}
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(d.mode.Load()), auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load()))
}

func (d *dentry) checkXattrPermissions(creds *auth.Credentials, name string, ats vfs.AccessTypes) error {
	// Deny access to the "system" namespaces since applications
	// may expect these to affect kernel behavior in unimplemented ways
	// (b/148380782). Allow all other extended attributes to be passed through
	// to the remote filesystem. This is inconsistent with Linux's 9p client,
	// but consistent with other filesystems (e.g. FUSE).
	//
	// NOTE(b/202533394): Also disallow "trusted" namespace for now. This is
	// consistent with the VFS1 gofer client.
	if strings.HasPrefix(name, linux.XATTR_SYSTEM_PREFIX) || strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
		return linuxerr.EOPNOTSUPP
	}
	mode := linux.FileMode(d.mode.Load())
	kuid := auth.KUID(d.uid.Load())
	kgid := auth.KGID(d.gid.Load())
	if err := vfs.GenericCheckPermissions(creds, ats, mode, kuid, kgid); err != nil {
		return err
	}
	return vfs.CheckXattrPermissions(creds, ats, mode, kuid, name)
}

func (d *dentry) mayDelete(creds *auth.Credentials, child *dentry) error {
	return vfs.CheckDeleteSticky(
		creds,
		linux.FileMode(d.mode.Load()),
		auth.KUID(d.uid.Load()),
		auth.KUID(child.uid.Load()),
		auth.KGID(child.gid.Load()),
	)
}

func dentryUID(uid lisafs.UID) uint32 {
	if !uid.Ok() {
		return uint32(auth.OverflowUID)
	}
	return uint32(uid)
}

func dentryGID(gid lisafs.GID) uint32 {
	if !gid.Ok() {
		return uint32(auth.OverflowGID)
	}
	return uint32(gid)
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	// d.refs may be 0 if d.fs.renameMu is locked, which serializes against
	// d.checkCachingLocked().
	r := d.refs.Add(1)
	if d.LogRefs() {
		refs.LogIncRef(d, r)
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
	if d.decRefNoCaching() == 0 {
		d.checkCachingLocked(ctx, false /* renameMuWriteLocked */)
	}
}

// decRefNoCaching decrements d's reference count without calling
// d.checkCachingLocked, even if d's reference count reaches 0; callers are
// responsible for ensuring that d.checkCachingLocked will be called later.
func (d *dentry) decRefNoCaching() int64 {
	r := d.refs.Add(-1)
	if d.LogRefs() {
		refs.LogDecRef(d, r)
	}
	if r < 0 {
		panic("gofer.dentry.decRefNoCaching() called without holding a reference")
	}
	return r
}

// RefType implements refs.CheckedObject.Type.
func (d *dentry) RefType() string {
	return "gofer.dentry"
}

// LeakMessage implements refs.CheckedObject.LeakMessage.
func (d *dentry) LeakMessage() string {
	return fmt.Sprintf("[gofer.dentry %p] reference count of %d instead of -1", d, d.refs.Load())
}

// LogRefs implements refs.CheckedObject.LogRefs.
//
// This should only be set to true for debugging purposes, as it can generate an
// extremely large amount of output and drastically degrade performance.
func (d *dentry) LogRefs() bool {
	return false
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if d.isDir() {
		events |= linux.IN_ISDIR
	}

	d.fs.renameMu.RLock()
	// The ordering below is important, Linux always notifies the parent first.
	if parent := d.parent.Load(); parent != nil {
		parent.watches.Notify(ctx, d.name, events, cookie, et, d.isDeleted())
	}
	d.watches.Notify(ctx, "", events, cookie, et, d.isDeleted())
	d.fs.renameMu.RUnlock()
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
//
// If no watches are left on this dentry and it has no references, cache it.
func (d *dentry) OnZeroWatches(ctx context.Context) {
	d.checkCachingLocked(ctx, false /* renameMuWriteLocked */)
}

// checkCachingLocked should be called after d's reference count becomes 0 or
// it becomes disowned.
//
// For performance, checkCachingLocked can also be called after d's reference
// count becomes non-zero, so that d can be removed from the LRU cache. This
// may help in reducing the size of the cache and hence reduce evictions. Note
// that this is not necessary for correctness.
//
// It may be called on a destroyed dentry. For example,
// renameMu[R]UnlockAndCheckCaching may call checkCachingLocked multiple times
// for the same dentry when the dentry is visited more than once in the same
// operation. One of the calls may destroy the dentry, so subsequent calls will
// do nothing.
//
// Preconditions: d.fs.renameMu must be locked for writing if
// renameMuWriteLocked is true; it may be temporarily unlocked.
func (d *dentry) checkCachingLocked(ctx context.Context, renameMuWriteLocked bool) {
	d.cachingMu.Lock()
	refs := d.refs.Load()
	if refs == -1 {
		// Dentry has already been destroyed.
		d.cachingMu.Unlock()
		return
	}
	if refs > 0 {
		// fs.dentryCache.dentries is permitted to contain dentries with non-zero
		// refs, which are skipped by fs.evictCachedDentryLocked() upon reaching
		// the end of the LRU. But it is still beneficial to remove d from the
		// cache as we are already holding d.cachingMu. Keeping a cleaner cache
		// also reduces the number of evictions (which is expensive as it acquires
		// fs.renameMu).
		d.removeFromCacheLocked()
		d.cachingMu.Unlock()
		return
	}
	// Deleted and invalidated dentries with zero references are no longer
	// reachable by path resolution and should be dropped immediately.
	if d.vfsd.IsDead() {
		d.removeFromCacheLocked()
		d.cachingMu.Unlock()
		if !renameMuWriteLocked {
			// Need to lock d.fs.renameMu for writing as needed by d.destroyLocked().
			d.fs.renameMu.Lock()
			defer d.fs.renameMu.Unlock()
			// Now that renameMu is locked for writing, no more refs can be taken on
			// d because path resolution requires renameMu for reading at least.
			if d.refs.Load() != 0 {
				// Destroy d only if its ref is still 0. If not, either someone took a
				// ref on it or it got destroyed before fs.renameMu could be acquired.
				return
			}
		}
		if d.isDeleted() {
			d.watches.HandleDeletion(ctx)
		}
		d.destroyLocked(ctx) // +checklocksforce: renameMu must be acquired at this point.
		return
	}
	if d.vfsd.IsEvictable() {
		d.cachingMu.Unlock()
		// Attempt to evict.
		if renameMuWriteLocked {
			d.evictLocked(ctx) // +checklocksforce: renameMu is locked in this case.
			return
		}
		d.evict(ctx)
		return
	}
	// If d still has inotify watches and it is not deleted or invalidated, it
	// can't be evicted. Otherwise, we will lose its watches, even if a new
	// dentry is created for the same file in the future. Note that the size of
	// d.watches cannot concurrently transition from zero to non-zero, because
	// adding a watch requires holding a reference on d.
	if d.watches.Size() > 0 {
		// As in the refs > 0 case, removing d is beneficial.
		d.removeFromCacheLocked()
		d.cachingMu.Unlock()
		return
	}

	if d.fs.released.Load() != 0 {
		d.cachingMu.Unlock()
		if !renameMuWriteLocked {
			// Need to lock d.fs.renameMu to access d.parent. Lock it for writing as
			// needed by d.destroyLocked() later.
			d.fs.renameMu.Lock()
			defer d.fs.renameMu.Unlock()
		}
		if parent := d.parent.Load(); parent != nil {
			parent.childrenMu.Lock()
			delete(parent.children, d.name)
			parent.childrenMu.Unlock()
		}
		d.destroyLocked(ctx) // +checklocksforce: see above.
		return
	}

	d.fs.dentryCache.mu.Lock()
	// If d is already cached, just move it to the front of the LRU.
	if d.cached {
		d.fs.dentryCache.dentries.Remove(&d.cacheEntry)
		d.fs.dentryCache.dentries.PushFront(&d.cacheEntry)
		d.fs.dentryCache.mu.Unlock()
		d.cachingMu.Unlock()
		return
	}
	// Cache the dentry, then evict the least recently used cached dentry if
	// the cache becomes over-full.
	d.fs.dentryCache.dentries.PushFront(&d.cacheEntry)
	d.fs.dentryCache.dentriesLen++
	d.cached = true
	shouldEvict := d.fs.dentryCache.dentriesLen > d.fs.dentryCache.maxCachedDentries
	d.fs.dentryCache.mu.Unlock()
	d.cachingMu.Unlock()

	if shouldEvict {
		if !renameMuWriteLocked {
			// Need to lock d.fs.renameMu for writing as needed by
			// d.evictCachedDentryLocked().
			d.fs.renameMu.Lock()
			defer d.fs.renameMu.Unlock()
		}
		d.fs.evictCachedDentryLocked(ctx) // +checklocksforce: see above.
	}
}

// Preconditions: d.cachingMu must be locked.
func (d *dentry) removeFromCacheLocked() {
	if d.cached {
		d.fs.dentryCache.mu.Lock()
		d.fs.dentryCache.dentries.Remove(&d.cacheEntry)
		d.fs.dentryCache.dentriesLen--
		d.fs.dentryCache.mu.Unlock()
		d.cached = false
	}
}

// Precondition: fs.renameMu must be locked for writing; it may be temporarily
// unlocked.
// +checklocks:fs.renameMu
func (fs *filesystem) evictAllCachedDentriesLocked(ctx context.Context) {
	for fs.dentryCache.dentriesLen != 0 {
		fs.evictCachedDentryLocked(ctx)
	}
}

// Preconditions:
//   - fs.renameMu must be locked for writing; it may be temporarily unlocked.
//
// +checklocks:fs.renameMu
func (fs *filesystem) evictCachedDentryLocked(ctx context.Context) {
	fs.dentryCache.mu.Lock()
	victim := fs.dentryCache.dentries.Back()
	fs.dentryCache.mu.Unlock()
	if victim == nil {
		// fs.dentryCache.dentries may have become empty between when it was
		// checked and when we locked fs.dentryCache.mu.
		return
	}

	if victim.d.fs == fs {
		victim.d.evictLocked(ctx) // +checklocksforce: owned as precondition, victim.fs == fs
		return
	}

	// The dentry cache is shared between all gofer filesystems and the victim is
	// from another filesystem. Have that filesystem do the work. We unlock
	// fs.renameMu to prevent deadlock: two filesystems could otherwise wait on
	// each others' renameMu.
	fs.renameMu.Unlock()
	defer fs.renameMu.Lock()
	victim.d.evict(ctx)
}

// Preconditions:
//   - d.fs.renameMu must not be locked for writing.
func (d *dentry) evict(ctx context.Context) {
	d.fs.renameMu.Lock()
	defer d.fs.renameMu.Unlock()
	d.evictLocked(ctx)
}

// Preconditions:
//   - d.fs.renameMu must be locked for writing; it may be temporarily unlocked.
//
// +checklocks:d.fs.renameMu
func (d *dentry) evictLocked(ctx context.Context) {
	d.cachingMu.Lock()
	d.removeFromCacheLocked()
	// d.refs or d.watches.Size() may have become non-zero from an earlier path
	// resolution since it was inserted into fs.dentryCache.dentries.
	if d.refs.Load() != 0 || d.watches.Size() != 0 {
		d.cachingMu.Unlock()
		return
	}
	if parent := d.parent.Load(); parent != nil {
		parent.opMu.Lock()
		if !d.vfsd.IsDead() {
			// Note that d can't be a mount point (in any mount namespace), since VFS
			// holds references on mount points.
			rcs := d.fs.vfsfs.VirtualFilesystem().InvalidateDentry(ctx, &d.vfsd)
			for _, rc := range rcs {
				rc.DecRef(ctx)
			}

			parent.childrenMu.Lock()
			delete(parent.children, d.name)
			parent.childrenMu.Unlock()

			// We're only deleting the dentry, not the file it
			// represents, so we don't need to update
			// victim parent.dirents etc.
		}
		parent.opMu.Unlock()
	}
	// Safe to unlock cachingMu now that d.vfsd.IsDead(). Henceforth any
	// concurrent caching attempts on d will attempt to destroy it and so will
	// try to acquire fs.renameMu (which we have already acquiredd). Hence,
	// fs.renameMu will synchronize the destroy attempts.
	d.cachingMu.Unlock()
	d.destroyLocked(ctx) // +checklocksforce: owned as precondition.
}

// destroyDisconnected destroys an uncached, unparented dentry. There are no
// locking preconditions.
func (d *dentry) destroyDisconnected(ctx context.Context) {
	mf := d.fs.mfp.MemoryFile()

	d.handleMu.Lock()
	d.dataMu.Lock()

	if d.isWriteHandleOk() {
		// Write dirty pages back to the remote filesystem.
		h := d.writeHandle()
		if err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size.Load(), mf, h.writeFromBlocksAt); err != nil {
			log.Warningf("gofer.dentry.destroyLocked: failed to write dirty data back: %v", err)
		}
	}
	// Discard cached data.
	if !d.cache.IsEmpty() {
		mf.MarkAllUnevictable(d)
		d.cache.DropAll(mf)
		d.dirty.RemoveAll()
	}
	d.dataMu.Unlock()

	// Close any resources held by the implementation.
	d.destroyImpl(ctx)

	// Can use RacyLoad() because handleMu is locked.
	if d.readFD.RacyLoad() >= 0 {
		_ = unix.Close(int(d.readFD.RacyLoad()))
	}
	if d.writeFD.RacyLoad() >= 0 && d.readFD.RacyLoad() != d.writeFD.RacyLoad() {
		_ = unix.Close(int(d.writeFD.RacyLoad()))
	}
	d.readFD = atomicbitops.FromInt32(-1)
	d.writeFD = atomicbitops.FromInt32(-1)
	d.mmapFD = atomicbitops.FromInt32(-1)
	d.handleMu.Unlock()

	if !d.isSynthetic() {
		// Note that it's possible that d.atimeDirty or d.mtimeDirty are true,
		// i.e. client and server timestamps may differ (because e.g. a client
		// write was serviced by the page cache, and only written back to the
		// remote file later). Ideally, we'd write client timestamps back to
		// the remote filesystem so that timestamps for a new dentry
		// instantiated for the same file would remain coherent. Unfortunately,
		// this turns out to be too expensive in many cases, so for now we
		// don't do this.

		// Remove d from the set of syncable dentries.
		d.fs.syncMu.Lock()
		d.fs.syncableDentries.Remove(&d.syncableListEntry)
		d.fs.syncMu.Unlock()
	}

	// Drop references and stop tracking this child.
	d.refs.Store(-1)
	refs.Unregister(d)
}

// destroyLocked destroys the dentry.
//
// Preconditions:
//   - d.fs.renameMu must be locked for writing; it may be temporarily unlocked.
//   - d.refs == 0.
//   - d.parent.children[d.name] != d, i.e. d is not reachable by path traversal
//     from its former parent dentry.
//
// +checklocks:d.fs.renameMu
func (d *dentry) destroyLocked(ctx context.Context) {
	switch d.refs.Load() {
	case 0:
		// Mark the dentry destroyed.
		d.refs.Store(-1)
	case -1:
		panic("dentry.destroyLocked() called on already destroyed dentry")
	default:
		panic("dentry.destroyLocked() called with references on the dentry")
	}

	// Allow the following to proceed without renameMu locked to improve
	// scalability.
	d.fs.renameMu.Unlock()

	// No locks need to be held during destoryDisconnected.
	d.destroyDisconnected(ctx)

	d.fs.renameMu.Lock()

	// Drop the reference held by d on its parent without recursively locking
	// d.fs.renameMu.

	if parent := d.parent.Load(); parent != nil && parent.decRefNoCaching() == 0 {
		parent.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	}
}

func (d *dentry) isDeleted() bool {
	return d.deleted.Load() != 0
}

func (d *dentry) setDeleted() {
	d.deleted.Store(1)
}

func (d *dentry) listXattr(ctx context.Context, size uint64) ([]string, error) {
	if d.isSynthetic() {
		return nil, nil
	}

	return d.listXattrImpl(ctx, size)
}

func (d *dentry) getXattr(ctx context.Context, creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	if d.isSynthetic() {
		return "", linuxerr.ENODATA
	}
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayRead); err != nil {
		return "", err
	}
	return d.getXattrImpl(ctx, opts)
}

func (d *dentry) setXattr(ctx context.Context, creds *auth.Credentials, opts *vfs.SetXattrOptions) error {
	if d.isSynthetic() {
		return linuxerr.EPERM
	}
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayWrite); err != nil {
		return err
	}
	return d.setXattrImpl(ctx, opts)
}

func (d *dentry) removeXattr(ctx context.Context, creds *auth.Credentials, name string) error {
	if d.isSynthetic() {
		return linuxerr.EPERM
	}
	if err := d.checkXattrPermissions(creds, name, vfs.MayWrite); err != nil {
		return err
	}
	return d.removeXattrImpl(ctx, name)
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.isRegularFile() || d.isDir().
//   - fs.renameMu is locked.
func (d *dentry) ensureSharedHandle(ctx context.Context, read, write, trunc bool) error {
	// O_TRUNC unconditionally requires us to obtain a new handle (opened with
	// O_TRUNC).
	if !trunc {
		d.handleMu.RLock()
		canReuseCurHandle := (!read || d.isReadHandleOk()) && (!write || d.isWriteHandleOk())
		d.handleMu.RUnlock()
		if canReuseCurHandle {
			// Current handles are sufficient.
			return nil
		}
	}

	d.handleMu.Lock()
	needNewHandle := (read && !d.isReadHandleOk()) || (write && !d.isWriteHandleOk()) || trunc
	if !needNewHandle {
		d.handleMu.Unlock()
		return nil
	}

	var fdsToCloseArr [2]int32
	fdsToClose := fdsToCloseArr[:0]
	invalidateTranslations := false
	// Get a new handle. If this file has been opened for both reading and
	// writing, try to get a single handle that is usable for both:
	//
	//	- Writable memory mappings of a host FD require that the host FD is
	//		opened for both reading and writing.
	//
	//	- NOTE(b/141991141): Some filesystems may not ensure coherence
	//		between multiple handles for the same file.
	openReadable := d.isReadHandleOk() || read
	openWritable := d.isWriteHandleOk() || write
	h, err := d.openHandle(ctx, openReadable, openWritable, trunc)
	if linuxerr.Equals(linuxerr.EACCES, err) && (openReadable != read || openWritable != write) {
		// It may not be possible to use a single handle for both
		// reading and writing, since permissions on the file may have
		// changed to e.g. disallow reading after previously being
		// opened for reading. In this case, we have no choice but to
		// use separate handles for reading and writing.
		ctx.Debugf("gofer.dentry.ensureSharedHandle: bifurcating read/write handles for dentry %p", d)
		openReadable = read
		openWritable = write
		h, err = d.openHandle(ctx, openReadable, openWritable, trunc)
	}
	if err != nil {
		d.handleMu.Unlock()
		return err
	}

	// Update d.readFD and d.writeFD
	if h.fd >= 0 {
		if openReadable && openWritable && (d.readFD.RacyLoad() < 0 || d.writeFD.RacyLoad() < 0 || d.readFD.RacyLoad() != d.writeFD.RacyLoad()) {
			// Replace existing FDs with this one.
			if d.readFD.RacyLoad() >= 0 {
				// We already have a readable FD that may be in use by
				// concurrent callers of d.pf.FD().
				if d.fs.opts.overlayfsStaleRead {
					// If overlayfsStaleRead is in effect, then the new FD
					// may not be coherent with the existing one, so we
					// have no choice but to switch to mappings of the new
					// FD in both the application and sentry.
					if err := d.pf.hostFileMapper.RegenerateMappings(int(h.fd)); err != nil {
						d.handleMu.Unlock()
						ctx.Warningf("gofer.dentry.ensureSharedHandle: failed to replace sentry mappings of old FD with mappings of new FD: %v", err)
						h.close(ctx)
						return err
					}
					fdsToClose = append(fdsToClose, d.readFD.RacyLoad())
					invalidateTranslations = true
					d.readFD.Store(h.fd)
				} else {
					// Otherwise, we want to avoid invalidating existing
					// memmap.Translations (which is expensive); instead, use
					// dup3 to make the old file descriptor refer to the new
					// file description, then close the new file descriptor
					// (which is no longer needed). Racing callers of d.pf.FD()
					// may use the old or new file description, but this
					// doesn't matter since they refer to the same file, and
					// any racing mappings must be read-only.
					if err := unix.Dup3(int(h.fd), int(d.readFD.RacyLoad()), unix.O_CLOEXEC); err != nil {
						oldFD := d.readFD.RacyLoad()
						d.handleMu.Unlock()
						ctx.Warningf("gofer.dentry.ensureSharedHandle: failed to dup fd %d to fd %d: %v", h.fd, oldFD, err)
						h.close(ctx)
						return err
					}
					fdsToClose = append(fdsToClose, h.fd)
					h.fd = d.readFD.RacyLoad()
				}
			} else {
				d.readFD.Store(h.fd)
			}
			if d.writeFD.RacyLoad() != h.fd && d.writeFD.RacyLoad() >= 0 {
				fdsToClose = append(fdsToClose, d.writeFD.RacyLoad())
			}
			d.writeFD.Store(h.fd)
			d.mmapFD.Store(h.fd)
		} else if openReadable && d.readFD.RacyLoad() < 0 {
			readHandleWasOk := d.isReadHandleOk()
			d.readFD.Store(h.fd)
			// If the file has not been opened for writing, the new FD may
			// be used for read-only memory mappings. If the file was
			// previously opened for reading (without an FD), then existing
			// translations of the file may use the internal page cache;
			// invalidate those mappings.
			if !d.isWriteHandleOk() {
				invalidateTranslations = readHandleWasOk
				d.mmapFD.Store(h.fd)
			}
		} else if openWritable && d.writeFD.RacyLoad() < 0 {
			d.writeFD.Store(h.fd)
			if d.readFD.RacyLoad() >= 0 {
				// We have an existing read-only FD, but the file has just
				// been opened for writing, so we need to start supporting
				// writable memory mappings. However, the new FD is not
				// readable, so we have no FD that can be used to create
				// writable memory mappings. Switch to using the internal
				// page cache.
				invalidateTranslations = true
				d.mmapFD.Store(-1)
			}
		} else {
			// The new FD is not useful.
			fdsToClose = append(fdsToClose, h.fd)
		}
	} else if openWritable && d.writeFD.RacyLoad() < 0 && d.mmapFD.RacyLoad() >= 0 {
		// We have an existing read-only FD, but the file has just been
		// opened for writing, so we need to start supporting writable
		// memory mappings. However, we have no writable host FD. Switch to
		// using the internal page cache.
		invalidateTranslations = true
		d.mmapFD.Store(-1)
	}

	d.updateHandles(ctx, h, openReadable, openWritable)
	d.handleMu.Unlock()

	if invalidateTranslations {
		// Invalidate application mappings that may be using an old FD; they
		// will be replaced with mappings using the new FD after future calls
		// to d.Translate(). This requires holding d.mapsMu, which precedes
		// d.handleMu in the lock order.
		d.mapsMu.Lock()
		d.mappings.InvalidateAll(memmap.InvalidateOpts{})
		d.mapsMu.Unlock()
	}
	for _, fd := range fdsToClose {
		unix.Close(int(fd))
	}

	return nil
}

func (d *dentry) syncRemoteFile(ctx context.Context) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	return d.syncRemoteFileLocked(ctx)
}

// Preconditions: d.handleMu must be locked.
func (d *dentry) syncRemoteFileLocked(ctx context.Context) error {
	// Prefer syncing write handles over read handles, since some remote
	// filesystem implementations may not sync changes made through write
	// handles otherwise.
	wh := d.writeHandle()
	wh.sync(ctx)
	rh := d.readHandle()
	rh.sync(ctx)
	return nil
}

func (d *dentry) syncCachedFile(ctx context.Context, forFilesystemSync bool) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	if d.isWriteHandleOk() {
		// Write back dirty pages to the remote file.
		d.dataMu.Lock()
		h := d.writeHandle()
		err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size.Load(), d.fs.mfp.MemoryFile(), h.writeFromBlocksAt)
		d.dataMu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := d.syncRemoteFileLocked(ctx); err != nil {
		if !forFilesystemSync {
			return err
		}
		// Only return err if we can reasonably have expected sync to succeed
		// (d is a regular file and was opened for writing).
		if d.isRegularFile() && d.isWriteHandleOk() {
			return err
		}
		ctx.Debugf("gofer.dentry.syncCachedFile: syncing non-writable or non-regular-file dentry failed: %v", err)
	}
	return nil
}

// incLinks increments link count.
func (d *dentry) incLinks() {
	if d.nlink.Load() == 0 {
		// The remote filesystem doesn't support link count.
		return
	}
	d.nlink.Add(1)
}

// decLinks decrements link count.
func (d *dentry) decLinks() {
	if d.nlink.Load() == 0 {
		// The remote filesystem doesn't support link count.
		return
	}
	d.nlink.Add(^uint32(0))
}

// fileDescription is embedded by gofer implementations of
// vfs.FileDescriptionImpl.
//
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

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	d := fd.dentry()
	const validMask = uint32(linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_SIZE | linux.STATX_BLOCKS | linux.STATX_BTIME)
	if !d.cachedMetadataAuthoritative() && opts.Mask&validMask != 0 && opts.Sync != linux.AT_STATX_DONT_SYNC {
		// Use specialFileFD.handle.fileLisa for the Stat if available, for the
		// same reason that we try to use open FD in updateMetadataLocked().
		var err error
		if sffd, ok := fd.vfsfd.Impl().(*specialFileFD); ok {
			err = sffd.updateMetadata(ctx)
		} else {
			err = d.updateMetadata(ctx)
		}
		if err != nil {
			return linux.Statx{}, err
		}
	}
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	fs := fd.filesystem()
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return fd.dentry().setStat(ctx, auth.CredentialsFromContext(ctx), &opts, fd.vfsfd.Mount())
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *fileDescription) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.dentry().listXattr(ctx, size)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *fileDescription) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.dentry().getXattr(ctx, auth.CredentialsFromContext(ctx), &opts)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *fileDescription) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	return fd.dentry().setXattr(ctx, auth.CredentialsFromContext(ctx), &opts)
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *fileDescription) RemoveXattr(ctx context.Context, name string) error {
	return fd.dentry().removeXattr(ctx, auth.CredentialsFromContext(ctx), name)
}

// LockBSD implements vfs.FileDescriptionImpl.LockBSD.
func (fd *fileDescription) LockBSD(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, block bool) error {
	fd.lockLogging.Do(func() {
		log.Infof("File lock using gofer file handled internally.")
	})
	return fd.LockFD.LockBSD(ctx, uid, ownerPID, t, block)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, r fslock.LockRange, block bool) error {
	fd.lockLogging.Do(func() {
		log.Infof("Range lock using gofer file handled internally.")
	})
	return fd.Locks().LockPOSIX(ctx, uid, ownerPID, t, r, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, r fslock.LockRange) error {
	return fd.Locks().UnlockPOSIX(ctx, uid, r)
}

// resolvingPath is just a wrapper around *vfs.ResolvingPath. It additionally
// holds some information around the intent behind resolving the path.
type resolvingPath struct {
	*vfs.ResolvingPath

	// excludeLast indicates whether the intent is to resolve until the last path
	// component. If true, the last path component should remain unresolved.
	excludeLast bool
}

func resolvingPathFull(rp *vfs.ResolvingPath) resolvingPath {
	return resolvingPath{ResolvingPath: rp, excludeLast: false}
}

func resolvingPathParent(rp *vfs.ResolvingPath) resolvingPath {
	return resolvingPath{ResolvingPath: rp, excludeLast: true}
}

func (rp *resolvingPath) done() bool {
	if rp.excludeLast {
		return rp.Final()
	}
	return rp.Done()
}

func (rp *resolvingPath) copy() resolvingPath {
	return resolvingPath{
		ResolvingPath: rp.ResolvingPath.Copy(),
		excludeLast:   rp.excludeLast,
	}
}

// Precondition: !rp.done() && rp.Component() is not "." or "..".
func (rp *resolvingPath) getComponents(emit func(string) bool) {
	rp.GetComponents(rp.excludeLast, emit)
}
