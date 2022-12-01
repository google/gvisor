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
// server, interchangably referred to as "gofers" throughout this package.
//
// Lock order:
//
//	regularFileFD/directoryFD.mu
//	  filesystem.renameMu
//	    dentry.cachingMu
//	      dentryCache.mu
//	      dentry.dirMu
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
// Locking dentry.dirMu and dentry.metadataMu in multiple dentries requires that
// either ancestor dentries are locked before descendant dentries, or that
// filesystem.renameMu is locked for writing.
package gofer

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
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
	moptTransport              = "trans"
	moptReadFD                 = "rfdno"
	moptWriteFD                = "wfdno"
	moptAname                  = "aname"
	moptDfltUID                = "dfltuid"
	moptDfltGID                = "dfltgid"
	moptMsize                  = "msize"
	moptVersion                = "version"
	moptCache                  = "cache"
	moptForcePageCache         = "force_page_cache"
	moptLimitHostFDTranslation = "limit_host_fd_translation"
	moptOverlayfsStaleRead     = "overlayfs_stale_read"
	moptLisafs                 = "lisafs"
)

// Valid values for the "cache" mount option.
const (
	cacheNone                = "none"
	cacheFSCache             = "fscache"
	cacheFSCacheWritethrough = "fscache_writethrough"
	cacheRemoteRevalidating  = "remote_revalidating"
)

const defaultMaxCachedDentries = 1000

// +stateify savable
type dentryCache struct {
	// mu protects the below fields.
	mu sync.Mutex `state:"nosave"`
	// dentries contains all dentries with 0 references. Due to race conditions,
	// it may also contain dentries with non-zero references.
	dentries dentryList
	// dentriesLen is the number of dentries in dentries.
	dentriesLen uint64
	// maxCachedDentries is the maximum number of cachable dentries.
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

	// client is the client used by this filesystem. client is immutable.
	client *p9.Client `state:"nosave"`

	// clientLisa is the client used for communicating with the server when
	// lisafs is enabled. lisafsCient is immutable.
	clientLisa *lisafs.Client `state:"nosave"`

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

	// inoByQIDPath maps previously-observed QID.Paths to inode numbers
	// assigned to those paths. inoByQIDPath is not preserved across
	// checkpoint/restore because QIDs may be reused between different gofer
	// processes, so QIDs may be repeated for different files across
	// checkpoint/restore. inoByQIDPath is protected by inoMu.
	inoMu        sync.Mutex        `state:"nosave"`
	inoByQIDPath map[uint64]uint64 `state:"nosave"`

	// inoByKey is the same as inoByQIDPath but only used by lisafs. It helps
	// identify inodes based on the device ID and host inode number provided
	// by the gofer process. It is not preserved across checkpoint/restore for
	// the same reason as above. inoByKey is protected by inoMu.
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
	// "Standard" 9P options.
	fd        int
	aname     string
	interop   InteropMode // derived from the "cache" mount option
	dfltuid   auth.KUID
	dfltgid   auth.KGID
	msize     uint32
	version9P string

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

	// lisaEnabled indicates whether the client will use lisafs protocol to
	// communicate with the server instead of 9P.
	lisaEnabled bool
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
		case cacheNone:
			fsopts.regularFilesUseSpecialFileFD = true
			fallthrough
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

	// Parse the 9P message size.
	fsopts.msize = 1024 * 1024 // 1M, tested to give good enough performance up to 64M
	if msizestr, ok := mopts[moptMsize]; ok {
		delete(mopts, moptMsize)
		msize, err := strconv.ParseUint(msizestr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid message size: %s=%s", moptMsize, msizestr)
			return nil, nil, linuxerr.EINVAL
		}
		fsopts.msize = uint32(msize)
	}

	// Handle simple flags.
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
	if lisafs, ok := mopts[moptLisafs]; ok {
		delete(mopts, moptLisafs)
		fsopts.lisaEnabled, err = strconv.ParseBool(lisafs)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid lisafs option: %s", lisafs)
			return nil, nil, linuxerr.EINVAL
		}
	}
	if !fsopts.lisaEnabled {
		// Parse the 9P protocol version.
		fsopts.version9P = p9.HighestVersionString()
		if version, ok := mopts[moptVersion]; ok {
			delete(mopts, moptVersion)
			fsopts.version9P = version
		}
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
		mfp:          mfp,
		opts:         fsopts,
		iopts:        iopts,
		clock:        ktime.RealtimeClockFromContext(ctx),
		devMinor:     devMinor,
		inoByQIDPath: make(map[uint64]uint64),
		inoByKey:     make(map[inoKey]uint64),
	}

	// Did the user configure a global dentry cache?
	if globalDentryCache != nil {
		fs.dentryCache = globalDentryCache
	} else {
		fs.dentryCache = &dentryCache{maxCachedDentries: defaultMaxCachedDentries}
	}

	fs.vfsfs.Init(vfsObj, &fstype, fs)

	if err := fs.initClientAndRoot(ctx); err != nil {
		fs.vfsfs.DecRef(ctx)
		return nil, nil, err
	}

	return &fs.vfsfs, &fs.root.vfsd, nil
}

func (fs *filesystem) initClientAndRoot(ctx context.Context) error {
	var err error
	if fs.opts.lisaEnabled {
		var rootInode lisafs.Inode
		rootInode, err = fs.initClientLisa(ctx)
		if err != nil {
			return err
		}
		fs.root, err = fs.newDentryLisa(ctx, &rootInode)
		if err != nil {
			fs.clientLisa.CloseFD(ctx, rootInode.ControlFD, false /* flush */)
		}
	} else {
		fs.root, err = fs.initClient(ctx)
	}

	// Set the root's reference count to 2. One reference is returned to the
	// caller, and the other is held by fs to prevent the root from being "cached"
	// and subsequently evicted.
	if err == nil {
		fs.root.refs = atomicbitops.FromInt64(2)
	}
	return err
}

func (fs *filesystem) initClientLisa(ctx context.Context) (lisafs.Inode, error) {
	sock, err := unet.NewSocket(fs.opts.fd)
	if err != nil {
		return lisafs.Inode{}, err
	}

	var rootInode lisafs.Inode
	ctx.UninterruptibleSleepStart(false)
	fs.clientLisa, rootInode, err = lisafs.NewClient(sock)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		return lisafs.Inode{}, err
	}
	if fs.opts.aname == "/" {
		return rootInode, nil
	}

	// Walk to the attach point from root inode. aname is always absolute.
	rootFD := fs.clientLisa.NewFD(rootInode.ControlFD)
	status, inodes, err := rootFD.WalkMultiple(ctx, strings.Split(fs.opts.aname, "/")[1:])
	rootFD.Close(ctx, false /* flush */)
	if err != nil {
		return lisafs.Inode{}, err
	}

	// Close all intermediate FDs to the attach point.
	numInodes := len(inodes)
	for i := 0; i < numInodes-1; i++ {
		curFD := fs.clientLisa.NewFD(inodes[i].ControlFD)
		curFD.Close(ctx, false /* flush */)
	}

	switch status {
	case lisafs.WalkSuccess:
		return inodes[numInodes-1], nil
	default:
		if numInodes > 0 {
			last := fs.clientLisa.NewFD(inodes[numInodes-1].ControlFD)
			last.Close(ctx, false /* flush */)
		}
		log.Warningf("initClientLisa failed because walk to attach point %q failed: lisafs.WalkStatus = %v", fs.opts.aname, status)
		return lisafs.Inode{}, unix.ENOENT
	}
}

func (fs *filesystem) initClient(ctx context.Context) (*dentry, error) {
	// Connect to the server.
	if err := fs.dial(ctx); err != nil {
		return nil, err
	}

	// Perform attach to obtain the filesystem root.
	ctx.UninterruptibleSleepStart(false)
	attached, err := fs.client.Attach(fs.opts.aname)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		return nil, err
	}
	attachFile := p9file{attached}
	qid, attrMask, attr, err := attachFile.getAttr(ctx, dentryAttrMask())
	if err != nil {
		attachFile.close(ctx)
		return nil, err
	}

	// Construct the root dentry.
	root, err := fs.newDentry(ctx, attachFile, qid, attrMask, &attr)
	if err != nil {
		attachFile.close(ctx)
		return nil, err
	}
	return root, nil
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

// Preconditions: fs.client == nil.
func (fs *filesystem) dial(ctx context.Context) error {
	// Establish a connection with the server.
	conn, err := unet.NewSocket(fs.opts.fd)
	if err != nil {
		return err
	}

	// Perform version negotiation with the server.
	ctx.UninterruptibleSleepStart(false)
	client, err := p9.NewClient(conn, fs.opts.msize, fs.opts.version9P)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		conn.Close()
		return err
	}
	// Ownership of conn has been transferred to client.

	fs.client = client
	return nil
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
		if h := d.writeHandleLocked(); h.isOpen() {
			// Write dirty cached data to the remote file.
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
		// Close the connection to the server. This implicitly clunks all fids.
		if fs.opts.lisaEnabled {
			if fs.clientLisa != nil {
				fs.clientLisa.Close()
			}
		} else {
			if fs.client != nil {
				fs.client.Close()
			}
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
		d.dirMu.Lock()
		for _, child := range d.children {
			children = append(children, child)
		}
		d.dirMu.Unlock()
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

func inoKeyFromStat(stat *linux.Statx) inoKey {
	return inoKey{
		ino:      stat.Ino,
		devMinor: stat.DevMinor,
		devMajor: stat.DevMajor,
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
	parent *dentry

	// name is the name of this dentry in its parent. If this dentry is a
	// filesystem root, name is the empty string. name is protected by
	// filesystem.renameMu.
	name string

	// qidPath is the p9.QID.Path for this file. qidPath is immutable.
	qidPath uint64

	// inoKey is used to identify this dentry's inode.
	inoKey inoKey

	// file is the unopened p9.File that backs this dentry. file is immutable.
	//
	// If file.isNil(), this dentry represents a synthetic file, i.e. a file
	// that does not exist on the remote filesystem. As of this writing, the
	// only files that can be synthetic are sockets, pipes, and directories.
	file p9file `state:"nosave"`

	// controlFDLisa is used by lisafs to perform path based operations on this
	// dentry.
	//
	// if !controlFDLisa.Ok(), this dentry represents a synthetic file, i.e. a
	// file that does not exist on the remote filesystem. As of this writing, the
	// only files that can be synthetic are sockets, pipes, and directories.
	controlFDLisa lisafs.ClientFD `state:"nosave"`

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

	dirMu sync.Mutex `state:"nosave"`

	// If this dentry represents a directory, children contains:
	//
	//	- Mappings of child filenames to dentries representing those children.
	//
	//	- Mappings of child filenames that are known not to exist to nil
	//		dentries (only if InteropModeShared is not in effect and the directory
	//		is not synthetic).
	//
	// children is protected by dirMu.
	children map[string]*dentry

	// If this dentry represents a directory, syntheticChildren is the number
	// of child dentries for which dentry.isSynthetic() == true.
	// syntheticChildren is protected by dirMu.
	syntheticChildren int

	// If this dentry represents a directory,
	// dentry.cachedMetadataAuthoritative() == true, and dirents is not nil, it
	// is a cache of all entries in the directory, in the order they were
	// returned by the server. childrenSet just stores the `Name` field of all
	// dirents in a set for fast query. dirents and childrenSet are protected by
	// dirMu and share the same lifecycle.
	dirents     []vfs.Dirent
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

	//	- If this dentry represents a regular file or directory, readFile is the
	//		p9.File used for reads by all regularFileFDs/directoryFDs representing
	//		this dentry, and readFD (if not -1) is a host FD equivalent to readFile
	//		used as a faster alternative.
	//
	//	- If this dentry represents a regular file, writeFile is the p9.File
	//		used for writes by all regularFileFDs representing this dentry, and
	//		writeFD (if not -1) is a host FD equivalent to writeFile used as a
	//		faster alternative.
	//
	//	- If this dentry represents a regular file, mmapFD is the host FD used
	//		for memory mappings. If mmapFD is -1, no such FD is available, and the
	//		internal page cache implementation is used for memory mappings instead.
	//
	// These fields are protected by handleMu. readFD, writeFD, and mmapFD are
	// additionally written using atomic memory operations, allowing them to be
	// read (albeit racily) with atomic.LoadInt32() without locking handleMu.
	//
	// readFile and writeFile may or may not represent the same p9.File. Once
	// either p9.File transitions from closed (isNil() == true) to open
	// (isNil() == false), it may be mutated with handleMu locked, but cannot
	// be closed until the dentry is destroyed.
	//
	// readFD and writeFD may or may not be the same file descriptor. mmapFD is
	// always either -1 or equal to readFD; if !writeFile.isNil() (the file has
	// been opened for writing), it is additionally either -1 or equal to
	// writeFD.
	handleMu    sync.RWMutex       `state:"nosave"`
	readFile    p9file             `state:"nosave"`
	writeFile   p9file             `state:"nosave"`
	readFDLisa  lisafs.ClientFD    `state:"nosave"`
	writeFDLisa lisafs.ClientFD    `state:"nosave"`
	readFD      atomicbitops.Int32 `state:"nosave"`
	writeFD     atomicbitops.Int32 `state:"nosave"`
	mmapFD      atomicbitops.Int32 `state:"nosave"`

	dataMu sync.RWMutex `state:"nosave"`

	// If this dentry represents a regular file that is client-cached, cache
	// maps offsets into the cached file to offsets into
	// filesystem.mfp.MemoryFile() that store the file's data. cache is
	// protected by dataMu.
	cache fsutil.FileRangeSet

	// If this dentry represents a regular file that is client-cached, dirty
	// tracks dirty segments in cache. dirty is protected by dataMu.
	dirty fsutil.DirtySet

	// pf implements platform.File for mappings of hostFD.
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
}

// +stateify savable
type dentryListElem struct {
	// d is the dentry that this elem represents.
	d *dentry
	dentryEntry
}

// dentryAttrMask returns a p9.AttrMask enabling all attributes used by the
// gofer client.
func dentryAttrMask() p9.AttrMask {
	return p9.AttrMask{
		Mode:  true,
		UID:   true,
		GID:   true,
		ATime: true,
		MTime: true,
		CTime: true,
		Size:  true,
		BTime: true,
	}
}

// newDentry creates a new dentry representing the given file. The dentry
// initially has no references, but is not cached; it is the caller's
// responsibility to set the dentry's reference count and/or call
// dentry.checkCachingLocked() as appropriate.
//
// Preconditions: !file.isNil().
func (fs *filesystem) newDentry(ctx context.Context, file p9file, qid p9.QID, mask p9.AttrMask, attr *p9.Attr) (*dentry, error) {
	if !mask.Mode {
		ctx.Warningf("can't create gofer.dentry without file type")
		return nil, linuxerr.EIO
	}
	if attr.Mode.FileType() == p9.ModeRegular && !mask.Size {
		ctx.Warningf("can't create regular file gofer.dentry without file size")
		return nil, linuxerr.EIO
	}

	d := &dentry{
		fs:        fs,
		qidPath:   qid.Path,
		file:      file,
		ino:       fs.inoFromQIDPath(qid.Path),
		mode:      atomicbitops.FromUint32(uint32(attr.Mode)),
		uid:       atomicbitops.FromUint32(uint32(fs.opts.dfltuid)),
		gid:       atomicbitops.FromUint32(uint32(fs.opts.dfltgid)),
		blockSize: atomicbitops.FromUint32(hostarch.PageSize),
		readFD:    atomicbitops.FromInt32(-1),
		writeFD:   atomicbitops.FromInt32(-1),
		mmapFD:    atomicbitops.FromInt32(-1),
	}
	d.pf.dentry = d
	d.cacheEntry.d = d
	d.syncableListEntry.d = d
	if mask.UID {
		d.uid = atomicbitops.FromUint32(dentryUIDFromP9UID(attr.UID))
	}
	if mask.GID {
		d.gid = atomicbitops.FromUint32(dentryGIDFromP9GID(attr.GID))
	}
	if mask.Size {
		d.size = atomicbitops.FromUint64(attr.Size)
	}
	if attr.BlockSize != 0 {
		d.blockSize = atomicbitops.FromUint32(uint32(attr.BlockSize))
	}
	if mask.ATime {
		d.atime = atomicbitops.FromInt64(dentryTimestampFromP9(attr.ATimeSeconds, attr.ATimeNanoSeconds))
	} else {
		d.atime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
	}
	if mask.MTime {
		d.mtime = atomicbitops.FromInt64(dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds))
	} else {
		d.mtime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
	}
	if mask.CTime {
		d.ctime = atomicbitops.FromInt64(dentryTimestampFromP9(attr.CTimeSeconds, attr.CTimeNanoSeconds))
	} else {
		// Approximate ctime with mtime if ctime isn't available.
		d.ctime = atomicbitops.FromInt64(d.mtime.Load())
	}
	if mask.BTime {
		d.btime = atomicbitops.FromInt64(dentryTimestampFromP9(attr.BTimeSeconds, attr.BTimeNanoSeconds))
	}
	if mask.NLink {
		d.nlink = atomicbitops.FromUint32(uint32(attr.NLink))
	} else {
		if attr.Mode.FileType() == p9.ModeDirectory {
			d.nlink = atomicbitops.FromUint32(2)
		} else {
			d.nlink = atomicbitops.FromUint32(1)
		}
	}
	d.vfsd.Init(d)
	refs.Register(d)
	fs.syncMu.Lock()
	fs.syncableDentries.PushBack(&d.syncableListEntry)
	fs.syncMu.Unlock()
	return d, nil
}

func (fs *filesystem) newDentryLisa(ctx context.Context, ino *lisafs.Inode) (*dentry, error) {
	if ino.Stat.Mask&linux.STATX_TYPE == 0 {
		ctx.Warningf("can't create gofer.dentry without file type")
		return nil, linuxerr.EIO
	}
	if ino.Stat.Mode&linux.FileTypeMask == linux.ModeRegular && ino.Stat.Mask&linux.STATX_SIZE == 0 {
		ctx.Warningf("can't create regular file gofer.dentry without file size")
		return nil, linuxerr.EIO
	}

	inoKey := inoKeyFromStat(&ino.Stat)
	d := &dentry{
		fs:            fs,
		inoKey:        inoKey,
		ino:           fs.inoFromKey(inoKey),
		mode:          atomicbitops.FromUint32(uint32(ino.Stat.Mode)),
		uid:           atomicbitops.FromUint32(uint32(fs.opts.dfltuid)),
		gid:           atomicbitops.FromUint32(uint32(fs.opts.dfltgid)),
		blockSize:     atomicbitops.FromUint32(hostarch.PageSize),
		readFD:        atomicbitops.FromInt32(-1),
		writeFD:       atomicbitops.FromInt32(-1),
		mmapFD:        atomicbitops.FromInt32(-1),
		controlFDLisa: fs.clientLisa.NewFD(ino.ControlFD),
	}
	d.pf.dentry = d
	d.cacheEntry.d = d
	d.syncableListEntry.d = d
	if ino.Stat.Mask&linux.STATX_UID != 0 {
		d.uid = atomicbitops.FromUint32(dentryUIDFromLisaUID(lisafs.UID(ino.Stat.UID)))
	}
	if ino.Stat.Mask&linux.STATX_GID != 0 {
		d.gid = atomicbitops.FromUint32(dentryGIDFromLisaGID(lisafs.GID(ino.Stat.GID)))
	}
	if ino.Stat.Mask&linux.STATX_SIZE != 0 {
		d.size = atomicbitops.FromUint64(ino.Stat.Size)
	}
	if ino.Stat.Blksize != 0 {
		d.blockSize = atomicbitops.FromUint32(ino.Stat.Blksize)
	}
	if ino.Stat.Mask&linux.STATX_ATIME != 0 {
		d.atime = atomicbitops.FromInt64(dentryTimestampFromLisa(ino.Stat.Atime))
	} else {
		d.atime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
	}
	if ino.Stat.Mask&linux.STATX_MTIME != 0 {
		d.mtime = atomicbitops.FromInt64(dentryTimestampFromLisa(ino.Stat.Mtime))
	} else {
		d.mtime = atomicbitops.FromInt64(fs.clock.Now().Nanoseconds())
	}
	if ino.Stat.Mask&linux.STATX_CTIME != 0 {
		d.ctime = atomicbitops.FromInt64(dentryTimestampFromLisa(ino.Stat.Ctime))
	} else {
		// Approximate ctime with mtime if ctime isn't available.
		d.ctime = atomicbitops.FromInt64(d.mtime.Load())
	}
	if ino.Stat.Mask&linux.STATX_BTIME != 0 {
		d.btime = atomicbitops.FromInt64(dentryTimestampFromLisa(ino.Stat.Btime))
	}
	if ino.Stat.Mask&linux.STATX_NLINK != 0 {
		d.nlink = atomicbitops.FromUint32(ino.Stat.Nlink)
	} else {
		if ino.Stat.Mode&linux.FileTypeMask == linux.ModeDirectory {
			d.nlink = atomicbitops.FromUint32(2)
		} else {
			d.nlink = atomicbitops.FromUint32(1)
		}
	}
	d.vfsd.Init(d)
	refs.Register(d)
	fs.syncMu.Lock()
	fs.syncableDentries.PushBack(&d.syncableListEntry)
	fs.syncMu.Unlock()
	return d, nil
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

func (fs *filesystem) inoFromQIDPath(qidPath uint64) uint64 {
	fs.inoMu.Lock()
	defer fs.inoMu.Unlock()
	if ino, ok := fs.inoByQIDPath[qidPath]; ok {
		return ino
	}
	ino := fs.nextIno()
	fs.inoByQIDPath[qidPath] = ino
	return ino
}

func (fs *filesystem) nextIno() uint64 {
	return fs.lastIno.Add(1)
}

func (d *dentry) isSynthetic() bool {
	return !d.isControlFileOk()
}

func (d *dentry) cachedMetadataAuthoritative() bool {
	return d.fs.opts.interop != InteropModeShared || d.isSynthetic()
}

// updateFromP9Attrs is called to update d's metadata after an update from the
// remote filesystem.
// Precondition: d.metadataMu must be locked.
// +checklocks:d.metadataMu
func (d *dentry) updateFromP9AttrsLocked(mask p9.AttrMask, attr *p9.Attr) {
	if mask.Mode {
		if got, want := uint32(attr.Mode.FileType()), d.fileType(); got != want {
			panic(fmt.Sprintf("gofer.dentry file type changed from %#o to %#o", want, got))
		}
		d.mode.Store(uint32(attr.Mode))
	}
	if mask.UID {
		d.uid.Store(dentryUIDFromP9UID(attr.UID))
	}
	if mask.GID {
		d.gid.Store(dentryGIDFromP9GID(attr.GID))
	}
	// There is no P9_GETATTR_* bit for I/O block size.
	if attr.BlockSize != 0 {
		d.blockSize.Store(uint32(attr.BlockSize))
	}
	// Don't override newer client-defined timestamps with old server-defined
	// ones.
	if mask.ATime && d.atimeDirty.Load() == 0 {
		d.atime.Store(dentryTimestampFromP9(attr.ATimeSeconds, attr.ATimeNanoSeconds))
	}
	if mask.MTime && d.mtimeDirty.Load() == 0 {
		d.mtime.Store(dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds))
	}
	if mask.CTime {
		d.ctime.Store(dentryTimestampFromP9(attr.CTimeSeconds, attr.CTimeNanoSeconds))
	}
	if mask.BTime {
		d.btime.Store(dentryTimestampFromP9(attr.BTimeSeconds, attr.BTimeNanoSeconds))
	}
	if mask.NLink {
		d.nlink.Store(uint32(attr.NLink))
	}
	if mask.Size {
		d.updateSizeLocked(attr.Size)
	}
}

// updateFromLisaStatLocked is called to update d's metadata after an update
// from the remote filesystem.
// Precondition: d.metadataMu must be locked.
// +checklocks:d.metadataMu
func (d *dentry) updateFromLisaStatLocked(stat *linux.Statx) {
	if stat.Mask&linux.STATX_TYPE != 0 {
		if got, want := stat.Mode&linux.FileTypeMask, d.fileType(); uint32(got) != want {
			panic(fmt.Sprintf("gofer.dentry file type changed from %#o to %#o", want, got))
		}
	}
	if stat.Mask&linux.STATX_MODE != 0 {
		d.mode.Store(uint32(stat.Mode))
	}
	if stat.Mask&linux.STATX_UID != 0 {
		d.uid.Store(dentryUIDFromLisaUID(lisafs.UID(stat.UID)))
	}
	if stat.Mask&linux.STATX_GID != 0 {
		d.gid.Store(dentryGIDFromLisaGID(lisafs.GID(stat.GID)))
	}
	if stat.Blksize != 0 {
		d.blockSize.Store(stat.Blksize)
	}
	// Don't override newer client-defined timestamps with old server-defined
	// ones.
	if stat.Mask&linux.STATX_ATIME != 0 && d.atimeDirty.Load() == 0 {
		d.atime.Store(dentryTimestampFromLisa(stat.Atime))
	}
	if stat.Mask&linux.STATX_MTIME != 0 && d.mtimeDirty.Load() == 0 {
		d.mtime.Store(dentryTimestampFromLisa(stat.Mtime))
	}
	if stat.Mask&linux.STATX_CTIME != 0 {
		d.ctime.Store(dentryTimestampFromLisa(stat.Ctime))
	}
	if stat.Mask&linux.STATX_BTIME != 0 {
		d.btime.Store(dentryTimestampFromLisa(stat.Btime))
	}
	if stat.Mask&linux.STATX_NLINK != 0 {
		d.nlink.Store(stat.Nlink)
	}
	if stat.Mask&linux.STATX_SIZE != 0 {
		d.updateSizeLocked(stat.Size)
	}
}

// Preconditions: !d.isSynthetic().
// Preconditions: d.metadataMu is locked.
// +checklocks:d.metadataMu
func (d *dentry) refreshSizeLocked(ctx context.Context) error {
	d.handleMu.RLock()

	// Can use RacyLoad() because handleMu is locked.
	if d.writeFD.RacyLoad() < 0 {
		d.handleMu.RUnlock()
		// Ask the gofer if we don't have a host FD.
		if d.fs.opts.lisaEnabled {
			return d.updateFromStatLisaLocked(ctx, nil)
		}
		return d.updateFromGetattrLocked(ctx, p9file{})
	}

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
func (d *dentry) updateFromGetattr(ctx context.Context) error {
	// d.metadataMu must be locked *before* we getAttr so that we do not end up
	// updating stale attributes in d.updateFromP9AttrsLocked().
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	if d.fs.opts.lisaEnabled {
		return d.updateFromStatLisaLocked(ctx, nil)
	}
	return d.updateFromGetattrLocked(ctx, p9file{})
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.metadataMu is locked.
//
// +checklocks:d.metadataMu
func (d *dentry) updateFromStatLisaLocked(ctx context.Context, fdLisa *lisafs.ClientFD) error {
	handleMuRLocked := false
	if fdLisa == nil {
		// Use open FDs in preferenece to the control FD. This may be significantly
		// more efficient in some implementations. Prefer a writable FD over a
		// readable one since some filesystem implementations may update a writable
		// FD's metadata after writes, without making metadata updates immediately
		// visible to read-only FDs representing the same file.
		d.handleMu.RLock()
		switch {
		case d.writeFDLisa.Ok():
			fdLisa = &d.writeFDLisa
			handleMuRLocked = true
		case d.readFDLisa.Ok():
			fdLisa = &d.readFDLisa
			handleMuRLocked = true
		default:
			fdLisa = &d.controlFDLisa
			d.handleMu.RUnlock()
		}
	}

	var stat linux.Statx
	err := fdLisa.StatTo(ctx, &stat)
	if handleMuRLocked {
		// handleMu must be released before updateFromLisaStatLocked().
		d.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	if err != nil {
		return err
	}
	d.updateFromLisaStatLocked(&stat)
	return nil
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.metadataMu is locked.
//
// +checklocks:d.metadataMu
func (d *dentry) updateFromGetattrLocked(ctx context.Context, file p9file) error {
	handleMuRLocked := false
	if file.isNil() {
		// Use d.readFile or d.writeFile, which represent 9P FIDs that have
		// been opened, in preference to d.file, which represents a 9P fid that
		// has not. This may be significantly more efficient in some
		// implementations. Prefer d.writeFile over d.readFile since some
		// filesystem implementations may update a writable handle's metadata
		// after writes to that handle, without making metadata updates
		// immediately visible to read-only handles representing the same file.
		d.handleMu.RLock()
		switch {
		case !d.writeFile.isNil():
			file = d.writeFile
			handleMuRLocked = true
		case !d.readFile.isNil():
			file = d.readFile
			handleMuRLocked = true
		default:
			file = d.file
			d.handleMu.RUnlock()
		}
	}

	_, attrMask, attr, err := file.getAttr(ctx, dentryAttrMask())
	if handleMuRLocked {
		// handleMu must be released before updateFromP9AttrsLocked().
		d.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	if err != nil {
		return err
	}
	d.updateFromP9AttrsLocked(attrMask, &attr)
	return nil
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
			if stat.Mask&linux.STATX_SIZE != 0 {
				// d.dataMu must be held around the update to both the remote
				// file's size and d.size to serialize with writeback (which
				// might otherwise write data back up to the old d.size after
				// the remote file has been truncated).
				d.dataMu.Lock()
			}
			if d.fs.opts.lisaEnabled {
				var err error
				failureMask, failureErr, err = d.controlFDLisa.SetStat(ctx, stat)
				if err != nil {
					if stat.Mask&linux.STATX_SIZE != 0 {
						d.dataMu.Unlock() // +checklocksforce: locked conditionally above
					}
					return err
				}
			} else {
				if err := d.file.setAttr(ctx, p9.SetAttrMask{
					Permissions:        stat.Mask&linux.STATX_MODE != 0,
					UID:                stat.Mask&linux.STATX_UID != 0,
					GID:                stat.Mask&linux.STATX_GID != 0,
					Size:               stat.Mask&linux.STATX_SIZE != 0,
					ATime:              stat.Mask&linux.STATX_ATIME != 0,
					MTime:              stat.Mask&linux.STATX_MTIME != 0,
					ATimeNotSystemTime: stat.Mask&linux.STATX_ATIME != 0 && stat.Atime.Nsec != linux.UTIME_NOW,
					MTimeNotSystemTime: stat.Mask&linux.STATX_MTIME != 0 && stat.Mtime.Nsec != linux.UTIME_NOW,
				}, p9.SetAttr{
					Permissions:      p9.FileMode(stat.Mode),
					UID:              p9.UID(stat.UID),
					GID:              p9.GID(stat.GID),
					Size:             stat.Size,
					ATimeSeconds:     uint64(stat.Atime.Sec),
					ATimeNanoSeconds: uint64(stat.Atime.Nsec),
					MTimeSeconds:     uint64(stat.Mtime.Sec),
					MTimeNanoSeconds: uint64(stat.Mtime.Nsec),
				}); err != nil {
					if stat.Mask&linux.STATX_SIZE != 0 {
						d.dataMu.Unlock() // +checklocksforce: locked conditionally above
					}
					return err
				}
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

// Preconditions:
// - filesystem.renameMu must be locked.
// - d.dirMu must be locked.
// - d.isDir().
// - fs.opts.lisaEnabled.
func (d *dentry) mknodLisaLocked(ctx context.Context, name string, creds *auth.Credentials, opts vfs.MknodOptions, ds **[]*dentry) error {
	if _, ok := opts.Endpoint.(transport.HostBoundEndpoint); !ok {
		childInode, err := d.controlFDLisa.MknodAt(ctx, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID), opts.DevMinor, opts.DevMajor)
		if err != nil {
			return err
		}
		return d.insertCreatedChildLocked(ctx, &childInode, name, nil, ds)
	}

	// This mknod(2) is coming from unix bind(2), as opts.Endpoint is set.
	sockType := opts.Endpoint.(transport.Endpoint).Type()
	childInode, boundSocketFD, err := d.controlFDLisa.BindAt(ctx, sockType, name, opts.Mode, lisafs.UID(creds.EffectiveKUID), lisafs.GID(creds.EffectiveKGID))
	if err != nil {
		return err
	}
	hbep := opts.Endpoint.(transport.HostBoundEndpoint)
	if err := hbep.SetBoundSocketFD(boundSocketFD); err != nil {
		boundSocketFD.Close(ctx)
		if err := d.controlFDLisa.UnlinkAt(ctx, name, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up socket which was created by BindAt RPC: %v", err)
		}
		d.fs.clientLisa.CloseFD(ctx, childInode.ControlFD, false /* flush */)
		return err
	}
	if err := d.insertCreatedChildLocked(ctx, &childInode, name, func(child *dentry) {
		// Set the endpoint on the newly created child dentry.
		child.endpoint = opts.Endpoint
	}, ds); err != nil {
		hbep.ResetBoundSocketFD(ctx)
		return err
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
	// Deny access to the "security" and "system" namespaces since applications
	// may expect these to affect kernel behavior in unimplemented ways
	// (b/148380782). Allow all other extended attributes to be passed through
	// to the remote filesystem. This is inconsistent with Linux's 9p client,
	// but consistent with other filesystems (e.g. FUSE).
	//
	// NOTE(b/202533394): Also disallow "trusted" namespace for now. This is
	// consistent with the VFS1 gofer client.
	if strings.HasPrefix(name, linux.XATTR_SECURITY_PREFIX) || strings.HasPrefix(name, linux.XATTR_SYSTEM_PREFIX) || strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
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

func dentryUIDFromP9UID(uid p9.UID) uint32 {
	if !uid.Ok() {
		return uint32(auth.OverflowUID)
	}
	return uint32(uid)
}

func dentryGIDFromP9GID(gid p9.GID) uint32 {
	if !gid.Ok() {
		return uint32(auth.OverflowGID)
	}
	return uint32(gid)
}

func dentryUIDFromLisaUID(uid lisafs.UID) uint32 {
	if !uid.Ok() {
		return uint32(auth.OverflowUID)
	}
	return uint32(uid)
}

func dentryGIDFromLisaGID(gid lisafs.GID) uint32 {
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
	if d.parent != nil {
		d.parent.watches.Notify(ctx, d.name, events, cookie, et, d.isDeleted())
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
		if d.parent != nil {
			d.parent.dirMu.Lock()
			delete(d.parent.children, d.name)
			d.parent.dirMu.Unlock()
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
	if d.parent != nil {
		d.parent.dirMu.Lock()
		if !d.vfsd.IsDead() {
			// Note that d can't be a mount point (in any mount namespace), since VFS
			// holds references on mount points.
			d.fs.vfsfs.VirtualFilesystem().InvalidateDentry(ctx, &d.vfsd)
			delete(d.parent.children, d.name)
			// We're only deleting the dentry, not the file it
			// represents, so we don't need to update
			// victim parent.dirents etc.
		}
		d.parent.dirMu.Unlock()
	}
	// Safe to unlock cachingMu now that d.vfsd.IsDead(). Henceforth any
	// concurrent caching attempts on d will attempt to destroy it and so will
	// try to acquire fs.renameMu (which we have already acquiredd). Hence,
	// fs.renameMu will synchronize the destroy attempts.
	d.cachingMu.Unlock()
	d.destroyLocked(ctx) // +checklocksforce: owned as precondition.
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

	mf := d.fs.mfp.MemoryFile()
	d.handleMu.Lock()
	d.dataMu.Lock()
	if h := d.writeHandleLocked(); h.isOpen() {
		// Write dirty pages back to the remote filesystem.
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
	if d.fs.opts.lisaEnabled {
		if d.readFDLisa.Ok() && d.readFDLisa.ID() != d.writeFDLisa.ID() {
			d.readFDLisa.Close(ctx, false /* flush */)
		}
		if d.writeFDLisa.Ok() {
			d.writeFDLisa.Close(ctx, false /* flush */)
		}
	} else {
		// Clunk open fids and close open host FDs.
		if !d.readFile.isNil() {
			_ = d.readFile.close(ctx)
		}
		if !d.writeFile.isNil() && d.readFile != d.writeFile {
			_ = d.writeFile.close(ctx)
		}
		d.readFile = p9file{}
		d.writeFile = p9file{}
	}
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

		// Close the control FD.
		if d.fs.opts.lisaEnabled {
			// Propagate the Close RPCs immediately to the server if the dentry being
			// destroyed is a deleted regular file. This is to release the disk space
			// on remote immediately.
			flushClose := d.isDeleted() && d.isRegularFile()
			d.controlFDLisa.Close(ctx, flushClose)
		} else {
			if err := d.file.close(ctx); err != nil {
				log.Warningf("gofer.dentry.destroyLocked: failed to close file: %v", err)
			}
			d.file = p9file{}
		}

		// Remove d from the set of syncable dentries.
		d.fs.syncMu.Lock()
		d.fs.syncableDentries.Remove(&d.syncableListEntry)
		d.fs.syncMu.Unlock()
	}

	d.fs.renameMu.Lock()

	// Drop the reference held by d on its parent without recursively locking
	// d.fs.renameMu.
	if d.parent != nil && d.parent.decRefNoCaching() == 0 {
		d.parent.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	}
	refs.Unregister(d)
}

func (d *dentry) isDeleted() bool {
	return d.deleted.Load() != 0
}

func (d *dentry) setDeleted() {
	d.deleted.Store(1)
}

func (d *dentry) isControlFileOk() bool {
	if d.fs.opts.lisaEnabled {
		return d.controlFDLisa.Ok()
	}
	return !d.file.isNil()
}

func (d *dentry) isReadFileOk() bool {
	if d.fs.opts.lisaEnabled {
		return d.readFDLisa.Ok()
	}
	return !d.readFile.isNil()
}

func (d *dentry) listXattr(ctx context.Context, size uint64) ([]string, error) {
	if !d.isControlFileOk() {
		return nil, nil
	}

	if d.fs.opts.lisaEnabled {
		return d.controlFDLisa.ListXattr(ctx, size)
	}

	xattrMap, err := d.file.listXattr(ctx, size)
	if err != nil {
		return nil, err
	}
	xattrs := make([]string, 0, len(xattrMap))
	for x := range xattrMap {
		xattrs = append(xattrs, x)
	}
	return xattrs, nil
}

func (d *dentry) getXattr(ctx context.Context, creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	if !d.isControlFileOk() {
		return "", linuxerr.ENODATA
	}
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayRead); err != nil {
		return "", err
	}
	if d.fs.opts.lisaEnabled {
		return d.controlFDLisa.GetXattr(ctx, opts.Name, opts.Size)
	}
	return d.file.getXattr(ctx, opts.Name, opts.Size)
}

func (d *dentry) setXattr(ctx context.Context, creds *auth.Credentials, opts *vfs.SetXattrOptions) error {
	if !d.isControlFileOk() {
		return linuxerr.EPERM
	}
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayWrite); err != nil {
		return err
	}
	if d.fs.opts.lisaEnabled {
		return d.controlFDLisa.SetXattr(ctx, opts.Name, opts.Value, opts.Flags)
	}
	return d.file.setXattr(ctx, opts.Name, opts.Value, opts.Flags)
}

func (d *dentry) removeXattr(ctx context.Context, creds *auth.Credentials, name string) error {
	if !d.isControlFileOk() {
		return linuxerr.EPERM
	}
	if err := d.checkXattrPermissions(creds, name, vfs.MayWrite); err != nil {
		return err
	}
	if d.fs.opts.lisaEnabled {
		return d.controlFDLisa.RemoveXattr(ctx, name)
	}
	return d.file.removeXattr(ctx, name)
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.isRegularFile() || d.isDir().
func (d *dentry) ensureSharedHandle(ctx context.Context, read, write, trunc bool) error {
	// O_TRUNC unconditionally requires us to obtain a new handle (opened with
	// O_TRUNC).
	if !trunc {
		d.handleMu.RLock()
		var canReuseCurHandle bool
		if d.fs.opts.lisaEnabled {
			canReuseCurHandle = (!read || d.readFDLisa.Ok()) && (!write || d.writeFDLisa.Ok())
		} else {
			canReuseCurHandle = (!read || !d.readFile.isNil()) && (!write || !d.writeFile.isNil())
		}
		d.handleMu.RUnlock()
		if canReuseCurHandle {
			// Current handles are sufficient.
			return nil
		}
	}

	var fdsToCloseArr [2]int32
	fdsToClose := fdsToCloseArr[:0]
	invalidateTranslations := false
	d.handleMu.Lock()
	var needNewHandle bool
	if d.fs.opts.lisaEnabled {
		needNewHandle = (read && !d.readFDLisa.Ok()) || (write && !d.writeFDLisa.Ok()) || trunc
	} else {
		needNewHandle = (read && d.readFile.isNil()) || (write && d.writeFile.isNil()) || trunc
	}
	if needNewHandle {
		// Get a new handle. If this file has been opened for both reading and
		// writing, try to get a single handle that is usable for both:
		//
		//	- Writable memory mappings of a host FD require that the host FD is
		//		opened for both reading and writing.
		//
		//	- NOTE(b/141991141): Some filesystems may not ensure coherence
		//		between multiple handles for the same file.
		var (
			openReadable bool
			openWritable bool
			h            handle
			err          error
		)
		if d.fs.opts.lisaEnabled {
			openReadable = d.readFDLisa.Ok() || read
			openWritable = d.writeFDLisa.Ok() || write
			h, err = openHandleLisa(ctx, d.controlFDLisa, openReadable, openWritable, trunc)
		} else {
			openReadable = !d.readFile.isNil() || read
			openWritable = !d.writeFile.isNil() || write
			h, err = openHandle(ctx, d.file, openReadable, openWritable, trunc)
		}
		if linuxerr.Equals(linuxerr.EACCES, err) && (openReadable != read || openWritable != write) {
			// It may not be possible to use a single handle for both
			// reading and writing, since permissions on the file may have
			// changed to e.g. disallow reading after previously being
			// opened for reading. In this case, we have no choice but to
			// use separate handles for reading and writing.
			ctx.Debugf("gofer.dentry.ensureSharedHandle: bifurcating read/write handles for dentry %p", d)
			openReadable = read
			openWritable = write
			if d.fs.opts.lisaEnabled {
				h, err = openHandleLisa(ctx, d.controlFDLisa, openReadable, openWritable, trunc)
			} else {
				h, err = openHandle(ctx, d.file, openReadable, openWritable, trunc)
			}
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
				d.readFD.Store(h.fd)
				// If the file has not been opened for writing, the new FD may
				// be used for read-only memory mappings. If the file was
				// previously opened for reading (without an FD), then existing
				// translations of the file may use the internal page cache;
				// invalidate those mappings.
				if d.fs.opts.lisaEnabled {
					if !d.writeFDLisa.Ok() {
						invalidateTranslations = d.readFDLisa.Ok()
						d.mmapFD.Store(h.fd)
					}
				} else {
					if d.writeFile.isNil() {
						invalidateTranslations = !d.readFile.isNil()
						d.mmapFD.Store(h.fd)
					}
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

		// Switch to new fids/FDs.
		if d.fs.opts.lisaEnabled {
			oldReadFD := lisafs.InvalidFDID
			if openReadable {
				oldReadFD = d.readFDLisa.ID()
				d.readFDLisa = h.fdLisa
			}
			oldWriteFD := lisafs.InvalidFDID
			if openWritable {
				oldWriteFD = d.writeFDLisa.ID()
				d.writeFDLisa = h.fdLisa
			}
			// NOTE(b/141991141): Close old FDs before making new fids visible (by
			// unlocking d.handleMu).
			if oldReadFD.Ok() {
				d.fs.clientLisa.CloseFD(ctx, oldReadFD, false /* flush */)
			}
			if oldWriteFD.Ok() && oldReadFD != oldWriteFD {
				d.fs.clientLisa.CloseFD(ctx, oldWriteFD, false /* flush */)
			}
		} else {
			var oldReadFile p9file
			if openReadable {
				oldReadFile = d.readFile
				d.readFile = h.file
			}
			var oldWriteFile p9file
			if openWritable {
				oldWriteFile = d.writeFile
				d.writeFile = h.file
			}
			// NOTE(b/141991141): Clunk old fids before making new fids visible (by
			// unlocking d.handleMu).
			if !oldReadFile.isNil() {
				oldReadFile.close(ctx)
			}
			if !oldWriteFile.isNil() && oldReadFile != oldWriteFile {
				oldWriteFile.close(ctx)
			}
		}
	}
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

// Preconditions: d.handleMu must be locked.
func (d *dentry) readHandleLocked() handle {
	return handle{
		fdLisa: d.readFDLisa,
		file:   d.readFile,
		fd:     d.readFD.RacyLoad(),
	}
}

// Preconditions: d.handleMu must be locked.
func (d *dentry) writeHandleLocked() handle {
	return handle{
		fdLisa: d.writeFDLisa,
		file:   d.writeFile,
		fd:     d.writeFD.RacyLoad(),
	}
}

func (d *dentry) syncRemoteFile(ctx context.Context) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	return d.syncRemoteFileLocked(ctx)
}

// Preconditions: d.handleMu must be locked.
func (d *dentry) syncRemoteFileLocked(ctx context.Context) error {
	// If we have a host FD, fsyncing it is likely to be faster than an fsync
	// RPC. Prefer syncing write handles over read handles, since some remote
	// filesystem implementations may not sync changes made through write
	// handles otherwise.
	if d.writeFD.RacyLoad() >= 0 {
		ctx.UninterruptibleSleepStart(false)
		err := unix.Fsync(int(d.writeFD.RacyLoad()))
		ctx.UninterruptibleSleepFinish(false)
		return err
	}
	if d.fs.opts.lisaEnabled && d.writeFDLisa.Ok() {
		return d.writeFDLisa.Sync(ctx)
	} else if !d.fs.opts.lisaEnabled && !d.writeFile.isNil() {
		return d.writeFile.fsync(ctx)
	}
	if d.readFD.RacyLoad() >= 0 {
		ctx.UninterruptibleSleepStart(false)
		err := unix.Fsync(int(d.readFD.RacyLoad()))
		ctx.UninterruptibleSleepFinish(false)
		return err
	}
	if d.fs.opts.lisaEnabled && d.readFDLisa.Ok() {
		return d.readFDLisa.Sync(ctx)
	} else if !d.fs.opts.lisaEnabled && !d.readFile.isNil() {
		return d.readFile.fsync(ctx)
	}
	return nil
}

func (d *dentry) syncCachedFile(ctx context.Context, forFilesystemSync bool) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	h := d.writeHandleLocked()
	if h.isOpen() {
		// Write back dirty pages to the remote file.
		d.dataMu.Lock()
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
		if d.isRegularFile() && h.isOpen() {
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
		if d.fs.opts.lisaEnabled {
			// Use specialFileFD.handle.fileLisa for the Stat if available, for the
			// same reason that we try to use open FD in updateFromStatLisaLocked().
			var fdLisa *lisafs.ClientFD
			if sffd, ok := fd.vfsfd.Impl().(*specialFileFD); ok {
				fdLisa = &sffd.handle.fdLisa
			}
			d.metadataMu.Lock()
			err := d.updateFromStatLisaLocked(ctx, fdLisa)
			d.metadataMu.Unlock()
			if err != nil {
				return linux.Statx{}, err
			}
		} else {
			// Use specialFileFD.handle.file for the getattr if available, for the
			// same reason that we try to use open file handles in
			// dentry.updateFromGetattrLocked().
			var file p9file
			if sffd, ok := fd.vfsfd.Impl().(*specialFileFD); ok {
				file = sffd.handle.file
			}
			d.metadataMu.Lock()
			err := d.updateFromGetattrLocked(ctx, file)
			d.metadataMu.Unlock()
			if err != nil {
				return linux.Statx{}, err
			}
		}
	}
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
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
