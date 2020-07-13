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
//   regularFileFD/directoryFD.mu
//     filesystem.renameMu
//       dentry.dirMu
//         filesystem.syncMu
//         dentry.metadataMu
//           *** "memmap.Mappable locks" below this point
//           dentry.mapsMu
//             *** "memmap.Mappable locks taken by Translate" below this point
//             dentry.handleMu
//               dentry.dataMu
//
// Locking dentry.dirMu in multiple dentries requires that either ancestor
// dentries are locked before descendant dentries, or that filesystem.renameMu
// is locked for writing.
package gofer

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Name is the default filesystem name.
const Name = "9p"

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// mfp is used to allocate memory that caches regular file contents. mfp is
	// immutable.
	mfp pgalloc.MemoryFileProvider

	// Immutable options.
	opts  filesystemOptions
	iopts InternalFilesystemOptions

	// client is the client used by this filesystem. client is immutable.
	client *p9.Client

	// clock is a realtime clock used to set timestamps in file operations.
	clock ktime.Clock

	// devMinor is the filesystem's minor device number. devMinor is immutable.
	devMinor uint32

	// renameMu serves two purposes:
	//
	// - It synchronizes path resolution with renaming initiated by this
	// client.
	//
	// - It is held by path resolution to ensure that reachable dentries remain
	// valid. A dentry is reachable by path resolution if it has a non-zero
	// reference count (such that it is usable as vfs.ResolvingPath.Start() or
	// is reachable from its children), or if it is a child dentry (such that
	// it is reachable from its parent).
	renameMu sync.RWMutex

	// cachedDentries contains all dentries with 0 references. (Due to race
	// conditions, it may also contain dentries with non-zero references.)
	// cachedDentriesLen is the number of dentries in cachedDentries. These
	// fields are protected by renameMu.
	cachedDentries    dentryList
	cachedDentriesLen uint64

	// syncableDentries contains all dentries in this filesystem for which
	// !dentry.file.isNil(). specialFileFDs contains all open specialFileFDs.
	// These fields are protected by syncMu.
	syncMu           sync.Mutex
	syncableDentries map[*dentry]struct{}
	specialFileFDs   map[*specialFileFD]struct{}

	// syntheticSeq stores a counter to used to generate unique inodeNumber for
	// synthetic dentries.
	syntheticSeq uint64
}

// inodeNumber represents inode number reported in Dirent.Ino. For regular
// dentries, it comes from QID.Path from the 9P server. Synthetic dentries
// have have their inodeNumber generated sequentially, with the MSB reserved to
// prevent conflicts with regular dentries.
type inodeNumber uint64

// Reserve MSB for synthetic mounts.
const syntheticInoMask = uint64(1) << 63

func inoFromPath(path uint64) inodeNumber {
	if path&syntheticInoMask != 0 {
		log.Warningf("Dropping MSB from ino, collision is possible. Original: %d, new: %d", path, path&^syntheticInoMask)
	}
	return inodeNumber(path &^ syntheticInoMask)
}

type filesystemOptions struct {
	// "Standard" 9P options.
	fd      int
	aname   string
	interop InteropMode // derived from the "cache" mount option
	dfltuid auth.KUID
	dfltgid auth.KGID
	msize   uint32
	version string

	// maxCachedDentries is the maximum number of dentries with 0 references
	// retained by the client.
	maxCachedDentries uint64

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
	// do. Note that this disables client caching and mmap for regular files.
	regularFilesUseSpecialFileFD bool
}

// InteropMode controls the client's interaction with other remote filesystem
// users.
type InteropMode uint32

const (
	// InteropModeExclusive is appropriate when the filesystem client is the
	// only user of the remote filesystem.
	//
	// - The client may cache arbitrary filesystem state (file data, metadata,
	// filesystem structure, etc.).
	//
	// - Client changes to filesystem state may be sent to the remote
	// filesystem asynchronously, except when server permission checks are
	// necessary.
	//
	// - File timestamps are based on client clocks. This ensures that users of
	// the client observe timestamps that are coherent with their own clocks
	// and consistent with Linux's semantics. However, since it is not always
	// possible for clients to set arbitrary atimes and mtimes, and never
	// possible for clients to set arbitrary ctimes, file timestamp changes are
	// stored in the client only and never sent to the remote filesystem.
	InteropModeExclusive InteropMode = iota

	// InteropModeWritethrough is appropriate when there are read-only users of
	// the remote filesystem that expect to observe changes made by the
	// filesystem client.
	//
	// - The client may cache arbitrary filesystem state.
	//
	// - Client changes to filesystem state must be sent to the remote
	// filesystem synchronously.
	//
	// - File timestamps are based on client clocks. As a corollary, access
	// timestamp changes from other remote filesystem users will not be visible
	// to the client.
	InteropModeWritethrough

	// InteropModeShared is appropriate when there are users of the remote
	// filesystem that may mutate its state other than the client.
	//
	// - The client must verify ("revalidate") cached filesystem state before
	// using it.
	//
	// - Client changes to filesystem state must be sent to the remote
	// filesystem synchronously.
	//
	// - File timestamps are based on server clocks. This is necessary to
	// ensure that timestamp changes are synchronized between remote filesystem
	// users.
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
type InternalFilesystemOptions struct {
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

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: context does not provide a pgalloc.MemoryFileProvider")
		return nil, nil, syserror.EINVAL
	}

	mopts := vfs.GenericParseMountOptions(opts.Data)
	var fsopts filesystemOptions

	// Check that the transport is "fd".
	trans, ok := mopts["trans"]
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: transport must be specified as 'trans=fd'")
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "trans")
	if trans != "fd" {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: unsupported transport: trans=%s", trans)
		return nil, nil, syserror.EINVAL
	}

	// Check that read and write FDs are provided and identical.
	rfdstr, ok := mopts["rfdno"]
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: read FD must be specified as 'rfdno=<file descriptor>")
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "rfdno")
	rfd, err := strconv.Atoi(rfdstr)
	if err != nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid read FD: rfdno=%s", rfdstr)
		return nil, nil, syserror.EINVAL
	}
	wfdstr, ok := mopts["wfdno"]
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: write FD must be specified as 'wfdno=<file descriptor>")
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "wfdno")
	wfd, err := strconv.Atoi(wfdstr)
	if err != nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid write FD: wfdno=%s", wfdstr)
		return nil, nil, syserror.EINVAL
	}
	if rfd != wfd {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: read FD (%d) and write FD (%d) must be equal", rfd, wfd)
		return nil, nil, syserror.EINVAL
	}
	fsopts.fd = rfd

	// Get the attach name.
	fsopts.aname = "/"
	if aname, ok := mopts["aname"]; ok {
		delete(mopts, "aname")
		fsopts.aname = aname
	}

	// Parse the cache policy. For historical reasons, this defaults to the
	// least generally-applicable option, InteropModeExclusive.
	fsopts.interop = InteropModeExclusive
	if cache, ok := mopts["cache"]; ok {
		delete(mopts, "cache")
		switch cache {
		case "fscache":
			fsopts.interop = InteropModeExclusive
		case "fscache_writethrough":
			fsopts.interop = InteropModeWritethrough
		case "none":
			fsopts.regularFilesUseSpecialFileFD = true
			fallthrough
		case "remote_revalidating":
			fsopts.interop = InteropModeShared
		default:
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid cache policy: cache=%s", cache)
			return nil, nil, syserror.EINVAL
		}
	}

	// Parse the default UID and GID.
	fsopts.dfltuid = _V9FS_DEFUID
	if dfltuidstr, ok := mopts["dfltuid"]; ok {
		delete(mopts, "dfltuid")
		dfltuid, err := strconv.ParseUint(dfltuidstr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid default UID: dfltuid=%s", dfltuidstr)
			return nil, nil, syserror.EINVAL
		}
		// In Linux, dfltuid is interpreted as a UID and is converted to a KUID
		// in the caller's user namespace, but goferfs isn't
		// application-mountable.
		fsopts.dfltuid = auth.KUID(dfltuid)
	}
	fsopts.dfltgid = _V9FS_DEFGID
	if dfltgidstr, ok := mopts["dfltgid"]; ok {
		delete(mopts, "dfltgid")
		dfltgid, err := strconv.ParseUint(dfltgidstr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid default UID: dfltgid=%s", dfltgidstr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.dfltgid = auth.KGID(dfltgid)
	}

	// Parse the 9P message size.
	fsopts.msize = 1024 * 1024 // 1M, tested to give good enough performance up to 64M
	if msizestr, ok := mopts["msize"]; ok {
		delete(mopts, "msize")
		msize, err := strconv.ParseUint(msizestr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid message size: msize=%s", msizestr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.msize = uint32(msize)
	}

	// Parse the 9P protocol version.
	fsopts.version = p9.HighestVersionString()
	if version, ok := mopts["version"]; ok {
		delete(mopts, "version")
		fsopts.version = version
	}

	// Parse the dentry cache limit.
	fsopts.maxCachedDentries = 1000
	if str, ok := mopts["dentry_cache_limit"]; ok {
		delete(mopts, "dentry_cache_limit")
		maxCachedDentries, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid dentry cache limit: dentry_cache_limit=%s", str)
			return nil, nil, syserror.EINVAL
		}
		fsopts.maxCachedDentries = maxCachedDentries
	}

	// Handle simple flags.
	if _, ok := mopts["force_page_cache"]; ok {
		delete(mopts, "force_page_cache")
		fsopts.forcePageCache = true
	}
	if _, ok := mopts["limit_host_fd_translation"]; ok {
		delete(mopts, "limit_host_fd_translation")
		fsopts.limitHostFDTranslation = true
	}
	if _, ok := mopts["overlayfs_stale_read"]; ok {
		delete(mopts, "overlayfs_stale_read")
		fsopts.overlayfsStaleRead = true
	}
	// fsopts.regularFilesUseSpecialFileFD can only be enabled by specifying
	// "cache=none".

	// Check for unparsed options.
	if len(mopts) != 0 {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, syserror.EINVAL
	}

	// Handle internal options.
	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if opts.InternalData != nil && !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: GetFilesystemOptions.InternalData has type %T, wanted gofer.InternalFilesystemOptions", opts.InternalData)
		return nil, nil, syserror.EINVAL
	}
	// If !ok, iopts being the zero value is correct.

	// Establish a connection with the server.
	conn, err := unet.NewSocket(fsopts.fd)
	if err != nil {
		return nil, nil, err
	}

	// Perform version negotiation with the server.
	ctx.UninterruptibleSleepStart(false)
	client, err := p9.NewClient(conn, fsopts.msize, fsopts.version)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	// Ownership of conn has been transferred to client.

	// Perform attach to obtain the filesystem root.
	ctx.UninterruptibleSleepStart(false)
	attached, err := client.Attach(fsopts.aname)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	attachFile := p9file{attached}
	qid, attrMask, attr, err := attachFile.getAttr(ctx, dentryAttrMask())
	if err != nil {
		attachFile.close(ctx)
		client.Close()
		return nil, nil, err
	}

	// Construct the filesystem object.
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		attachFile.close(ctx)
		client.Close()
		return nil, nil, err
	}
	fs := &filesystem{
		mfp:              mfp,
		opts:             fsopts,
		iopts:            iopts,
		client:           client,
		clock:            ktime.RealtimeClockFromContext(ctx),
		devMinor:         devMinor,
		syncableDentries: make(map[*dentry]struct{}),
		specialFileFDs:   make(map[*specialFileFD]struct{}),
	}
	fs.vfsfs.Init(vfsObj, &fstype, fs)

	// Construct the root dentry.
	root, err := fs.newDentry(ctx, attachFile, qid, attrMask, &attr)
	if err != nil {
		attachFile.close(ctx)
		fs.vfsfs.DecRef()
		return nil, nil, err
	}
	// Set the root's reference count to 2. One reference is returned to the
	// caller, and the other is deliberately leaked to prevent the root from
	// being "cached" and subsequently evicted. Its resources will still be
	// cleaned up by fs.Release().
	root.refs = 2

	return &fs.vfsfs, &root.vfsd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	ctx := context.Background()
	mf := fs.mfp.MemoryFile()

	fs.syncMu.Lock()
	for d := range fs.syncableDentries {
		d.handleMu.Lock()
		d.dataMu.Lock()
		if d.handleWritable {
			// Write dirty cached data to the remote file.
			if err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size, fs.mfp.MemoryFile(), d.handle.writeFromBlocksAt); err != nil {
				log.Warningf("gofer.filesystem.Release: failed to flush dentry: %v", err)
			}
			// TODO(jamieliu): Do we need to flushf/fsync d?
		}
		// Discard cached pages.
		d.cache.DropAll(mf)
		d.dirty.RemoveAll()
		d.dataMu.Unlock()
		// Close the host fd if one exists.
		if d.handle.fd >= 0 {
			syscall.Close(int(d.handle.fd))
			d.handle.fd = -1
		}
		d.handleMu.Unlock()
	}
	// There can't be any specialFileFDs still using fs, since each such
	// FileDescription would hold a reference on a Mount holding a reference on
	// fs.
	fs.syncMu.Unlock()

	if !fs.iopts.LeakConnection {
		// Close the connection to the server. This implicitly clunks all fids.
		fs.client.Close()
	}

	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	// refs is the reference count. Each dentry holds a reference on its
	// parent, even if disowned. An additional reference is held on all
	// synthetic dentries until they are unlinked or invalidated. When refs
	// reaches 0, the dentry may be added to the cache or destroyed. If refs ==
	// -1, the dentry has already been destroyed. refs is accessed using atomic
	// memory operations.
	refs int64

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

	// We don't support hard links, so each dentry maps 1:1 to an inode.

	// file is the unopened p9.File that backs this dentry. file is immutable.
	//
	// If file.isNil(), this dentry represents a synthetic file, i.e. a file
	// that does not exist on the remote filesystem. As of this writing, the
	// only files that can be synthetic are sockets, pipes, and directories.
	file p9file

	// If deleted is non-zero, the file represented by this dentry has been
	// deleted. deleted is accessed using atomic memory operations.
	deleted uint32

	// If cached is true, dentryEntry links dentry into
	// filesystem.cachedDentries. cached and dentryEntry are protected by
	// filesystem.renameMu.
	cached bool
	dentryEntry

	dirMu sync.Mutex

	// If this dentry represents a directory, children contains:
	//
	// - Mappings of child filenames to dentries representing those children.
	//
	// - Mappings of child filenames that are known not to exist to nil
	// dentries (only if InteropModeShared is not in effect and the directory
	// is not synthetic).
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
	// returned by the server. dirents is protected by dirMu.
	dirents []vfs.Dirent

	// Cached metadata; protected by metadataMu.
	// To access:
	//   - In situations where consistency is not required (like stat), these
	//     can be accessed using atomic operations only (without locking).
	//   - Lock metadataMu and can access without atomic operations.
	// To mutate:
	//   - Lock metadataMu and use atomic operations to update because we might
	//     have atomic readers that don't hold the lock.
	metadataMu sync.Mutex
	ino        inodeNumber // immutable
	mode       uint32      // type is immutable, perms are mutable
	uid        uint32      // auth.KUID, but stored as raw uint32 for sync/atomic
	gid        uint32      // auth.KGID, but ...
	blockSize  uint32      // 0 if unknown
	// Timestamps, all nsecs from the Unix epoch.
	atime int64
	mtime int64
	ctime int64
	btime int64
	// File size, protected by both metadataMu and dataMu (i.e. both must be
	// locked to mutate it; locking either is sufficient to access it).
	size uint64

	// nlink counts the number of hard links to this dentry. It's updated and
	// accessed using atomic operations. It's not protected by metadataMu like the
	// other metadata fields.
	nlink uint32

	mapsMu sync.Mutex

	// If this dentry represents a regular file, mappings tracks mappings of
	// the file into memmap.MappingSpaces. mappings is protected by mapsMu.
	mappings memmap.MappingSet

	// If this dentry represents a regular file or directory:
	//
	// - handle is the I/O handle used by all regularFileFDs/directoryFDs
	// representing this dentry.
	//
	// - handleReadable is true if handle is readable.
	//
	// - handleWritable is true if handle is writable.
	//
	// Invariants:
	//
	// - If handleReadable == handleWritable == false, then handle.file == nil
	// (i.e. there is no open handle). Conversely, if handleReadable ||
	// handleWritable == true, then handle.file != nil (i.e. there is an open
	// handle).
	//
	// - handleReadable and handleWritable cannot transition from true to false
	// (i.e. handles may not be downgraded).
	//
	// These fields are protected by handleMu.
	handleMu       sync.RWMutex
	handle         handle
	handleReadable bool
	handleWritable bool

	dataMu sync.RWMutex

	// If this dentry represents a regular file that is client-cached, cache
	// maps offsets into the cached file to offsets into
	// filesystem.mfp.MemoryFile() that store the file's data. cache is
	// protected by dataMu.
	cache fsutil.FileRangeSet

	// If this dentry represents a regular file that is client-cached, dirty
	// tracks dirty segments in cache. dirty is protected by dataMu.
	dirty fsutil.DirtySet

	// pf implements platform.File for mappings of handle.fd.
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
	watches vfs.Watches
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
		return nil, syserror.EIO
	}
	if attr.Mode.FileType() == p9.ModeRegular && !mask.Size {
		ctx.Warningf("can't create regular file gofer.dentry without file size")
		return nil, syserror.EIO
	}

	d := &dentry{
		fs:        fs,
		file:      file,
		ino:       inoFromPath(qid.Path),
		mode:      uint32(attr.Mode),
		uid:       uint32(fs.opts.dfltuid),
		gid:       uint32(fs.opts.dfltgid),
		blockSize: usermem.PageSize,
		handle: handle{
			fd: -1,
		},
	}
	d.pf.dentry = d
	if mask.UID {
		d.uid = dentryUIDFromP9UID(attr.UID)
	}
	if mask.GID {
		d.gid = dentryGIDFromP9GID(attr.GID)
	}
	if mask.Size {
		d.size = attr.Size
	}
	if attr.BlockSize != 0 {
		d.blockSize = uint32(attr.BlockSize)
	}
	if mask.ATime {
		d.atime = dentryTimestampFromP9(attr.ATimeSeconds, attr.ATimeNanoSeconds)
	}
	if mask.MTime {
		d.mtime = dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds)
	}
	if mask.CTime {
		d.ctime = dentryTimestampFromP9(attr.CTimeSeconds, attr.CTimeNanoSeconds)
	}
	if mask.BTime {
		d.btime = dentryTimestampFromP9(attr.BTimeSeconds, attr.BTimeNanoSeconds)
	}
	if mask.NLink {
		d.nlink = uint32(attr.NLink)
	}
	d.vfsd.Init(d)

	fs.syncMu.Lock()
	fs.syncableDentries[d] = struct{}{}
	fs.syncMu.Unlock()
	return d, nil
}

func (d *dentry) isSynthetic() bool {
	return d.file.isNil()
}

func (d *dentry) cachedMetadataAuthoritative() bool {
	return d.fs.opts.interop != InteropModeShared || d.isSynthetic()
}

// updateFromP9Attrs is called to update d's metadata after an update from the
// remote filesystem.
func (d *dentry) updateFromP9Attrs(mask p9.AttrMask, attr *p9.Attr) {
	d.metadataMu.Lock()
	if mask.Mode {
		if got, want := uint32(attr.Mode.FileType()), d.fileType(); got != want {
			d.metadataMu.Unlock()
			panic(fmt.Sprintf("gofer.dentry file type changed from %#o to %#o", want, got))
		}
		atomic.StoreUint32(&d.mode, uint32(attr.Mode))
	}
	if mask.UID {
		atomic.StoreUint32(&d.uid, dentryUIDFromP9UID(attr.UID))
	}
	if mask.GID {
		atomic.StoreUint32(&d.gid, dentryGIDFromP9GID(attr.GID))
	}
	// There is no P9_GETATTR_* bit for I/O block size.
	if attr.BlockSize != 0 {
		atomic.StoreUint32(&d.blockSize, uint32(attr.BlockSize))
	}
	if mask.ATime {
		atomic.StoreInt64(&d.atime, dentryTimestampFromP9(attr.ATimeSeconds, attr.ATimeNanoSeconds))
	}
	if mask.MTime {
		atomic.StoreInt64(&d.mtime, dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds))
	}
	if mask.CTime {
		atomic.StoreInt64(&d.ctime, dentryTimestampFromP9(attr.CTimeSeconds, attr.CTimeNanoSeconds))
	}
	if mask.BTime {
		atomic.StoreInt64(&d.btime, dentryTimestampFromP9(attr.BTimeSeconds, attr.BTimeNanoSeconds))
	}
	if mask.NLink {
		atomic.StoreUint32(&d.nlink, uint32(attr.NLink))
	}
	if mask.Size {
		d.updateFileSizeLocked(attr.Size)
	}
	d.metadataMu.Unlock()
}

// Preconditions: !d.isSynthetic()
func (d *dentry) updateFromGetattr(ctx context.Context) error {
	// Use d.handle.file, which represents a 9P fid that has been opened, in
	// preference to d.file, which represents a 9P fid that has not. This may
	// be significantly more efficient in some implementations.
	var (
		file            p9file
		handleMuRLocked bool
	)
	d.handleMu.RLock()
	if !d.handle.file.isNil() {
		file = d.handle.file
		handleMuRLocked = true
	} else {
		file = d.file
		d.handleMu.RUnlock()
	}
	_, attrMask, attr, err := file.getAttr(ctx, dentryAttrMask())
	if handleMuRLocked {
		d.handleMu.RUnlock()
	}
	if err != nil {
		return err
	}
	d.updateFromP9Attrs(attrMask, &attr)
	return nil
}

func (d *dentry) fileType() uint32 {
	return atomic.LoadUint32(&d.mode) & linux.S_IFMT
}

func (d *dentry) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS | linux.STATX_BTIME
	stat.Blksize = atomic.LoadUint32(&d.blockSize)
	stat.Nlink = atomic.LoadUint32(&d.nlink)
	if stat.Nlink == 0 {
		// The remote filesystem doesn't support link count; just make
		// something up. This is consistent with Linux, where
		// fs/inode.c:inode_init_always() initializes link count to 1, and
		// fs/9p/vfs_inode_dotl.c:v9fs_stat2inode_dotl() doesn't touch it if
		// it's not provided by the remote filesystem.
		stat.Nlink = 1
	}
	stat.UID = atomic.LoadUint32(&d.uid)
	stat.GID = atomic.LoadUint32(&d.gid)
	stat.Mode = uint16(atomic.LoadUint32(&d.mode))
	stat.Ino = uint64(d.ino)
	stat.Size = atomic.LoadUint64(&d.size)
	// This is consistent with regularFileFD.Seek(), which treats regular files
	// as having no holes.
	stat.Blocks = (stat.Size + 511) / 512
	stat.Atime = statxTimestampFromDentry(atomic.LoadInt64(&d.atime))
	stat.Btime = statxTimestampFromDentry(atomic.LoadInt64(&d.btime))
	stat.Ctime = statxTimestampFromDentry(atomic.LoadInt64(&d.ctime))
	stat.Mtime = statxTimestampFromDentry(atomic.LoadInt64(&d.mtime))
	stat.DevMajor = linux.UNNAMED_MAJOR
	stat.DevMinor = d.fs.devMinor
}

func (d *dentry) setStat(ctx context.Context, creds *auth.Credentials, stat *linux.Statx, mnt *vfs.Mount) error {
	if stat.Mask == 0 {
		return nil
	}
	if stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_SIZE) != 0 {
		return syserror.EPERM
	}
	mode := linux.FileMode(atomic.LoadUint32(&d.mode))
	if err := vfs.CheckSetStat(ctx, creds, stat, mode, auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid))); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	setLocalAtime := false
	setLocalMtime := false
	if d.cachedMetadataAuthoritative() {
		// Timestamp updates will be handled locally.
		setLocalAtime = stat.Mask&linux.STATX_ATIME != 0
		setLocalMtime = stat.Mask&linux.STATX_MTIME != 0
		stat.Mask &^= linux.STATX_ATIME | linux.STATX_MTIME

		// Prepare for truncate.
		if stat.Mask&linux.STATX_SIZE != 0 {
			switch mode.FileType() {
			case linux.ModeRegular:
				if !setLocalMtime {
					// Truncate updates mtime.
					setLocalMtime = true
					stat.Mtime.Nsec = linux.UTIME_NOW
				}
			case linux.ModeDirectory:
				return syserror.EISDIR
			default:
				return syserror.EINVAL
			}
		}
	}
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	if stat.Mask&linux.STATX_SIZE != 0 {
		// The size needs to be changed even when
		// !d.cachedMetadataAuthoritative() because d.mappings has to be
		// updated.
		d.updateFileSizeLocked(stat.Size)
	}
	if !d.isSynthetic() {
		if stat.Mask != 0 {
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
				return err
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
	now := d.fs.clock.Now().Nanoseconds()
	if stat.Mask&linux.STATX_MODE != 0 {
		atomic.StoreUint32(&d.mode, d.fileType()|uint32(stat.Mode))
	}
	if stat.Mask&linux.STATX_UID != 0 {
		atomic.StoreUint32(&d.uid, stat.UID)
	}
	if stat.Mask&linux.STATX_GID != 0 {
		atomic.StoreUint32(&d.gid, stat.GID)
	}
	if setLocalAtime {
		if stat.Atime.Nsec == linux.UTIME_NOW {
			atomic.StoreInt64(&d.atime, now)
		} else {
			atomic.StoreInt64(&d.atime, dentryTimestampFromStatx(stat.Atime))
		}
		// Restore mask bits that we cleared earlier.
		stat.Mask |= linux.STATX_ATIME
	}
	if setLocalMtime {
		if stat.Mtime.Nsec == linux.UTIME_NOW {
			atomic.StoreInt64(&d.mtime, now)
		} else {
			atomic.StoreInt64(&d.mtime, dentryTimestampFromStatx(stat.Mtime))
		}
		// Restore mask bits that we cleared earlier.
		stat.Mask |= linux.STATX_MTIME
	}
	atomic.StoreInt64(&d.ctime, now)
	return nil
}

// Preconditions: d.metadataMu must be locked.
func (d *dentry) updateFileSizeLocked(newSize uint64) {
	d.dataMu.Lock()
	oldSize := d.size
	atomic.StoreUint64(&d.size, newSize)
	// d.dataMu must be unlocked to lock d.mapsMu and invalidate mappings
	// below. This allows concurrent calls to Read/Translate/etc. These
	// functions synchronize with truncation by refusing to use cache
	// contents beyond the new d.size. (We are still holding d.metadataMu,
	// so we can't race with Write or another truncate.)
	d.dataMu.Unlock()
	if d.size < oldSize {
		oldpgend, _ := usermem.PageRoundUp(oldSize)
		newpgend, _ := usermem.PageRoundUp(d.size)
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
		d.cache.Truncate(d.size, d.fs.mfp.MemoryFile())
		d.dirty.KeepClean(memmap.MappableRange{d.size, oldpgend})
		d.dataMu.Unlock()
	}
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(atomic.LoadUint32(&d.mode)), auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid)))
}

func (d *dentry) mayDelete(creds *auth.Credentials, child *dentry) error {
	return vfs.CheckDeleteSticky(creds, linux.FileMode(atomic.LoadUint32(&d.mode)), auth.KUID(atomic.LoadUint32(&child.uid)))
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

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	// d.refs may be 0 if d.fs.renameMu is locked, which serializes against
	// d.checkCachingLocked().
	atomic.AddInt64(&d.refs, 1)
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&d.refs)
		if refs <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&d.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef() {
	if refs := atomic.AddInt64(&d.refs, -1); refs == 0 {
		d.fs.renameMu.Lock()
		d.checkCachingLocked()
		d.fs.renameMu.Unlock()
	} else if refs < 0 {
		panic("gofer.dentry.DecRef() called without holding a reference")
	}
}

// decRefLocked decrements d's reference count without calling
// d.checkCachingLocked, even if d's reference count reaches 0; callers are
// responsible for ensuring that d.checkCachingLocked will be called later.
func (d *dentry) decRefLocked() {
	if refs := atomic.AddInt64(&d.refs, -1); refs < 0 {
		panic("gofer.dentry.decRefLocked() called without holding a reference")
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(events, cookie uint32, et vfs.EventType) {
	if d.isDir() {
		events |= linux.IN_ISDIR
	}

	d.fs.renameMu.RLock()
	// The ordering below is important, Linux always notifies the parent first.
	if d.parent != nil {
		d.parent.watches.Notify(d.name, events, cookie, et, d.isDeleted())
	}
	d.watches.Notify("", events, cookie, et, d.isDeleted())
	d.fs.renameMu.RUnlock()
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
//
// If no watches are left on this dentry and it has no references, cache it.
func (d *dentry) OnZeroWatches() {
	if atomic.LoadInt64(&d.refs) == 0 {
		d.fs.renameMu.Lock()
		d.checkCachingLocked()
		d.fs.renameMu.Unlock()
	}
}

// checkCachingLocked should be called after d's reference count becomes 0 or it
// becomes disowned.
//
// It may be called on a destroyed dentry. For example,
// renameMu[R]UnlockAndCheckCaching may call checkCachingLocked multiple times
// for the same dentry when the dentry is visited more than once in the same
// operation. One of the calls may destroy the dentry, so subsequent calls will
// do nothing.
//
// Preconditions: d.fs.renameMu must be locked for writing.
func (d *dentry) checkCachingLocked() {
	// Dentries with a non-zero reference count must be retained. (The only way
	// to obtain a reference on a dentry with zero references is via path
	// resolution, which requires renameMu, so if d.refs is zero then it will
	// remain zero while we hold renameMu for writing.)
	refs := atomic.LoadInt64(&d.refs)
	if refs > 0 {
		if d.cached {
			d.fs.cachedDentries.Remove(d)
			d.fs.cachedDentriesLen--
			d.cached = false
		}
		return
	}
	if refs == -1 {
		// Dentry has already been destroyed.
		return
	}
	// Deleted and invalidated dentries with zero references are no longer
	// reachable by path resolution and should be dropped immediately.
	if d.vfsd.IsDead() {
		if d.isDeleted() {
			d.watches.HandleDeletion()
		}
		if d.cached {
			d.fs.cachedDentries.Remove(d)
			d.fs.cachedDentriesLen--
			d.cached = false
		}
		d.destroyLocked()
		return
	}
	// If d still has inotify watches and it is not deleted or invalidated, we
	// cannot cache it and allow it to be evicted. Otherwise, we will lose its
	// watches, even if a new dentry is created for the same file in the future.
	// Note that the size of d.watches cannot concurrently transition from zero
	// to non-zero, because adding a watch requires holding a reference on d.
	if d.watches.Size() > 0 {
		return
	}
	// If d is already cached, just move it to the front of the LRU.
	if d.cached {
		d.fs.cachedDentries.Remove(d)
		d.fs.cachedDentries.PushFront(d)
		return
	}
	// Cache the dentry, then evict the least recently used cached dentry if
	// the cache becomes over-full.
	d.fs.cachedDentries.PushFront(d)
	d.fs.cachedDentriesLen++
	d.cached = true
	if d.fs.cachedDentriesLen > d.fs.opts.maxCachedDentries {
		victim := d.fs.cachedDentries.Back()
		d.fs.cachedDentries.Remove(victim)
		d.fs.cachedDentriesLen--
		victim.cached = false
		// victim.refs may have become non-zero from an earlier path resolution
		// since it was inserted into fs.cachedDentries.
		if atomic.LoadInt64(&victim.refs) == 0 {
			if victim.parent != nil {
				victim.parent.dirMu.Lock()
				if !victim.vfsd.IsDead() {
					// Note that victim can't be a mount point (in any mount
					// namespace), since VFS holds references on mount points.
					d.fs.vfsfs.VirtualFilesystem().InvalidateDentry(&victim.vfsd)
					delete(victim.parent.children, victim.name)
					// We're only deleting the dentry, not the file it
					// represents, so we don't need to update
					// victimParent.dirents etc.
				}
				victim.parent.dirMu.Unlock()
			}
			victim.destroyLocked()
		}
		// Whether or not victim was destroyed, we brought fs.cachedDentriesLen
		// back down to fs.opts.maxCachedDentries, so we don't loop.
	}
}

// destroyLocked destroys the dentry. It may flushes dirty pages from cache,
// close p9 file and remove reference on parent dentry.
//
// Preconditions: d.fs.renameMu must be locked for writing. d.refs == 0. d is
// not a child dentry.
func (d *dentry) destroyLocked() {
	switch atomic.LoadInt64(&d.refs) {
	case 0:
		// Mark the dentry destroyed.
		atomic.StoreInt64(&d.refs, -1)
	case -1:
		panic("dentry.destroyLocked() called on already destroyed dentry")
	default:
		panic("dentry.destroyLocked() called with references on the dentry")
	}

	ctx := context.Background()
	d.handleMu.Lock()
	if !d.handle.file.isNil() {
		mf := d.fs.mfp.MemoryFile()
		d.dataMu.Lock()
		// Write dirty pages back to the remote filesystem.
		if d.handleWritable {
			if err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size, mf, d.handle.writeFromBlocksAt); err != nil {
				log.Warningf("gofer.dentry.DecRef: failed to write dirty data back: %v", err)
			}
		}
		// Discard cached data.
		d.cache.DropAll(mf)
		d.dirty.RemoveAll()
		d.dataMu.Unlock()
		// Clunk open fids and close open host FDs.
		d.handle.close(ctx)
	}
	d.handleMu.Unlock()

	if !d.file.isNil() {
		d.file.close(ctx)
		d.file = p9file{}
		// Remove d from the set of syncable dentries.
		d.fs.syncMu.Lock()
		delete(d.fs.syncableDentries, d)
		d.fs.syncMu.Unlock()
	}
	// Drop the reference held by d on its parent without recursively locking
	// d.fs.renameMu.
	if d.parent != nil {
		if refs := atomic.AddInt64(&d.parent.refs, -1); refs == 0 {
			d.parent.checkCachingLocked()
		} else if refs < 0 {
			panic("gofer.dentry.DecRef() called without holding a reference")
		}
	}
}

func (d *dentry) isDeleted() bool {
	return atomic.LoadUint32(&d.deleted) != 0
}

func (d *dentry) setDeleted() {
	atomic.StoreUint32(&d.deleted, 1)
}

// We only support xattrs prefixed with "user." (see b/148380782). Currently,
// there is no need to expose any other xattrs through a gofer.
func (d *dentry) listxattr(ctx context.Context, creds *auth.Credentials, size uint64) ([]string, error) {
	if d.file.isNil() || !d.userXattrSupported() {
		return nil, nil
	}
	xattrMap, err := d.file.listXattr(ctx, size)
	if err != nil {
		return nil, err
	}
	xattrs := make([]string, 0, len(xattrMap))
	for x := range xattrMap {
		if strings.HasPrefix(x, linux.XATTR_USER_PREFIX) {
			xattrs = append(xattrs, x)
		}
	}
	return xattrs, nil
}

func (d *dentry) getxattr(ctx context.Context, creds *auth.Credentials, opts *vfs.GetxattrOptions) (string, error) {
	if d.file.isNil() {
		return "", syserror.ENODATA
	}
	if err := d.checkPermissions(creds, vfs.MayRead); err != nil {
		return "", err
	}
	if !strings.HasPrefix(opts.Name, linux.XATTR_USER_PREFIX) {
		return "", syserror.EOPNOTSUPP
	}
	if !d.userXattrSupported() {
		return "", syserror.ENODATA
	}
	return d.file.getXattr(ctx, opts.Name, opts.Size)
}

func (d *dentry) setxattr(ctx context.Context, creds *auth.Credentials, opts *vfs.SetxattrOptions) error {
	if d.file.isNil() {
		return syserror.EPERM
	}
	if err := d.checkPermissions(creds, vfs.MayWrite); err != nil {
		return err
	}
	if !strings.HasPrefix(opts.Name, linux.XATTR_USER_PREFIX) {
		return syserror.EOPNOTSUPP
	}
	if !d.userXattrSupported() {
		return syserror.EPERM
	}
	return d.file.setXattr(ctx, opts.Name, opts.Value, opts.Flags)
}

func (d *dentry) removexattr(ctx context.Context, creds *auth.Credentials, name string) error {
	if d.file.isNil() {
		return syserror.EPERM
	}
	if err := d.checkPermissions(creds, vfs.MayWrite); err != nil {
		return err
	}
	if !strings.HasPrefix(name, linux.XATTR_USER_PREFIX) {
		return syserror.EOPNOTSUPP
	}
	if !d.userXattrSupported() {
		return syserror.EPERM
	}
	return d.file.removeXattr(ctx, name)
}

// Extended attributes in the user.* namespace are only supported for regular
// files and directories.
func (d *dentry) userXattrSupported() bool {
	filetype := linux.FileMode(atomic.LoadUint32(&d.mode)).FileType()
	return filetype == linux.ModeRegular || filetype == linux.ModeDirectory
}

// Preconditions: !d.isSynthetic(). d.isRegularFile() || d.isDir().
func (d *dentry) ensureSharedHandle(ctx context.Context, read, write, trunc bool) error {
	// O_TRUNC unconditionally requires us to obtain a new handle (opened with
	// O_TRUNC).
	if !trunc {
		d.handleMu.RLock()
		if (!read || d.handleReadable) && (!write || d.handleWritable) {
			// The current handle is sufficient.
			d.handleMu.RUnlock()
			return nil
		}
		d.handleMu.RUnlock()
	}

	haveOldFD := false
	d.handleMu.Lock()
	if (read && !d.handleReadable) || (write && !d.handleWritable) || trunc {
		// Get a new handle.
		wantReadable := d.handleReadable || read
		wantWritable := d.handleWritable || write
		h, err := openHandle(ctx, d.file, wantReadable, wantWritable, trunc)
		if err != nil {
			d.handleMu.Unlock()
			return err
		}
		if !d.handle.file.isNil() {
			// Check that old and new handles are compatible: If the old handle
			// includes a host file descriptor but the new one does not, or
			// vice versa, old and new memory mappings may be incoherent.
			haveOldFD = d.handle.fd >= 0
			haveNewFD := h.fd >= 0
			if haveOldFD != haveNewFD {
				d.handleMu.Unlock()
				ctx.Warningf("gofer.dentry.ensureSharedHandle: can't change host FD availability from %v to %v across dentry handle upgrade", haveOldFD, haveNewFD)
				h.close(ctx)
				return syserror.EIO
			}
			if haveOldFD {
				// We may have raced with callers of d.pf.FD() that are now
				// using the old file descriptor, preventing us from safely
				// closing it. We could handle this by invalidating existing
				// memmap.Translations, but this is expensive. Instead, use
				// dup3 to make the old file descriptor refer to the new file
				// description, then close the new file descriptor (which is no
				// longer needed). Racing callers may use the old or new file
				// description, but this doesn't matter since they refer to the
				// same file (unless d.fs.opts.overlayfsStaleRead is true,
				// which we handle separately).
				if err := syscall.Dup3(int(h.fd), int(d.handle.fd), syscall.O_CLOEXEC); err != nil {
					d.handleMu.Unlock()
					ctx.Warningf("gofer.dentry.ensureSharedHandle: failed to dup fd %d to fd %d: %v", h.fd, d.handle.fd, err)
					h.close(ctx)
					return err
				}
				syscall.Close(int(h.fd))
				h.fd = d.handle.fd
				if d.fs.opts.overlayfsStaleRead {
					// Replace sentry mappings of the old FD with mappings of
					// the new FD, since the two are not necessarily coherent.
					if err := d.pf.hostFileMapper.RegenerateMappings(int(h.fd)); err != nil {
						d.handleMu.Unlock()
						ctx.Warningf("gofer.dentry.ensureSharedHandle: failed to replace sentry mappings of old FD with mappings of new FD: %v", err)
						h.close(ctx)
						return err
					}
				}
				// Clunk the old fid before making the new handle visible (by
				// unlocking d.handleMu).
				d.handle.file.close(ctx)
			}
		}
		// Switch to the new handle.
		d.handle = h
		d.handleReadable = wantReadable
		d.handleWritable = wantWritable
	}
	d.handleMu.Unlock()

	if d.fs.opts.overlayfsStaleRead && haveOldFD {
		// Invalidate application mappings that may be using the old FD; they
		// will be replaced with mappings using the new FD after future calls
		// to d.Translate(). This requires holding d.mapsMu, which precedes
		// d.handleMu in the lock order.
		d.mapsMu.Lock()
		d.mappings.InvalidateAll(memmap.InvalidateOpts{})
		d.mapsMu.Unlock()
	}

	return nil
}

// incLinks increments link count.
func (d *dentry) incLinks() {
	if atomic.LoadUint32(&d.nlink) == 0 {
		// The remote filesystem doesn't support link count.
		return
	}
	atomic.AddUint32(&d.nlink, 1)
}

// decLinks decrements link count.
func (d *dentry) decLinks() {
	if atomic.LoadUint32(&d.nlink) == 0 {
		// The remote filesystem doesn't support link count.
		return
	}
	atomic.AddUint32(&d.nlink, ^uint32(0))
}

// fileDescription is embedded by gofer implementations of
// vfs.FileDescriptionImpl.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	lockLogging sync.Once
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
		// TODO(jamieliu): Use specialFileFD.handle.file for the getattr if
		// available?
		if err := d.updateFromGetattr(ctx); err != nil {
			return linux.Statx{}, err
		}
	}
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if err := fd.dentry().setStat(ctx, auth.CredentialsFromContext(ctx), &opts.Stat, fd.vfsfd.Mount()); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		fd.dentry().InotifyWithParent(ev, 0, vfs.InodeEvent)
	}
	return nil
}

// Listxattr implements vfs.FileDescriptionImpl.Listxattr.
func (fd *fileDescription) Listxattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.dentry().listxattr(ctx, auth.CredentialsFromContext(ctx), size)
}

// Getxattr implements vfs.FileDescriptionImpl.Getxattr.
func (fd *fileDescription) Getxattr(ctx context.Context, opts vfs.GetxattrOptions) (string, error) {
	return fd.dentry().getxattr(ctx, auth.CredentialsFromContext(ctx), &opts)
}

// Setxattr implements vfs.FileDescriptionImpl.Setxattr.
func (fd *fileDescription) Setxattr(ctx context.Context, opts vfs.SetxattrOptions) error {
	d := fd.dentry()
	if err := d.setxattr(ctx, auth.CredentialsFromContext(ctx), &opts); err != nil {
		return err
	}
	d.InotifyWithParent(linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// Removexattr implements vfs.FileDescriptionImpl.Removexattr.
func (fd *fileDescription) Removexattr(ctx context.Context, name string) error {
	d := fd.dentry()
	if err := d.removexattr(ctx, auth.CredentialsFromContext(ctx), name); err != nil {
		return err
	}
	d.InotifyWithParent(linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// LockBSD implements vfs.FileDescriptionImpl.LockBSD.
func (fd *fileDescription) LockBSD(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, block fslock.Blocker) error {
	fd.lockLogging.Do(func() {
		log.Infof("File lock using gofer file handled internally.")
	})
	return fd.LockFD.LockBSD(ctx, uid, t, block)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	fd.lockLogging.Do(func() {
		log.Infof("Range lock using gofer file handled internally.")
	})
	return fd.Locks().LockPOSIX(ctx, &fd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return fd.Locks().UnlockPOSIX(ctx, &fd.vfsfd, uid, start, length, whence)
}
