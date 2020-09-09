// Copyright 2020 The gVisor Authors.
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

// Package verity provides a filesystem implementation that is a wrapper of
// another file system.
// The verity file system provides integrity check for the underlying file
// system by providing verification for path traversals and each read.
// The verity file system is read-only, except for one case: when
// allowRuntimeEnable is true, additional Merkle files can be generated using
// the FS_IOC_ENABLE_VERITY ioctl.
package verity

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Name is the default filesystem name.
const Name = "verity"

// merklePrefix is the prefix of the Merkle tree files. For example, the Merkle
// tree file for "/foo" is "/.merkle.verity.foo".
const merklePrefix = ".merkle.verity."

// noCrashOnVerificationFailure indicates whether the sandbox should panic
// whenever verification fails. If true, an error is returned instead of
// panicking. This should only be set for tests.
// TOOD(b/165661693): Decide whether to panic or return error based on this
// flag.
var noCrashOnVerificationFailure bool

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// creds is a copy of the filesystem's creator's credentials, which are
	// used for accesses to the underlying file system. creds is immutable.
	creds *auth.Credentials

	// allowRuntimeEnable is true if using ioctl with FS_IOC_ENABLE_VERITY
	// to build Merkle trees in the verity file system is allowed. If this
	// is false, no new Merkle trees can be built, and only the files that
	// had Merkle trees before startup (e.g. from a host filesystem mounted
	// with gofer fs) can be verified.
	allowRuntimeEnable bool

	// lowerMount is the underlying file system mount.
	lowerMount *vfs.Mount

	// rootDentry is the mount root Dentry for this file system, which
	// stores the root hash of the whole file system in bytes.
	rootDentry *dentry

	// renameMu synchronizes renaming with non-renaming operations in order
	// to ensure consistent lock ordering between dentry.dirMu in different
	// dentries.
	renameMu sync.RWMutex
}

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
type InternalFilesystemOptions struct {
	// RootMerkleFileName is the name of the verity root Merkle tree file.
	RootMerkleFileName string

	// LowerName is the name of the filesystem wrapped by verity fs.
	LowerName string

	// RootHash is the root hash of the overall verity file system.
	RootHash []byte

	// AllowRuntimeEnable specifies whether the verity file system allows
	// enabling verification for files (i.e. building Merkle trees) during
	// runtime.
	AllowRuntimeEnable bool

	// LowerGetFSOptions is the file system option for the lower layer file
	// system wrapped by verity file system.
	LowerGetFSOptions vfs.GetFilesystemOptions

	// NoCrashOnVerificationFailure indicates whether the sandbox should
	// panic whenever verification fails. If true, an error is returned
	// instead of panicking. This should only be set for tests.
	NoCrashOnVerificationFailure bool
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if !ok {
		ctx.Warningf("verity.FilesystemType.GetFilesystem: missing verity configs")
		return nil, nil, syserror.EINVAL
	}
	noCrashOnVerificationFailure = iopts.NoCrashOnVerificationFailure

	// Mount the lower file system. The lower file system is wrapped inside
	// verity, and should not be exposed or connected.
	mopts := &vfs.MountOptions{
		GetFilesystemOptions: iopts.LowerGetFSOptions,
	}
	mnt, err := vfsObj.MountDisconnected(ctx, creds, "", iopts.LowerName, mopts)
	if err != nil {
		return nil, nil, err
	}

	fs := &filesystem{
		creds:              creds.Fork(),
		lowerMount:         mnt,
		allowRuntimeEnable: iopts.AllowRuntimeEnable,
	}
	fs.vfsfs.Init(vfsObj, &fstype, fs)

	// Construct the root dentry.
	d := fs.newDentry()
	d.refs = 1
	lowerVD := vfs.MakeVirtualDentry(mnt, mnt.Root())
	lowerVD.IncRef()
	d.lowerVD = lowerVD

	rootMerkleName := merklePrefix + iopts.RootMerkleFileName

	lowerMerkleVD, err := vfsObj.GetDentryAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
		Path:  fspath.Parse(rootMerkleName),
	}, &vfs.GetDentryOptions{})

	// If runtime enable is allowed, the root merkle tree may be absent. We
	// should create the tree file.
	if err == syserror.ENOENT && fs.allowRuntimeEnable {
		lowerMerkleFD, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  lowerVD,
			Start: lowerVD,
			Path:  fspath.Parse(rootMerkleName),
		}, &vfs.OpenOptions{
			Flags: linux.O_RDWR | linux.O_CREAT,
			Mode:  0644,
		})
		if err != nil {
			fs.vfsfs.DecRef(ctx)
			d.DecRef(ctx)
			return nil, nil, err
		}
		lowerMerkleFD.DecRef(ctx)
		lowerMerkleVD, err = vfsObj.GetDentryAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  lowerVD,
			Start: lowerVD,
			Path:  fspath.Parse(rootMerkleName),
		}, &vfs.GetDentryOptions{})
		if err != nil {
			fs.vfsfs.DecRef(ctx)
			d.DecRef(ctx)
			return nil, nil, err
		}
	} else if err != nil {
		// Failed to get dentry for the root Merkle file. This indicates
		// an attack that removed/renamed the root Merkle file, or it's
		// never generated.
		if noCrashOnVerificationFailure {
			fs.vfsfs.DecRef(ctx)
			d.DecRef(ctx)
			return nil, nil, err
		}
		panic("Failed to find root Merkle file")
	}
	d.lowerMerkleVD = lowerMerkleVD

	// Get metadata from the underlying file system.
	const statMask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID
	stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
	}, &vfs.StatOptions{
		Mask: statMask,
	})
	if err != nil {
		fs.vfsfs.DecRef(ctx)
		d.DecRef(ctx)
		return nil, nil, err
	}

	// TODO(b/162788573): Verify Metadata.
	d.mode = uint32(stat.Mode)
	d.uid = stat.UID
	d.gid = stat.GID

	d.rootHash = make([]byte, len(iopts.RootHash))
	copy(d.rootHash, iopts.RootHash)
	d.vfsd.Init(d)

	return &fs.vfsfs, &d.vfsd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.lowerMount.DecRef(ctx)
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	refs int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// mode, uid and gid are the file mode, owner, and group of the file in
	// the underlying file system.
	mode uint32
	uid  uint32
	gid  uint32

	// parent is the dentry corresponding to this dentry's parent directory.
	// name is this dentry's name in parent. If this dentry is a filesystem
	// root, parent is nil and name is the empty string. parent and name are
	// protected by fs.renameMu.
	parent *dentry
	name   string

	// If this dentry represents a directory, children maps the names of
	// children for which dentries have been instantiated to those dentries,
	// and dirents (if not nil) is a cache of dirents as returned by
	// directoryFDs representing this directory. children is protected by
	// dirMu.
	dirMu    sync.Mutex
	children map[string]*dentry

	// lowerVD is the VirtualDentry in the underlying file system.
	lowerVD vfs.VirtualDentry

	// lowerMerkleVD is the VirtualDentry of the corresponding Merkle tree
	// in the underlying file system.
	lowerMerkleVD vfs.VirtualDentry

	// rootHash is the rootHash for the current file or directory.
	rootHash []byte
}

// newDentry creates a new dentry representing the given verity file. The
// dentry initially has no references; it is the caller's responsibility to set
// the dentry's reference count and/or call dentry.destroy() as appropriate.
// The dentry is initially invalid in that it contains no underlying dentry;
// the caller is responsible for setting them.
func (fs *filesystem) newDentry() *dentry {
	d := &dentry{
		fs: fs,
	}
	d.vfsd.Init(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
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
func (d *dentry) DecRef(ctx context.Context) {
	if refs := atomic.AddInt64(&d.refs, -1); refs == 0 {
		d.fs.renameMu.Lock()
		d.checkDropLocked(ctx)
		d.fs.renameMu.Unlock()
	} else if refs < 0 {
		panic("verity.dentry.DecRef() called without holding a reference")
	}
}

// checkDropLocked should be called after d's reference count becomes 0 or it
// becomes deleted.
func (d *dentry) checkDropLocked(ctx context.Context) {
	// Dentries with a positive reference count must be retained. Dentries
	// with a negative reference count have already been destroyed.
	if atomic.LoadInt64(&d.refs) != 0 {
		return
	}
	// Refs is still zero; destroy it.
	d.destroyLocked(ctx)
	return
}

// destroyLocked destroys the dentry.
//
// Preconditions: d.fs.renameMu must be locked for writing. d.refs == 0.
func (d *dentry) destroyLocked(ctx context.Context) {
	switch atomic.LoadInt64(&d.refs) {
	case 0:
		// Mark the dentry destroyed.
		atomic.StoreInt64(&d.refs, -1)
	case -1:
		panic("verity.dentry.destroyLocked() called on already destroyed dentry")
	default:
		panic("verity.dentry.destroyLocked() called with references on the dentry")
	}

	if d.lowerVD.Ok() {
		d.lowerVD.DecRef(ctx)
	}

	if d.lowerMerkleVD.Ok() {
		d.lowerMerkleVD.DecRef(ctx)
	}

	if d.parent != nil {
		d.parent.dirMu.Lock()
		if !d.vfsd.IsDead() {
			delete(d.parent.children, d.name)
		}
		d.parent.dirMu.Unlock()
		if refs := atomic.AddInt64(&d.parent.refs, -1); refs == 0 {
			d.parent.checkDropLocked(ctx)
		} else if refs < 0 {
			panic("verity.dentry.DecRef() called without holding a reference")
		}
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	//TODO(b/159261227): Implement InotifyWithParent.
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	//TODO(b/159261227): Implement Watches.
	return nil
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches(context.Context) {
	//TODO(b/159261227): Implement OnZeroWatches.
}

func (d *dentry) isSymlink() bool {
	return atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFLNK
}

func (d *dentry) isDir() bool {
	return atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFDIR
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(atomic.LoadUint32(&d.mode)), auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid)))
}

func (d *dentry) readlink(ctx context.Context) (string, error) {
	return d.fs.vfsfs.VirtualFilesystem().ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
	})
}

// FileDescription implements vfs.FileDescriptionImpl for verity fds.
// FileDescription is a wrapper of the underlying lowerFD, with support to build
// Merkle trees through the Linux fs-verity API to verify contents read from
// lowerFD.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	// d is the corresponding dentry to the fileDescription.
	d *dentry

	// isDir specifies whehter the fileDescription points to a directory.
	isDir bool

	// lowerFD is the FileDescription corresponding to the file in the
	// underlying file system.
	lowerFD *vfs.FileDescription

	// merkleReader is the read-only FileDescription corresponding to the
	// Merkle tree file in the underlying file system.
	merkleReader *vfs.FileDescription

	// merkleWriter is the FileDescription corresponding to the Merkle tree
	// file in the underlying file system for writing. This should only be
	// used when allowRuntimeEnable is set to true.
	merkleWriter *vfs.FileDescription

	// parentMerkleWriter is the FileDescription of the Merkle tree for the
	// directory that contains the current file/directory. This is only used
	// if allowRuntimeEnable is set to true.
	parentMerkleWriter *vfs.FileDescription
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release(ctx context.Context) {
	fd.lowerFD.DecRef(ctx)
	fd.merkleReader.DecRef(ctx)
	if fd.merkleWriter != nil {
		fd.merkleWriter.DecRef(ctx)
	}
	if fd.parentMerkleWriter != nil {
		fd.parentMerkleWriter.DecRef(ctx)
	}
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	// TODO(b/162788573): Add integrity check for metadata.
	stat, err := fd.lowerFD.Stat(ctx, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	// Verity files are read-only.
	return syserror.EPERM
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return fd.Locks().LockPOSIX(ctx, &fd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return fd.Locks().UnlockPOSIX(ctx, &fd.vfsfd, uid, start, length, whence)
}
