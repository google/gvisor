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
//
// Lock order:
//
// filesystem.renameMu
//   dentry.dirMu
//     fileDescription.mu
//       filesystem.verityMu
//         dentry.hashMu
//
// Locking dentry.dirMu in multiple dentries requires that parent dentries are
// locked before child dentries, and that filesystem.renameMu is locked to
// stabilize this relationship.
package verity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/merkletree"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// Name is the default filesystem name.
	Name = "verity"

	// merklePrefix is the prefix of the Merkle tree files. For example, the Merkle
	// tree file for "/foo" is "/.merkle.verity.foo".
	merklePrefix = ".merkle.verity."

	// merkleRootPrefix is the prefix of the Merkle tree root file. This
	// needs to be different from merklePrefix to avoid name collision.
	merkleRootPrefix = ".merkleroot.verity."

	// merkleOffsetInParentXattr is the extended attribute name specifying the
	// offset of the child hash in its parent's Merkle tree.
	merkleOffsetInParentXattr = "user.merkle.offset"

	// merkleSizeXattr is the extended attribute name specifying the size of data
	// hashed by the corresponding Merkle tree. For a regular file, this is the
	// file size. For a directory, this is the size of all its children's hashes.
	merkleSizeXattr = "user.merkle.size"

	// childrenOffsetXattr is the extended attribute name specifying the
	// names of the offset of the serialized children names in the Merkle
	// tree file.
	childrenOffsetXattr = "user.merkle.childrenOffset"

	// childrenSizeXattr is the extended attribute name specifying the size
	// of the serialized children names.
	childrenSizeXattr = "user.merkle.childrenSize"

	// sizeOfStringInt32 is the size for a 32 bit integer stored as string in
	// extended attributes. The maximum value of a 32 bit integer has 10 digits.
	sizeOfStringInt32 = 10
)

var (
	// verityMu synchronizes concurrent operations that enable verity and perform
	// verification checks.
	verityMu sync.RWMutex
)

// Mount option names for verityfs.
const (
	moptLowerPath = "lower_path"
	moptRootHash  = "root_hash"
	moptRootName  = "root_name"
)

// HashAlgorithm is a type specifying the algorithm used to hash the file
// content.
type HashAlgorithm int

// ViolationAction is a type specifying the action when an integrity violation
// is detected.
type ViolationAction int

const (
	// PanicOnViolation terminates the sentry on detected violation.
	PanicOnViolation ViolationAction = 0
	// ErrorOnViolation returns an error from the violating system call on
	// detected violation.
	ErrorOnViolation = 1
)

// Currently supported hashing algorithms include SHA256 and SHA512.
const (
	SHA256 HashAlgorithm = iota
	SHA512
)

func (alg HashAlgorithm) toLinuxHashAlg() int {
	switch alg {
	case SHA256:
		return linux.FS_VERITY_HASH_ALG_SHA256
	case SHA512:
		return linux.FS_VERITY_HASH_ALG_SHA512
	default:
		return 0
	}
}

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
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

	// alg is the algorithms used to hash the files in the verity file
	// system.
	alg HashAlgorithm

	// action specifies the action towards detected violation.
	action ViolationAction

	// opts is the string mount options passed to opts.Data.
	opts string

	// renameMu synchronizes renaming with non-renaming operations in order
	// to ensure consistent lock ordering between dentry.dirMu in different
	// dentries.
	renameMu sync.RWMutex `state:"nosave"`

	// verityMu synchronizes enabling verity files, protects files or
	// directories from being enabled by different threads simultaneously.
	// It also ensures that verity does not access files that are being
	// enabled.
	//
	// Also, the directory Merkle trees depends on the generated trees of
	// its children. So they shouldn't be enabled the same time. This lock
	// is for the whole file system to ensure that no more than one file is
	// enabled the same time.
	verityMu sync.RWMutex `state:"nosave"`
}

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
//
// +stateify savable
type InternalFilesystemOptions struct {
	// LowerName is the name of the filesystem wrapped by verity fs.
	LowerName string

	// Alg is the algorithms used to hash the files in the verity file
	// system.
	Alg HashAlgorithm

	// AllowRuntimeEnable specifies whether the verity file system allows
	// enabling verification for files (i.e. building Merkle trees) during
	// runtime.
	AllowRuntimeEnable bool

	// LowerGetFSOptions is the file system option for the lower layer file
	// system wrapped by verity file system.
	LowerGetFSOptions vfs.GetFilesystemOptions

	// Action specifies the action on an integrity violation.
	Action ViolationAction
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// alertIntegrityViolation alerts a violation of integrity, which usually means
// unexpected modification to the file system is detected. In ErrorOnViolation
// mode, it returns EIO, otherwise it panic.
func (fs *filesystem) alertIntegrityViolation(msg string) error {
	if fs.action == ErrorOnViolation {
		return linuxerr.EIO
	}
	panic(msg)
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mopts := vfs.GenericParseMountOptions(opts.Data)
	var rootHash []byte
	if encodedRootHash, ok := mopts[moptRootHash]; ok {
		delete(mopts, moptRootHash)
		hash, err := hex.DecodeString(encodedRootHash)
		if err != nil {
			ctx.Warningf("verity.FilesystemType.GetFilesystem: Failed to decode root hash: %v", err)
			return nil, nil, linuxerr.EINVAL
		}
		rootHash = hash
	}
	var lowerPathname string
	if path, ok := mopts[moptLowerPath]; ok {
		delete(mopts, moptLowerPath)
		lowerPathname = path
	}
	rootName := "root"
	if root, ok := mopts[moptRootName]; ok {
		delete(mopts, moptRootName)
		rootName = root
	}

	// Check for unparsed options.
	if len(mopts) != 0 {
		ctx.Warningf("verity.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, linuxerr.EINVAL
	}

	// Handle internal options.
	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if len(lowerPathname) == 0 && !ok {
		ctx.Warningf("verity.FilesystemType.GetFilesystem: missing verity configs")
		return nil, nil, linuxerr.EINVAL
	}
	if len(lowerPathname) != 0 {
		if ok {
			ctx.Warningf("verity.FilesystemType.GetFilesystem: unexpected verity configs with specified lower path")
			return nil, nil, linuxerr.EINVAL
		}
		iopts = InternalFilesystemOptions{
			AllowRuntimeEnable: len(rootHash) == 0,
			Action:             ErrorOnViolation,
		}
	}

	var lowerMount *vfs.Mount
	var mountedLowerVD vfs.VirtualDentry
	// Use an existing mount if lowerPath is provided.
	if len(lowerPathname) != 0 {
		vfsroot := vfs.RootFromContext(ctx)
		if vfsroot.Ok() {
			defer vfsroot.DecRef(ctx)
		}
		lowerPath := fspath.Parse(lowerPathname)
		if !lowerPath.Absolute {
			ctx.Infof("verity.FilesystemType.GetFilesystem: lower_path %q must be absolute", lowerPathname)
			return nil, nil, linuxerr.EINVAL
		}
		var err error
		mountedLowerVD, err = vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
			Root:               vfsroot,
			Start:              vfsroot,
			Path:               lowerPath,
			FollowFinalSymlink: true,
		}, &vfs.GetDentryOptions{
			CheckSearchable: true,
		})
		if err != nil {
			ctx.Infof("verity.FilesystemType.GetFilesystem: failed to resolve lower_path %q: %v", lowerPathname, err)
			return nil, nil, err
		}
		lowerMount = mountedLowerVD.Mount()
		defer mountedLowerVD.DecRef(ctx)
	} else {
		// Mount the lower file system. The lower file system is wrapped inside
		// verity, and should not be exposed or connected.
		mountOpts := &vfs.MountOptions{
			GetFilesystemOptions: iopts.LowerGetFSOptions,
			InternalMount:        true,
		}
		mnt, err := vfsObj.MountDisconnected(ctx, creds, "", iopts.LowerName, mountOpts)
		if err != nil {
			return nil, nil, err
		}
		lowerMount = mnt
	}

	fs := &filesystem{
		creds:              creds.Fork(),
		alg:                iopts.Alg,
		lowerMount:         lowerMount,
		action:             iopts.Action,
		opts:               opts.Data,
		allowRuntimeEnable: iopts.AllowRuntimeEnable,
	}
	fs.vfsfs.Init(vfsObj, &fstype, fs)

	// Construct the root dentry.
	d := fs.newDentry()
	d.refs = 1
	lowerVD := vfs.MakeVirtualDentry(lowerMount, lowerMount.Root())
	lowerVD.IncRef()
	d.lowerVD = lowerVD

	rootMerkleName := merkleRootPrefix + rootName

	lowerMerkleVD, err := vfsObj.GetDentryAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
		Path:  fspath.Parse(rootMerkleName),
	}, &vfs.GetDentryOptions{})

	// If runtime enable is allowed, the root merkle tree may be absent. We
	// should create the tree file.
	if linuxerr.Equals(linuxerr.ENOENT, err) && fs.allowRuntimeEnable {
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
		// Failed to get dentry for the root Merkle file. This
		// indicates an unexpected modification that removed/renamed
		// the root Merkle file, or it's never generated.
		fs.vfsfs.DecRef(ctx)
		d.DecRef(ctx)
		return nil, nil, fs.alertIntegrityViolation("Failed to find root Merkle file")
	}

	// Clear the Merkle tree file if they are to be generated at runtime.
	// TODO(b/182315468): Optimize the Merkle tree generate process to
	// allow only updating certain files/directories.
	if fs.allowRuntimeEnable {
		lowerMerkleFD, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  lowerMerkleVD,
			Start: lowerMerkleVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_RDWR | linux.O_TRUNC,
			Mode:  0644,
		})
		if err != nil {
			return nil, nil, err
		}
		lowerMerkleFD.DecRef(ctx)
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

	d.mode = uint32(stat.Mode)
	d.uid = stat.UID
	d.gid = stat.GID
	d.childrenNames = make(map[string]struct{})

	d.hashMu.Lock()
	d.hash = make([]byte, len(rootHash))
	copy(d.hash, rootHash)
	d.hashMu.Unlock()

	fs.rootDentry = d

	if !d.isDir() {
		ctx.Warningf("verity root must be a directory")
		return nil, nil, linuxerr.EINVAL
	}

	if !fs.allowRuntimeEnable {
		// Get children names from the underlying file system.
		offString, err := vfsObj.GetXattrAt(ctx, creds, &vfs.PathOperation{
			Root:  lowerMerkleVD,
			Start: lowerMerkleVD,
		}, &vfs.GetXattrOptions{
			Name: childrenOffsetXattr,
			Size: sizeOfStringInt32,
		})
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENODATA, err) {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s: %v", childrenOffsetXattr, err))
		}
		if err != nil {
			return nil, nil, err
		}

		off, err := strconv.Atoi(offString)
		if err != nil {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s to int: %v", childrenOffsetXattr, err))
		}

		sizeString, err := vfsObj.GetXattrAt(ctx, creds, &vfs.PathOperation{
			Root:  lowerMerkleVD,
			Start: lowerMerkleVD,
		}, &vfs.GetXattrOptions{
			Name: childrenSizeXattr,
			Size: sizeOfStringInt32,
		})
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENODATA, err) {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s: %v", childrenSizeXattr, err))
		}
		if err != nil {
			return nil, nil, err
		}
		size, err := strconv.Atoi(sizeString)
		if err != nil {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s to int: %v", childrenSizeXattr, err))
		}

		lowerMerkleFD, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  lowerMerkleVD,
			Start: lowerMerkleVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_RDONLY,
		})
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to open root Merkle file: %v", err))
		}
		if err != nil {
			return nil, nil, err
		}

		defer lowerMerkleFD.DecRef(ctx)

		childrenNames := make([]byte, size)
		if _, err := lowerMerkleFD.PRead(ctx, usermem.BytesIOSequence(childrenNames), int64(off), vfs.ReadOptions{}); err != nil {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to read root children map: %v", err))
		}

		if err := json.Unmarshal(childrenNames, &d.childrenNames); err != nil {
			return nil, nil, fs.alertIntegrityViolation(fmt.Sprintf("Failed to deserialize childrenNames: %v", err))
		}

		if err := fs.verifyStatAndChildrenLocked(ctx, d, stat); err != nil {
			return nil, nil, err
		}
		d.generateChildrenList()
	}

	d.vfsd.Init(d)

	return &fs.vfsfs, &d.vfsd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.lowerMount.DecRef(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return fs.opts
}

// dentry implements vfs.DentryImpl.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	refs int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// mode, uid, gid and size are the file mode, owner, group, and size of
	// the file in the underlying file system. They are set when a dentry
	// is initialized, and never modified.
	mode uint32
	uid  uint32
	gid  uint32
	size uint32

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
	dirMu    sync.Mutex `state:"nosave"`
	children map[string]*dentry

	// childrenNames stores the name of all children of the dentry. This is
	// used by verity to check whether a child is expected. This is only
	// populated by enableVerity. childrenNames is also protected by dirMu.
	childrenNames map[string]struct{}

	// childrenList is a complete sorted list of childrenNames. This list
	// is generated when verity is enabled, or the first time the file is
	// verified in non runtime enable mode.
	childrenList []string

	// lowerVD is the VirtualDentry in the underlying file system. It is
	// never modified after initialized.
	lowerVD vfs.VirtualDentry

	// lowerMerkleVD is the VirtualDentry of the corresponding Merkle tree
	// in the underlying file system. It is never modified after
	// initialized.
	lowerMerkleVD vfs.VirtualDentry

	// symlinkTarget is the target path of a symlink file in the underlying filesystem.
	symlinkTarget string

	// hash is the calculated hash for the current file or directory. hash
	// is protected by hashMu.
	hashMu sync.RWMutex `state:"nosave"`
	hash   []byte
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
	refsvfs2.Register(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	r := atomic.AddInt64(&d.refs, 1)
	if d.LogRefs() {
		refsvfs2.LogIncRef(d, r)
	}
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		r := atomic.LoadInt64(&d.refs)
		if r <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&d.refs, r, r+1) {
			if d.LogRefs() {
				refsvfs2.LogTryIncRef(d, r+1)
			}
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(ctx context.Context) {
	r := atomic.AddInt64(&d.refs, -1)
	if d.LogRefs() {
		refsvfs2.LogDecRef(d, r)
	}
	if r == 0 {
		d.fs.renameMu.Lock()
		d.checkDropLocked(ctx)
		d.fs.renameMu.Unlock()
	} else if r < 0 {
		panic("verity.dentry.DecRef() called without holding a reference")
	}
}

func (d *dentry) decRefLocked(ctx context.Context) {
	r := atomic.AddInt64(&d.refs, -1)
	if d.LogRefs() {
		refsvfs2.LogDecRef(d, r)
	}
	if r == 0 {
		d.checkDropLocked(ctx)
	} else if r < 0 {
		panic("verity.dentry.decRefLocked() called without holding a reference")
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
// Preconditions:
// * d.fs.renameMu must be locked for writing.
// * d.refs == 0.
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
		d.parent.decRefLocked(ctx)
	}
	refsvfs2.Unregister(d)
}

// RefType implements refsvfs2.CheckedObject.Type.
func (d *dentry) RefType() string {
	return "verity.dentry"
}

// LeakMessage implements refsvfs2.CheckedObject.LeakMessage.
func (d *dentry) LeakMessage() string {
	return fmt.Sprintf("[verity.dentry %p] reference count of %d instead of -1", d, atomic.LoadInt64(&d.refs))
}

// LogRefs implements refsvfs2.CheckedObject.LogRefs.
//
// This should only be set to true for debugging purposes, as it can generate an
// extremely large amount of output and drastically degrade performance.
func (d *dentry) LogRefs() bool {
	return false
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

// verityEnabled checks whether the file is enabled with verity features. It
// should always be true if runtime enable is not allowed. In runtime enable
// mode, it returns true if the target has been enabled with
// ioctl(FS_IOC_ENABLE_VERITY).
func (d *dentry) verityEnabled() bool {
	d.hashMu.RLock()
	defer d.hashMu.RUnlock()
	return !d.fs.allowRuntimeEnable || len(d.hash) != 0
}

// generateChildrenList generates a sorted childrenList from childrenNames, and
// cache it in d for hashing.
func (d *dentry) generateChildrenList() {
	if len(d.childrenList) == 0 && len(d.childrenNames) != 0 {
		for child := range d.childrenNames {
			d.childrenList = append(d.childrenList, child)
		}
		sort.Strings(d.childrenList)
	}
}

// getLowerAt returns the dentry in the underlying file system, which is
// represented by filename relative to d.
func (d *dentry) getLowerAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, filename string) (vfs.VirtualDentry, error) {
	return vfsObj.GetDentryAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(filename),
	}, &vfs.GetDentryOptions{})
}

func (d *dentry) readlink(ctx context.Context) (string, error) {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	if d.verityEnabled() {
		stat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerVD,
			Start: d.lowerVD,
		}, &vfs.StatOptions{})
		if err != nil {
			return "", err
		}
		d.dirMu.Lock()
		defer d.dirMu.Unlock()
		if err := d.fs.verifyStatAndChildrenLocked(ctx, d, stat); err != nil {
			return "", err
		}
		return d.symlinkTarget, nil
	}

	return d.fs.vfsfs.VirtualFilesystem().ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
	})
}

// FileDescription implements vfs.FileDescriptionImpl for verity fds.
// FileDescription is a wrapper of the underlying lowerFD, with support to build
// Merkle trees through the Linux fs-verity API to verify contents read from
// lowerFD.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	// d is the corresponding dentry to the fileDescription.
	d *dentry

	// isDir specifies whehter the fileDescription points to a directory.
	isDir bool

	// lowerFD is the FileDescription corresponding to the file in the
	// underlying file system.
	lowerFD *vfs.FileDescription

	// lowerMappable is the memmap.Mappable corresponding to this file in the
	// underlying file system.
	lowerMappable memmap.Mappable

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

	// off is the file offset. off is protected by mu.
	mu  sync.Mutex `state:"nosave"`
	off int64
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
	stat, err := fd.lowerFD.Stat(ctx, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	fd.d.dirMu.Lock()
	if fd.d.verityEnabled() {
		if err := fd.d.fs.verifyStatAndChildrenLocked(ctx, fd.d, stat); err != nil {
			return linux.Statx{}, err
		}
	}
	fd.d.dirMu.Unlock()
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	// Verity files are read-only.
	return linuxerr.EPERM
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *fileDescription) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	if !fd.d.isDir() {
		return linuxerr.ENOTDIR
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()

	if _, err := fd.lowerFD.Seek(ctx, fd.off, linux.SEEK_SET); err != nil {
		return err
	}

	var ds []vfs.Dirent
	err := fd.lowerFD.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
		// Do not include the Merkle tree files.
		if strings.Contains(dirent.Name, merklePrefix) || strings.Contains(dirent.Name, merkleRootPrefix) {
			return nil
		}
		if fd.d.verityEnabled() {
			// Verify that the child is expected.
			if dirent.Name != "." && dirent.Name != ".." {
				if _, ok := fd.d.childrenNames[dirent.Name]; !ok {
					return fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Unexpected children %s", dirent.Name))
				}
			}
		}
		ds = append(ds, dirent)
		return nil
	}))

	if err != nil {
		return err
	}

	// The result should be a part of all children plus "." and "..", counting from fd.off.
	if fd.d.verityEnabled() && len(ds) != len(fd.d.childrenNames)+2-int(fd.off) {
		return fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Unexpected children number %d", len(ds)))
	}

	for fd.off < int64(len(ds)) {
		if err := cb.Handle(ds[fd.off]); err != nil {
			return err
		}
		fd.off++
	}
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *fileDescription) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	n := int64(0)
	switch whence {
	case linux.SEEK_SET:
		// use offset as specified
	case linux.SEEK_CUR:
		n = fd.off
	case linux.SEEK_END:
		n = int64(fd.d.size)
	default:
		return 0, linuxerr.EINVAL
	}
	if offset > math.MaxInt64-n {
		return 0, linuxerr.EINVAL
	}
	offset += n
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// generateMerkleLocked generates a Merkle tree file for fd. If fd points to a
// file /foo/bar, a Merkle tree file /foo/.merkle.verity.bar is generated. The
// hash of the generated Merkle tree and the data size is returned.  If fd
// points to a regular file, the data is the content of the file. If fd points
// to a directory, the data is all hashes of its children, written to the Merkle
// tree file. If fd represents a symlink, the data is empty and nothing is written
// to the Merkle tree file.
//
// Preconditions: fd.d.fs.verityMu must be locked.
func (fd *fileDescription) generateMerkleLocked(ctx context.Context) ([]byte, uint64, error) {
	fdReader := FileReadWriteSeeker{
		FD:  fd.lowerFD,
		Ctx: ctx,
	}
	merkleReader := FileReadWriteSeeker{
		FD:  fd.merkleReader,
		Ctx: ctx,
	}
	merkleWriter := FileReadWriteSeeker{
		FD:  fd.merkleWriter,
		Ctx: ctx,
	}

	stat, err := fd.lowerFD.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		return nil, 0, err
	}

	fd.d.generateChildrenList()

	params := &merkletree.GenerateParams{
		TreeReader:     &merkleReader,
		TreeWriter:     &merkleWriter,
		Children:       fd.d.childrenList,
		HashAlgorithms: fd.d.fs.alg.toLinuxHashAlg(),
		Name:           fd.d.name,
		Mode:           uint32(stat.Mode),
		UID:            stat.UID,
		GID:            stat.GID,
	}

	switch atomic.LoadUint32(&fd.d.mode) & linux.S_IFMT {
	case linux.S_IFREG:
		// For a regular file, generate a Merkle tree based on its
		// content.
		params.File = &fdReader
		params.Size = int64(stat.Size)
		params.DataAndTreeInSameFile = false
	case linux.S_IFDIR:
		// For a directory, generate a Merkle tree based on the hashes
		// of its children that has already been written to the Merkle
		// tree file.
		merkleStat, err := fd.merkleReader.Stat(ctx, vfs.StatOptions{})
		if err != nil {
			return nil, 0, err
		}

		params.Size = int64(merkleStat.Size)
		params.File = &merkleReader
		params.DataAndTreeInSameFile = true
	case linux.S_IFLNK:
		// For a symlink, generate a Merkle tree file but do not write the root hash
		// of the target file content to it. Return a hash of a VerityDescriptor object
		// which includes the symlink target name.
		target, err := fd.d.readlink(ctx)
		if err != nil {
			return nil, 0, err
		}

		params.Size = int64(stat.Size)
		params.DataAndTreeInSameFile = false
		params.SymlinkTarget = target
	default:
		// TODO(b/167728857): Investigate whether and how we should
		// enable other types of file.
		return nil, 0, linuxerr.EINVAL
	}
	hash, err := merkletree.Generate(params)
	return hash, uint64(params.Size), err
}

// recordChildrenLocked writes the names of fd's children into the
// corresponding Merkle tree file, and saves the offset/size of the map into
// xattrs.
//
// Preconditions:
// * fd.d.fs.verityMu must be locked.
// * fd.d.isDir() == true.
func (fd *fileDescription) recordChildrenLocked(ctx context.Context) error {
	// Record the children names in the Merkle tree file.
	childrenNames, err := json.Marshal(fd.d.childrenNames)
	if err != nil {
		return err
	}

	stat, err := fd.merkleWriter.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		return err
	}

	if err := fd.merkleWriter.SetXattr(ctx, &vfs.SetXattrOptions{
		Name:  childrenOffsetXattr,
		Value: strconv.Itoa(int(stat.Size)),
	}); err != nil {
		return err
	}
	if err := fd.merkleWriter.SetXattr(ctx, &vfs.SetXattrOptions{
		Name:  childrenSizeXattr,
		Value: strconv.Itoa(len(childrenNames)),
	}); err != nil {
		return err
	}

	if _, err = fd.merkleWriter.Write(ctx, usermem.BytesIOSequence(childrenNames), vfs.WriteOptions{}); err != nil {
		return err
	}

	return nil
}

// enableVerity enables verity features on fd by generating a Merkle tree file
// and stores its hash in its parent directory's Merkle tree.
func (fd *fileDescription) enableVerity(ctx context.Context) (uintptr, error) {
	if !fd.d.fs.allowRuntimeEnable {
		return 0, linuxerr.EPERM
	}

	fd.d.fs.verityMu.Lock()
	defer fd.d.fs.verityMu.Unlock()

	// In allowRuntimeEnable mode, the underlying fd and read/write fd for
	// the Merkle tree file should have all been initialized. For any file
	// or directory other than the root, the parent Merkle tree file should
	// have also been initialized.
	if fd.lowerFD == nil || fd.merkleReader == nil || fd.merkleWriter == nil || (fd.parentMerkleWriter == nil && fd.d != fd.d.fs.rootDentry) {
		return 0, fd.d.fs.alertIntegrityViolation("Unexpected verity fd: missing expected underlying fds")
	}

	// Populate children names here. We cannot rely on the children
	// dentries to populate parent dentry's children names, because the
	// parent dentry may be destroyed before users enable verity if its ref
	// count drops to zero.
	if fd.d.isDir() {
		if err := fd.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
			if dirent.Name != "." && dirent.Name != ".." {
				fd.d.childrenNames[dirent.Name] = struct{}{}
			}
			return nil
		})); err != nil {
			return 0, err
		}
	}

	hash, dataSize, err := fd.generateMerkleLocked(ctx)
	if err != nil {
		return 0, err
	}

	if fd.parentMerkleWriter != nil {
		stat, err := fd.parentMerkleWriter.Stat(ctx, vfs.StatOptions{})
		if err != nil {
			return 0, err
		}

		// Write the hash of fd to the parent directory's Merkle tree
		// file, as it should be part of the parent Merkle tree data.
		// parentMerkleWriter is open with O_APPEND, so it should write
		// directly to the end of the file.
		if _, err = fd.parentMerkleWriter.Write(ctx, usermem.BytesIOSequence(hash), vfs.WriteOptions{}); err != nil {
			return 0, err
		}

		// Record the offset of the hash of fd in parent directory's
		// Merkle tree file.
		if err := fd.merkleWriter.SetXattr(ctx, &vfs.SetXattrOptions{
			Name:  merkleOffsetInParentXattr,
			Value: strconv.Itoa(int(stat.Size)),
		}); err != nil {
			return 0, err
		}
	}

	// Record the size of the data being hashed for fd.
	if err := fd.merkleWriter.SetXattr(ctx, &vfs.SetXattrOptions{
		Name:  merkleSizeXattr,
		Value: strconv.Itoa(int(dataSize)),
	}); err != nil {
		return 0, err
	}

	if fd.d.isDir() {
		if err := fd.recordChildrenLocked(ctx); err != nil {
			return 0, err
		}
	}
	fd.d.hashMu.Lock()
	fd.d.hash = hash
	fd.d.hashMu.Unlock()
	return 0, nil
}

// measureVerity returns the hash of fd, saved in verityDigest.
func (fd *fileDescription) measureVerity(ctx context.Context, verityDigest hostarch.Addr) (uintptr, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return 0, linuxerr.EINVAL
	}
	var metadata linux.DigestMetadata

	fd.d.hashMu.RLock()
	defer fd.d.hashMu.RUnlock()

	// If allowRuntimeEnable is true, an empty fd.d.hash indicates that
	// verity is not enabled for the file. If allowRuntimeEnable is false,
	// this is an integrity violation because all files should have verity
	// enabled, in which case fd.d.hash should be set.
	if len(fd.d.hash) == 0 {
		if fd.d.fs.allowRuntimeEnable {
			return 0, linuxerr.ENODATA
		}
		return 0, fd.d.fs.alertIntegrityViolation("Ioctl measureVerity: no hash found")
	}

	// The first part of VerityDigest is the metadata.
	if _, err := metadata.CopyIn(t, verityDigest); err != nil {
		return 0, err
	}
	if metadata.DigestSize < uint16(len(fd.d.hash)) {
		return 0, linuxerr.EOVERFLOW
	}

	// Populate the output digest size, since DigestSize is both input and
	// output.
	metadata.DigestSize = uint16(len(fd.d.hash))

	// First copy the metadata.
	if _, err := metadata.CopyOut(t, verityDigest); err != nil {
		return 0, err
	}

	// Now copy the root hash bytes to the memory after metadata.
	_, err := t.CopyOutBytes(hostarch.Addr(uintptr(verityDigest)+linux.SizeOfDigestMetadata), fd.d.hash)
	return 0, err
}

func (fd *fileDescription) verityFlags(ctx context.Context, flags hostarch.Addr) (uintptr, error) {
	f := int32(0)

	fd.d.hashMu.RLock()
	// All enabled files should store a hash. This flag is not settable via
	// FS_IOC_SETFLAGS.
	if len(fd.d.hash) != 0 {
		f |= linux.FS_VERITY_FL
	}
	fd.d.hashMu.RUnlock()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return 0, linuxerr.EINVAL
	}
	_, err := primitive.CopyInt32Out(t, flags, f)
	return 0, err
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *fileDescription) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch cmd := args[1].Uint(); cmd {
	case linux.FS_IOC_ENABLE_VERITY:
		return fd.enableVerity(ctx)
	case linux.FS_IOC_MEASURE_VERITY:
		return fd.measureVerity(ctx, args[2].Pointer())
	case linux.FS_IOC_GETFLAGS:
		return fd.verityFlags(ctx, args[2].Pointer())
	default:
		return 0, linuxerr.ENOSYS
	}
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// Implement Read with PRead by setting offset.
	fd.mu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// No need to verify if the file is not enabled yet in
	// allowRuntimeEnable mode.
	if !fd.d.verityEnabled() {
		return fd.lowerFD.PRead(ctx, dst, offset, opts)
	}

	fd.d.fs.verityMu.RLock()
	defer fd.d.fs.verityMu.RUnlock()
	// dataSize is the size of the whole file.
	dataSize, err := fd.merkleReader.GetXattr(ctx, &vfs.GetXattrOptions{
		Name: merkleSizeXattr,
		Size: sizeOfStringInt32,
	})

	// The Merkle tree file for the child should have been created and
	// contains the expected xattrs. If the xattr does not exist, it
	// indicates unexpected modifications to the file system.
	if linuxerr.Equals(linuxerr.ENODATA, err) {
		return 0, fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s: %v", merkleSizeXattr, err))
	}
	if err != nil {
		return 0, err
	}

	// The dataSize xattr should be an integer. If it's not, it indicates
	// unexpected modifications to the file system.
	size, err := strconv.Atoi(dataSize)
	if err != nil {
		return 0, fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s to int: %v", merkleSizeXattr, err))
	}

	dataReader := FileReadWriteSeeker{
		FD:  fd.lowerFD,
		Ctx: ctx,
	}

	merkleReader := FileReadWriteSeeker{
		FD:  fd.merkleReader,
		Ctx: ctx,
	}

	fd.d.hashMu.RLock()
	n, err := merkletree.Verify(&merkletree.VerifyParams{
		Out:                   dst.Writer(ctx),
		File:                  &dataReader,
		Tree:                  &merkleReader,
		Size:                  int64(size),
		Name:                  fd.d.name,
		Mode:                  fd.d.mode,
		UID:                   fd.d.uid,
		GID:                   fd.d.gid,
		Children:              fd.d.childrenList,
		HashAlgorithms:        fd.d.fs.alg.toLinuxHashAlg(),
		ReadOffset:            offset,
		ReadSize:              dst.NumBytes(),
		Expected:              fd.d.hash,
		DataAndTreeInSameFile: false,
	})
	fd.d.hashMu.RUnlock()
	if err != nil {
		return 0, fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Verification failed: %v", err))
	}
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EROFS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EROFS
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *fileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if err := fd.lowerFD.ConfigureMMap(ctx, opts); err != nil {
		return err
	}
	fd.lowerMappable = opts.Mappable
	if opts.MappingIdentity != nil {
		opts.MappingIdentity.DecRef(ctx)
		opts.MappingIdentity = nil
	}

	// Check if mmap is allowed on the lower filesystem.
	if !opts.SentryOwnedContent {
		return linuxerr.ENODEV
	}
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd, opts)
}

// SupportsLocks implements vfs.FileDescriptionImpl.SupportsLocks.
func (fd *fileDescription) SupportsLocks() bool {
	return fd.lowerFD.SupportsLocks()
}

// LockBSD implements vfs.FileDescriptionImpl.LockBSD.
func (fd *fileDescription) LockBSD(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, block fslock.Blocker) error {
	return fd.lowerFD.LockBSD(ctx, ownerPID, t, block)
}

// UnlockBSD implements vfs.FileDescriptionImpl.UnlockBSD.
func (fd *fileDescription) UnlockBSD(ctx context.Context, uid fslock.UniqueID) error {
	return fd.lowerFD.UnlockBSD(ctx)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, r fslock.LockRange, block fslock.Blocker) error {
	return fd.lowerFD.LockPOSIX(ctx, uid, ownerPID, t, r, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, r fslock.LockRange) error {
	return fd.lowerFD.UnlockPOSIX(ctx, uid, r)
}

// TestPOSIX implements vfs.FileDescriptionImpl.TestPOSIX.
func (fd *fileDescription) TestPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, r fslock.LockRange) (linux.Flock, error) {
	return fd.lowerFD.TestPOSIX(ctx, uid, t, r)
}

// Translate implements memmap.Mappable.Translate.
func (fd *fileDescription) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	ts, err := fd.lowerMappable.Translate(ctx, required, optional, at)
	if err != nil {
		return nil, err
	}

	// dataSize is the size of the whole file.
	dataSize, err := fd.merkleReader.GetXattr(ctx, &vfs.GetXattrOptions{
		Name: merkleSizeXattr,
		Size: sizeOfStringInt32,
	})

	// The Merkle tree file for the child should have been created and
	// contains the expected xattrs. If the xattr does not exist, it
	// indicates unexpected modifications to the file system.
	if linuxerr.Equals(linuxerr.ENODATA, err) {
		return nil, fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Failed to get xattr %s: %v", merkleSizeXattr, err))
	}
	if err != nil {
		return nil, err
	}

	// The dataSize xattr should be an integer. If it's not, it indicates
	// unexpected modifications to the file system.
	size, err := strconv.Atoi(dataSize)
	if err != nil {
		return nil, fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Failed to convert xattr %s to int: %v", merkleSizeXattr, err))
	}

	merkleReader := FileReadWriteSeeker{
		FD:  fd.merkleReader,
		Ctx: ctx,
	}

	for _, t := range ts {
		// Content integrity relies on sentry owning the backing data. MapInternal is guaranteed
		// to fetch sentry owned memory because we disallow verity mmaps otherwise.
		ims, err := t.File.MapInternal(memmap.FileRange{t.Offset, t.Offset + t.Source.Length()}, hostarch.Read)
		if err != nil {
			return nil, err
		}
		dataReader := mmapReadSeeker{ims, t.Source.Start}
		var buf bytes.Buffer
		_, err = merkletree.Verify(&merkletree.VerifyParams{
			Out:                   &buf,
			File:                  &dataReader,
			Tree:                  &merkleReader,
			Size:                  int64(size),
			Name:                  fd.d.name,
			Mode:                  fd.d.mode,
			UID:                   fd.d.uid,
			GID:                   fd.d.gid,
			HashAlgorithms:        fd.d.fs.alg.toLinuxHashAlg(),
			ReadOffset:            int64(t.Source.Start),
			ReadSize:              int64(t.Source.Length()),
			Expected:              fd.d.hash,
			DataAndTreeInSameFile: false,
		})
		if err != nil {
			return nil, fd.d.fs.alertIntegrityViolation(fmt.Sprintf("Verification failed: %v", err))
		}
	}
	return ts, err
}

// AddMapping implements memmap.Mappable.AddMapping.
func (fd *fileDescription) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	return fd.lowerMappable.AddMapping(ctx, ms, ar, offset, writable)
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (fd *fileDescription) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	fd.lowerMappable.RemoveMapping(ctx, ms, ar, offset, writable)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (fd *fileDescription) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return fd.lowerMappable.CopyMapping(ctx, ms, srcAR, dstAR, offset, writable)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (fd *fileDescription) InvalidateUnsavable(context.Context) error {
	return nil
}

// mmapReadSeeker is a helper struct used by fileDescription.Translate to pass
// a safemem.BlockSeq pointing to the mapped region as io.ReaderAt.
type mmapReadSeeker struct {
	safemem.BlockSeq
	Offset uint64
}

// ReadAt implements io.ReaderAt.ReadAt. off is the offset into the mapped file.
func (r *mmapReadSeeker) ReadAt(p []byte, off int64) (int, error) {
	bs := r.BlockSeq
	// Adjust the offset into the mapped file to get the offset into the internally
	// mapped region.
	readOffset := off - int64(r.Offset)
	if readOffset < 0 {
		return 0, linuxerr.EINVAL
	}
	bs.DropFirst64(uint64(readOffset))
	view := bs.TakeFirst64(uint64(len(p)))
	dst := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(p))
	n, err := safemem.CopySeq(dst, view)
	return int(n), err
}

// FileReadWriteSeeker is a helper struct to pass a vfs.FileDescription as
// io.Reader/io.Writer/io.ReadSeeker/io.ReaderAt/io.WriterAt/etc.
type FileReadWriteSeeker struct {
	FD    *vfs.FileDescription
	Ctx   context.Context
	ROpts vfs.ReadOptions
	WOpts vfs.WriteOptions
}

// ReadAt implements io.ReaderAt.ReadAt.
func (f *FileReadWriteSeeker) ReadAt(p []byte, off int64) (int, error) {
	dst := usermem.BytesIOSequence(p)
	n, err := f.FD.PRead(f.Ctx, dst, off, f.ROpts)
	return int(n), err
}

// Read implements io.ReadWriteSeeker.Read.
func (f *FileReadWriteSeeker) Read(p []byte) (int, error) {
	dst := usermem.BytesIOSequence(p)
	n, err := f.FD.Read(f.Ctx, dst, f.ROpts)
	return int(n), err
}

// Seek implements io.ReadWriteSeeker.Seek.
func (f *FileReadWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	return f.FD.Seek(f.Ctx, offset, int32(whence))
}

// WriteAt implements io.WriterAt.WriteAt.
func (f *FileReadWriteSeeker) WriteAt(p []byte, off int64) (int, error) {
	dst := usermem.BytesIOSequence(p)
	n, err := f.FD.PWrite(f.Ctx, dst, off, f.WOpts)
	return int(n), err
}

// Write implements io.ReadWriteSeeker.Write.
func (f *FileReadWriteSeeker) Write(p []byte) (int, error) {
	buf := usermem.BytesIOSequence(p)
	n, err := f.FD.Write(f.Ctx, buf, f.WOpts)
	return int(n), err
}
