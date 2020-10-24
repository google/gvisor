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

// Package overlay provides an overlay filesystem implementation, which
// synthesizes a filesystem by composing one or more immutable filesystems
// ("lower layers") with an optional mutable filesystem ("upper layer").
//
// Lock order:
//
// directoryFD.mu / regularFileFD.mu
//   filesystem.renameMu
//     dentry.dirMu
//       dentry.copyMu
//         *** "memmap.Mappable locks" below this point
//         dentry.mapsMu
//           *** "memmap.Mappable locks taken by Translate" below this point
//           dentry.dataMu
//
// Locking dentry.dirMu in multiple dentries requires that parent dentries are
// locked before child dentries, and that filesystem.renameMu is locked to
// stabilize this relationship.
package overlay

import (
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Name is the default filesystem name.
const Name = "overlay"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// FilesystemOptions may be passed as vfs.GetFilesystemOptions.InternalData to
// FilesystemType.GetFilesystem.
//
// +stateify savable
type FilesystemOptions struct {
	// Callers passing FilesystemOptions to
	// overlay.FilesystemType.GetFilesystem() are responsible for ensuring that
	// the vfs.Mounts comprising the layers of the overlay filesystem do not
	// contain submounts.

	// If UpperRoot.Ok(), it is the root of the writable upper layer of the
	// overlay.
	UpperRoot vfs.VirtualDentry

	// LowerRoots contains the roots of the immutable lower layers of the
	// overlay. LowerRoots is immutable.
	LowerRoots []vfs.VirtualDentry
}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	vfsfs vfs.Filesystem

	// Immutable options.
	opts FilesystemOptions

	// creds is a copy of the filesystem's creator's credentials, which are
	// used for accesses to the filesystem's layers. creds is immutable.
	creds *auth.Credentials

	// dirDevMinor is the device minor number used for directories. dirDevMinor
	// is immutable.
	dirDevMinor uint32

	// lowerDevMinors maps lower layer filesystems to device minor numbers
	// assigned to non-directory files originating from that filesystem.
	// lowerDevMinors is immutable.
	lowerDevMinors map[*vfs.Filesystem]uint32

	// renameMu synchronizes renaming with non-renaming operations in order to
	// ensure consistent lock ordering between dentry.dirMu in different
	// dentries.
	renameMu sync.RWMutex `state:"nosave"`

	// lastDirIno is the last inode number assigned to a directory. lastDirIno
	// is accessed using atomic memory operations.
	lastDirIno uint64
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mopts := vfs.GenericParseMountOptions(opts.Data)
	fsoptsRaw := opts.InternalData
	fsopts, haveFSOpts := fsoptsRaw.(FilesystemOptions)
	if fsoptsRaw != nil && !haveFSOpts {
		ctx.Infof("overlay.FilesystemType.GetFilesystem: GetFilesystemOptions.InternalData has type %T, wanted overlay.FilesystemOptions or nil", fsoptsRaw)
		return nil, nil, syserror.EINVAL
	}
	if haveFSOpts {
		if len(fsopts.LowerRoots) == 0 {
			ctx.Infof("overlay.FilesystemType.GetFilesystem: LowerRoots must be non-empty")
			return nil, nil, syserror.EINVAL
		}
		if len(fsopts.LowerRoots) < 2 && !fsopts.UpperRoot.Ok() {
			ctx.Infof("overlay.FilesystemType.GetFilesystem: at least two LowerRoots are required when UpperRoot is unspecified")
			return nil, nil, syserror.EINVAL
		}
		// We don't enforce a maximum number of lower layers when not
		// configured by applications; the sandbox owner can have an overlay
		// filesystem with any number of lower layers.
	} else {
		vfsroot := vfs.RootFromContext(ctx)
		defer vfsroot.DecRef(ctx)
		upperPathname, ok := mopts["upperdir"]
		if ok {
			delete(mopts, "upperdir")
			// Linux overlayfs also requires a workdir when upperdir is
			// specified; we don't, so silently ignore this option.
			delete(mopts, "workdir")
			upperPath := fspath.Parse(upperPathname)
			if !upperPath.Absolute {
				ctx.Infof("overlay.FilesystemType.GetFilesystem: upperdir %q must be absolute", upperPathname)
				return nil, nil, syserror.EINVAL
			}
			upperRoot, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
				Root:               vfsroot,
				Start:              vfsroot,
				Path:               upperPath,
				FollowFinalSymlink: true,
			}, &vfs.GetDentryOptions{
				CheckSearchable: true,
			})
			if err != nil {
				ctx.Infof("overlay.FilesystemType.GetFilesystem: failed to resolve upperdir %q: %v", upperPathname, err)
				return nil, nil, err
			}
			defer upperRoot.DecRef(ctx)
			privateUpperRoot, err := clonePrivateMount(vfsObj, upperRoot, false /* forceReadOnly */)
			if err != nil {
				ctx.Infof("overlay.FilesystemType.GetFilesystem: failed to make private bind mount of upperdir %q: %v", upperPathname, err)
				return nil, nil, err
			}
			defer privateUpperRoot.DecRef(ctx)
			fsopts.UpperRoot = privateUpperRoot
		}
		lowerPathnamesStr, ok := mopts["lowerdir"]
		if !ok {
			ctx.Infof("overlay.FilesystemType.GetFilesystem: missing required option lowerdir")
			return nil, nil, syserror.EINVAL
		}
		delete(mopts, "lowerdir")
		lowerPathnames := strings.Split(lowerPathnamesStr, ":")
		const maxLowerLayers = 500 // Linux: fs/overlay/super.c:OVL_MAX_STACK
		if len(lowerPathnames) < 2 && !fsopts.UpperRoot.Ok() {
			ctx.Infof("overlay.FilesystemType.GetFilesystem: at least two lowerdirs are required when upperdir is unspecified")
			return nil, nil, syserror.EINVAL
		}
		if len(lowerPathnames) > maxLowerLayers {
			ctx.Infof("overlay.FilesystemType.GetFilesystem: %d lowerdirs specified, maximum %d", len(lowerPathnames), maxLowerLayers)
			return nil, nil, syserror.EINVAL
		}
		for _, lowerPathname := range lowerPathnames {
			lowerPath := fspath.Parse(lowerPathname)
			if !lowerPath.Absolute {
				ctx.Infof("overlay.FilesystemType.GetFilesystem: lowerdir %q must be absolute", lowerPathname)
				return nil, nil, syserror.EINVAL
			}
			lowerRoot, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
				Root:               vfsroot,
				Start:              vfsroot,
				Path:               lowerPath,
				FollowFinalSymlink: true,
			}, &vfs.GetDentryOptions{
				CheckSearchable: true,
			})
			if err != nil {
				ctx.Infof("overlay.FilesystemType.GetFilesystem: failed to resolve lowerdir %q: %v", lowerPathname, err)
				return nil, nil, err
			}
			defer lowerRoot.DecRef(ctx)
			privateLowerRoot, err := clonePrivateMount(vfsObj, lowerRoot, true /* forceReadOnly */)
			if err != nil {
				ctx.Infof("overlay.FilesystemType.GetFilesystem: failed to make private bind mount of lowerdir %q: %v", lowerPathname, err)
				return nil, nil, err
			}
			defer privateLowerRoot.DecRef(ctx)
			fsopts.LowerRoots = append(fsopts.LowerRoots, privateLowerRoot)
		}
	}
	if len(mopts) != 0 {
		ctx.Infof("overlay.FilesystemType.GetFilesystem: unused options: %v", mopts)
		return nil, nil, syserror.EINVAL
	}

	// Allocate device numbers.
	dirDevMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	lowerDevMinors := make(map[*vfs.Filesystem]uint32)
	for _, lowerRoot := range fsopts.LowerRoots {
		lowerFS := lowerRoot.Mount().Filesystem()
		if _, ok := lowerDevMinors[lowerFS]; !ok {
			devMinor, err := vfsObj.GetAnonBlockDevMinor()
			if err != nil {
				vfsObj.PutAnonBlockDevMinor(dirDevMinor)
				for _, lowerDevMinor := range lowerDevMinors {
					vfsObj.PutAnonBlockDevMinor(lowerDevMinor)
				}
				return nil, nil, err
			}
			lowerDevMinors[lowerFS] = devMinor
		}
	}

	// Take extra references held by the filesystem.
	if fsopts.UpperRoot.Ok() {
		fsopts.UpperRoot.IncRef()
	}
	for _, lowerRoot := range fsopts.LowerRoots {
		lowerRoot.IncRef()
	}

	fs := &filesystem{
		opts:           fsopts,
		creds:          creds.Fork(),
		dirDevMinor:    dirDevMinor,
		lowerDevMinors: lowerDevMinors,
	}
	fs.vfsfs.Init(vfsObj, &fstype, fs)

	// Construct the root dentry.
	root := fs.newDentry()
	root.refs = 1
	if fs.opts.UpperRoot.Ok() {
		fs.opts.UpperRoot.IncRef()
		root.copiedUp = 1
		root.upperVD = fs.opts.UpperRoot
	}
	for _, lowerRoot := range fs.opts.LowerRoots {
		lowerRoot.IncRef()
		root.lowerVDs = append(root.lowerVDs, lowerRoot)
	}
	rootTopVD := root.topLayer()
	// Get metadata from the topmost layer. See fs.lookupLocked().
	const rootStatMask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO
	rootStat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:  rootTopVD,
		Start: rootTopVD,
	}, &vfs.StatOptions{
		Mask: rootStatMask,
	})
	if err != nil {
		root.destroyLocked(ctx)
		fs.vfsfs.DecRef(ctx)
		return nil, nil, err
	}
	if rootStat.Mask&rootStatMask != rootStatMask {
		root.destroyLocked(ctx)
		fs.vfsfs.DecRef(ctx)
		return nil, nil, syserror.EREMOTE
	}
	if isWhiteout(&rootStat) {
		ctx.Infof("overlay.FilesystemType.GetFilesystem: filesystem root is a whiteout")
		root.destroyLocked(ctx)
		fs.vfsfs.DecRef(ctx)
		return nil, nil, syserror.EINVAL
	}
	root.mode = uint32(rootStat.Mode)
	root.uid = rootStat.UID
	root.gid = rootStat.GID
	if rootStat.Mode&linux.S_IFMT == linux.S_IFDIR {
		root.devMajor = linux.UNNAMED_MAJOR
		root.devMinor = fs.dirDevMinor
		root.ino = fs.newDirIno()
	} else if !root.upperVD.Ok() {
		root.devMajor = linux.UNNAMED_MAJOR
		root.devMinor = fs.lowerDevMinors[root.lowerVDs[0].Mount().Filesystem()]
		root.ino = rootStat.Ino
	} else {
		root.devMajor = rootStat.DevMajor
		root.devMinor = rootStat.DevMinor
		root.ino = rootStat.Ino
	}

	return &fs.vfsfs, &root.vfsd, nil
}

// clonePrivateMount creates a non-recursive bind mount rooted at vd, not
// associated with any MountNamespace, and returns the root of the new mount.
// (This is required to ensure that each layer of an overlay comprises only a
// single mount, and therefore can't cross into e.g. the overlay filesystem
// itself, risking lock recursion.) A reference is held on the returned
// VirtualDentry.
func clonePrivateMount(vfsObj *vfs.VirtualFilesystem, vd vfs.VirtualDentry, forceReadOnly bool) (vfs.VirtualDentry, error) {
	oldmnt := vd.Mount()
	opts := oldmnt.Options()
	if forceReadOnly {
		opts.ReadOnly = true
	}
	newmnt, err := vfsObj.NewDisconnectedMount(oldmnt.Filesystem(), vd.Dentry(), &opts)
	if err != nil {
		return vfs.VirtualDentry{}, err
	}
	// Take a reference on the dentry which will be owned by the returned
	// VirtualDentry.
	d := vd.Dentry()
	d.IncRef()
	return vfs.MakeVirtualDentry(newmnt, d), nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	vfsObj := fs.vfsfs.VirtualFilesystem()
	vfsObj.PutAnonBlockDevMinor(fs.dirDevMinor)
	for _, lowerDevMinor := range fs.lowerDevMinors {
		vfsObj.PutAnonBlockDevMinor(lowerDevMinor)
	}
	if fs.opts.UpperRoot.Ok() {
		fs.opts.UpperRoot.DecRef(ctx)
	}
	for _, lowerRoot := range fs.opts.LowerRoots {
		lowerRoot.DecRef(ctx)
	}
}

func (fs *filesystem) statFS(ctx context.Context) (linux.Statfs, error) {
	// Always statfs the root of the topmost layer. Compare Linux's
	// fs/overlayfs/super.c:ovl_statfs().
	var rootVD vfs.VirtualDentry
	if fs.opts.UpperRoot.Ok() {
		rootVD = fs.opts.UpperRoot
	} else {
		rootVD = fs.opts.LowerRoots[0]
	}
	fsstat, err := fs.vfsfs.VirtualFilesystem().StatFSAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  rootVD,
		Start: rootVD,
	})
	if err != nil {
		return linux.Statfs{}, err
	}
	fsstat.Type = linux.OVERLAYFS_SUPER_MAGIC
	return fsstat, nil
}

func (fs *filesystem) newDirIno() uint64 {
	return atomic.AddUint64(&fs.lastDirIno, 1)
}

// dentry implements vfs.DentryImpl.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	refs int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// mode, uid, and gid are the file mode, owner, and group of the file in
	// the topmost layer (and therefore the overlay file as well), and are used
	// for permission checks on this dentry. These fields are protected by
	// copyMu and accessed using atomic memory operations.
	mode uint32
	uid  uint32
	gid  uint32

	// copiedUp is 1 if this dentry has been copied-up (i.e. upperVD.Ok()) and
	// 0 otherwise. copiedUp is accessed using atomic memory operations.
	copiedUp uint32

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
	dirents  []vfs.Dirent

	// upperVD and lowerVDs are the files from the overlay filesystem's layers
	// that comprise the file on the overlay filesystem.
	//
	// If !upperVD.Ok(), it can transition to a valid vfs.VirtualDentry (i.e.
	// be copied up) with copyMu locked for writing; otherwise, it is
	// immutable. lowerVDs is always immutable.
	copyMu   sync.RWMutex `state:"nosave"`
	upperVD  vfs.VirtualDentry
	lowerVDs []vfs.VirtualDentry

	// inlineLowerVDs backs lowerVDs in the common case where len(lowerVDs) <=
	// len(inlineLowerVDs).
	inlineLowerVDs [1]vfs.VirtualDentry

	// devMajor, devMinor, and ino are the device major/minor and inode numbers
	// used by this dentry. These fields are protected by copyMu and accessed
	// using atomic memory operations.
	devMajor uint32
	devMinor uint32
	ino      uint64

	// If this dentry represents a regular file, then:
	//
	// - mapsMu is used to synchronize between copy-up and memmap.Mappable
	// methods on dentry preceding mm.MemoryManager.activeMu in the lock order.
	//
	// - dataMu is used to synchronize between copy-up and
	// dentry.(memmap.Mappable).Translate.
	//
	// - lowerMappings tracks memory mappings of the file. lowerMappings is
	// used to invalidate mappings of the lower layer when the file is copied
	// up to ensure that they remain coherent with subsequent writes to the
	// file. (Note that, as of this writing, Linux overlayfs does not do this;
	// this feature is a gVisor extension.) lowerMappings is protected by
	// mapsMu.
	//
	// - If this dentry is copied-up, then wrappedMappable is the Mappable
	// obtained from a call to the current top layer's
	// FileDescription.ConfigureMMap(). Once wrappedMappable becomes non-nil
	// (from a call to regularFileFD.ensureMappable()), it cannot become nil.
	// wrappedMappable is protected by mapsMu and dataMu.
	//
	// - isMappable is non-zero iff wrappedMappable is non-nil. isMappable is
	// accessed using atomic memory operations.
	mapsMu          sync.Mutex `state:"nosave"`
	lowerMappings   memmap.MappingSet
	dataMu          sync.RWMutex `state:"nosave"`
	wrappedMappable memmap.Mappable
	isMappable      uint32

	locks vfs.FileLocks

	// watches is the set of inotify watches on the file repesented by this dentry.
	//
	// Note that hard links to the same file will not share the same set of
	// watches, due to the fact that we do not have inode structures in this
	// overlay implementation.
	watches vfs.Watches
}

// newDentry creates a new dentry. The dentry initially has no references; it
// is the caller's responsibility to set the dentry's reference count and/or
// call dentry.destroy() as appropriate. The dentry is initially invalid in
// that it contains no layers; the caller is responsible for setting them.
func (fs *filesystem) newDentry() *dentry {
	d := &dentry{
		fs: fs,
	}
	d.lowerVDs = d.inlineLowerVDs[:0]
	d.vfsd.Init(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	// d.refs may be 0 if d.fs.renameMu is locked, which serializes against
	// d.checkDropLocked().
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
		panic("overlay.dentry.DecRef() called without holding a reference")
	}
}

// checkDropLocked should be called after d's reference count becomes 0 or it
// becomes deleted.
//
// Preconditions: d.fs.renameMu must be locked for writing.
func (d *dentry) checkDropLocked(ctx context.Context) {
	// Dentries with a positive reference count must be retained. (The only way
	// to obtain a reference on a dentry with zero references is via path
	// resolution, which requires renameMu, so if d.refs is zero then it will
	// remain zero while we hold renameMu for writing.) Dentries with a
	// negative reference count have already been destroyed.
	if atomic.LoadInt64(&d.refs) != 0 {
		return
	}

	// Make sure that we do not lose watches on dentries that have not been
	// deleted. Note that overlayfs never calls VFS.InvalidateDentry(), so
	// d.vfsd.IsDead() indicates that d was deleted.
	if !d.vfsd.IsDead() && d.watches.Size() > 0 {
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
		panic("overlay.dentry.destroyLocked() called on already destroyed dentry")
	default:
		panic("overlay.dentry.destroyLocked() called with references on the dentry")
	}

	if d.upperVD.Ok() {
		d.upperVD.DecRef(ctx)
	}
	for _, lowerVD := range d.lowerVDs {
		lowerVD.DecRef(ctx)
	}

	d.watches.HandleDeletion(ctx)

	if d.parent != nil {
		d.parent.dirMu.Lock()
		if !d.vfsd.IsDead() {
			delete(d.parent.children, d.name)
		}
		d.parent.dirMu.Unlock()
		// Drop the reference held by d on its parent without recursively
		// locking d.fs.renameMu.
		if refs := atomic.AddInt64(&d.parent.refs, -1); refs == 0 {
			d.parent.checkDropLocked(ctx)
		} else if refs < 0 {
			panic("overlay.dentry.DecRef() called without holding a reference")
		}
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events uint32, cookie uint32, et vfs.EventType) {
	if d.isDir() {
		events |= linux.IN_ISDIR
	}

	// overlayfs never calls VFS.InvalidateDentry(), so d.vfsd.IsDead() indicates
	// that d was deleted.
	deleted := d.vfsd.IsDead()

	d.fs.renameMu.RLock()
	// The ordering below is important, Linux always notifies the parent first.
	if d.parent != nil {
		d.parent.watches.Notify(ctx, d.name, events, cookie, et, deleted)
	}
	d.watches.Notify(ctx, "", events, cookie, et, deleted)
	d.fs.renameMu.RUnlock()
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches(ctx context.Context) {
	if atomic.LoadInt64(&d.refs) == 0 {
		d.fs.renameMu.Lock()
		d.checkDropLocked(ctx)
		d.fs.renameMu.Unlock()
	}
}

// iterLayers invokes yield on each layer comprising d, from top to bottom. If
// any call to yield returns false, iterLayer stops iteration.
func (d *dentry) iterLayers(yield func(vd vfs.VirtualDentry, isUpper bool) bool) {
	if d.isCopiedUp() {
		if !yield(d.upperVD, true) {
			return
		}
	}
	for _, lowerVD := range d.lowerVDs {
		if !yield(lowerVD, false) {
			return
		}
	}
}

func (d *dentry) topLayerInfo() (vd vfs.VirtualDentry, isUpper bool) {
	if d.isCopiedUp() {
		return d.upperVD, true
	}
	return d.lowerVDs[0], false
}

func (d *dentry) topLayer() vfs.VirtualDentry {
	vd, _ := d.topLayerInfo()
	return vd
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(atomic.LoadUint32(&d.mode)), auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid)))
}

func (d *dentry) checkXattrPermissions(creds *auth.Credentials, name string, ats vfs.AccessTypes) error {
	mode := linux.FileMode(atomic.LoadUint32(&d.mode))
	kuid := auth.KUID(atomic.LoadUint32(&d.uid))
	kgid := auth.KGID(atomic.LoadUint32(&d.gid))
	if err := vfs.GenericCheckPermissions(creds, ats, mode, kuid, kgid); err != nil {
		return err
	}
	return vfs.CheckXattrPermissions(creds, ats, mode, kuid, name)
}

// statInternalMask is the set of stat fields that is set by
// dentry.statInternalTo().
const statInternalMask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO

// statInternalTo writes fields to stat that are stored in d, and therefore do
// not requiring invoking StatAt on the overlay's layers.
func (d *dentry) statInternalTo(ctx context.Context, opts *vfs.StatOptions, stat *linux.Statx) {
	stat.Mask |= statInternalMask
	if d.isDir() {
		// Linux sets nlink to 1 for merged directories
		// (fs/overlayfs/inode.c:ovl_getattr()); we set it to 2 because this is
		// correct more often ("." and the directory's entry in its parent),
		// and some of our tests expect this.
		stat.Nlink = 2
	}
	stat.UID = atomic.LoadUint32(&d.uid)
	stat.GID = atomic.LoadUint32(&d.gid)
	stat.Mode = uint16(atomic.LoadUint32(&d.mode))
	stat.Ino = atomic.LoadUint64(&d.ino)
	stat.DevMajor = atomic.LoadUint32(&d.devMajor)
	stat.DevMinor = atomic.LoadUint32(&d.devMinor)
}

// Preconditions: d.copyMu must be locked for writing.
func (d *dentry) updateAfterSetStatLocked(opts *vfs.SetStatOptions) {
	if opts.Stat.Mask&linux.STATX_MODE != 0 {
		atomic.StoreUint32(&d.mode, (d.mode&linux.S_IFMT)|uint32(opts.Stat.Mode&^linux.S_IFMT))
	}
	if opts.Stat.Mask&linux.STATX_UID != 0 {
		atomic.StoreUint32(&d.uid, opts.Stat.UID)
	}
	if opts.Stat.Mask&linux.STATX_GID != 0 {
		atomic.StoreUint32(&d.gid, opts.Stat.GID)
	}
}

// fileDescription is embedded by overlay implementations of
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

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *fileDescription) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.filesystem().listXattr(ctx, fd.dentry(), size)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *fileDescription) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.filesystem().getXattr(ctx, fd.dentry(), auth.CredentialsFromContext(ctx), &opts)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *fileDescription) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	fs := fd.filesystem()
	d := fd.dentry()

	fs.renameMu.RLock()
	err := fs.setXattrLocked(ctx, d, fd.vfsfd.Mount(), auth.CredentialsFromContext(ctx), &opts)
	fs.renameMu.RUnlock()
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *fileDescription) RemoveXattr(ctx context.Context, name string) error {
	fs := fd.filesystem()
	d := fd.dentry()

	fs.renameMu.RLock()
	err := fs.removeXattrLocked(ctx, d, fd.vfsfd.Mount(), auth.CredentialsFromContext(ctx), name)
	fs.renameMu.RUnlock()
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return fd.Locks().LockPOSIX(ctx, &fd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return fd.Locks().UnlockPOSIX(ctx, &fd.vfsfd, uid, start, length, whence)
}
