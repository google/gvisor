// Copyright 2022 The gVisor Authors.
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

package gofer

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fsutil"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// We do *not* define an interface for dentry.impl because making interface
// method calls is almost 2.5x slower than calling the same method on a
// concrete type. Instead, we use type assertions in switch statements. The
// asserted type is a concrete dentry implementation and methods are called
// directly on the concrete type. This helps in the following ways:
//
// 1. This is faster because concrete type assertion just needs to compare the
//    itab pointer in the interface value to a constant which is relatively
//    cheap. Benchmarking showed that such type switches don't add almost any
//    overhead.
// 2. Passing any pointer to an interface method immediately causes the pointed
//    object to escape to heap. Making concrete method calls allows escape
//    analysis to proceed as usual and avoids heap allocations.
//
// Also note that the default case in these type switch statements panics. We
// do not do panic(fmt.Sprintf("... %T", i.impl)) because somehow it adds a lot
// of overhead to the type switch. So instead we panic with a constant string.

// Precondition: i.handleMu must be locked.
func (i *inode) isReadHandleOk() bool {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.readFDLisa.Ok()
	case *directfsInode:
		return it.readFD.RacyLoad() >= 0
	case nil: // synthetic inode
		return false
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: i.handleMu must be locked.
func (i *inode) isWriteHandleOk() bool {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.writeFDLisa.Ok()
	case *directfsInode:
		return i.writeFD.RacyLoad() >= 0
	case nil: // synthetic inode
		return false
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: i.handleMu must be locked.
func (i *inode) readHandle() handle {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return handle{
			fdLisa: it.readFDLisa,
			fd:     i.readFD.RacyLoad(),
		}
	case *directfsInode:
		return handle{fd: i.readFD.RacyLoad()}
	case nil: // synthetic dentry
		return noHandle
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: i.handleMu must be locked.
func (i *inode) writeHandle() handle {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return handle{
			fdLisa: it.writeFDLisa,
			fd:     i.writeFD.RacyLoad(),
		}
	case *directfsInode:
		return handle{fd: i.writeFD.RacyLoad()}
	case nil: // synthetic inode
		return noHandle
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - fs.renameMu is locked.
func (d *dentry) openHandle(ctx context.Context, read, write, trunc bool) (handle, error) {
	flags := uint32(unix.O_RDONLY)
	switch {
	case read && write:
		flags = unix.O_RDWR
	case read:
		flags = unix.O_RDONLY
	case write:
		flags = unix.O_WRONLY
	default:
		log.Debugf("openHandle called with read = write = false. Falling back to read only FD.")
	}
	if trunc {
		flags |= unix.O_TRUNC
	}
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.openHandle(ctx, flags)
	case *directfsInode:
		return it.openHandle(ctx, flags, d)
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - i.handleMu must be locked.
//   - !d.isSynthetic().
func (i *inode) updateHandles(ctx context.Context, h handle, readable, writable bool) {
	switch it := i.impl.(type) {
	case *lisafsInode:
		it.updateHandles(ctx, h, readable, writable)
	case *directfsInode:
		// No update needed.
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - i.handleMu must be locked.
//   - !d.isSynthetic().
func (i *inode) closeHostFDs() {
	// We can use RacyLoad() because i.handleMu is locked.
	if i.readFD.RacyLoad() >= 0 {
		_ = unix.Close(int(i.readFD.RacyLoad()))
	}
	if i.writeFD.RacyLoad() >= 0 && i.readFD.RacyLoad() != i.writeFD.RacyLoad() {
		_ = unix.Close(int(i.writeFD.RacyLoad()))
	}
	i.readFD = atomicbitops.FromInt32(-1)
	i.writeFD = atomicbitops.FromInt32(-1)
	i.mmapFD = atomicbitops.FromInt32(-1)

	switch it := i.impl.(type) {
	case *directfsInode:
		if it.controlFD >= 0 {
			_ = unix.Close(it.controlFD)
			it.controlFD = -1
		}
	}
}

// updateMetadataLocked updates the dentry's metadata fields. The h parameter
// is optional. If it is not provided, an appropriate FD should be chosen to
// stat the remote file.
//
// Preconditions:
//   - !d.isSynthetic().
//   - i.metadataMu is locked.
//
// +checklocks:i.metadataMu
func (i *inode) updateMetadataLocked(ctx context.Context, h handle) error {
	// Need checklocksforce below because checklocks has no way of knowing that
	// i.impl.(*dentryImpl).dentry == d. It can't know that the right metadataMu
	// is already locked.
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.updateMetadataLocked(ctx, h) // +checklocksforce: acquired by precondition.
	case *directfsInode:
		return it.updateMetadataLocked(h) // +checklocksforce: acquired by precondition.
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - fs.renameMu is locked.
func (d *dentry) prepareSetStat(ctx context.Context, stat *linux.Statx) error {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		// Nothing to be done.
		return nil
	case *directfsInode:
		return it.prepareSetStat(ctx, stat, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: fs.renameMu is locked if d is a socket.
func (d *dentry) chmod(ctx context.Context, mode uint16) error {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return chmod(ctx, it.controlFD, mode)
	case *directfsInode:
		return it.chmod(ctx, mode, d)
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - i.handleMu is locked.
//   - fs.renameMu is locked.
func (d *dentry) setStatLocked(ctx context.Context, stat *linux.Statx) (uint32, error, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.controlFD.SetStat(ctx, stat)
	case *directfsInode:
		failureMask, failureErr := it.setStatLocked(ctx, stat, d)
		return failureMask, failureErr, nil
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: i.handleMu must be locked.
func (i *inode) destroyImpl(ctx context.Context, d *dentry) {
	switch i := i.impl.(type) {
	case *lisafsInode:
		i.destroy(ctx, d)
	case *directfsInode:
		i.destroy(ctx)
	case nil: // synthetic dentry
	default:
		panic("unknown inode implementation")
	}
}

// Postcondition: Caller must do dentry caching appropriately.
//
// +checklocksread:d.opMu
func (d *dentry) getRemoteChild(ctx context.Context, name string) (*dentry, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.getRemoteChild(ctx, name)
	case *directfsInode:
		return it.getHostChild(name)
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.opMu must be locked for reading.
//   - parent.isDir().
//   - !rp.Done() && rp.Component() is not "." or "..".
//
// Postcondition: The returned dentry is already cached appropriately.
//
// +checklocksread:d.opMu
func (i *inode) getRemoteChildAndWalkPathLocked(ctx context.Context, rp resolvingPath, ds **[]*dentry, d *dentry) (*dentry, error) {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.getRemoteChildAndWalkPathLocked(ctx, rp, ds, d)
	case *directfsInode:
		// We need to check for races because opMu is read locked which allows
		// concurrent walks to occur.
		return i.fs.getRemoteChildLocked(ctx, d, rp.Component(), true /* checkForRace */, ds)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) listXattrImpl(ctx context.Context, size uint64) ([]string, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.controlFD.ListXattr(ctx, size)
	case *directfsInode:
		// Consistent with runsc/fsgofer.
		return nil, linuxerr.EOPNOTSUPP
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) getXattrImpl(ctx context.Context, opts *vfs.GetXattrOptions) (string, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.controlFD.GetXattr(ctx, opts.Name, opts.Size)
	case *directfsInode:
		return it.getXattr(ctx, opts.Name, opts.Size, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) setXattrImpl(ctx context.Context, opts *vfs.SetXattrOptions) error {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.controlFD.SetXattr(ctx, opts.Name, opts.Value, opts.Flags)
	case *directfsInode:
		// Consistent with runsc/fsgofer.
		return linuxerr.EOPNOTSUPP
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) removeXattrImpl(ctx context.Context, name string) error {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.controlFD.RemoveXattr(ctx, name)
	case *directfsInode:
		// Consistent with runsc/fsgofer.
		return linuxerr.EOPNOTSUPP
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.mknod(ctx, name, creds, opts)
	case *directfsInode:
		return it.mknod(ctx, name, creds, opts, d)
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - !target.isSynthetic().
//   - i.fs.renameMu must be locked.
func (d *dentry) link(ctx context.Context, target *dentry, name string) (*dentry, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.link(ctx, target.inode.impl.(*lisafsInode), name)
	case *directfsInode:
		return it.link(target, name, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) mkdir(ctx context.Context, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID, createDentry bool) (*dentry, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.mkdir(ctx, name, mode, uid, gid, createDentry)
	case *directfsInode:
		return it.mkdir(name, mode, uid, gid, createDentry, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) symlink(ctx context.Context, name, target string, creds *auth.Credentials) (*dentry, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.symlink(ctx, name, target, creds)
	case *directfsInode:
		return it.symlink(name, target, creds, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) openCreate(ctx context.Context, name string, accessFlags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID, createDentry bool) (*dentry, handle, error) {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.openCreate(ctx, name, accessFlags, mode, uid, gid, createDentry)
	case *directfsInode:
		return it.openCreate(name, accessFlags, mode, uid, gid, createDentry, d)
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - d.isDir().
//   - i.handleMu must be locked.
//   - !d.isSynthetic().
func (d *dentry) getDirentsLocked(ctx context.Context, recordDirent func(name string, key inoKey, dType uint8)) error {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.getDirentsLocked(ctx, recordDirent)
	case *directfsInode:
		return it.getDirentsLocked(recordDirent, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) flush(ctx context.Context) error {
	i.handleMu.RLock()
	defer i.handleMu.RUnlock()
	switch it := i.impl.(type) {
	case *lisafsInode:
		return flush(ctx, it.writeFDLisa)
	case *directfsInode:
		// Nothing to do here.
		return nil
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) allocate(ctx context.Context, mode, offset, length uint64) error {
	i.handleMu.RLock()
	defer i.handleMu.RUnlock()
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.writeFDLisa.Allocate(ctx, mode, offset, length)
	case *directfsInode:
		return unix.Fallocate(int(i.writeFD.RacyLoad()), uint32(mode), int64(offset), int64(length))
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - fs.renameMu is locked.
func (d *dentry) connect(ctx context.Context, sockType linux.SockType) (int, error) {
	creds := auth.CredentialsOrNilFromContext(ctx)
	euid := lisafs.NoUID
	egid := lisafs.NoGID
	if creds != nil {
		euid = lisafs.UID(creds.EffectiveKUID)
		egid = lisafs.GID(creds.EffectiveKGID)
	}
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		return it.controlFD.Connect(ctx, sockType, euid, egid)
	case *directfsInode:
		return it.connect(ctx, sockType, euid, egid, d)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) readlinkImpl(ctx context.Context) (string, error) {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.controlFD.ReadLinkAt(ctx)
	case *directfsInode:
		return it.readlink()
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) unlink(ctx context.Context, name string, flags uint32) error {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.controlFD.UnlinkAt(ctx, name, flags)
	case *directfsInode:
		return unix.Unlinkat(it.controlFD, name, int(flags))
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) rename(ctx context.Context, oldName string, newParent *dentry, newName string) error {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.controlFD.RenameAt(ctx, oldName, newParent.inode.impl.(*lisafsInode).controlFD.ID(), newName)
	case *directfsInode:
		return fsutil.RenameAt(it.controlFD, oldName, newParent.inode.impl.(*directfsInode).controlFD, newName)
	default:
		panic("unknown inode implementation")
	}
}

// Precondition: !d.isSynthetic().
func (i *inode) statfs(ctx context.Context) (linux.Statfs, error) {
	switch it := i.impl.(type) {
	case *lisafsInode:
		return it.statfs(ctx)
	case *directfsInode:
		return it.statfs()
	default:
		panic("unknown inode implementation")
	}
}

func (fs *filesystem) restoreRoot(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	rootInode, rootHostFD, err := fs.initClientAndGetRoot(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize client and get root: %w", err)
	}

	// The root is always non-synthetic.
	switch it := fs.root.inode.impl.(type) {
	case *lisafsInode:
		return it.restoreInode(ctx, &rootInode, opts, fs.root)
	case *directfsInode:
		it.controlFDLisa = fs.client.NewFD(rootInode.ControlFD)
		return it.restoreFile(ctx, rootHostFD, opts, fs.root)
	default:
		panic("unknown inode implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.parent != nil and has been restored.
func (d *dentry) restoreFile(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	switch it := d.inode.impl.(type) {
	case *lisafsInode:
		// With inode sharing, we may have multiple references to the same inode.
		// There is a possibility we try to restore the same inode multiple times.
		// If we already have a controlFD, we don't need to do anything.
		if it.controlFD.Ok() {
			return nil
		}
		controlFD := d.parent.Load().inode.impl.(*lisafsInode).controlFD
		inode, err := controlFD.Walk(ctx, d.name)
		if err != nil {
			if !d.isDir() || !d.forMountpoint {
				return fmt.Errorf("failed to walk %q of type %x: %w", genericDebugPathname(it.fs, d), it.inode.fileType(), err)
			}

			// Recreate directories that were created during volume mounting, since
			// during restore we don't attempt to remount them.
			inode, err = controlFD.MkdirAt(ctx, d.name, linux.FileMode(it.mode.Load()), lisafs.UID(it.uid.Load()), lisafs.GID(it.gid.Load()))
			if err != nil {
				return fmt.Errorf("failed to create mountpoint directory at %q: %w", genericDebugPathname(it.fs, d), err)
			}
		}
		return it.restoreInode(ctx, &inode, opts, d)

	case *directfsInode:
		// With inode sharing, we may have multiple references to the same inode.
		// There is a possibility we try to restore the same inode multiple times.
		// If we already have a controlFD, we don't need to do anything.
		if it.controlFD >= 0 {
			return nil
		}
		controlFD := d.parent.Load().inode.impl.(*directfsInode).controlFD
		childFD, err := tryOpen(func(flags int) (int, error) {
			n, err := unix.Openat(controlFD, d.name, flags, 0)
			return n, err
		})
		if err != nil {
			if !d.isDir() || !d.forMountpoint {
				return fmt.Errorf("failed to walk %q of type %x: %w", genericDebugPathname(it.fs, d), it.inode.fileType(), err)
			}

			// Recreate directories that were created during volume mounting, since
			// during restore we don't attempt to remount them.
			if err := unix.Mkdirat(controlFD, d.name, it.mode.Load()); err != nil {
				return fmt.Errorf("failed to create mountpoint directory at %q: %w", genericDebugPathname(it.fs, d), err)
			}

			// Try again...
			childFD, err = tryOpen(func(flags int) (int, error) {
				return unix.Openat(controlFD, d.name, flags, 0)
			})
			if err != nil {
				return fmt.Errorf("failed to open %q: %w", genericDebugPathname(it.fs, d), err)
			}
		}
		return it.restoreFile(ctx, childFD, opts, d)

	default:
		panic("unknown inode implementation")
	}
}

// Precondition: d.handleMu is read locked.
func (d *dentry) readHandleForDeleted(ctx context.Context) (handle, error) {
	if d.inode.isReadHandleOk() {
		return d.inode.readHandle(), nil
	}
	switch dt := d.inode.impl.(type) {
	case *lisafsInode:
		// ensureSharedHandle locks handleMu for write. Unlock it temporarily.
		d.inode.handleMu.RUnlock()
		err := d.ensureSharedHandle(ctx, true /* read */, false /* write */, false /* trunc */)
		d.inode.handleMu.RLock()
		if err != nil {
			return handle{}, fmt.Errorf("failed to open read handle: %w", err)
		}
		return d.inode.readHandle(), nil
	case *directfsInode:
		// The sentry does not have access to any procfs mount which it could use
		// to re-open dt.controlFD with a different mode (via /proc/self/fd/). The
		// file is unlinked, so we can't use openat(parent.controlFD, name) either.
		// dt.controlFD must be a read-only FD (see tryOpen() documentation). Just
		// seek the control FD to 0 and return it. The control FD is not used for
		// reading by the sentry, so this should be safe.
		// TODO(b/431481259): Use dentry.ensureSharedHandle() here as well.
		if _, err := unix.Seek(dt.controlFD, 0, unix.SEEK_SET); err != nil {
			return handle{}, fmt.Errorf("failed to seek control FD to 0: %w", err)
		}
		return handle{fd: int32(dt.controlFD)}, nil
	default:
		panic("unknown inode implementation")
	}
}

// doRevalidation calls into r.start's dentry implementation to perform
// revalidation on all the dentries contained in r.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - InteropModeShared is in effect.
func (r *revalidateState) doRevalidation(ctx context.Context, vfsObj *vfs.VirtualFilesystem, ds **[]*dentry) error {
	// Skip synthetic dentries because there is no actual implementation that can
	// be used to walk the remote filesystem. A start dentry cannot be replaced.
	if r.start.inode.isSynthetic() {
		return nil
	}
	switch r.start.inode.impl.(type) {
	case *lisafsInode:
		return doRevalidationLisafs(ctx, vfsObj, r, ds)
	case *directfsInode:
		return doRevalidationDirectfs(ctx, vfsObj, r, ds)
	default:
		panic("unknown inode implementation")
	}
}
