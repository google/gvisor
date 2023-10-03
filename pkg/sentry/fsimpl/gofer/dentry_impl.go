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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fsutil"
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
// do not do panic(fmt.Sprintf("... %T", d.impl)) because somehow it adds a lot
// of overhead to the type switch. So instead we panic with a constant string.

// Precondition: d.handleMu must be locked.
func (d *dentry) isReadHandleOk() bool {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.readFDLisa.Ok()
	case *directfsDentry:
		return d.readFD.RacyLoad() >= 0
	case nil: // synthetic dentry
		return false
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: d.handleMu must be locked.
func (d *dentry) isWriteHandleOk() bool {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.writeFDLisa.Ok()
	case *directfsDentry:
		return d.writeFD.RacyLoad() >= 0
	case nil: // synthetic dentry
		return false
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: d.handleMu must be locked.
func (d *dentry) readHandle() handle {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return handle{
			fdLisa: dt.readFDLisa,
			fd:     d.readFD.RacyLoad(),
		}
	case *directfsDentry:
		return handle{fd: d.readFD.RacyLoad()}
	case nil: // synthetic dentry
		return noHandle
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: d.handleMu must be locked.
func (d *dentry) writeHandle() handle {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return handle{
			fdLisa: dt.writeFDLisa,
			fd:     d.writeFD.RacyLoad(),
		}
	case *directfsDentry:
		return handle{fd: d.writeFD.RacyLoad()}
	case nil: // synthetic dentry
		return noHandle
	default:
		panic("unknown dentry implementation")
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
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.openHandle(ctx, flags)
	case *directfsDentry:
		return dt.openHandle(ctx, flags)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - d.handleMu must be locked.
//   - !d.isSynthetic().
func (d *dentry) updateHandles(ctx context.Context, h handle, readable, writable bool) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		dt.updateHandles(ctx, h, readable, writable)
	case *directfsDentry:
		// No update needed.
	default:
		panic("unknown dentry implementation")
	}
}

// updateMetadataLocked updates the dentry's metadata fields. The h parameter
// is optional. If it is not provided, an appropriate FD should be chosen to
// stat the remote file.
//
// Preconditions:
//   - !d.isSynthetic().
//   - d.metadataMu is locked.
//
// +checklocks:d.metadataMu
func (d *dentry) updateMetadataLocked(ctx context.Context, h handle) error {
	// Need checklocksforce below because checklocks has no way of knowing that
	// d.impl.(*dentryImpl).dentry == d. It can't know that the right metadataMu
	// is already locked.
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.updateMetadataLocked(ctx, h) // +checklocksforce: acquired by precondition.
	case *directfsDentry:
		return dt.updateMetadataLocked(h) // +checklocksforce: acquired by precondition.
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - fs.renameMu is locked.
func (d *dentry) prepareSetStat(ctx context.Context, stat *linux.Statx) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		// Nothing to be done.
		return nil
	case *directfsDentry:
		return dt.prepareSetStat(ctx, stat)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: fs.renameMu is locked if d is a socket.
func (d *dentry) chmod(ctx context.Context, mode uint16) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return chmod(ctx, dt.controlFD, mode)
	case *directfsDentry:
		return dt.chmod(ctx, mode)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.handleMu is locked.
//   - fs.renameMu is locked.
func (d *dentry) setStatLocked(ctx context.Context, stat *linux.Statx) (uint32, error, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.SetStat(ctx, stat)
	case *directfsDentry:
		failureMask, failureErr := dt.setStatLocked(ctx, stat)
		return failureMask, failureErr, nil
	default:
		panic("unknown dentry implementation")
	}
}

func (d *dentry) destroyImpl(ctx context.Context) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		dt.destroy(ctx)
	case *directfsDentry:
		dt.destroy(ctx)
	case nil: // synthetic dentry
	default:
		panic("unknown dentry implementation")
	}
}

// Postcondition: Caller must do dentry caching appropriately.
//
// +checklocksread:d.opMu
func (d *dentry) getRemoteChild(ctx context.Context, name string) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.getRemoteChild(ctx, name)
	case *directfsDentry:
		return dt.getHostChild(name)
	default:
		panic("unknown dentry implementation")
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
func (d *dentry) getRemoteChildAndWalkPathLocked(ctx context.Context, rp resolvingPath, ds **[]*dentry) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.getRemoteChildAndWalkPathLocked(ctx, rp, ds)
	case *directfsDentry:
		// We need to check for races because opMu is read locked which allows
		// concurrent walks to occur.
		return d.fs.getRemoteChildLocked(ctx, d, rp.Component(), true /* checkForRace */, ds)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) listXattrImpl(ctx context.Context, size uint64) ([]string, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.ListXattr(ctx, size)
	case *directfsDentry:
		// Consistent with runsc/fsgofer.
		return nil, linuxerr.EOPNOTSUPP
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) getXattrImpl(ctx context.Context, opts *vfs.GetXattrOptions) (string, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.GetXattr(ctx, opts.Name, opts.Size)
	case *directfsDentry:
		// Consistent with runsc/fsgofer.
		return "", linuxerr.EOPNOTSUPP
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) setXattrImpl(ctx context.Context, opts *vfs.SetXattrOptions) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.SetXattr(ctx, opts.Name, opts.Value, opts.Flags)
	case *directfsDentry:
		// Consistent with runsc/fsgofer.
		return linuxerr.EOPNOTSUPP
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) removeXattrImpl(ctx context.Context, name string) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.RemoveXattr(ctx, name)
	case *directfsDentry:
		// Consistent with runsc/fsgofer.
		return linuxerr.EOPNOTSUPP
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.mknod(ctx, name, creds, opts)
	case *directfsDentry:
		return dt.mknod(ctx, name, creds, opts)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.fs.renameMu must be locked.
func (d *dentry) link(ctx context.Context, target *dentry, name string) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.link(ctx, target.impl.(*lisafsDentry), name)
	case *directfsDentry:
		return dt.link(target.impl.(*directfsDentry), name)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) mkdir(ctx context.Context, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.mkdir(ctx, name, mode, uid, gid)
	case *directfsDentry:
		return dt.mkdir(name, mode, uid, gid)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) symlink(ctx context.Context, name, target string, creds *auth.Credentials) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.symlink(ctx, name, target, creds)
	case *directfsDentry:
		return dt.symlink(name, target, creds)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) openCreate(ctx context.Context, name string, accessFlags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, handle, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.openCreate(ctx, name, accessFlags, mode, uid, gid)
	case *directfsDentry:
		return dt.openCreate(name, accessFlags, mode, uid, gid)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - d.isDir().
//   - d.handleMu must be locked.
//   - !d.isSynthetic().
func (d *dentry) getDirentsLocked(ctx context.Context, recordDirent func(name string, key inoKey, dType uint8)) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.getDirentsLocked(ctx, recordDirent)
	case *directfsDentry:
		return dt.getDirentsLocked(recordDirent)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) flush(ctx context.Context) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return flush(ctx, dt.writeFDLisa)
	case *directfsDentry:
		// Nothing to do here.
		return nil
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) allocate(ctx context.Context, mode, offset, length uint64) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.writeFDLisa.Allocate(ctx, mode, offset, length)
	case *directfsDentry:
		return unix.Fallocate(int(d.writeFD.RacyLoad()), uint32(mode), int64(offset), int64(length))
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - fs.renameMu is locked.
func (d *dentry) connect(ctx context.Context, sockType linux.SockType) (int, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.Connect(ctx, sockType)
	case *directfsDentry:
		return dt.connect(ctx, sockType)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) readlinkImpl(ctx context.Context) (string, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.ReadLinkAt(ctx)
	case *directfsDentry:
		return dt.readlink()
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) unlink(ctx context.Context, name string, flags uint32) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.UnlinkAt(ctx, name, flags)
	case *directfsDentry:
		return unix.Unlinkat(dt.controlFD, name, int(flags))
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) rename(ctx context.Context, oldName string, newParent *dentry, newName string) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.RenameAt(ctx, oldName, newParent.impl.(*lisafsDentry).controlFD.ID(), newName)
	case *directfsDentry:
		return fsutil.RenameAt(dt.controlFD, oldName, newParent.impl.(*directfsDentry).controlFD, newName)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) statfs(ctx context.Context) (linux.Statfs, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.statfs(ctx)
	case *directfsDentry:
		return dt.statfs()
	default:
		panic("unknown dentry implementation")
	}
}

func (fs *filesystem) restoreRoot(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	rootInode, rootHostFD, err := fs.initClientAndGetRoot(ctx)
	if err != nil {
		return err
	}

	// The root is always non-synthetic.
	switch dt := fs.root.impl.(type) {
	case *lisafsDentry:
		return dt.restoreFile(ctx, &rootInode, opts)
	case *directfsDentry:
		dt.controlFDLisa = fs.client.NewFD(rootInode.ControlFD)
		return dt.restoreFile(ctx, rootHostFD, opts)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.parent != nil and has been restored.
func (d *dentry) restoreFile(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		inode, err := d.parent.Load().impl.(*lisafsDentry).controlFD.Walk(ctx, d.name)
		if err != nil {
			return err
		}
		return dt.restoreFile(ctx, &inode, opts)
	case *directfsDentry:
		childFD, err := tryOpen(func(flags int) (int, error) {
			return unix.Openat(d.parent.Load().impl.(*directfsDentry).controlFD, d.name, flags, 0)
		})
		if err != nil {
			return err
		}
		return dt.restoreFile(ctx, childFD, opts)
	default:
		panic("unknown dentry implementation")
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
	if r.start.isSynthetic() {
		return nil
	}
	switch r.start.impl.(type) {
	case *lisafsDentry:
		return doRevalidationLisafs(ctx, vfsObj, r, ds)
	case *directfsDentry:
		return doRevalidationDirectfs(ctx, vfsObj, r, ds)
	default:
		panic("unknown dentry implementation")
	}
}
