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
	case nil: // synthetic dentry
		return noHandle
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
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
		openFD, hostFD, err := dt.controlFD.OpenAt(ctx, flags)
		if err != nil {
			return noHandle, err
		}
		return handle{
			fdLisa: dt.controlFD.Client().NewFD(openFD),
			fd:     int32(hostFD),
		}, nil
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
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.updateMetadataLocked(ctx, h) // +checklocksforce: acquired by precondition.
	default:
		panic("unknown dentry implementation")
	}
}

func (d *dentry) chmod(ctx context.Context, mode uint16) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return chmod(ctx, dt.controlFD, mode)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.handleMu is locked.
func (d *dentry) setStatLocked(ctx context.Context, stat *linux.Statx) (uint32, error, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.SetStat(ctx, stat)
	default:
		panic("unknown dentry implementation")
	}
}

func (d *dentry) destroyImpl(ctx context.Context) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		dt.destroy(ctx)
	case nil: // synthetic dentry
	default:
		panic("unknown dentry implementation")
	}
}

// Postcondition: Caller must do dentry caching appropriately.
func (d *dentry) getRemoteChild(ctx context.Context, name string) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.getRemoteChild(ctx, name)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.dirMu must be locked.
//   - parent.isDir().
//   - name is not "." or "..".
//   - dentry at name must not already exist in dentry tree.
//
// Postcondition: The returned dentry is already cached appropriately.
func (d *dentry) getRemoteChildAndWalkPathLocked(ctx context.Context, rp *vfs.ResolvingPath, ds **[]*dentry) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.getRemoteChildAndWalkPathLocked(ctx, rp, ds)
		// TODO(b/258687694): For directfs, remember to use fs.getRemoteChildLocked
		// so that dentry caching is done properly.
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) listXattrImpl(ctx context.Context, size uint64) ([]string, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.ListXattr(ctx, size)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) getXattrImpl(ctx context.Context, opts *vfs.GetXattrOptions) (string, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.GetXattr(ctx, opts.Name, opts.Size)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) setXattrImpl(ctx context.Context, opts *vfs.SetXattrOptions) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.SetXattr(ctx, opts.Name, opts.Value, opts.Flags)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) removeXattrImpl(ctx context.Context, name string) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.RemoveXattr(ctx, name)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) mknod(ctx context.Context, name string, creds *auth.Credentials, opts *vfs.MknodOptions) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.mknod(ctx, name, creds, opts)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) link(ctx context.Context, target *dentry, name string) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.link(ctx, target.impl.(*lisafsDentry), name)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) mkdir(ctx context.Context, name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.mkdir(ctx, name, mode, uid, gid)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) symlink(ctx context.Context, name, target string, creds *auth.Credentials) (*dentry, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.symlink(ctx, name, target, creds)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) openCreate(ctx context.Context, name string, accessFlags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (*dentry, handle, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.openCreate(ctx, name, accessFlags, mode, uid, gid)
	default:
		panic("unknown dentry implementation")
	}
}

// Preconditions:
//   - d.isDir().
//   - d.handleMu must be locked.
//   - !d.isSynthetic().
func (d *dentry) getDirentsLocked(ctx context.Context, count int, recordDirent func(name string, key inoKey, dType uint8)) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.getDirentsLocked(ctx, count, recordDirent)
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
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) connect(ctx context.Context, sockType linux.SockType) (int, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.Connect(ctx, sockType)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) readlinkImpl(ctx context.Context) (string, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.ReadLinkAt(ctx)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) unlink(ctx context.Context, name string, flags uint32) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.UnlinkAt(ctx, name, flags)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) rename(ctx context.Context, oldName string, newParent *dentry, newName string) error {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.controlFD.RenameAt(ctx, oldName, newParent.impl.(*lisafsDentry).controlFD.ID(), newName)
	default:
		panic("unknown dentry implementation")
	}
}

// Precondition: !d.isSynthetic().
func (d *dentry) statfs(ctx context.Context) (linux.Statfs, error) {
	switch dt := d.impl.(type) {
	case *lisafsDentry:
		return dt.statfs(ctx)
	default:
		panic("unknown dentry implementation")
	}
}

func (fs *filesystem) restoreRoot(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	// The root is always non-synthetic.
	switch dt := fs.root.impl.(type) {
	case *lisafsDentry:
		rootInode, err := fs.initClient(ctx)
		if err != nil {
			return err
		}
		return dt.restoreFile(ctx, &rootInode, opts)
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
		inode, err := d.parent.impl.(*lisafsDentry).controlFD.Walk(ctx, d.name)
		if err != nil {
			return err
		}
		return dt.restoreFile(ctx, &inode, opts)
	default:
		panic("unknown dentry implementation")
	}
}
