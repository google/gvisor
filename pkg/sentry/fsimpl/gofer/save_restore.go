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

package gofer

import (
	goContext "context"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// +stateify savable
type savedDentryRW struct {
	read  bool
	write bool
}

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	if len(fs.iopts.UniqueID.Path) == 0 {
		return fmt.Errorf("gofer.filesystem with no UniqueID cannot be saved")
	}

	// Purge cached dentries, which may not be reopenable after restore due to
	// permission changes.
	fs.renameMu.Lock()
	fs.evictAllCachedDentriesLocked(ctx)
	fs.renameMu.Unlock()

	// Buffer pipe data so that it's available for reading after restore. (This
	// is a legacy VFS1 feature.)
	fs.syncMu.Lock()
	for sffd := fs.specialFileFDs.Front(); sffd != nil; sffd = sffd.Next() {
		if sffd.dentry().fileType() == linux.S_IFIFO && sffd.vfsfd.IsReadable() {
			if err := sffd.savePipeData(ctx); err != nil {
				fs.syncMu.Unlock()
				return err
			}
		}
	}
	fs.syncMu.Unlock()

	// Flush local state to the remote filesystem.
	if err := fs.Sync(ctx); err != nil {
		return err
	}

	fs.savedDentryRW = make(map[*dentry]savedDentryRW)
	return fs.root.prepareSaveRecursive(ctx)
}

// Preconditions:
//   - fd represents a pipe.
//   - fd is readable.
func (fd *specialFileFD) savePipeData(ctx context.Context) error {
	fd.bufMu.Lock()
	defer fd.bufMu.Unlock()
	var buf [hostarch.PageSize]byte
	for {
		n, err := fd.handle.readToBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:])), ^uint64(0))
		if n != 0 {
			fd.buf = append(fd.buf, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF || linuxerr.Equals(linuxerr.EAGAIN, err) {
				break
			}
			return err
		}
	}
	if len(fd.buf) != 0 {
		fd.haveBuf.Store(1)
	}
	return nil
}

func (d *dentry) prepareSaveRecursive(ctx context.Context) error {
	if d.isRegularFile() && !d.cachedMetadataAuthoritative() {
		// Get updated metadata for d in case we need to perform metadata
		// validation during restore.
		if err := d.updateMetadata(ctx); err != nil {
			return err
		}
	}
	if d.isReadHandleOk() || d.isWriteHandleOk() {
		d.fs.savedDentryRW[d] = savedDentryRW{
			read:  d.isReadHandleOk(),
			write: d.isWriteHandleOk(),
		}
	}
	d.childrenMu.Lock()
	defer d.childrenMu.Unlock()
	for childName, child := range d.children {
		if child == nil {
			// Unsaved filesystem state may change across save/restore. Remove
			// negative entries from d.children to ensure that files created
			// after save are visible after restore.
			delete(d.children, childName)
			continue
		}
		if err := child.prepareSaveRecursive(ctx); err != nil {
			return err
		}
	}
	return nil
}

// beforeSave is invoked by stateify.
func (d *dentry) beforeSave() {
	if d.vfsd.IsDead() {
		panic(fmt.Sprintf("gofer.dentry(%q).beforeSave: deleted and invalidated dentries can't be restored", genericDebugPathname(d)))
	}
}

// afterLoad is invoked by stateify.
func (fs *filesystem) afterLoad(ctx goContext.Context) {
	fs.mf = pgalloc.MemoryFileFromContext(ctx)
}

// afterLoad is invoked by stateify.
func (d *dentry) afterLoad(goContext.Context) {
	d.readFD = atomicbitops.FromInt32(-1)
	d.writeFD = atomicbitops.FromInt32(-1)
	d.mmapFD = atomicbitops.FromInt32(-1)
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}

// afterLoad is invoked by stateify.
func (d *directfsDentry) afterLoad(goContext.Context) {
	d.controlFD = -1
}

// afterLoad is invoked by stateify.
func (d *dentryPlatformFile) afterLoad(goContext.Context) {
	if d.hostFileMapper.IsInited() {
		// Ensure that we don't call d.hostFileMapper.Init() again.
		d.hostFileMapperInitOnce.Do(func() {})
	}
}

// afterLoad is invoked by stateify.
func (fd *specialFileFD) afterLoad(goContext.Context) {
	fd.handle.fd = -1
	if fd.hostFileMapper.IsInited() {
		// Ensure that we don't call fd.hostFileMapper.Init() again.
		fd.hostFileMapperInitOnce.Do(func() {})
	}
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ goContext.Context, parent *dentry) {
	d.parent.Store(parent)
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	if fdmap == nil {
		return fmt.Errorf("no server FD map available")
	}
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		return fmt.Errorf("no server FD available for filesystem with unique ID %+v, map: %v", fs.iopts.UniqueID, fdmap)
	}
	fs.opts.fd = fd
	fs.inoByKey = make(map[inoKey]uint64)

	if err := fs.restoreRoot(ctx, &opts); err != nil {
		return err
	}

	// Restore remaining dentries.
	if err := fs.root.restoreDescendantsRecursive(ctx, &opts); err != nil {
		return err
	}

	// Re-open handles for specialFileFDs. Unlike the initial open
	// (dentry.openSpecialFile()), pipes are always opened without blocking;
	// non-readable pipe FDs are opened last to ensure that they don't get
	// ENXIO if another specialFileFD represents the read end of the same pipe.
	// This is consistent with VFS1.
	haveWriteOnlyPipes := false
	for fd := fs.specialFileFDs.Front(); fd != nil; fd = fd.Next() {
		if fd.dentry().fileType() == linux.S_IFIFO && !fd.vfsfd.IsReadable() {
			haveWriteOnlyPipes = true
			continue
		}
		if err := fd.completeRestore(ctx); err != nil {
			return err
		}
	}
	if haveWriteOnlyPipes {
		for fd := fs.specialFileFDs.Front(); fd != nil; fd = fd.Next() {
			if fd.dentry().fileType() == linux.S_IFIFO && !fd.vfsfd.IsReadable() {
				if err := fd.completeRestore(ctx); err != nil {
					return err
				}
			}
		}
	}

	// Discard state only required during restore.
	fs.savedDentryRW = nil

	return nil
}

// Preconditions: d is not synthetic.
func (d *dentry) restoreDescendantsRecursive(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	d.childrenMu.Lock()
	defer d.childrenMu.Unlock()
	for _, child := range d.children {
		if child == nil {
			continue
		}
		if child.isSynthetic() {
			continue
		}
		if err := child.restoreFile(ctx, opts); err != nil {
			return err
		}
		if err := child.restoreDescendantsRecursive(ctx, opts); err != nil {
			return err
		}
	}
	return nil
}

func (fd *specialFileFD) completeRestore(ctx context.Context) error {
	d := fd.dentry()
	h, err := d.openHandle(ctx, fd.vfsfd.IsReadable(), fd.vfsfd.IsWritable(), false /* trunc */)
	if err != nil {
		return err
	}
	fd.handle = h

	ftype := d.fileType()
	fd.haveQueue = (ftype == linux.S_IFIFO || ftype == linux.S_IFSOCK) && fd.handle.fd >= 0
	if fd.haveQueue {
		if err := fdnotifier.AddFD(fd.handle.fd, &fd.queue); err != nil {
			return err
		}
	}

	return nil
}
