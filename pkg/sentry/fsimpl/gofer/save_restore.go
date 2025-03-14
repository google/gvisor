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
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

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
	fs.savedDentryRW = make(map[*dentry]savedDentryRW)

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
	// Save file data for deleted regular files which are still accessible via
	// open application FDs.
	for sd := fs.syncableDentries.Front(); sd != nil; sd = sd.Next() {
		if sd.d.vfsd.IsDead() {
			if err := sd.d.prepareSaveDead(ctx); err != nil {
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

func (d *dentry) prepareSaveDead(ctx context.Context) error {
	if !d.isRegularFile() && !d.isDir() {
		return fmt.Errorf("gofer.dentry(%q).prepareSaveDead: only regular or directory deleted dentries can be saved, got %s", genericDebugPathname(d.fs, d), linux.FileMode(d.mode.Load()))
	}
	if !d.isDeleted() {
		return fmt.Errorf("gofer.dentry(%q).prepareSaveDead: invalidated dentries can't be saved", genericDebugPathname(d.fs, d))
	}
	if !d.cachedMetadataAuthoritative() {
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
	
	// Directory case - no need to store the data, just mark as saved
	if d.isDir() {
		if d.fs.savedDeletedOpenDentries == nil {
			d.fs.savedDeletedOpenDentries = make(map[*dentry]struct{})
		}
		d.fs.savedDeletedOpenDentries[d] = struct{}{}
		return nil
	}
	
	// Regular file case
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	var h handle
	if d.isReadHandleOk() {
		h = d.readHandle()
	} else {
		var err error
		h, err = d.openHandle(ctx, true /* read */, false /* write */, false /* trunc */)
		if err != nil {
			return fmt.Errorf("failed to open read handle for deleted file %q: %w", genericDebugPathname(d.fs, d), err)
		}
		defer h.close(ctx)
	}
	d.dataMu.RLock()
	defer d.dataMu.RUnlock()
	d.deletedDataSR = make([]byte, d.size.Load())
	done := uint64(0)
	for done < uint64(len(d.deletedDataSR)) {
		n, err := h.readToBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(d.deletedDataSR[done:])), done)
		done += n
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read deleted file %q: %w", genericDebugPathname(d.fs, d), err)
		}
	}
	if done < uint64(len(d.deletedDataSR)) {
		return fmt.Errorf("failed to read all of deleted file %q: read %d bytes, expected %d", genericDebugPathname(d.fs, d), done, len(d.deletedDataSR))
	}
	d.deletedDataSR = d.deletedDataSR[:done]
	if d.fs.savedDeletedOpenDentries == nil {
		d.fs.savedDeletedOpenDentries = make(map[*dentry]struct{})
	}
	d.fs.savedDeletedOpenDentries[d] = struct{}{}
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
	if d.vfsd.IsDead() && d.deletedDataSR == nil && !d.isDir() {
		panic(fmt.Sprintf("gofer.dentry(%q).beforeSave: deletedDataSR is nil for dead dentry (deleted=%t, synthetic=%t)", genericDebugPathname(d.fs, d), d.isDeleted(), d.isSynthetic()))
	}
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {
	for d := range fs.savedDeletedOpenDentries {
		d.deletedDataSR = nil
	}
	fs.savedDeletedOpenDentries = nil
	fs.savedDentryRW = nil
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
		return vfs.PrependErrMsg("failed to restore root", err)
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

	// Restore deleted files which are still accessible via open application FDs.
	for d := range fs.savedDeletedOpenDentries {
		if err := d.restoreDead(ctx, &opts); err != nil {
			return err
		}
	}

	// Discard state only required during restore.
	fs.savedDeletedOpenDentries = nil
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

// verifyParentPath checks if the parent path exists and is accessible
func verifyParentPath(ctx context.Context, parent *dentry) error {
	if parent == nil {
		return fmt.Errorf("parent is nil")
	}

	// Check if parent's parent is accessible if not root
	if parent != parent.fs.root {
		parentParent := parent.parent.Load()
		if parentParent == nil {
			return fmt.Errorf("parent's parent is nil and not root")
		}
	}

	// Verify parent is a directory
	if !parent.isDir() {
		return fmt.Errorf("parent is not a directory")
	}

	return nil
}

// restoreDead restores a deleted regular file or directory.
//
// Preconditions: For regular files, d.deletedDataSR != nil.
func (d *dentry) restoreDead(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	parent := d.parent.Load()
	if parent == nil {
		return fmt.Errorf("cannot restore %q: parent is nil", genericDebugPathname(d.fs, d))
	}

	// Handle directory case
	if d.isDir() {
		// Make sure the parent path exists and is accessible
		if err := verifyParentPath(ctx, parent); err != nil {
			return fmt.Errorf("failed to verify parent path for %q: %w", genericDebugPathname(d.fs, d), err)
		}
		
		log.Debugf("Recreating deleted directory %q in parent %q", d.name, genericDebugPathname(d.fs, parent))
		
		// Recreate the directory on the host filesystem
		_, err := parent.mkdir(ctx, d.name, linux.FileMode(d.mode.Load()), auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load()))
		if err != nil {
			return fmt.Errorf("failed to re-create deleted directory %q: %w", genericDebugPathname(d.fs, d), err)
		}

		// In case of errors, clean up the recreated directory
		unlinkCU := cleanup.Make(func() {
			if err := parent.unlink(ctx, d.name, linux.AT_REMOVEDIR); err != nil {
				log.Warningf("failed to clean up recreated deleted directory %q: %v", genericDebugPathname(d.fs, d), err)
			}
		})
		defer unlinkCU.Clean()

		// Restore the directory
		recreateOpts := *opts
		recreateOpts.ValidateFileModificationTimestamps = false
		if err := d.restoreFile(ctx, &recreateOpts); err != nil {
			return err
		}

		// Finally, unlink the recreated directory
		unlinkCU.Release()
		if err := parent.unlink(ctx, d.name, linux.AT_REMOVEDIR); err != nil {
			return fmt.Errorf("failed to clean up recreated deleted directory %q: %v", genericDebugPathname(d.fs, d), err)
		}
		return nil
	}

	// Regular file case
	// Make sure the parent path exists and is accessible
	if err := verifyParentPath(ctx, parent); err != nil {
		return fmt.Errorf("failed to verify parent path for %q: %w", genericDebugPathname(d.fs, d), err)
	}

	log.Debugf("Recreating deleted file %q in parent %q", d.name, genericDebugPathname(d.fs, parent))
	
	// Recreate the file on the host filesystem (this is temporary).
	_, h, err := parent.openCreate(ctx, d.name, linux.O_WRONLY, linux.FileMode(d.mode.Load()), auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load()), false /* createDentry */)
	if err != nil {
		return fmt.Errorf("failed to re-create deleted file %q: %w", genericDebugPathname(d.fs, d), err)
	}
	defer h.close(ctx)
	// In case of errors, clean up the recreated file.
	unlinkCU := cleanup.Make(func() {
		if err := parent.unlink(ctx, d.name, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up recreated deleted file %q: %v", genericDebugPathname(d.fs, d), err)
		}
	})
	defer unlinkCU.Clean()
	// Write the file data to the recreated file.
	n, err := h.writeFromBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(d.deletedDataSR)), 0)
	if err != nil {
		return fmt.Errorf("failed to write deleted file %q: %w", genericDebugPathname(d.fs, d), err)
	}
	if n != uint64(len(d.deletedDataSR)) {
		return fmt.Errorf("failed to write all of deleted file %q: wrote %d bytes, expected %d", genericDebugPathname(d.fs, d), n, len(d.deletedDataSR))
	}
	d.deletedDataSR = nil
	// Restore the file. Note that timestamps may not match since we re-created
	// the file on the host.
	recreateOpts := *opts
	recreateOpts.ValidateFileModificationTimestamps = false
	if err := d.restoreFile(ctx, &recreateOpts); err != nil {
		return err
	}
	// Finally, unlink the recreated file.
	unlinkCU.Release()
	if err := parent.unlink(ctx, d.name, 0 /* flags */); err != nil {
		return fmt.Errorf("failed to clean up recreated deleted file %q: %v", genericDebugPathname(d.fs, d), err)
	}
	return nil
}

func (fd *specialFileFD) completeRestore(ctx context.Context) error {
	d := fd.dentry()
	h, err := d.openHandle(ctx, fd.vfsfd.IsReadable(), fd.vfsfd.IsWritable(), false /* trunc */)
	if err != nil {
		return fmt.Errorf("failed to open handle for specialFileFD for %q: %w", genericDebugPathname(d.fs, d), err)
	}
	fd.handle = h

	ftype := d.fileType()
	fd.haveQueue = (ftype == linux.S_IFIFO || ftype == linux.S_IFSOCK) && fd.handle.fd >= 0
	if fd.haveQueue {
		if err := fdnotifier.AddFD(fd.handle.fd, &fd.queue); err != nil {
			return fmt.Errorf("failed to add FD to fdnotified for %q: %w", genericDebugPathname(d.fs, d), err)
		}
	}

	return nil
}
