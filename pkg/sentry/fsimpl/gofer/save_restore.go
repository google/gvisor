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
	"encoding/hex"
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
	"gvisor.dev/gvisor/pkg/rand"
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
		if sffd.dentry().inode.fileType() == linux.S_IFIFO && sffd.vfsfd.IsReadable() {
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
	if !d.inode.isRegularFile() && !d.isDir() {
		return fmt.Errorf("gofer.dentry(%q).prepareSaveDead: only deleted dentries for regular files and directories can be saved, got %s", genericDebugPathname(d.inode.fs, d), linux.FileMode(d.inode.mode.Load()))
	}
	if !d.isDeleted() {
		return fmt.Errorf("gofer.dentry(%q).prepareSaveDead: invalidated dentries can't be saved", genericDebugPathname(d.inode.fs, d))
	}
	if d.inode.isRegularFile() {
		if !d.inode.cachedMetadataAuthoritative() {
			// Get updated metadata for d in case we need to perform metadata
			// validation during restore.
			if err := d.inode.updateMetadata(ctx); err != nil {
				return err
			}
		}
		if err := d.prepareSaveDeletedRegularFile(ctx); err != nil {
			return err
		}
	}
	if d.inode.isReadHandleOk() || d.inode.isWriteHandleOk() {
		d.inode.fs.savedDentryRW[d] = savedDentryRW{
			read:  d.inode.isReadHandleOk(),
			write: d.inode.isWriteHandleOk(),
		}
	}
	if d.inode.fs.savedDeletedOpenDentries == nil {
		d.inode.fs.savedDeletedOpenDentries = make(map[*dentry]struct{})
	}
	d.inode.fs.savedDeletedOpenDentries[d] = struct{}{}
	return nil
}

// Preconditions:
//   - d.inode.isRegularFile()
//   - d.isDeleted()
func (d *dentry) prepareSaveDeletedRegularFile(ctx context.Context) error {
	// Fetch an appropriate handle to read the deleted file.
	d.inode.handleMu.RLock()
	defer d.inode.handleMu.RUnlock()
	h, err := d.readHandleForDeleted(ctx)
	if err != nil {
		return fmt.Errorf("failed to open read handle for deleted file %q: %w", genericDebugPathname(d.inode.fs, d), err)
	}
	// Read the file data and store it in d.inode.savedDeletedData.
	d.inode.dataMu.RLock()
	defer d.inode.dataMu.RUnlock()
	d.inode.savedDeletedData = make([]byte, d.inode.size.Load())
	done := uint64(0)
	for done < uint64(len(d.inode.savedDeletedData)) {
		n, err := h.readToBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(d.inode.savedDeletedData[done:])), done)
		done += n
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read deleted file %q: %w", genericDebugPathname(d.inode.fs, d), err)
		}
	}
	if done < uint64(len(d.inode.savedDeletedData)) {
		return fmt.Errorf("failed to read all of deleted file %q: read %d bytes, expected %d", genericDebugPathname(d.inode.fs, d), done, len(d.inode.savedDeletedData))
	}
	return nil
}

func (d *dentry) prepareSaveRecursive(ctx context.Context) error {
	if d.inode.isRegularFile() && !d.inode.cachedMetadataAuthoritative() {
		// Get updated metadata for d in case we need to perform metadata
		// validation during restore.
		if err := d.inode.updateMetadata(ctx); err != nil {
			return err
		}
	}
	if d.inode.isReadHandleOk() || d.inode.isWriteHandleOk() {
		d.inode.fs.savedDentryRW[d] = savedDentryRW{
			read:  d.inode.isReadHandleOk(),
			write: d.inode.isWriteHandleOk(),
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
		if _, ok := d.inode.fs.savedDeletedOpenDentries[d]; !ok {
			panic(fmt.Sprintf("gofer.dentry(%q).beforeSave: dead dentry is not saved in fs.savedDeletedOpenDentries (deleted=%t, synthetic=%t)", genericDebugPathname(d.inode.fs, d), d.isDeleted(), d.inode.isSynthetic()))
		}
	}
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {
	for d := range fs.savedDeletedOpenDentries {
		d.inode.savedDeletedData = nil
	}
	fs.savedDeletedOpenDentries = nil
	fs.savedDentryRW = nil
}

// afterLoad is invoked by stateify.
func (fs *filesystem) afterLoad(ctx goContext.Context) {
	fs.mf = pgalloc.MemoryFileFromContext(ctx)
}

// afterLoad is invoked by stateify.
func (i *inode) afterLoad(goContext.Context) {
	i.readFD = atomicbitops.FromInt32(-1)
	i.writeFD = atomicbitops.FromInt32(-1)
	i.mmapFD = atomicbitops.FromInt32(-1)
}

// afterLoad is invoked by stateify.
func (d *dentry) afterLoad(goContext.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}

// afterLoad is invoked by stateify.
func (i *directfsInode) afterLoad(goContext.Context) {
	i.controlFD = -1
}

// afterLoad is invoked by stateify.
func (i *inodePlatformFile) afterLoad(goContext.Context) {
	if i.hostFileMapper.IsInited() {
		// Ensure that we don't call d.hostFileMapper.Init() again.
		i.hostFileMapperInitOnce.Do(func() {})
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
	fs.inodeByKey = make(map[inoKey]*inode)

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
		if fd.dentry().inode.fileType() == linux.S_IFIFO && !fd.vfsfd.IsReadable() {
			haveWriteOnlyPipes = true
			continue
		}
		if err := fd.completeRestore(ctx); err != nil {
			return err
		}
	}
	if haveWriteOnlyPipes {
		for fd := fs.specialFileFDs.Front(); fd != nil; fd = fd.Next() {
			if fd.dentry().inode.fileType() == linux.S_IFIFO && !fd.vfsfd.IsReadable() {
				if err := fd.completeRestore(ctx); err != nil {
					return err
				}
			}
		}
	}

	// Restore deleted files which are still accessible via open application FDs.
	dirsToDelete := make(map[*dentry]string)
	for d := range fs.savedDeletedOpenDentries {
		if err := d.restoreDeleted(ctx, &opts, dirsToDelete); err != nil {
			return err
		}
	}
	for len(dirsToDelete) > 0 {
		// In case of nested deleted directories, only leaf directories can be
		// deleted. Then repeat as parent directories become leaves.
		leafDirectories := make(map[*dentry]struct{})
		for d := range dirsToDelete {
			leafDirectories[d] = struct{}{}
		}
		for d := range dirsToDelete {
			delete(leafDirectories, d.parent.Load())
		}
		for leafD := range leafDirectories {
			// Note that we use the name specified in dirsToDelete map, which is the
			// name used to create the temporary directory. This name may differ from
			// leafD.name if another non-deleted directory already exists there.
			if err := leafD.parent.Load().inode.unlink(ctx, dirsToDelete[leafD], linux.AT_REMOVEDIR); err != nil {
				return fmt.Errorf("failed to clean up recreated deleted directory %q: %v", genericDebugPathname(fs, leafD), err)
			}
			delete(dirsToDelete, leafD)
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
		if child.inode.isSynthetic() {
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

// restoreDeleted restores a deleted dentry for a directory or regular file.
//
// Preconditions:
//   - d.isRegularFile() || d.isDir()
//   - d.savedDeletedData != nil iff d.isRegularFile()
func (d *dentry) restoreDeleted(ctx context.Context, opts *vfs.CompleteRestoreOptions, dirsToDelete map[*dentry]string) error {
	parent := d.parent.Load()
	if _, ok := d.inode.fs.savedDeletedOpenDentries[parent]; ok {
		// Recursively restore the parent first if the parent is also deleted.
		if err := parent.restoreDeleted(ctx, opts, dirsToDelete); err != nil {
			return err
		}
	}
	switch {
	case d.inode.isRegularFile():
		return d.restoreDeletedRegularFile(ctx, opts)
	case d.isDir():
		return d.restoreDeletedDirectory(ctx, opts, dirsToDelete)
	default:
		return fmt.Errorf("gofer.dentry(%q).restoreDeleted: invalid file type %s", genericDebugPathname(d.inode.fs, d), linux.FileMode(d.inode.mode.Load()))
	}
}

func randomNameForDeleted(name string) string {
	var randBuf [8]byte
	rand.Read(randBuf[:])
	return fmt.Sprintf("%s.tmp-gvisor-restore-%s", name, hex.EncodeToString(randBuf[:]))
}

func (d *dentry) restoreDeletedDirectory(ctx context.Context, opts *vfs.CompleteRestoreOptions, dirsToDelete map[*dentry]string) error {
	// Recreate the directory on the host filesystem. This will be deleted later.
	parent := d.parent.Load()
	_, err := parent.mkdir(ctx, d.name, linux.FileMode(d.inode.mode.Load()), auth.KUID(d.inode.uid.Load()), auth.KGID(d.inode.gid.Load()), false /* createDentry */)
	if linuxerr.Equals(linuxerr.EEXIST, err) {
		// Change d.name for the remainder of this function.
		origName := d.name
		d.name = randomNameForDeleted(d.name)
		defer func() {
			d.name = origName
		}()
		log.Warningf("Deleted directory %q was replaced with a new directory at the same path, using new name %q", genericDebugPathname(d.inode.fs, d), d.name)
		_, err = parent.mkdir(ctx, d.name, linux.FileMode(d.inode.mode.Load()), auth.KUID(d.inode.uid.Load()), auth.KGID(d.inode.gid.Load()), false /* createDentry */)
	}
	if err != nil {
		return fmt.Errorf("failed to re-create deleted directory %q: %w", genericDebugPathname(d.inode.fs, d), err)
	}
	// Restore the directory.
	if err := d.restoreFile(ctx, opts); err != nil {
		if err := parent.inode.unlink(ctx, d.name, linux.AT_REMOVEDIR); err != nil {
			log.Warningf("failed to clean up recreated deleted directory %q: %v", genericDebugPathname(d.inode.fs, d), err)
		}
		return fmt.Errorf("failed to restore deleted directory: %w", err)
	}
	// We will delete the directory later. We need to keep it around in case any
	// of its children need to be restored after this.
	dirsToDelete[d] = d.name
	delete(d.inode.fs.savedDeletedOpenDentries, d)
	return nil
}

func (d *dentry) restoreDeletedRegularFile(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	// Recreate the file on the host filesystem (this is temporary).
	parent := d.parent.Load()
	_, h, err := parent.openCreate(ctx, d.name, linux.O_WRONLY, linux.FileMode(d.inode.mode.Load()), auth.KUID(d.inode.uid.Load()), auth.KGID(d.inode.gid.Load()), false /* createDentry */)
	if linuxerr.Equals(linuxerr.EEXIST, err) {
		// Change d.name for the remainder of this function.
		origName := d.name
		d.name = randomNameForDeleted(d.name)
		defer func() {
			d.name = origName
		}()
		log.Warningf("Deleted file %q was replaced with a new file at the same path, using new name %q", genericDebugPathname(d.inode.fs, d), d.name)
		_, h, err = parent.openCreate(ctx, d.name, linux.O_WRONLY, linux.FileMode(d.inode.mode.Load()), auth.KUID(d.inode.uid.Load()), auth.KGID(d.inode.gid.Load()), false /* createDentry */)
	}
	if err != nil {
		return fmt.Errorf("failed to re-create deleted file %q: %w", genericDebugPathname(d.inode.fs, d), err)
	}
	defer h.close(ctx)
	// In case of errors, clean up the recreated file.
	unlinkCU := cleanup.Make(func() {
		if err := parent.inode.unlink(ctx, d.name, 0 /* flags */); err != nil {
			log.Warningf("failed to clean up recreated deleted file %q: %v", genericDebugPathname(d.inode.fs, d), err)
		}
	})
	defer unlinkCU.Clean()
	// Write the file data to the recreated file.
	n, err := h.writeFromBlocksAt(ctx, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(d.inode.savedDeletedData)), 0)
	if err != nil {
		return fmt.Errorf("failed to write deleted file %q: %w", genericDebugPathname(d.inode.fs, d), err)
	}
	if n != uint64(len(d.inode.savedDeletedData)) {
		return fmt.Errorf("failed to write all of deleted file %q: wrote %d bytes, expected %d", genericDebugPathname(d.inode.fs, d), n, len(d.inode.savedDeletedData))
	}
	d.inode.savedDeletedData = nil
	// Restore the file. Note that timestamps may not match since we re-created
	// the file on the host.
	recreateOpts := *opts
	recreateOpts.ValidateFileModificationTimestamps = false
	if err := d.restoreFile(ctx, &recreateOpts); err != nil {
		return fmt.Errorf("failed to restore deleted regular file: %w", err)
	}
	// Finally, unlink the recreated file.
	unlinkCU.Release()
	if err := parent.inode.unlink(ctx, d.name, 0 /* flags */); err != nil {
		return fmt.Errorf("failed to clean up recreated deleted file %q: %v", genericDebugPathname(d.inode.fs, d), err)
	}
	delete(d.inode.fs.savedDeletedOpenDentries, d)
	return nil
}

func (fd *specialFileFD) completeRestore(ctx context.Context) error {
	d := fd.dentry()
	h, err := d.openHandle(ctx, fd.vfsfd.IsReadable(), fd.vfsfd.IsWritable(), false /* trunc */)
	if err != nil {
		return fmt.Errorf("failed to open handle for specialFileFD for %q: %w", genericDebugPathname(d.inode.fs, d), err)
	}
	fd.handle = h

	ftype := d.inode.fileType()
	fd.haveQueue = (ftype == linux.S_IFIFO || ftype == linux.S_IFSOCK) && fd.handle.fd >= 0
	if fd.haveQueue {
		if err := fdnotifier.AddFD(fd.handle.fd, &fd.queue); err != nil {
			return fmt.Errorf("failed to add FD to fdnotified for %q: %w", genericDebugPathname(d.inode.fs, d), err)
		}
	}

	return nil
}
