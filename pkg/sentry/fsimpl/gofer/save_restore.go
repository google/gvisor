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
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

type saveRestoreContextID int

const (
	// CtxRestoreServerFDMap is a Context.Value key for a map[string]int
	// mapping filesystem unique IDs (cf. InternalFilesystemOptions.UniqueID)
	// to host FDs.
	CtxRestoreServerFDMap saveRestoreContextID = iota
)

// +stateify savable
type savedDentryRW struct {
	read  bool
	write bool
}

// PreprareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	if len(fs.iopts.UniqueID) == 0 {
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
		if err := d.updateFromGetattr(ctx); err != nil {
			return err
		}
	}
	if d.fs.opts.lisaEnabled {
		if d.readFDLisa.Ok() || d.writeFDLisa.Ok() {
			d.fs.savedDentryRW[d] = savedDentryRW{
				read:  d.readFDLisa.Ok(),
				write: d.writeFDLisa.Ok(),
			}
		}
	} else {
		if !d.readFile.isNil() || !d.writeFile.isNil() {
			d.fs.savedDentryRW[d] = savedDentryRW{
				read:  !d.readFile.isNil(),
				write: !d.writeFile.isNil(),
			}
		}
	}
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	for _, child := range d.children {
		if child != nil {
			if err := child.prepareSaveRecursive(ctx); err != nil {
				return err
			}
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
func (d *dentry) afterLoad() {
	d.readFD = atomicbitops.FromInt32(-1)
	d.writeFD = atomicbitops.FromInt32(-1)
	d.mmapFD = atomicbitops.FromInt32(-1)
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}

// afterLoad is invoked by stateify.
func (d *dentryPlatformFile) afterLoad() {
	if d.hostFileMapper.IsInited() {
		// Ensure that we don't call d.hostFileMapper.Init() again.
		d.hostFileMapperInitOnce.Do(func() {})
	}
}

// afterLoad is invoked by stateify.
func (fd *specialFileFD) afterLoad() {
	fd.handle.fd = -1
	if fd.hostFileMapper.IsInited() {
		// Ensure that we don't call fd.hostFileMapper.Init() again.
		fd.hostFileMapperInitOnce.Do(func() {})
	}
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	fdmapv := ctx.Value(CtxRestoreServerFDMap)
	if fdmapv == nil {
		return fmt.Errorf("no server FD map available")
	}
	fdmap := fdmapv.(map[string]int)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		return fmt.Errorf("no server FD available for filesystem with unique ID %q", fs.iopts.UniqueID)
	}
	fs.opts.fd = fd
	fs.inoByQIDPath = make(map[uint64]uint64)
	fs.inoByKey = make(map[inoKey]uint64)

	if fs.opts.lisaEnabled {
		rootInode, err := fs.initClientLisa(ctx)
		if err != nil {
			return err
		}
		if err := fs.root.restoreFileLisa(ctx, &rootInode, &opts); err != nil {
			return err
		}
	} else {
		if err := fs.dial(ctx); err != nil {
			return err
		}

		// Restore the filesystem root.
		ctx.UninterruptibleSleepStart(false)
		attached, err := fs.client.Attach(fs.opts.aname)
		ctx.UninterruptibleSleepFinish(false)
		if err != nil {
			return err
		}
		attachFile := p9file{attached}
		qid, attrMask, attr, err := attachFile.getAttr(ctx, dentryAttrMask())
		if err != nil {
			return err
		}
		if err := fs.root.restoreFile(ctx, attachFile, qid, attrMask, &attr, &opts); err != nil {
			return err
		}
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

func (d *dentry) restoreFile(ctx context.Context, file p9file, qid p9.QID, attrMask p9.AttrMask, attr *p9.Attr, opts *vfs.CompleteRestoreOptions) error {
	d.file = file

	// Gofers do not preserve QID across checkpoint/restore, so:
	//
	//	- We must assume that the remote filesystem did not change in a way that
	//		would invalidate dentries, since we can't revalidate dentries by
	//		checking QIDs.
	//
	//	- We need to associate the new QID.Path with the existing d.ino.
	d.qidPath = qid.Path
	d.fs.inoMu.Lock()
	d.fs.inoByQIDPath[qid.Path] = d.ino
	d.fs.inoMu.Unlock()

	// Check metadata stability before updating metadata.
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	if d.isRegularFile() {
		if opts.ValidateFileSizes {
			if !attrMask.Size {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: file size not available", genericDebugPathname(d))}
			}
			if d.size.Load() != attr.Size {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: size changed from %d to %d", genericDebugPathname(d), d.size.Load(), attr.Size)}
			}
		}
		if opts.ValidateFileModificationTimestamps {
			if !attrMask.MTime {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime not available", genericDebugPathname(d))}
			}
			if want := dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds); d.mtime.Load() != want {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime changed from %+v to %+v", genericDebugPathname(d), linux.NsecToStatxTimestamp(d.mtime.Load()), linux.NsecToStatxTimestamp(want))}
			}
		}
	}
	if !d.cachedMetadataAuthoritative() {
		d.updateFromP9AttrsLocked(attrMask, attr)
	}

	if rw, ok := d.fs.savedDentryRW[d]; ok {
		if err := d.ensureSharedHandle(ctx, rw.read, rw.write, false /* trunc */); err != nil {
			return err
		}
	}

	return nil
}

func (d *dentry) restoreFileLisa(ctx context.Context, inode *lisafs.Inode, opts *vfs.CompleteRestoreOptions) error {
	d.controlFDLisa = d.fs.clientLisa.NewFD(inode.ControlFD)

	// Gofers do not preserve inoKey across checkpoint/restore, so:
	//
	//	- We must assume that the remote filesystem did not change in a way that
	//		would invalidate dentries, since we can't revalidate dentries by
	//		checking inoKey.
	//
	//	- We need to associate the new inoKey with the existing d.ino.
	d.inoKey = inoKeyFromStat(&inode.Stat)
	d.fs.inoMu.Lock()
	d.fs.inoByKey[d.inoKey] = d.ino
	d.fs.inoMu.Unlock()

	// Check metadata stability before updating metadata.
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	if d.isRegularFile() {
		if opts.ValidateFileSizes {
			if inode.Stat.Mask&linux.STATX_SIZE == 0 {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: file size not available", genericDebugPathname(d))}
			}
			if d.size.RacyLoad() != inode.Stat.Size {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: file size validation failed: size changed from %d to %d", genericDebugPathname(d), d.size.Load(), inode.Stat.Size)}
			}
		}
		if opts.ValidateFileModificationTimestamps {
			if inode.Stat.Mask&linux.STATX_MTIME != 0 {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime not available", genericDebugPathname(d))}
			}
			if want := dentryTimestampFromLisa(inode.Stat.Mtime); d.mtime.RacyLoad() != want {
				return vfs.ErrCorruption{fmt.Errorf("gofer.dentry(%q).restoreFile: mtime validation failed: mtime changed from %+v to %+v", genericDebugPathname(d), linux.NsecToStatxTimestamp(d.mtime.RacyLoad()), linux.NsecToStatxTimestamp(want))}
			}
		}
	}
	if !d.cachedMetadataAuthoritative() {
		d.updateFromLisaStatLocked(&inode.Stat)
	}

	if rw, ok := d.fs.savedDentryRW[d]; ok {
		if err := d.ensureSharedHandle(ctx, rw.read, rw.write, false /* trunc */); err != nil {
			return err
		}
	}

	return nil
}

// Preconditions: d is not synthetic.
func (d *dentry) restoreDescendantsRecursive(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	for _, child := range d.children {
		if child == nil {
			continue
		}
		// child is synthetic if it does not exist in fs.syncableDentries.
		if child.syncableListEntry.Next() == nil && child.syncableListEntry.Prev() == nil && d.fs.syncableDentries.Front() != &child.syncableListEntry {
			continue
		}
		if err := child.restoreRecursive(ctx, opts); err != nil {
			return err
		}
	}
	return nil
}

// Preconditions: d is not synthetic (but note that since this function
// restores d.file, d.file.isNil() is always true at this point, so this can
// only be detected by checking filesystem.syncableDentries). d.parent has been
// restored.
func (d *dentry) restoreRecursive(ctx context.Context, opts *vfs.CompleteRestoreOptions) error {
	if d.fs.opts.lisaEnabled {
		inode, err := d.parent.controlFDLisa.Walk(ctx, d.name)
		if err != nil {
			return err
		}
		if err := d.restoreFileLisa(ctx, &inode, opts); err != nil {
			return err
		}
	} else {
		qid, file, attrMask, attr, err := d.parent.file.walkGetAttrOne(ctx, d.name)
		if err != nil {
			return err
		}
		if err := d.restoreFile(ctx, file, qid, attrMask, &attr, opts); err != nil {
			return err
		}
	}
	return d.restoreDescendantsRecursive(ctx, opts)
}

func (fd *specialFileFD) completeRestore(ctx context.Context) error {
	d := fd.dentry()
	var h handle
	var err error
	if d.fs.opts.lisaEnabled {
		h, err = openHandleLisa(ctx, d.controlFDLisa, fd.vfsfd.IsReadable(), fd.vfsfd.IsWritable(), false /* trunc */)
	} else {
		h, err = openHandle(ctx, d.file, fd.vfsfd.IsReadable(), fd.vfsfd.IsWritable(), false /* trunc */)
	}
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
