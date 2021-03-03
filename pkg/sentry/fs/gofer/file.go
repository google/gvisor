// Copyright 2018 The gVisor Authors.
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
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// fileOperations implements fs.FileOperations for a remote file system.
//
// +stateify savable
type fileOperations struct {
	fsutil.FileNoIoctl  `state:"nosave"`
	fsutil.FileNoSplice `state:"nosplice"`
	waiter.AlwaysReady  `state:"nosave"`

	// inodeOperations is the inodeOperations backing the file. It is protected
	// by a reference held by File.Dirent.Inode which is stable until
	// FileOperations.Release is called.
	inodeOperations *inodeOperations `state:"wait"`

	// dirCursor is the directory cursor.
	dirCursor string

	// handles are the opened remote file system handles, which may
	// be shared with other files.
	handles *handles `state:"nosave"`

	// flags are the flags used to open handles.
	flags fs.FileFlags `state:"wait"`
}

// fileOperations implements fs.FileOperations.
var _ fs.FileOperations = (*fileOperations)(nil)

// NewFile returns a file. NewFile is not appropriate with host pipes and sockets.
//
// The `name` argument is only used to log a warning if we are returning a
// writeable+executable file. (A metric counter is incremented in this case as
// well.) Note that we cannot call d.BaseName() directly in this function,
// because that would lead to a lock order violation, since this is called in
// d.Create which holds d.mu, while d.BaseName() takes d.parent.mu, and the two
// locks must be taken in the opposite order.
func NewFile(ctx context.Context, dirent *fs.Dirent, name string, flags fs.FileFlags, i *inodeOperations, handles *handles) *fs.File {
	// Remote file systems enforce readability/writability at an offset,
	// see fs/9p/vfs_inode.c:v9fs_vfs_atomic_open -> fs/open.c:finish_open.
	flags.Pread = true
	flags.Pwrite = true

	if fs.IsFile(dirent.Inode.StableAttr) {
		// If cache policy is "remote revalidating", then we must
		// ensure that we have a host FD. Otherwise, the
		// sentry-internal page cache will be used, and we can end up
		// in an inconsistent state if the remote file changes.
		cp := dirent.Inode.InodeOperations.(*inodeOperations).session().cachePolicy
		if cp == cacheRemoteRevalidating && handles.Host == nil {
			panic(fmt.Sprintf("remote-revalidating cache policy requires gofer to donate host FD, but file %q did not have host FD", name))
		}
	}

	f := &fileOperations{
		inodeOperations: i,
		handles:         handles,
		flags:           flags,
	}
	if flags.Write {
		if err := dirent.Inode.CheckPermission(ctx, fs.PermMask{Execute: true}); err == nil {
			fsmetric.GoferOpensWX.Increment()
			log.Warningf("Opened a writable executable: %q", name)
		}
	}
	if handles.Host != nil {
		fsmetric.GoferOpensHost.Increment()
	} else {
		fsmetric.GoferOpens9P.Increment()
	}
	return fs.NewFile(ctx, dirent, flags, f)
}

// Release implements fs.FileOpeations.Release.
func (f *fileOperations) Release(context.Context) {
	f.handles.DecRef()
}

// Readdir implements fs.FileOperations.Readdir.
func (f *fileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	if root != nil {
		defer root.DecRef(ctx)
	}

	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &f.dirCursor,
	}
	n, err := fs.DirentReaddir(ctx, file.Dirent, f, root, dirCtx, file.Offset())
	if f.inodeOperations.session().cachePolicy.cacheUAttrs(file.Dirent.Inode) {
		f.inodeOperations.cachingInodeOps.TouchAccessTime(ctx, file.Dirent.Inode)
	}
	return n, err
}

// IterateDir implements fs.DirIterator.IterateDir.
func (f *fileOperations) IterateDir(ctx context.Context, d *fs.Dirent, dirCtx *fs.DirCtx, offset int) (int, error) {
	f.inodeOperations.readdirMu.Lock()
	defer f.inodeOperations.readdirMu.Unlock()

	// Fetch directory entries if needed.
	if !f.inodeOperations.session().cachePolicy.cacheReaddir() || f.inodeOperations.readdirCache == nil {
		entries, err := f.readdirAll(ctx)
		if err != nil {
			return offset, err
		}

		// Cache the readdir result.
		f.inodeOperations.readdirCache = fs.NewSortedDentryMap(entries)
	}

	// Serialize the entries.
	n, err := fs.GenericReaddir(dirCtx, f.inodeOperations.readdirCache)
	return offset + n, err
}

// readdirAll fetches fs.DentAttrs for f, using the attributes of g.
func (f *fileOperations) readdirAll(ctx context.Context) (map[string]fs.DentAttr, error) {
	entries := make(map[string]fs.DentAttr)
	var readOffset uint64
	for {
		// We choose some arbitrary high number of directory entries (64k) and call
		// Readdir until we've exhausted them all.
		dirents, err := f.handles.File.readdir(ctx, readOffset, 64*1024)
		if err != nil {
			return nil, err
		}
		if len(dirents) == 0 {
			// We're done, we reached EOF.
			break
		}

		// The last dirent contains the offset into the next set of dirents.  The gofer
		// returns the offset as an index into directories, not as a byte offset, because
		// converting a byte offset to an index into directories entries is a huge pain.
		// But everything is fine if we're consistent.
		readOffset = dirents[len(dirents)-1].Offset

		for _, dirent := range dirents {
			if dirent.Name == "." || dirent.Name == ".." {
				// These must not be included in Readdir results.
				continue
			}

			// Find a best approximation of the type.
			var nt fs.InodeType
			switch dirent.Type {
			case p9.TypeDir:
				nt = fs.Directory
			case p9.TypeSymlink:
				nt = fs.Symlink
			default:
				nt = fs.RegularFile
			}

			// Install the DentAttr.
			entries[dirent.Name] = fs.DentAttr{
				Type: nt,
				// Construct the key to find the virtual inode.
				// Directory entries reside on the same Device
				// and SecondaryDevice as their parent.
				InodeID: goferDevice.Map(device.MultiDeviceKey{
					Device:          f.inodeOperations.fileState.key.Device,
					SecondaryDevice: f.inodeOperations.fileState.key.SecondaryDevice,
					Inode:           dirent.QID.Path,
				}),
			}
		}
	}

	return entries, nil
}

// maybeSync will call FSync on the file if either the cache policy or file
// flags require it.
func (f *fileOperations) maybeSync(ctx context.Context, file *fs.File, offset, n int64) error {
	if n == 0 {
		// Nothing to sync.
		return nil
	}

	if f.inodeOperations.session().cachePolicy.writeThrough(file.Dirent.Inode) {
		// Call WriteOut directly, as some "writethrough" filesystems
		// do not support sync.
		return f.inodeOperations.cachingInodeOps.WriteOut(ctx, file.Dirent.Inode)
	}

	flags := file.Flags()
	var syncType fs.SyncType
	switch {
	case flags.Direct || flags.Sync:
		syncType = fs.SyncAll
	case flags.DSync:
		syncType = fs.SyncData
	default:
		// No need to sync.
		return nil
	}

	return f.Fsync(ctx, file, offset, offset+n, syncType)
}

// Write implements fs.FileOperations.Write.
func (f *fileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	if fs.IsDir(file.Dirent.Inode.StableAttr) {
		// Not all remote file systems enforce this so this client does.
		return 0, syserror.EISDIR
	}

	var (
		n   int64
		err error
	)
	// The write is handled in different ways depending on the cache policy
	// and availability of a host-mappable FD.
	if f.inodeOperations.session().cachePolicy.useCachingInodeOps(file.Dirent.Inode) {
		n, err = f.inodeOperations.cachingInodeOps.Write(ctx, src, offset)
	} else if f.inodeOperations.fileState.hostMappable != nil {
		n, err = f.inodeOperations.fileState.hostMappable.Write(ctx, src, offset)
	} else {
		n, err = src.CopyInTo(ctx, f.handles.readWriterAt(ctx, offset))
	}

	// We may need to sync the written bytes.
	if syncErr := f.maybeSync(ctx, file, offset, n); syncErr != nil {
		// Sync failed. Report 0 bytes written, since none of them are
		// guaranteed to have been synced.
		return 0, syncErr
	}

	return n, err
}

// incrementReadCounters increments the read counters for the read starting at the given time. We
// use this function rather than using a defer in Read() to avoid the performance hit of defer.
func (f *fileOperations) incrementReadCounters(start time.Time) {
	if f.handles.Host != nil {
		fsmetric.GoferReadsHost.Increment()
		fsmetric.FinishReadWait(fsmetric.GoferReadWaitHost, start)
	} else {
		fsmetric.GoferReads9P.Increment()
		fsmetric.FinishReadWait(fsmetric.GoferReadWait9P, start)
	}
}

// Read implements fs.FileOperations.Read.
func (f *fileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	start := fsmetric.StartReadWait()
	if fs.IsDir(file.Dirent.Inode.StableAttr) {
		// Not all remote file systems enforce this so this client does.
		f.incrementReadCounters(start)
		return 0, syserror.EISDIR
	}

	if f.inodeOperations.session().cachePolicy.useCachingInodeOps(file.Dirent.Inode) {
		n, err := f.inodeOperations.cachingInodeOps.Read(ctx, file, dst, offset)
		f.incrementReadCounters(start)
		return n, err
	}
	n, err := dst.CopyOutFrom(ctx, f.handles.readWriterAt(ctx, offset))
	f.incrementReadCounters(start)
	return n, err
}

// Fsync implements fs.FileOperations.Fsync.
func (f *fileOperations) Fsync(ctx context.Context, file *fs.File, start, end int64, syncType fs.SyncType) error {
	switch syncType {
	case fs.SyncAll, fs.SyncData:
		if err := file.Dirent.Inode.WriteOut(ctx); err != nil {
			return err
		}
		fallthrough
	case fs.SyncBackingStorage:
		// Sync remote caches.
		if f.handles.Host != nil {
			// Sync the host fd directly.
			return unix.Fsync(f.handles.Host.FD())
		}
		// Otherwise sync on the p9.File handle.
		return f.handles.File.fsync(ctx)
	}
	panic("invalid sync type")
}

// Flush implements fs.FileOperations.Flush.
func (f *fileOperations) Flush(ctx context.Context, file *fs.File) error {
	// If this file is not opened writable then there is nothing to flush.
	// We do this because some p9 server implementations of Flush are
	// over-zealous.
	//
	// FIXME(edahlgren): weaken these implementations and remove this check.
	if !file.Flags().Write {
		return nil
	}
	// Execute the flush.
	return f.handles.File.flush(ctx)
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (f *fileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	return f.inodeOperations.configureMMap(file, opts)
}

// UnstableAttr implements fs.FileOperations.UnstableAttr.
func (f *fileOperations) UnstableAttr(ctx context.Context, file *fs.File) (fs.UnstableAttr, error) {
	s := f.inodeOperations.session()
	if s.cachePolicy.cacheUAttrs(file.Dirent.Inode) {
		return f.inodeOperations.cachingInodeOps.UnstableAttr(ctx, file.Dirent.Inode)
	}
	// Use f.handles.File, which represents 9P fids that have been opened,
	// instead of inodeFileState.file, which represents 9P fids that have not.
	// This may be significantly more efficient in some implementations.
	_, valid, pattr, err := getattr(ctx, f.handles.File)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	return unstable(ctx, valid, pattr, s.mounter, s.client), nil
}

// Seek implements fs.FileOperations.Seek.
func (f *fileOperations) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return fsutil.SeekWithDirCursor(ctx, file, whence, offset, &f.dirCursor)
}
