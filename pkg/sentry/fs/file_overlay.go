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

package fs

import (
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// overlayFile gets a handle to a file from the upper or lower filesystem
// in an overlay. The caller is responsible for calling File.DecRef on
// the returned file.
func overlayFile(ctx context.Context, inode *Inode, flags FileFlags) (*File, error) {
	// Do a song and dance to eventually get to:
	//
	//   File -> single reference
	//   Dirent -> single reference
	//   Inode -> multiple references
	//
	// So that File.DecRef() -> File.destroy -> Dirent.DecRef -> Dirent.destroy,
	// and both the transitory File and Dirent can be GC'ed but the Inode
	// remains.

	// Take another reference on the Inode.
	inode.IncRef()

	// Start with a single reference on the Dirent. It inherits the reference
	// we just took on the Inode above.
	dirent := NewTransientDirent(inode)

	// Get a File. This will take another reference on the Dirent.
	f, err := inode.GetFile(ctx, dirent, flags)

	// Drop the extra reference on the Dirent. Now there's only one reference
	// on the dirent, either owned by f (if non-nil), or the Dirent is about
	// to be destroyed (if GetFile failed).
	dirent.DecRef(ctx)

	return f, err
}

// overlayFileOperations implements FileOperations for a file in an overlay.
//
// +stateify savable
type overlayFileOperations struct {
	// upperMu protects upper below. In contrast lower is stable.
	upperMu sync.Mutex `state:"nosave"`

	// We can't share Files in upper and lower filesystems between all Files
	// in an overlay because some file systems expect to get distinct handles
	// that are not consistent with each other on open(2).
	//
	// So we lazily acquire an upper File when the overlayEntry acquires an
	// upper Inode (it might have one from the start). This synchronizes with
	// copy up.
	//
	// If upper is non-nil and this is not a directory, then lower is ignored.
	//
	// For directories, upper and lower are ignored because it is always
	// necessary to acquire new directory handles so that the directory cursors
	// of the upper and lower Files are not exhausted.
	upper *File
	lower *File

	// dirCursor is a directory cursor for a directory in an overlay. It is
	// protected by File.mu of the owning file, which is held during
	// Readdir and Seek calls.
	dirCursor string
}

// Release implements FileOperations.Release.
func (f *overlayFileOperations) Release(ctx context.Context) {
	if f.upper != nil {
		f.upper.DecRef(ctx)
	}
	if f.lower != nil {
		f.lower.DecRef(ctx)
	}
}

// EventRegister implements FileOperations.EventRegister.
func (f *overlayFileOperations) EventRegister(we *waiter.Entry, mask waiter.EventMask) {
	f.upperMu.Lock()
	defer f.upperMu.Unlock()
	if f.upper != nil {
		f.upper.EventRegister(we, mask)
		return
	}
	f.lower.EventRegister(we, mask)
}

// EventUnregister implements FileOperations.Unregister.
func (f *overlayFileOperations) EventUnregister(we *waiter.Entry) {
	f.upperMu.Lock()
	defer f.upperMu.Unlock()
	if f.upper != nil {
		f.upper.EventUnregister(we)
		return
	}
	f.lower.EventUnregister(we)
}

// Readiness implements FileOperations.Readiness.
func (f *overlayFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	f.upperMu.Lock()
	defer f.upperMu.Unlock()
	if f.upper != nil {
		return f.upper.Readiness(mask)
	}
	return f.lower.Readiness(mask)
}

// Seek implements FileOperations.Seek.
func (f *overlayFileOperations) Seek(ctx context.Context, file *File, whence SeekWhence, offset int64) (int64, error) {
	f.upperMu.Lock()
	defer f.upperMu.Unlock()

	var seekDir bool
	var n int64
	if f.upper != nil {
		var err error
		if n, err = f.upper.FileOperations.Seek(ctx, file, whence, offset); err != nil {
			return n, err
		}
		seekDir = IsDir(f.upper.Dirent.Inode.StableAttr)
	} else {
		var err error
		if n, err = f.lower.FileOperations.Seek(ctx, file, whence, offset); err != nil {
			return n, err
		}
		seekDir = IsDir(f.lower.Dirent.Inode.StableAttr)
	}

	// If this was a seek on a directory, we must update the cursor.
	if seekDir && whence == SeekSet && offset == 0 {
		// Currently only seeking to 0 on a directory is supported.
		// FIXME(b/33075855): Lift directory seeking limitations.
		f.dirCursor = ""
	}
	return n, nil
}

// Readdir implements FileOperations.Readdir.
func (f *overlayFileOperations) Readdir(ctx context.Context, file *File, serializer DentrySerializer) (int64, error) {
	root := RootFromContext(ctx)
	if root != nil {
		defer root.DecRef(ctx)
	}

	dirCtx := &DirCtx{
		Serializer: serializer,
		DirCursor:  &f.dirCursor,
	}
	return DirentReaddir(ctx, file.Dirent, f, root, dirCtx, file.Offset())
}

// IterateDir implements DirIterator.IterateDir.
func (f *overlayFileOperations) IterateDir(ctx context.Context, d *Dirent, dirCtx *DirCtx, offset int) (int, error) {
	o := d.Inode.overlay
	o.copyMu.RLock()
	defer o.copyMu.RUnlock()
	return overlayIterateDirLocked(ctx, o, d, dirCtx, offset)
}

// Preconditions: o.copyMu must be locked.
func overlayIterateDirLocked(ctx context.Context, o *overlayEntry, d *Dirent, dirCtx *DirCtx, offset int) (int, error) {
	if !d.Inode.MountSource.CacheReaddir() {
		// Can't use the dirCache. Simply read the entries.
		entries, err := readdirEntriesLocked(ctx, o)
		if err != nil {
			return offset, err
		}
		n, err := GenericReaddir(dirCtx, entries)
		return offset + n, err
	}

	// Otherwise, use or create cached entries.

	o.dirCacheMu.RLock()
	if o.dirCache != nil {
		n, err := GenericReaddir(dirCtx, o.dirCache)
		o.dirCacheMu.RUnlock()
		return offset + n, err
	}
	o.dirCacheMu.RUnlock()

	// We must hold dirCacheMu around both readdirEntries and setting
	// o.dirCache to synchronize with dirCache invalidations done by
	// Create, Remove, Rename.
	o.dirCacheMu.Lock()

	// We expect dirCache to be nil (we just checked above), but there is a
	// chance that a racing call managed to just set it, in which case we
	// can use that new value.
	if o.dirCache == nil {
		dirCache, err := readdirEntriesLocked(ctx, o)
		if err != nil {
			o.dirCacheMu.Unlock()
			return offset, err
		}
		o.dirCache = dirCache
	}

	o.dirCacheMu.DowngradeLock()
	n, err := GenericReaddir(dirCtx, o.dirCache)
	o.dirCacheMu.RUnlock()

	return offset + n, err
}

// onTop performs the given operation on the top-most available layer.
func (f *overlayFileOperations) onTop(ctx context.Context, file *File, fn func(*File, FileOperations) error) error {
	file.Dirent.Inode.overlay.copyMu.RLock()
	defer file.Dirent.Inode.overlay.copyMu.RUnlock()

	// Only lower layer is available.
	if file.Dirent.Inode.overlay.upper == nil {
		return fn(f.lower, f.lower.FileOperations)
	}

	f.upperMu.Lock()
	if f.upper == nil {
		upper, err := overlayFile(ctx, file.Dirent.Inode.overlay.upper, file.Flags())
		if err != nil {
			// Something very wrong; return a generic filesystem
			// error to avoid propagating internals.
			f.upperMu.Unlock()
			return syserror.EIO
		}

		// Save upper file.
		f.upper = upper
	}
	f.upperMu.Unlock()

	return fn(f.upper, f.upper.FileOperations)
}

// Read implements FileOperations.Read.
func (f *overlayFileOperations) Read(ctx context.Context, file *File, dst usermem.IOSequence, offset int64) (n int64, err error) {
	err = f.onTop(ctx, file, func(file *File, ops FileOperations) error {
		n, err = ops.Read(ctx, file, dst, offset)
		return err // Will overwrite itself.
	})
	return
}

// WriteTo implements FileOperations.WriteTo.
func (f *overlayFileOperations) WriteTo(ctx context.Context, file *File, dst io.Writer, count int64, dup bool) (n int64, err error) {
	err = f.onTop(ctx, file, func(file *File, ops FileOperations) error {
		n, err = ops.WriteTo(ctx, file, dst, count, dup)
		return err // Will overwrite itself.
	})
	return
}

// Write implements FileOperations.Write.
func (f *overlayFileOperations) Write(ctx context.Context, file *File, src usermem.IOSequence, offset int64) (int64, error) {
	// f.upper must be non-nil. See inode_overlay.go:overlayGetFile, where the
	// file is copied up and opened in the upper filesystem if FileFlags.Write.
	// Write cannot be called if !FileFlags.Write, see FileOperations.Write.
	return f.upper.FileOperations.Write(ctx, f.upper, src, offset)
}

// ReadFrom implements FileOperations.ReadFrom.
func (f *overlayFileOperations) ReadFrom(ctx context.Context, file *File, src io.Reader, count int64) (n int64, err error) {
	// See above; f.upper must be non-nil.
	return f.upper.FileOperations.ReadFrom(ctx, f.upper, src, count)
}

// Fsync implements FileOperations.Fsync.
func (f *overlayFileOperations) Fsync(ctx context.Context, file *File, start, end int64, syncType SyncType) (err error) {
	f.upperMu.Lock()
	if f.upper != nil {
		err = f.upper.FileOperations.Fsync(ctx, f.upper, start, end, syncType)
	}
	f.upperMu.Unlock()
	if err == nil && f.lower != nil {
		// N.B. Fsync on the lower filesystem can cause writes of file
		// attributes (i.e. access time) despite the fact that we must
		// treat the lower filesystem as read-only.
		//
		// This matches the semantics of fsync(2) in Linux overlayfs.
		err = f.lower.FileOperations.Fsync(ctx, f.lower, start, end, syncType)
	}
	return err
}

// Flush implements FileOperations.Flush.
func (f *overlayFileOperations) Flush(ctx context.Context, file *File) (err error) {
	// Flush whatever handles we have.
	f.upperMu.Lock()
	if f.upper != nil {
		err = f.upper.FileOperations.Flush(ctx, f.upper)
	}
	f.upperMu.Unlock()
	if err == nil && f.lower != nil {
		err = f.lower.FileOperations.Flush(ctx, f.lower)
	}
	return err
}

// ConfigureMMap implements FileOperations.ConfigureMMap.
func (*overlayFileOperations) ConfigureMMap(ctx context.Context, file *File, opts *memmap.MMapOpts) error {
	o := file.Dirent.Inode.overlay

	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	// If there is no lower inode, the overlay will never need to do a
	// copy-up, and thus will never need to invalidate any mappings. We can
	// call ConfigureMMap directly on the upper file.
	if o.lower == nil {
		f := file.FileOperations.(*overlayFileOperations)
		if err := f.upper.ConfigureMMap(ctx, opts); err != nil {
			return err
		}

		// ConfigureMMap will set the MappableIdentity to the upper
		// file and take a reference on it, but we must also hold a
		// reference to the overlay file during the lifetime of the
		// Mappable. If we do not do this, the overlay file can be
		// Released before the upper file is Released, and we will be
		// unable to traverse to the upper file during Save, thus
		// preventing us from saving a proper inode mapping for the
		// file.
		file.IncRef()
		id := overlayMappingIdentity{
			id:          opts.MappingIdentity,
			overlayFile: file,
		}
		id.EnableLeakCheck("fs.overlayMappingIdentity")

		// Swap out the old MappingIdentity for the wrapped one.
		opts.MappingIdentity = &id
		return nil
	}

	if !o.isMappableLocked() {
		return syserror.ENODEV
	}

	// FIXME(jamieliu): This is a copy/paste of fsutil.GenericConfigureMMap,
	// which we can't use because the overlay implementation is in package fs,
	// so depending on fs/fsutil would create a circular dependency. Move
	// overlay to fs/overlay.
	opts.Mappable = o
	opts.MappingIdentity = file
	file.IncRef()
	return nil
}

// UnstableAttr implements fs.FileOperations.UnstableAttr.
func (f *overlayFileOperations) UnstableAttr(ctx context.Context, file *File) (UnstableAttr, error) {
	// Hot path. Avoid defers.
	f.upperMu.Lock()
	if f.upper != nil {
		attr, err := f.upper.UnstableAttr(ctx)
		f.upperMu.Unlock()
		return attr, err
	}
	f.upperMu.Unlock()

	// It's possible that copy-up has occurred, but we haven't opened a upper
	// file yet. If this is the case, just use the upper inode's UnstableAttr
	// rather than opening a file.
	o := file.Dirent.Inode.overlay
	o.copyMu.RLock()
	if o.upper != nil {
		attr, err := o.upper.UnstableAttr(ctx)
		o.copyMu.RUnlock()
		return attr, err
	}
	o.copyMu.RUnlock()

	return f.lower.UnstableAttr(ctx)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (f *overlayFileOperations) Ioctl(ctx context.Context, overlayFile *File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	f.upperMu.Lock()
	defer f.upperMu.Unlock()

	if f.upper == nil {
		// It's possible that ioctl changes the file. Since we don't know all
		// possible ioctls, only allow them to propagate to the upper. Triggering a
		// copy up on any ioctl would be too drastic. In the future, it can have a
		// list of ioctls that are safe to send to lower and a list that triggers a
		// copy up.
		return 0, syserror.ENOTTY
	}
	return f.upper.FileOperations.Ioctl(ctx, f.upper, io, args)
}

// FifoSize implements FifoSizer.FifoSize.
func (f *overlayFileOperations) FifoSize(ctx context.Context, overlayFile *File) (rv int64, err error) {
	err = f.onTop(ctx, overlayFile, func(file *File, ops FileOperations) error {
		sz, ok := ops.(FifoSizer)
		if !ok {
			return linuxerr.EINVAL
		}
		rv, err = sz.FifoSize(ctx, file)
		return err
	})
	return
}

// SetFifoSize implements FifoSizer.SetFifoSize.
func (f *overlayFileOperations) SetFifoSize(size int64) (rv int64, err error) {
	f.upperMu.Lock()
	defer f.upperMu.Unlock()

	if f.upper == nil {
		// Named pipes cannot be copied up and changes to the lower are prohibited.
		return 0, linuxerr.EINVAL
	}
	sz, ok := f.upper.FileOperations.(FifoSizer)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	return sz.SetFifoSize(size)
}

// readdirEntriesLocked returns a sorted map of directory entries from the
// upper and/or lower filesystem.
//
// Preconditions: o.copyMu must be locked.
func readdirEntriesLocked(ctx context.Context, o *overlayEntry) (*SortedDentryMap, error) {
	// Assert that there is at least one upper or lower entry.
	if o.upper == nil && o.lower == nil {
		panic("invalid overlayEntry, needs at least one Inode")
	}
	entries := make(map[string]DentAttr)

	// Try the upper filesystem first.
	if o.upper != nil {
		var err error
		entries, err = readdirOne(ctx, NewTransientDirent(o.upper))
		if err != nil {
			return nil, err
		}
	}

	// Try the lower filesystem next.
	if o.lower != nil {
		lowerEntries, err := readdirOne(ctx, NewTransientDirent(o.lower))
		if err != nil {
			return nil, err
		}
		for name, entry := range lowerEntries {
			// Skip this name if it is a negative entry in the
			// upper or there exists a whiteout for it.
			if o.upper != nil {
				if overlayHasWhiteout(ctx, o.upper, name) {
					continue
				}
			}
			// Prefer the entries from the upper filesystem
			// when names overlap.
			if _, ok := entries[name]; !ok {
				entries[name] = entry
			}
		}
	}

	// Sort and return the entries.
	return NewSortedDentryMap(entries), nil
}

// readdirOne reads all of the directory entries from d.
func readdirOne(ctx context.Context, d *Dirent) (map[string]DentAttr, error) {
	dir, err := d.Inode.GetFile(ctx, d, FileFlags{Read: true})
	if err != nil {
		return nil, err
	}
	defer dir.DecRef(ctx)

	// Use a stub serializer to read the entries into memory.
	stubSerializer := &CollectEntriesSerializer{}
	if err := dir.Readdir(ctx, stubSerializer); err != nil {
		return nil, err
	}
	// The "." and ".." entries are from the overlay Inode's Dirent, not the stub.
	delete(stubSerializer.Entries, ".")
	delete(stubSerializer.Entries, "..")
	return stubSerializer.Entries, nil
}

// overlayMappingIdentity wraps a MappingIdentity, and also holds a reference
// on a file during its lifetime.
//
// +stateify savable
type overlayMappingIdentity struct {
	refs.AtomicRefCount
	id          memmap.MappingIdentity
	overlayFile *File
}

// DecRef implements AtomicRefCount.DecRef.
func (omi *overlayMappingIdentity) DecRef(ctx context.Context) {
	omi.AtomicRefCount.DecRefWithDestructor(ctx, func(context.Context) {
		omi.overlayFile.DecRef(ctx)
		omi.id.DecRef(ctx)
	})
}

// DeviceID implements MappingIdentity.DeviceID using the device id from the
// overlayFile.
func (omi *overlayMappingIdentity) DeviceID() uint64 {
	return omi.overlayFile.Dirent.Inode.StableAttr.DeviceID
}

// DeviceID implements MappingIdentity.InodeID using the inode id from the
// overlayFile.
func (omi *overlayMappingIdentity) InodeID() uint64 {
	return omi.overlayFile.Dirent.Inode.StableAttr.InodeID
}

// MappedName implements MappingIdentity.MappedName.
func (omi *overlayMappingIdentity) MappedName(ctx context.Context) string {
	root := RootFromContext(ctx)
	if root != nil {
		defer root.DecRef(ctx)
	}
	name, _ := omi.overlayFile.Dirent.FullName(root)
	return name
}

// Msync implements MappingIdentity.Msync.
func (omi *overlayMappingIdentity) Msync(ctx context.Context, mr memmap.MappableRange) error {
	return omi.id.Msync(ctx, mr)
}
