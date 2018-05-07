// Copyright 2018 Google Inc.
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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
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
	dirent.DecRef()

	return f, err
}

// overlayFileOperations implements FileOperations for a file in an overlay.
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

	// dirCursor is a directory cursor for a directory in an overlay.
	dirCursor string

	// dirCache is cache of DentAttrs from upper and lower Inodes.
	dirCache *SortedDentryMap
}

// Release implements FileOperations.Release.
func (f *overlayFileOperations) Release() {
	if f.upper != nil {
		f.upper.DecRef()
	}
	if f.lower != nil {
		f.lower.DecRef()
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
		// FIXME: Lift directory seeking limitations.
		f.dirCursor = ""
	}
	return n, nil
}

// Readdir implements FileOperations.Readdir.
func (f *overlayFileOperations) Readdir(ctx context.Context, file *File, serializer DentrySerializer) (int64, error) {
	o := file.Dirent.Inode.overlay

	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	var err error
	f.dirCache, err = readdirEntries(ctx, o)
	if err != nil {
		return file.Offset(), err
	}

	root := RootFromContext(ctx)
	defer root.DecRef()

	dirCtx := &DirCtx{
		Serializer: serializer,
		DirCursor:  &f.dirCursor,
	}
	return DirentReaddir(ctx, file.Dirent, f, root, dirCtx, file.Offset())
}

// IterateDir implements DirIterator.IterateDir.
func (f *overlayFileOperations) IterateDir(ctx context.Context, dirCtx *DirCtx, offset int) (int, error) {
	n, err := GenericReaddir(dirCtx, f.dirCache)
	return offset + n, err
}

// Read implements FileOperations.Read.
func (f *overlayFileOperations) Read(ctx context.Context, file *File, dst usermem.IOSequence, offset int64) (int64, error) {
	o := file.Dirent.Inode.overlay

	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	if o.upper != nil {
		// We may need to acquire an open file handle to read from if
		// copy up has occurred. Otherwise we risk reading from the
		// wrong source.
		f.upperMu.Lock()
		if f.upper == nil {
			var err error
			f.upper, err = overlayFile(ctx, o.upper, file.Flags())
			if err != nil {
				f.upperMu.Unlock()
				log.Warningf("failed to acquire handle with flags %v: %v", file.Flags(), err)
				return 0, syserror.EIO
			}
		}
		f.upperMu.Unlock()
		return f.upper.FileOperations.Read(ctx, f.upper, dst, offset)
	}
	return f.lower.FileOperations.Read(ctx, f.lower, dst, offset)
}

// Write implements FileOperations.Write.
func (f *overlayFileOperations) Write(ctx context.Context, file *File, src usermem.IOSequence, offset int64) (int64, error) {
	// f.upper must be non-nil. See inode_overlay.go:overlayGetFile, where the
	// file is copied up and opened in the upper filesystem if FileFlags.Write.
	// Write cannot be called if !FileFlags.Write, see FileOperations.Write.
	return f.upper.FileOperations.Write(ctx, f.upper, src, offset)
}

// Fsync implements FileOperations.Fsync.
func (f *overlayFileOperations) Fsync(ctx context.Context, file *File, start, end int64, syncType SyncType) error {
	var err error
	f.upperMu.Lock()
	if f.upper != nil {
		err = f.upper.FileOperations.Fsync(ctx, f.upper, start, end, syncType)
	}
	f.upperMu.Unlock()
	if f.lower != nil {
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
func (f *overlayFileOperations) Flush(ctx context.Context, file *File) error {
	// Flush whatever handles we have.
	var err error
	f.upperMu.Lock()
	if f.upper != nil {
		err = f.upper.FileOperations.Flush(ctx, f.upper)
	}
	f.upperMu.Unlock()
	if f.lower != nil {
		err = f.lower.FileOperations.Flush(ctx, f.lower)
	}
	return err
}

// ConfigureMMap implements FileOperations.ConfigureMMap.
func (*overlayFileOperations) ConfigureMMap(ctx context.Context, file *File, opts *memmap.MMapOpts) error {
	o := file.Dirent.Inode.overlay

	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	if !o.isMappableLocked() {
		return syserror.ENODEV
	}
	// FIXME: This is a copy/paste of fsutil.GenericConfigureMMap,
	// which we can't use because the overlay implementation is in package fs,
	// so depending on fs/fsutil would create a circular dependency. Move
	// overlay to fs/overlay.
	opts.Mappable = o
	opts.MappingIdentity = file
	file.IncRef()
	return nil
}

// Ioctl implements fs.FileOperations.Ioctl and always returns ENOTTY.
func (*overlayFileOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
}

// readdirEntries returns a sorted map of directory entries from the
// upper and/or lower filesystem.
func readdirEntries(ctx context.Context, o *overlayEntry) (*SortedDentryMap, error) {
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
				if overlayHasWhiteout(o.upper, name) {
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
	defer dir.DecRef()

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
