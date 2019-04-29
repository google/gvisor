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
	"fmt"
	"io"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// copyUp copies a file in an overlay from a lower filesystem to an
// upper filesytem so that the file can be modified in the upper
// filesystem. Copying a file involves several steps:
//
// - All parent directories of the file are created in the upper
//   filesystem if they don't exist there. For instance:
//
//     upper /dir0
//     lower /dir0/dir1/file
//
//   copyUp of /dir0/dir1/file creates /dir0/dir1 in order to create
//   /dir0/dir1/file.
//
// - The file content is copied from the lower file to the upper
//   file. For symlinks this is the symlink target. For directories,
//   upper directory entries are merged with lower directory entries
//   so there is no need to copy any entries.
//
// - A subset of file attributes of the lower file are set on the
//   upper file. These are the file owner, the file timestamps,
//   and all non-overlay extended attributes. copyUp will fail if
//   the upper filesystem does not support the setting of these
//   attributes.
//
//   The file's permissions are set when the file is created and its
//   size will be brought up to date when its contents are copied.
//   Notably no attempt is made to bring link count up to date because
//   hard links are currently not preserved across overlay filesystems.
//
// - Memory mappings of the lower file are invalidated and memory
//   references are transferred to the upper file. From this point on,
//   memory mappings of the file will be backed by content in the upper
//   filesystem.
//
// Synchronization:
//
// copyUp synchronizes with rename(2) using renameMu to ensure that
// parentage does not change while a file is being copied. In the context
// of rename(2), copyUpLockedForRename should be used to avoid deadlock on
// renameMu.
//
// The following operations synchronize with copyUp using copyMu:
//
// - InodeOperations, i.e. to ensure that looking up a directory takes
//   into account new upper filesystem directories created by copy up,
//   which subsequently can be modified.
//
// - FileOperations, i.e. to ensure that reading from a file does not
//   continue using a stale, lower filesystem handle when the file is
//   written to.
//
// Lock ordering: Dirent.mu -> Inode.overlay.copyMu -> Inode.mu.
//
// Caveats:
//
// If any step in copying up a file fails, copyUp cleans the upper
// filesystem of any partially up-to-date file. If this cleanup fails,
// the overlay may be in an unacceptable, inconsistent state, so copyUp
// panics. If copyUp fails because any step (above) fails, a generic
// error is returned.
//
// copyUp currently makes no attempt to optimize copying up file content.
// For large files, this means that copyUp blocks until the entire file
// is copied synchronously.
func copyUp(ctx context.Context, d *Dirent) error {
	renameMu.RLock()
	defer renameMu.RUnlock()
	return copyUpLockedForRename(ctx, d)
}

// copyUpLockedForRename is the same as copyUp except that it does not lock
// renameMu.
//
// It copies each component of d that does not yet exist in the upper
// filesystem. If d already exists in the upper filesystem, it is a no-op.
//
// Any error returned indicates a failure to copy all of d. This may
// leave the upper filesystem filled with any number of parent directories
// but the upper filesystem will never be in an inconsistent state.
//
// Preconditions:
// - d.Inode.overlay is non-nil.
func copyUpLockedForRename(ctx context.Context, d *Dirent) error {
	for {
		// Did we race with another copy up or does there
		// already exist something in the upper filesystem
		// for d?
		d.Inode.overlay.copyMu.Lock()
		if d.Inode.overlay.upper != nil {
			d.Inode.overlay.copyMu.Unlock()
			// Done, d is in the upper filesystem.
			return nil
		}
		d.Inode.overlay.copyMu.Unlock()

		// Find the next component to copy up. We will work our way
		// down to the last component of d and finally copy it.
		next := findNextCopyUp(ctx, d)

		// Attempt to copy.
		if err := doCopyUp(ctx, next); err != nil {
			return err
		}
	}
}

// findNextCopyUp finds the next component of d from root that does not
// yet exist in the upper filesystem. The parent of this component is
// also returned, which is the root of the overlay in the worst case.
func findNextCopyUp(ctx context.Context, d *Dirent) *Dirent {
	next := d
	for parent := next.parent; ; /* checked in-loop */ /* updated in-loop */ {
		// Does this parent have a non-nil upper Inode?
		parent.Inode.overlay.copyMu.RLock()
		if parent.Inode.overlay.upper != nil {
			parent.Inode.overlay.copyMu.RUnlock()
			// Note that since we found an upper, it is stable.
			return next
		}
		parent.Inode.overlay.copyMu.RUnlock()

		// Continue searching for a parent with a non-nil
		// upper Inode.
		next = parent
		parent = next.parent
	}
}

func doCopyUp(ctx context.Context, d *Dirent) error {
	// Wait to get exclusive access to the upper Inode.
	d.Inode.overlay.copyMu.Lock()
	defer d.Inode.overlay.copyMu.Unlock()
	if d.Inode.overlay.upper != nil {
		// We raced with another doCopyUp, no problem.
		return nil
	}

	// Perform the copy.
	return copyUpLocked(ctx, d.parent, d)
}

// copyUpLocked creates a copy of next in the upper filesystem of parent.
//
// copyUpLocked must be called with d.Inode.overlay.copyMu locked.
//
// Returns a generic error on failure.
//
// Preconditions:
// - parent.Inode.overlay.upper must be non-nil.
// - next.Inode.overlay.copyMu must be locked writable.
// - next.Inode.overlay.lower must be non-nil.
// - upper filesystem must support setting file ownership and timestamps.
func copyUpLocked(ctx context.Context, parent *Dirent, next *Dirent) error {
	// Extract the attributes of the file we wish to copy.
	attrs, err := next.Inode.overlay.lower.UnstableAttr(ctx)
	if err != nil {
		log.Warningf("copy up failed to get lower attributes: %v", err)
		return syserror.EIO
	}

	var childUpperInode *Inode
	parentUpper := parent.Inode.overlay.upper
	root := RootFromContext(ctx)
	if root != nil {
		defer root.DecRef()
	}

	// Create the file in the upper filesystem and get an Inode for it.
	switch next.Inode.StableAttr.Type {
	case RegularFile:
		childFile, err := parentUpper.Create(ctx, root, next.name, FileFlags{Read: true, Write: true}, attrs.Perms)
		if err != nil {
			log.Warningf("copy up failed to create file: %v", err)
			return syserror.EIO
		}
		defer childFile.DecRef()
		childUpperInode = childFile.Dirent.Inode

	case Directory:
		if err := parentUpper.CreateDirectory(ctx, root, next.name, attrs.Perms); err != nil {
			log.Warningf("copy up failed to create directory: %v", err)
			return syserror.EIO
		}
		childUpper, err := parentUpper.Lookup(ctx, next.name)
		if err != nil {
			log.Warningf("copy up failed to lookup directory: %v", err)
			cleanupUpper(ctx, parentUpper, next.name)
			return syserror.EIO
		}
		defer childUpper.DecRef()
		childUpperInode = childUpper.Inode

	case Symlink:
		childLower := next.Inode.overlay.lower
		link, err := childLower.Readlink(ctx)
		if err != nil {
			log.Warningf("copy up failed to read symlink value: %v", err)
			return syserror.EIO
		}
		if err := parentUpper.CreateLink(ctx, root, link, next.name); err != nil {
			log.Warningf("copy up failed to create symlink: %v", err)
			return syserror.EIO
		}
		childUpper, err := parentUpper.Lookup(ctx, next.name)
		if err != nil {
			log.Warningf("copy up failed to lookup symlink: %v", err)
			cleanupUpper(ctx, parentUpper, next.name)
			return syserror.EIO
		}
		defer childUpper.DecRef()
		childUpperInode = childUpper.Inode

	default:
		return syserror.EINVAL
	}

	// Bring file attributes up to date. This does not include size, which will be
	// brought up to date with copyContentsLocked.
	if err := copyAttributesLocked(ctx, childUpperInode, next.Inode.overlay.lower); err != nil {
		log.Warningf("copy up failed to copy up attributes: %v", err)
		cleanupUpper(ctx, parentUpper, next.name)
		return syserror.EIO
	}

	// Copy the entire file.
	if err := copyContentsLocked(ctx, childUpperInode, next.Inode.overlay.lower, attrs.Size); err != nil {
		log.Warningf("copy up failed to copy up contents: %v", err)
		cleanupUpper(ctx, parentUpper, next.name)
		return syserror.EIO
	}

	lowerMappable := next.Inode.overlay.lower.Mappable()
	upperMappable := childUpperInode.Mappable()
	if lowerMappable != nil && upperMappable == nil {
		log.Warningf("copy up failed: cannot ensure memory mapping coherence")
		cleanupUpper(ctx, parentUpper, next.name)
		return syserror.EIO
	}

	// Propagate memory mappings to the upper Inode.
	next.Inode.overlay.mapsMu.Lock()
	defer next.Inode.overlay.mapsMu.Unlock()
	if upperMappable != nil {
		// Remember which mappings we added so we can remove them on failure.
		allAdded := make(map[memmap.MappableRange]memmap.MappingsOfRange)
		for seg := next.Inode.overlay.mappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			added := make(memmap.MappingsOfRange)
			for m := range seg.Value() {
				if err := upperMappable.AddMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable); err != nil {
					for m := range added {
						upperMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable)
					}
					for mr, mappings := range allAdded {
						for m := range mappings {
							upperMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, mr.Start, m.Writable)
						}
					}
					return err
				}
				added[m] = struct{}{}
			}
			allAdded[seg.Range()] = added
		}
	}

	// Take a reference on the upper Inode (transferred to
	// next.Inode.overlay.upper) and make new translations use it.
	next.Inode.overlay.dataMu.Lock()
	childUpperInode.IncRef()
	next.Inode.overlay.upper = childUpperInode
	next.Inode.overlay.dataMu.Unlock()

	// Invalidate existing translations through the lower Inode.
	next.Inode.overlay.mappings.InvalidateAll(memmap.InvalidateOpts{})

	// Remove existing memory mappings from the lower Inode.
	if lowerMappable != nil {
		for seg := next.Inode.overlay.mappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			for m := range seg.Value() {
				lowerMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable)
			}
		}
	}

	return nil
}

// cleanupUpper removes name from parent, and panics if it is unsuccessful.
func cleanupUpper(ctx context.Context, parent *Inode, name string) {
	if err := parent.InodeOperations.Remove(ctx, parent, name); err != nil {
		// Unfortunately we don't have much choice. We shouldn't
		// willingly give the caller access to a nonsense filesystem.
		panic(fmt.Sprintf("overlay filesystem is in an inconsistent state: failed to remove %q from upper filesystem: %v", name, err))
	}
}

// copyUpBuffers is a buffer pool for copying file content. The buffer
// size is the same used by io.Copy.
var copyUpBuffers = sync.Pool{New: func() interface{} { return make([]byte, 8*usermem.PageSize) }}

// copyContentsLocked copies the contents of lower to upper. It panics if
// less than size bytes can be copied.
func copyContentsLocked(ctx context.Context, upper *Inode, lower *Inode, size int64) error {
	// We don't support copying up for anything other than regular files.
	if lower.StableAttr.Type != RegularFile {
		return nil
	}

	// Get a handle to the upper filesystem, which we will write to.
	upperFile, err := overlayFile(ctx, upper, FileFlags{Write: true})
	if err != nil {
		return err
	}
	defer upperFile.DecRef()

	// Get a handle to the lower filesystem, which we will read from.
	lowerFile, err := overlayFile(ctx, lower, FileFlags{Read: true})
	if err != nil {
		return err
	}
	defer lowerFile.DecRef()

	// Use a buffer pool to minimize allocations.
	buf := copyUpBuffers.Get().([]byte)
	defer copyUpBuffers.Put(buf)

	// Transfer the contents.
	//
	// One might be able to optimize this by doing parallel reads, parallel writes and reads, larger
	// buffers, etc. But we really don't know anything about the underlying implementation, so these
	// optimizations could be self-defeating. So we leave this as simple as possible.
	var offset int64
	for {
		nr, err := lowerFile.FileOperations.Read(ctx, lowerFile, usermem.BytesIOSequence(buf), offset)
		if err != nil && err != io.EOF {
			return err
		}
		if nr == 0 {
			if offset != size {
				// Same as in cleanupUpper, we cannot live
				// with ourselves if we do anything less.
				panic(fmt.Sprintf("filesystem is in an inconsistent state: wrote only %d bytes of %d sized file", offset, size))
			}
			return nil
		}
		nw, err := upperFile.FileOperations.Write(ctx, upperFile, usermem.BytesIOSequence(buf[:nr]), offset)
		if err != nil {
			return err
		}
		offset += nw
	}
}

// copyAttributesLocked copies a subset of lower's attributes to upper,
// specifically owner, timestamps (except of status change time), and
// extended attributes. Notably no attempt is made to copy link count.
// Size and permissions are set on upper when the file content is copied
// and when the file is created respectively.
func copyAttributesLocked(ctx context.Context, upper *Inode, lower *Inode) error {
	// Extract attributes fro the lower filesystem.
	lowerAttr, err := lower.UnstableAttr(ctx)
	if err != nil {
		return err
	}
	lowerXattr, err := lower.Listxattr()
	if err != nil && err != syserror.EOPNOTSUPP {
		return err
	}

	// Set the attributes on the upper filesystem.
	if err := upper.InodeOperations.SetOwner(ctx, upper, lowerAttr.Owner); err != nil {
		return err
	}
	if err := upper.InodeOperations.SetTimestamps(ctx, upper, TimeSpec{
		ATime: lowerAttr.AccessTime,
		MTime: lowerAttr.ModificationTime,
	}); err != nil {
		return err
	}
	for name := range lowerXattr {
		// Don't copy-up attributes that configure an overlay in the
		// lower.
		if isXattrOverlay(name) {
			continue
		}
		value, err := lower.Getxattr(name)
		if err != nil {
			return err
		}
		if err := upper.InodeOperations.Setxattr(upper, name, value); err != nil {
			return err
		}
	}
	return nil
}
