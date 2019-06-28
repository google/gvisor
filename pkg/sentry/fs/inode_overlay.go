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
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserror"
)

func overlayHasWhiteout(parent *Inode, name string) bool {
	s, err := parent.Getxattr(XattrOverlayWhiteout(name))
	return err == nil && s == "y"
}

func overlayCreateWhiteout(parent *Inode, name string) error {
	return parent.InodeOperations.Setxattr(parent, XattrOverlayWhiteout(name), "y")
}

func overlayWriteOut(ctx context.Context, o *overlayEntry) error {
	// Hot path. Avoid defers.
	var err error
	o.copyMu.RLock()
	if o.upper != nil {
		err = o.upper.InodeOperations.WriteOut(ctx, o.upper)
	}
	o.copyMu.RUnlock()
	return err
}

// overlayLookup performs a lookup in parent.
//
// If name exists, it returns true if the Dirent is in the upper, false if the
// Dirent is in the lower.
func overlayLookup(ctx context.Context, parent *overlayEntry, inode *Inode, name string) (*Dirent, bool, error) {
	// Hot path. Avoid defers.
	parent.copyMu.RLock()

	// Assert that there is at least one upper or lower entry.
	if parent.upper == nil && parent.lower == nil {
		parent.copyMu.RUnlock()
		panic("invalid overlayEntry, needs at least one Inode")
	}

	var upperInode *Inode
	var lowerInode *Inode

	// We must remember whether the upper fs returned a negative dirent,
	// because it is only safe to return one if the upper did.
	var negativeUpperChild bool

	// Does the parent directory exist in the upper file system?
	if parent.upper != nil {
		// First check if a file object exists in the upper file system.
		// A file could have been created over a whiteout, so we need to
		// check if something exists in the upper file system first.
		child, err := parent.upper.Lookup(ctx, name)
		if err != nil && err != syserror.ENOENT {
			// We encountered an error that an overlay cannot handle,
			// we must propagate it to the caller.
			parent.copyMu.RUnlock()
			return nil, false, err
		}
		if child != nil {
			if child.IsNegative() {
				negativeUpperChild = true
			} else {
				upperInode = child.Inode
				upperInode.IncRef()
			}
			child.DecRef()
		}

		// Are we done?
		if overlayHasWhiteout(parent.upper, name) {
			if upperInode == nil {
				parent.copyMu.RUnlock()
				if negativeUpperChild {
					// If the upper fs returnd a negative
					// Dirent, then the upper is OK with
					// that negative Dirent being cached in
					// the Dirent tree, so we can return
					// one from the overlay.
					return NewNegativeDirent(name), false, nil
				}
				// Upper fs is not OK with a negative Dirent
				// being cached in the Dirent tree, so don't
				// return one.
				return nil, false, syserror.ENOENT
			}
			entry, err := newOverlayEntry(ctx, upperInode, nil, false)
			if err != nil {
				// Don't leak resources.
				upperInode.DecRef()
				parent.copyMu.RUnlock()
				return nil, false, err
			}
			d, err := NewDirent(ctx, newOverlayInode(ctx, entry, inode.MountSource), name), nil
			parent.copyMu.RUnlock()
			return d, true, err
		}
	}

	// Check the lower file system. We do this unconditionally (even for
	// non-directories) because we may need to use stable attributes from
	// the lower filesystem (e.g. device number, inode number) that were
	// visible before a copy up.
	if parent.lower != nil {
		// Check the lower file system.
		child, err := parent.lower.Lookup(ctx, name)
		// Same song and dance as above.
		if err != nil && err != syserror.ENOENT {
			// Don't leak resources.
			if upperInode != nil {
				upperInode.DecRef()
			}
			parent.copyMu.RUnlock()
			return nil, false, err
		}
		if child != nil {
			if !child.IsNegative() {
				if upperInode == nil {
					// If nothing was in the upper, use what we found in the lower.
					lowerInode = child.Inode
					lowerInode.IncRef()
				} else {
					// If we have something from the upper, we can only use it if the types
					// match.
					// NOTE(b/112312863): Allow SpecialDirectories and Directories to merge.
					// This is needed to allow submounts in /proc and /sys.
					if upperInode.StableAttr.Type == child.Inode.StableAttr.Type ||
						(IsDir(upperInode.StableAttr) && IsDir(child.Inode.StableAttr)) {
						lowerInode = child.Inode
						lowerInode.IncRef()
					}
				}
			}
			child.DecRef()
		}
	}

	// Was all of this for naught?
	if upperInode == nil && lowerInode == nil {
		parent.copyMu.RUnlock()
		// We can only return a negative dirent if the upper returned
		// one as well. See comments above regarding negativeUpperChild
		// for more info.
		if negativeUpperChild {
			return NewNegativeDirent(name), false, nil
		}
		return nil, false, syserror.ENOENT
	}

	// Did we find a lower Inode? Remember this because we may decide we don't
	// actually need the lower Inode (see below).
	lowerExists := lowerInode != nil

	// If we found something in the upper filesystem and the lower filesystem,
	// use the stable attributes from the lower filesystem. If we don't do this,
	// then it may appear that the file was magically recreated across copy up.
	if upperInode != nil && lowerInode != nil {
		// Steal attributes.
		upperInode.StableAttr = lowerInode.StableAttr

		// For non-directories, the lower filesystem resource is strictly
		// unnecessary because we don't need to copy-up and we will always
		// operate (e.g. read/write) on the upper Inode.
		if !IsDir(upperInode.StableAttr) {
			lowerInode.DecRef()
			lowerInode = nil
		}
	}

	// Phew, finally done.
	entry, err := newOverlayEntry(ctx, upperInode, lowerInode, lowerExists)
	if err != nil {
		// Well, not quite, we failed at the last moment, how depressing.
		// Be sure not to leak resources.
		if upperInode != nil {
			upperInode.DecRef()
		}
		if lowerInode != nil {
			lowerInode.DecRef()
		}
		parent.copyMu.RUnlock()
		return nil, false, err
	}
	d, err := NewDirent(ctx, newOverlayInode(ctx, entry, inode.MountSource), name), nil
	parent.copyMu.RUnlock()
	return d, upperInode != nil, err
}

func overlayCreate(ctx context.Context, o *overlayEntry, parent *Dirent, name string, flags FileFlags, perm FilePermissions) (*File, error) {
	// Dirent.Create takes renameMu if the Inode is an overlay Inode.
	if err := copyUpLockedForRename(ctx, parent); err != nil {
		return nil, err
	}

	upperFile, err := o.upper.InodeOperations.Create(ctx, o.upper, name, flags, perm)
	if err != nil {
		return nil, err
	}

	// We've added to the directory so we must drop the cache.
	o.markDirectoryDirty()

	// Take another reference on the upper file's inode, which will be
	// owned by the overlay entry.
	upperFile.Dirent.Inode.IncRef()
	entry, err := newOverlayEntry(ctx, upperFile.Dirent.Inode, nil, false)
	if err != nil {
		cleanupUpper(ctx, o.upper, name)
		return nil, err
	}

	// NOTE(b/71766861): Replace the Dirent with a transient Dirent, since
	// we are about to create the real Dirent: an overlay Dirent.
	//
	// This ensures the *fs.File returned from overlayCreate is in the same
	// state as the *fs.File returned by overlayGetFile, where the upper
	// file has a transient Dirent.
	//
	// This is necessary for Save/Restore, as otherwise the upper Dirent
	// (which has no path as it is unparented and never reachable by the
	// user) will clobber the real path for the underlying Inode.
	upperFile.Dirent.Inode.IncRef()
	upperDirent := NewTransientDirent(upperFile.Dirent.Inode)
	upperFile.Dirent.DecRef()
	upperFile.Dirent = upperDirent

	// Create the overlay inode and dirent.  We need this to construct the
	// overlay file.
	overlayInode := newOverlayInode(ctx, entry, parent.Inode.MountSource)
	// d will own the inode reference.
	overlayDirent := NewDirent(ctx, overlayInode, name)
	// The overlay file created below with NewFile will take a reference on
	// the overlayDirent, and it should be the only thing holding a
	// reference at the time of creation, so we must drop this reference.
	defer overlayDirent.DecRef()

	// Create a new overlay file that wraps the upper file.
	flags.Pread = upperFile.Flags().Pread
	flags.Pwrite = upperFile.Flags().Pwrite
	overlayFile := NewFile(ctx, overlayDirent, flags, &overlayFileOperations{upper: upperFile})

	return overlayFile, nil
}

func overlayCreateDirectory(ctx context.Context, o *overlayEntry, parent *Dirent, name string, perm FilePermissions) error {
	// Dirent.CreateDirectory takes renameMu if the Inode is an overlay
	// Inode.
	if err := copyUpLockedForRename(ctx, parent); err != nil {
		return err
	}
	if err := o.upper.InodeOperations.CreateDirectory(ctx, o.upper, name, perm); err != nil {
		return err
	}
	// We've added to the directory so we must drop the cache.
	o.markDirectoryDirty()
	return nil
}

func overlayCreateLink(ctx context.Context, o *overlayEntry, parent *Dirent, oldname string, newname string) error {
	// Dirent.CreateLink takes renameMu if the Inode is an overlay Inode.
	if err := copyUpLockedForRename(ctx, parent); err != nil {
		return err
	}
	if err := o.upper.InodeOperations.CreateLink(ctx, o.upper, oldname, newname); err != nil {
		return err
	}
	// We've added to the directory so we must drop the cache.
	o.markDirectoryDirty()
	return nil
}

func overlayCreateHardLink(ctx context.Context, o *overlayEntry, parent *Dirent, target *Dirent, name string) error {
	// Dirent.CreateHardLink takes renameMu if the Inode is an overlay
	// Inode.
	if err := copyUpLockedForRename(ctx, parent); err != nil {
		return err
	}
	if err := copyUpLockedForRename(ctx, target); err != nil {
		return err
	}
	if err := o.upper.InodeOperations.CreateHardLink(ctx, o.upper, target.Inode.overlay.upper, name); err != nil {
		return err
	}
	// We've added to the directory so we must drop the cache.
	o.markDirectoryDirty()
	return nil
}

func overlayCreateFifo(ctx context.Context, o *overlayEntry, parent *Dirent, name string, perm FilePermissions) error {
	// Dirent.CreateFifo takes renameMu if the Inode is an overlay Inode.
	if err := copyUpLockedForRename(ctx, parent); err != nil {
		return err
	}
	if err := o.upper.InodeOperations.CreateFifo(ctx, o.upper, name, perm); err != nil {
		return err
	}
	// We've added to the directory so we must drop the cache.
	o.markDirectoryDirty()
	return nil
}

func overlayRemove(ctx context.Context, o *overlayEntry, parent *Dirent, child *Dirent) error {
	// Dirent.Remove and Dirent.RemoveDirectory take renameMu if the Inode
	// is an overlay Inode.
	if err := copyUpLockedForRename(ctx, parent); err != nil {
		return err
	}
	child.Inode.overlay.copyMu.RLock()
	defer child.Inode.overlay.copyMu.RUnlock()
	if child.Inode.overlay.upper != nil {
		if child.Inode.StableAttr.Type == Directory {
			if err := o.upper.InodeOperations.RemoveDirectory(ctx, o.upper, child.name); err != nil {
				return err
			}
		} else {
			if err := o.upper.InodeOperations.Remove(ctx, o.upper, child.name); err != nil {
				return err
			}
		}
	}
	if child.Inode.overlay.lowerExists {
		return overlayCreateWhiteout(o.upper, child.name)
	}
	// We've removed from the directory so we must drop the cache.
	o.markDirectoryDirty()
	return nil
}

func overlayRename(ctx context.Context, o *overlayEntry, oldParent *Dirent, renamed *Dirent, newParent *Dirent, newName string, replacement bool) error {
	// To be able to copy these up below, they have to be part of an
	// overlay file system.
	//
	// Maybe some day we can allow the more complicated case of
	// non-overlay X overlay renames, but that's not necessary right now.
	if renamed.Inode.overlay == nil || newParent.Inode.overlay == nil || oldParent.Inode.overlay == nil {
		return syserror.EXDEV
	}

	if replacement {
		// Check here if the file to be replaced exists and is a
		// non-empty directory. If we copy up first, we may end up
		// copying the directory but none of its children, so the
		// directory will appear empty in the upper fs, which will then
		// allow the rename to proceed when it should return ENOTEMPTY.
		//
		// NOTE(b/111808347): Ideally, we'd just pass in the replaced
		// Dirent from Rename, but we must drop the reference on
		// replaced before we make the rename call, so Rename can't
		// pass the Dirent to the Inode without significantly
		// complicating the API. Thus we look it up again here.
		//
		// For the same reason we can't use defer here.
		replaced, inUpper, err := overlayLookup(ctx, newParent.Inode.overlay, newParent.Inode, newName)
		// If err == ENOENT or a negative Dirent is returned, then
		// newName has been removed out from under us. That's fine;
		// filesystems where that can happen must handle stale
		// 'replaced'.
		if err != nil && err != syserror.ENOENT {
			return err
		}
		if err == nil {
			if !inUpper {
				// newName doesn't exist in
				// newParent.Inode.overlay.upper, thus from
				// that Inode's perspective this won't be a
				// replacing rename.
				replacement = false
			}

			if !replaced.IsNegative() && IsDir(replaced.Inode.StableAttr) {
				children, err := readdirOne(ctx, replaced)
				if err != nil {
					replaced.DecRef()
					return err
				}

				// readdirOne ensures that "." and ".." are not
				// included among the returned children, so we don't
				// need to bother checking for them.
				if len(children) > 0 {
					replaced.DecRef()
					return syserror.ENOTEMPTY
				}
			}

			replaced.DecRef()
		}
	}

	if err := copyUpLockedForRename(ctx, renamed); err != nil {
		return err
	}
	if err := copyUpLockedForRename(ctx, newParent); err != nil {
		return err
	}
	oldName := renamed.name
	if err := o.upper.InodeOperations.Rename(ctx, renamed.Inode.overlay.upper, oldParent.Inode.overlay.upper, oldName, newParent.Inode.overlay.upper, newName, replacement); err != nil {
		return err
	}
	if renamed.Inode.overlay.lowerExists {
		return overlayCreateWhiteout(oldParent.Inode.overlay.upper, oldName)
	}
	// We've changed the directory so we must drop the cache.
	o.markDirectoryDirty()
	return nil
}

func overlayBind(ctx context.Context, o *overlayEntry, parent *Dirent, name string, data transport.BoundEndpoint, perm FilePermissions) (*Dirent, error) {
	if err := copyUp(ctx, parent); err != nil {
		return nil, err
	}

	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	d, err := o.upper.InodeOperations.Bind(ctx, o.upper, name, data, perm)
	if err != nil {
		return nil, err
	}

	// We've added to the directory so we must drop the cache.
	o.markDirectoryDirty()

	// Grab the inode and drop the dirent, we don't need it.
	inode := d.Inode
	inode.IncRef()
	d.DecRef()

	// Create a new overlay entry and dirent for the socket.
	entry, err := newOverlayEntry(ctx, inode, nil, false)
	if err != nil {
		inode.DecRef()
		return nil, err
	}
	return NewDirent(ctx, newOverlayInode(ctx, entry, inode.MountSource), name), nil
}

func overlayBoundEndpoint(o *overlayEntry, path string) transport.BoundEndpoint {
	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	if o.upper != nil {
		return o.upper.InodeOperations.BoundEndpoint(o.upper, path)
	}

	return o.lower.BoundEndpoint(path)
}

func overlayGetFile(ctx context.Context, o *overlayEntry, d *Dirent, flags FileFlags) (*File, error) {
	// Hot path. Avoid defers.
	if flags.Write {
		if err := copyUp(ctx, d); err != nil {
			return nil, err
		}
	}

	o.copyMu.RLock()

	if o.upper != nil {
		upper, err := overlayFile(ctx, o.upper, flags)
		if err != nil {
			o.copyMu.RUnlock()
			return nil, err
		}
		flags.Pread = upper.Flags().Pread
		flags.Pwrite = upper.Flags().Pwrite
		f, err := NewFile(ctx, d, flags, &overlayFileOperations{upper: upper}), nil
		o.copyMu.RUnlock()
		return f, err
	}

	lower, err := overlayFile(ctx, o.lower, flags)
	if err != nil {
		o.copyMu.RUnlock()
		return nil, err
	}
	flags.Pread = lower.Flags().Pread
	flags.Pwrite = lower.Flags().Pwrite
	o.copyMu.RUnlock()
	return NewFile(ctx, d, flags, &overlayFileOperations{lower: lower}), nil
}

func overlayUnstableAttr(ctx context.Context, o *overlayEntry) (UnstableAttr, error) {
	// Hot path. Avoid defers.
	var (
		attr UnstableAttr
		err  error
	)
	o.copyMu.RLock()
	if o.upper != nil {
		attr, err = o.upper.UnstableAttr(ctx)
	} else {
		attr, err = o.lower.UnstableAttr(ctx)
	}
	o.copyMu.RUnlock()
	return attr, err
}

func overlayGetxattr(o *overlayEntry, name string) (string, error) {
	// Hot path. This is how the overlay checks for whiteout files.
	// Avoid defers.
	var (
		s   string
		err error
	)

	// Don't forward the value of the extended attribute if it would
	// unexpectedly change the behavior of a wrapping overlay layer.
	if strings.HasPrefix(XattrOverlayPrefix, name) {
		return "", syserror.ENODATA
	}

	o.copyMu.RLock()
	if o.upper != nil {
		s, err = o.upper.Getxattr(name)
	} else {
		s, err = o.lower.Getxattr(name)
	}
	o.copyMu.RUnlock()
	return s, err
}

func overlayListxattr(o *overlayEntry) (map[string]struct{}, error) {
	o.copyMu.RLock()
	defer o.copyMu.RUnlock()
	var names map[string]struct{}
	var err error
	if o.upper != nil {
		names, err = o.upper.Listxattr()
	} else {
		names, err = o.lower.Listxattr()
	}
	for name := range names {
		// Same as overlayGetxattr, we shouldn't forward along
		// overlay attributes.
		if strings.HasPrefix(XattrOverlayPrefix, name) {
			delete(names, name)
		}
	}
	return names, err
}

func overlayCheck(ctx context.Context, o *overlayEntry, p PermMask) error {
	o.copyMu.RLock()
	// Hot path. Avoid defers.
	var err error
	if o.upper != nil {
		err = o.upper.check(ctx, p)
	} else {
		if p.Write {
			// Since writes will be redirected to the upper filesystem, the lower
			// filesystem need not be writable, but must be readable for copy-up.
			p.Write = false
			p.Read = true
		}
		err = o.lower.check(ctx, p)
	}
	o.copyMu.RUnlock()
	return err
}

func overlaySetPermissions(ctx context.Context, o *overlayEntry, d *Dirent, f FilePermissions) bool {
	if err := copyUp(ctx, d); err != nil {
		return false
	}
	return o.upper.InodeOperations.SetPermissions(ctx, o.upper, f)
}

func overlaySetOwner(ctx context.Context, o *overlayEntry, d *Dirent, owner FileOwner) error {
	if err := copyUp(ctx, d); err != nil {
		return err
	}
	return o.upper.InodeOperations.SetOwner(ctx, o.upper, owner)
}

func overlaySetTimestamps(ctx context.Context, o *overlayEntry, d *Dirent, ts TimeSpec) error {
	if err := copyUp(ctx, d); err != nil {
		return err
	}
	return o.upper.InodeOperations.SetTimestamps(ctx, o.upper, ts)
}

func overlayTruncate(ctx context.Context, o *overlayEntry, d *Dirent, size int64) error {
	if err := copyUp(ctx, d); err != nil {
		return err
	}
	return o.upper.InodeOperations.Truncate(ctx, o.upper, size)
}

func overlayAllocate(ctx context.Context, o *overlayEntry, d *Dirent, offset, length int64) error {
	if err := copyUp(ctx, d); err != nil {
		return err
	}
	return o.upper.InodeOperations.Allocate(ctx, o.upper, offset, length)
}

func overlayReadlink(ctx context.Context, o *overlayEntry) (string, error) {
	o.copyMu.RLock()
	defer o.copyMu.RUnlock()
	if o.upper != nil {
		return o.upper.Readlink(ctx)
	}
	return o.lower.Readlink(ctx)
}

func overlayGetlink(ctx context.Context, o *overlayEntry) (*Dirent, error) {
	var dirent *Dirent
	var err error

	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	if o.upper != nil {
		dirent, err = o.upper.Getlink(ctx)
	} else {
		dirent, err = o.lower.Getlink(ctx)
	}
	if dirent != nil {
		// This dirent is likely bogus (its Inode likely doesn't contain
		// the right overlayEntry). So we're forced to drop it on the
		// ground and claim that jumping around the filesystem like this
		// is not supported.
		name, _ := dirent.FullName(nil)
		dirent.DecRef()

		// Claim that the path is not accessible.
		err = syserror.EACCES
		log.Warningf("Getlink not supported in overlay for %q", name)
	}
	return nil, err
}

func overlayStatFS(ctx context.Context, o *overlayEntry) (Info, error) {
	o.copyMu.RLock()
	defer o.copyMu.RUnlock()

	var i Info
	var err error
	if o.upper != nil {
		i, err = o.upper.StatFS(ctx)
	} else {
		i, err = o.lower.StatFS(ctx)
	}
	if err != nil {
		return Info{}, err
	}

	i.Type = linux.OVERLAYFS_SUPER_MAGIC

	return i, nil
}

// NewTestOverlayDir returns an overlay Inode for tests.
//
// If `revalidate` is true, then the upper filesystem will require
// revalidation.
func NewTestOverlayDir(ctx context.Context, upper, lower *Inode, revalidate bool) *Inode {
	fs := &overlayFilesystem{}
	var upperMsrc *MountSource
	if revalidate {
		upperMsrc = NewRevalidatingMountSource(ctx, fs, MountSourceFlags{})
	} else {
		upperMsrc = NewNonCachingMountSource(ctx, fs, MountSourceFlags{})
	}
	msrc := NewMountSource(ctx, &overlayMountSourceOperations{
		upper: upperMsrc,
		lower: NewNonCachingMountSource(ctx, fs, MountSourceFlags{}),
	}, fs, MountSourceFlags{})
	overlay := &overlayEntry{
		upper: upper,
		lower: lower,
	}
	return newOverlayInode(ctx, overlay, msrc)
}

// TestHasUpperFS returns true if i is an overlay Inode and it has a pointer
// to an Inode on an upper filesystem.
func (i *Inode) TestHasUpperFS() bool {
	return i.overlay != nil && i.overlay.upper != nil
}

// TestHasLowerFS returns true if i is an overlay Inode and it has a pointer
// to an Inode on a lower filesystem.
func (i *Inode) TestHasLowerFS() bool {
	return i.overlay != nil && i.overlay.lower != nil
}
