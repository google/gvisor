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
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// The virtual filesystem implements an overlay configuration. For a high-level
// description, see README.md.
//
// Note on whiteouts:
//
// This implementation does not use the "Docker-style" whiteouts (symlinks with
// ".wh." prefix). Instead upper filesystem directories support a set of extended
// attributes to encode whiteouts: "trusted.overlay.whiteout.<filename>". This
// gives flexibility to persist whiteouts independently of the filesystem layout
// while additionally preventing name conflicts with files prefixed with ".wh.".
//
// Known deficiencies:
//
// - The device number of two files under the same overlay mount point may be
//   different. This can happen if a file is found in the lower filesystem (takes
//   the lower filesystem device) and another file is created in the upper
//   filesystem (takes the upper filesystem device). This may appear odd but
//   should not break applications.
//
// - Registered events on files (i.e. for notification of read/write readiness)
//   are not copied across copy up. This is fine in the common case of files that
//   do not block. For files that do block, like pipes and sockets, copy up is not
//   supported.
//
// - Hardlinks in a lower filesystem are broken by copy up. For this reason, no
//   attempt is made to preserve link count across copy up.
//
// - The maximum length of an extended attribute name is the same as the maximum
//   length of a file path in Linux (XATTR_NAME_MAX == NAME_MAX). This means that
//   whiteout attributes, if set directly on the host, are limited additionally by
//   the extra whiteout prefix length (file paths must be strictly shorter than
//   NAME_MAX). This is not a problem for in-memory filesystems which don't enforce
//   XATTR_NAME_MAX.

const (
	// XattrOverlayPrefix is the prefix for extended attributes that affect
	// the behavior of an overlay.
	XattrOverlayPrefix = "trusted.overlay."

	// XattrOverlayWhiteoutPrefix is the prefix for extended attributes
	// that indicate that a whiteout exists.
	XattrOverlayWhiteoutPrefix = XattrOverlayPrefix + "whiteout."
)

// XattrOverlayWhiteout returns an extended attribute that indicates a
// whiteout exists for name. It is supported by directories that wish to
// mask the existence of name.
func XattrOverlayWhiteout(name string) string {
	return XattrOverlayWhiteoutPrefix + name
}

// isXattrOverlay returns whether the given extended attribute configures the
// overlay.
func isXattrOverlay(name string) bool {
	return strings.HasPrefix(name, XattrOverlayPrefix)
}

// NewOverlayRoot produces the root of an overlay.
//
// Preconditions:
// * upper and lower must be non-nil.
// * upper must not be an overlay.
// * lower should not expose character devices, pipes, or sockets, because
//   copying up these types of files is not supported.
// * lower must not require that file objects be revalidated.
// * lower must not have dynamic file/directory content.
func NewOverlayRoot(ctx context.Context, upper *Inode, lower *Inode, flags MountSourceFlags) (*Inode, error) {
	if !IsDir(upper.StableAttr) {
		return nil, fmt.Errorf("upper Inode is a %v, not a directory", upper.StableAttr.Type)
	}
	if !IsDir(lower.StableAttr) {
		return nil, fmt.Errorf("lower Inode is a %v, not a directory", lower.StableAttr.Type)
	}
	if upper.overlay != nil {
		return nil, fmt.Errorf("cannot nest overlay in upper file of another overlay")
	}

	msrc := newOverlayMountSource(ctx, upper.MountSource, lower.MountSource, flags)
	overlay, err := newOverlayEntry(ctx, upper, lower, true)
	if err != nil {
		msrc.DecRef(ctx)
		return nil, err
	}

	return newOverlayInode(ctx, overlay, msrc), nil
}

// NewOverlayRootFile produces the root of an overlay that points to a file.
//
// Preconditions:
// * lower must be non-nil.
// * lower should not expose character devices, pipes, or sockets, because
//   copying up these types of files is not supported. Neither it can be a dir.
// * lower must not require that file objects be revalidated.
// * lower must not have dynamic file/directory content.
func NewOverlayRootFile(ctx context.Context, upperMS *MountSource, lower *Inode, flags MountSourceFlags) (*Inode, error) {
	if !IsRegular(lower.StableAttr) {
		return nil, fmt.Errorf("lower Inode is not a regular file")
	}
	msrc := newOverlayMountSource(ctx, upperMS, lower.MountSource, flags)
	overlay, err := newOverlayEntry(ctx, nil, lower, true)
	if err != nil {
		msrc.DecRef(ctx)
		return nil, err
	}
	return newOverlayInode(ctx, overlay, msrc), nil
}

// newOverlayInode creates a new Inode for an overlay.
func newOverlayInode(ctx context.Context, o *overlayEntry, msrc *MountSource) *Inode {
	var inode *Inode
	if o.upper != nil {
		inode = NewInode(ctx, nil, msrc, o.upper.StableAttr)
	} else {
		inode = NewInode(ctx, nil, msrc, o.lower.StableAttr)
	}
	inode.overlay = o
	return inode
}

// overlayEntry is the overlay metadata of an Inode. It implements Mappable.
//
// +stateify savable
type overlayEntry struct {
	// lowerExists is true if an Inode exists for this file in the lower
	// filesystem. If lowerExists is true, then the overlay must create
	// a whiteout entry when renaming and removing this entry to mask the
	// lower Inode.
	//
	// Note that this is distinct from actually holding onto a non-nil
	// lower Inode (below). The overlay does not need to keep a lower Inode
	// around unless it needs to operate on it, but it always needs to know
	// whether the lower Inode exists to correctly execute a rename or
	// remove operation.
	lowerExists bool

	// lower is an Inode from a lower filesystem. Modifications are
	// never made on this Inode.
	lower *Inode

	// copyMu serializes copy-up for operations above
	// mm.MemoryManager.mappingMu in the lock order.
	copyMu sync.RWMutex `state:"nosave"`

	// mapsMu serializes copy-up for operations between
	// mm.MemoryManager.mappingMu and mm.MemoryManager.activeMu in the lock
	// order.
	mapsMu sync.Mutex `state:"nosave"`

	// mappings tracks memory mappings of this Mappable so they can be removed
	// from the lower filesystem Mappable and added to the upper filesystem
	// Mappable when copy up occurs. It is strictly unnecessary after copy-up.
	//
	// mappings is protected by mapsMu.
	mappings memmap.MappingSet

	// dataMu serializes copy-up for operations below mm.MemoryManager.activeMu
	// in the lock order.
	dataMu sync.RWMutex `state:"nosave"`

	// upper is an Inode from an upper filesystem. It is non-nil if
	// the file exists in the upper filesystem. It becomes non-nil
	// when the Inode that owns this overlayEntry is modified.
	//
	// upper is protected by all of copyMu, mapsMu, and dataMu. Holding any of
	// these locks is sufficient to read upper; holding all three for writing
	// is required to mutate it.
	upper *Inode

	// dirCacheMu protects dirCache.
	dirCacheMu sync.RWMutex `state:"nosave"`

	// dirCache is cache of DentAttrs from upper and lower Inodes.
	dirCache *SortedDentryMap
}

// newOverlayEntry returns a new overlayEntry.
func newOverlayEntry(ctx context.Context, upper *Inode, lower *Inode, lowerExists bool) (*overlayEntry, error) {
	if upper == nil && lower == nil {
		panic("invalid overlayEntry, needs at least one Inode")
	}
	if upper != nil && upper.overlay != nil {
		panic("nested writable layers are not supported")
	}
	// Check for supported lower filesystem types.
	if lower != nil {
		switch lower.StableAttr.Type {
		case RegularFile, Directory, Symlink, Socket:
		default:
			// We don't support copying up from character devices,
			// named pipes, or anything weird (like proc files).
			log.Warningf("%s not supported in lower filesytem", lower.StableAttr.Type)
			return nil, syserror.EINVAL
		}
	}
	return &overlayEntry{
		lowerExists: lowerExists,
		lower:       lower,
		upper:       upper,
	}, nil
}

func (o *overlayEntry) release(ctx context.Context) {
	// We drop a reference on upper and lower file system Inodes
	// rather than releasing them, because in-memory filesystems
	// may hold an extra reference to these Inodes so that they
	// stay in memory.
	if o.upper != nil {
		o.upper.DecRef(ctx)
	}
	if o.lower != nil {
		o.lower.DecRef(ctx)
	}
}

// overlayUpperMountSource gives the upper mount of an overlay mount.
//
// The caller may not use this MountSource past the lifetime of overlayMountSource and may
// not call DecRef on it.
func overlayUpperMountSource(overlayMountSource *MountSource) *MountSource {
	return overlayMountSource.MountSourceOperations.(*overlayMountSourceOperations).upper
}

// Preconditions: At least one of o.copyMu, o.mapsMu, or o.dataMu must be locked.
func (o *overlayEntry) inodeLocked() *Inode {
	if o.upper != nil {
		return o.upper
	}
	return o.lower
}

// Preconditions: At least one of o.copyMu, o.mapsMu, or o.dataMu must be locked.
func (o *overlayEntry) isMappableLocked() bool {
	return o.inodeLocked().Mappable() != nil
}

// markDirectoryDirty marks any cached data dirty for this directory. This is
// necessary in order to ensure that this node does not retain stale state
// throughout its lifetime across multiple open directory handles.
//
// Currently this means invalidating any readdir caches.
func (o *overlayEntry) markDirectoryDirty() {
	o.dirCacheMu.Lock()
	o.dirCache = nil
	o.dirCacheMu.Unlock()
}

// AddMapping implements memmap.Mappable.AddMapping.
func (o *overlayEntry) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	o.mapsMu.Lock()
	defer o.mapsMu.Unlock()
	if err := o.inodeLocked().Mappable().AddMapping(ctx, ms, ar, offset, writable); err != nil {
		return err
	}
	o.mappings.AddMapping(ms, ar, offset, writable)
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (o *overlayEntry) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	o.mapsMu.Lock()
	defer o.mapsMu.Unlock()
	o.inodeLocked().Mappable().RemoveMapping(ctx, ms, ar, offset, writable)
	o.mappings.RemoveMapping(ms, ar, offset, writable)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (o *overlayEntry) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	o.mapsMu.Lock()
	defer o.mapsMu.Unlock()
	if err := o.inodeLocked().Mappable().CopyMapping(ctx, ms, srcAR, dstAR, offset, writable); err != nil {
		return err
	}
	o.mappings.AddMapping(ms, dstAR, offset, writable)
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (o *overlayEntry) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	o.dataMu.RLock()
	defer o.dataMu.RUnlock()
	return o.inodeLocked().Mappable().Translate(ctx, required, optional, at)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (o *overlayEntry) InvalidateUnsavable(ctx context.Context) error {
	o.mapsMu.Lock()
	defer o.mapsMu.Unlock()
	return o.inodeLocked().Mappable().InvalidateUnsavable(ctx)
}
