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
	"bytes"
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/context"
)

// DirentOperations provide file systems greater control over how long a Dirent stays pinned
// in core. Implementations must not take Dirent.mu.
type DirentOperations interface {
	// Revalidate is called during lookup each time we encounter a Dirent
	// in the cache. Implementations may update stale properties of the
	// child Inode. If Revalidate returns true, then the entire Inode will
	// be reloaded.
	//
	// Revalidate will never be called on a Inode that is mounted.
	Revalidate(ctx context.Context, name string, parent, child *Inode) bool

	// Keep returns true if the Dirent should be kept in memory for as long
	// as possible beyond any active references.
	Keep(dirent *Dirent) bool
}

// MountSourceOperations contains filesystem specific operations.
type MountSourceOperations interface {
	// DirentOperations provide optional extra management of Dirents.
	DirentOperations

	// Destroy destroys the MountSource.
	Destroy()

	// Below are MountSourceOperations that do not conform to Linux.

	// ResetInodeMappings clears all mappings of Inodes before SaveInodeMapping
	// is called.
	ResetInodeMappings()

	// SaveInodeMappings is called during saving to store, for each reachable
	// Inode in the mounted filesystem, a mapping of Inode.StableAttr.InodeID
	// to the Inode's path relative to its mount point. If an Inode is
	// reachable at more than one path due to hard links, it is unspecified
	// which path is mapped. Filesystems that do not use this information to
	// restore inodes can make SaveInodeMappings a no-op.
	SaveInodeMapping(inode *Inode, path string)
}

// InodeMappings defines a fmt.Stringer MountSource Inode mappings.
type InodeMappings map[uint64]string

// String implements fmt.Stringer.String.
func (i InodeMappings) String() string {
	var mappingsBuf bytes.Buffer
	mappingsBuf.WriteString("\n")
	for ino, name := range i {
		mappingsBuf.WriteString(fmt.Sprintf("\t%q\t\tinode number %d\n", name, ino))
	}
	return mappingsBuf.String()
}

// MountSource represents a source of file objects.
//
// MountSource corresponds to struct super_block in Linux.
//
// A mount source may represent a physical device (or a partition of a physical
// device) or a virtual source of files such as procfs for a specific PID
// namespace. There should be only one mount source per logical device. E.g.
// there should be only procfs mount source for a given PID namespace.
//
// A mount source represents files as inodes. Every inode belongs to exactly
// one mount source. Each file object may only be represented using one inode
// object in a sentry instance.
//
// TODO(b/63601033): Move Flags out of MountSource to Mount.
//
// +stateify savable
type MountSource struct {
	refs.AtomicRefCount

	// MountSourceOperations defines filesystem specific behavior.
	MountSourceOperations

	// FilesystemType is the type of the filesystem backing this mount.
	FilesystemType string

	// Flags are the flags that this filesystem was mounted with.
	Flags MountSourceFlags

	// fscache keeps Dirents pinned beyond application references to them.
	// It must be flushed before kernel.SaveTo.
	fscache *DirentCache

	// direntRefs is the sum of references on all Dirents in this MountSource.
	//
	// direntRefs is increased when a Dirent in MountSource is IncRef'd, and
	// decreased when a Dirent in MountSource is DecRef'd.
	//
	// To cleanly unmount a MountSource, one must check that no direntRefs are
	// held anymore. To check, one must hold root.parent.dirMu of the
	// MountSource's root Dirent before reading direntRefs to prevent further
	// walks to Dirents in this MountSource.
	//
	// direntRefs must be atomically changed.
	direntRefs uint64
}

// DefaultDirentCacheSize is the number of Dirents that the VFS can hold an
// extra reference on.
const DefaultDirentCacheSize uint64 = 1000

// NewMountSource returns a new MountSource. Filesystem may be nil if there is no
// filesystem backing the mount.
func NewMountSource(ctx context.Context, mops MountSourceOperations, filesystem Filesystem, flags MountSourceFlags) *MountSource {
	fsType := "none"
	if filesystem != nil {
		fsType = filesystem.Name()
	}
	return &MountSource{
		MountSourceOperations: mops,
		Flags:                 flags,
		FilesystemType:        fsType,
		fscache:               NewDirentCache(DefaultDirentCacheSize),
	}
}

// DirentRefs returns the current mount direntRefs.
func (msrc *MountSource) DirentRefs() uint64 {
	return atomic.LoadUint64(&msrc.direntRefs)
}

// IncDirentRefs increases direntRefs.
func (msrc *MountSource) IncDirentRefs() {
	atomic.AddUint64(&msrc.direntRefs, 1)
}

// DecDirentRefs decrements direntRefs.
func (msrc *MountSource) DecDirentRefs() {
	if atomic.AddUint64(&msrc.direntRefs, ^uint64(0)) == ^uint64(0) {
		panic("Decremented zero mount reference direntRefs")
	}
}

func (msrc *MountSource) destroy() {
	if c := msrc.DirentRefs(); c != 0 {
		panic(fmt.Sprintf("MountSource with non-zero direntRefs is being destroyed: %d", c))
	}
	msrc.MountSourceOperations.Destroy()
}

// DecRef drops a reference on the MountSource.
func (msrc *MountSource) DecRef() {
	msrc.DecRefWithDestructor(msrc.destroy)
}

// FlushDirentRefs drops all references held by the MountSource on Dirents.
func (msrc *MountSource) FlushDirentRefs() {
	msrc.fscache.Invalidate()
}

// SetDirentCacheMaxSize sets the max size to the dirent cache associated with
// this mount source.
func (msrc *MountSource) SetDirentCacheMaxSize(max uint64) {
	msrc.fscache.setMaxSize(max)
}

// SetDirentCacheLimiter sets the limiter objcet to the dirent cache associated
// with this mount source.
func (msrc *MountSource) SetDirentCacheLimiter(l *DirentCacheLimiter) {
	msrc.fscache.limit = l
}

// NewCachingMountSource returns a generic mount that will cache dirents
// aggressively.
func NewCachingMountSource(ctx context.Context, filesystem Filesystem, flags MountSourceFlags) *MountSource {
	return NewMountSource(ctx, &SimpleMountSourceOperations{
		keep:       true,
		revalidate: false,
	}, filesystem, flags)
}

// NewNonCachingMountSource returns a generic mount that will never cache dirents.
func NewNonCachingMountSource(ctx context.Context, filesystem Filesystem, flags MountSourceFlags) *MountSource {
	return NewMountSource(ctx, &SimpleMountSourceOperations{
		keep:       false,
		revalidate: false,
	}, filesystem, flags)
}

// NewRevalidatingMountSource returns a generic mount that will cache dirents,
// but will revalidate them on each lookup.
func NewRevalidatingMountSource(ctx context.Context, filesystem Filesystem, flags MountSourceFlags) *MountSource {
	return NewMountSource(ctx, &SimpleMountSourceOperations{
		keep:       true,
		revalidate: true,
	}, filesystem, flags)
}

// NewPseudoMountSource returns a "pseudo" mount source that is not backed by
// an actual filesystem. It is always non-caching.
func NewPseudoMountSource(ctx context.Context) *MountSource {
	return NewMountSource(ctx, &SimpleMountSourceOperations{
		keep:       false,
		revalidate: false,
	}, nil, MountSourceFlags{})
}

// SimpleMountSourceOperations implements MountSourceOperations.
//
// +stateify savable
type SimpleMountSourceOperations struct {
	keep       bool
	revalidate bool
}

// Revalidate implements MountSourceOperations.Revalidate.
func (smo *SimpleMountSourceOperations) Revalidate(context.Context, string, *Inode, *Inode) bool {
	return smo.revalidate
}

// Keep implements MountSourceOperations.Keep.
func (smo *SimpleMountSourceOperations) Keep(*Dirent) bool {
	return smo.keep
}

// ResetInodeMappings implements MountSourceOperations.ResetInodeMappings.
func (*SimpleMountSourceOperations) ResetInodeMappings() {}

// SaveInodeMapping implements MountSourceOperations.SaveInodeMapping.
func (*SimpleMountSourceOperations) SaveInodeMapping(*Inode, string) {}

// Destroy implements MountSourceOperations.Destroy.
func (*SimpleMountSourceOperations) Destroy() {}

// Info defines attributes of a filesystem.
type Info struct {
	// Type is the filesystem type magic value.
	Type uint64

	// TotalBlocks is the total data blocks in the filesystem.
	TotalBlocks uint64

	// FreeBlocks is the number of free blocks available.
	FreeBlocks uint64

	// TotalFiles is the total file nodes in the filesystem.
	TotalFiles uint64

	// FreeFiles is the number of free file nodes.
	FreeFiles uint64
}
