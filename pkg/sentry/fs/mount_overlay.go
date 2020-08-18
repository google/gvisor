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
	"gvisor.dev/gvisor/pkg/context"
)

// overlayMountSourceOperations implements MountSourceOperations for an overlay
// mount point. The upper filesystem determines the caching behavior of the
// overlay.
//
// +stateify savable
type overlayMountSourceOperations struct {
	upper *MountSource
	lower *MountSource
}

func newOverlayMountSource(ctx context.Context, upper, lower *MountSource, flags MountSourceFlags) *MountSource {
	upper.IncRef()
	lower.IncRef()
	msrc := NewMountSource(ctx, &overlayMountSourceOperations{
		upper: upper,
		lower: lower,
	}, &overlayFilesystem{}, flags)

	// Use the minimum number to keep resource usage under limits.
	size := lower.fscache.maxSize
	if size > upper.fscache.maxSize {
		size = upper.fscache.maxSize
	}
	msrc.fscache.setMaxSize(size)

	return msrc
}

// Revalidate implements MountSourceOperations.Revalidate for an overlay by
// delegating to the upper filesystem's Revalidate method. We cannot reload
// files from the lower filesystem, so we panic if the lower filesystem's
// Revalidate method returns true.
func (o *overlayMountSourceOperations) Revalidate(ctx context.Context, name string, parent, child *Inode) bool {
	if child.overlay == nil {
		panic("overlay cannot revalidate inode that is not an overlay")
	}

	// Revalidate is never called on a mount point, so parent and child
	// must be from the same mount, and thus must both be overlay inodes.
	if parent.overlay == nil {
		panic("trying to revalidate an overlay inode but the parent is not an overlay")
	}

	// We can't revalidate from the lower filesystem.
	if child.overlay.lower != nil && o.lower.Revalidate(ctx, name, parent.overlay.lower, child.overlay.lower) {
		panic("an overlay cannot revalidate file objects from the lower fs")
	}

	var revalidate bool
	child.overlay.copyMu.RLock()
	if child.overlay.upper != nil {
		// Does the upper require revalidation?
		revalidate = o.upper.Revalidate(ctx, name, parent.overlay.upper, child.overlay.upper)
	} else {
		// Nothing to revalidate.
		revalidate = false
	}
	child.overlay.copyMu.RUnlock()
	return revalidate
}

// Keep implements MountSourceOperations by delegating to the upper
// filesystem's Keep method.
func (o *overlayMountSourceOperations) Keep(dirent *Dirent) bool {
	return o.upper.Keep(dirent)
}

// CacheReaddir implements MountSourceOperations.CacheReaddir for an overlay by
// performing the logical AND of the upper and lower filesystems' CacheReaddir
// methods.
//
// N.B. This is fs-global instead of inode-specific because it must always
// return the same value. If it was inode-specific, we couldn't guarantee that
// property across copy up.
func (o *overlayMountSourceOperations) CacheReaddir() bool {
	return o.lower.CacheReaddir() && o.upper.CacheReaddir()
}

// ResetInodeMappings propagates the call to both upper and lower MountSource.
func (o *overlayMountSourceOperations) ResetInodeMappings() {
	o.upper.ResetInodeMappings()
	o.lower.ResetInodeMappings()
}

// SaveInodeMapping propagates the call to both upper and lower MountSource.
func (o *overlayMountSourceOperations) SaveInodeMapping(inode *Inode, path string) {
	inode.overlay.copyMu.RLock()
	defer inode.overlay.copyMu.RUnlock()
	if inode.overlay.upper != nil {
		o.upper.SaveInodeMapping(inode.overlay.upper, path)
	}
	if inode.overlay.lower != nil {
		o.lower.SaveInodeMapping(inode.overlay.lower, path)
	}
}

// Destroy drops references on the upper and lower MountSource.
func (o *overlayMountSourceOperations) Destroy(ctx context.Context) {
	o.upper.DecRef(ctx)
	o.lower.DecRef(ctx)
}

// type overlayFilesystem is the filesystem for overlay mounts.
//
// +stateify savable
type overlayFilesystem struct{}

// Name implements Filesystem.Name.
func (ofs *overlayFilesystem) Name() string {
	return "overlayfs"
}

// Flags implements Filesystem.Flags.
func (ofs *overlayFilesystem) Flags() FilesystemFlags {
	return 0
}

// AllowUserMount implements Filesystem.AllowUserMount.
func (ofs *overlayFilesystem) AllowUserMount() bool {
	return false
}

// AllowUserList implements Filesystem.AllowUserList.
func (*overlayFilesystem) AllowUserList() bool {
	return true
}

// Mount implements Filesystem.Mount.
func (ofs *overlayFilesystem) Mount(ctx context.Context, device string, flags MountSourceFlags, data string, _ interface{}) (*Inode, error) {
	panic("overlayFilesystem.Mount should not be called!")
}
