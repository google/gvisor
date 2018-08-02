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

import "gvisor.googlesource.com/gvisor/pkg/sentry/context"

// overlayMountSourceOperations implements MountSourceOperations for an overlay
// mount point.
type overlayMountSourceOperations struct {
	upper *MountSource
	lower *MountSource
}

func newOverlayMountSource(upper, lower *MountSource, flags MountSourceFlags) *MountSource {
	upper.IncRef()
	lower.IncRef()
	return NewMountSource(&overlayMountSourceOperations{
		upper: upper,
		lower: lower,
	}, &overlayFilesystem{}, flags)
}

// Revalidate panics if the upper or lower MountSource require that dirent be
// revalidated. Otherwise always returns false.
func (o *overlayMountSourceOperations) Revalidate(ctx context.Context, dirent *Dirent) bool {
	if o.upper.Revalidate(ctx, dirent) || o.lower.Revalidate(ctx, dirent) {
		panic("an overlay cannot revalidate file objects")
	}
	return false
}

// Keep returns true if either upper or lower MountSource require that the
// dirent be kept in memory.
func (o *overlayMountSourceOperations) Keep(dirent *Dirent) bool {
	return o.upper.Keep(dirent) || o.lower.Keep(dirent)
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
func (o *overlayMountSourceOperations) Destroy() {
	o.upper.DecRef()
	o.lower.DecRef()
}

// type overlayFilesystem is the filesystem for overlay mounts.
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
func (ofs *overlayFilesystem) Mount(ctx context.Context, device string, flags MountSourceFlags, data string) (*Inode, error) {
	panic("overlayFilesystem.Mount should not be called!")
}
