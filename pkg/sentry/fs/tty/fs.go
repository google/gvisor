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

package tty

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// ptsDevice is the pseudo-filesystem device.
var ptsDevice = device.NewAnonDevice()

// filesystem is a devpts filesystem.
//
// This devpts is always in the new "multi-instance" mode. i.e., it contains a
// ptmx device tied to this mount.
type filesystem struct{}

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// Name matches drivers/devpts/indoe.c:devpts_fs_type.name.
func (*filesystem) Name() string {
	return "devpts"
}

// AllowUserMount allows users to mount(2) this file system.
func (*filesystem) AllowUserMount() bool {
	// TODO: Users may mount this once the terminals are in a
	// usable state.
	return false
}

// Flags returns that there is nothing special about this file system.
func (*filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// MountSource returns a devpts root that can be positioned in the vfs.
func (f *filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string) (*fs.Inode, error) {
	// device is always ignored.

	// No options are supported.
	if data != "" {
		return nil, syserror.EINVAL
	}

	return newDir(ctx, fs.NewMountSource(&superOperations{}, f, flags)), nil
}

// superOperations implements fs.MountSourceOperations, preventing caching.
type superOperations struct{}

// Revalidate implements fs.DirentOperations.Revalidate.
//
// It always returns true, forcing a Lookup for all entries.
//
// Slave entries are dropped from dir when their master is closed, so an
// existing slave Dirent in the tree is not sufficient to guarantee that it
// still exists on the filesystem.
func (superOperations) Revalidate(*fs.Dirent) bool {
	return true
}

// Keep implements fs.DirentOperations.Keep.
//
// Keep returns false because Revalidate would force a lookup on cached entries
// anyways.
func (superOperations) Keep(*fs.Dirent) bool {
	return false
}

// ResetInodeMappings implements MountSourceOperations.ResetInodeMappings.
func (superOperations) ResetInodeMappings() {}

// SaveInodeMapping implements MountSourceOperations.SaveInodeMapping.
func (superOperations) SaveInodeMapping(*fs.Inode, string) {}

// Destroy implements MountSourceOperations.Destroy.
func (superOperations) Destroy() {}
