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

package dev

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// filesystem is a devtmpfs.
//
// +stateify savable
type filesystem struct{}

var _ fs.Filesystem = (*filesystem)(nil)

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// FilesystemName is the name under which the filesystem is registered.
// Name matches drivers/base/devtmpfs.c:dev_fs_type.name.
const FilesystemName = "devtmpfs"

// Name is the name of the file system.
func (*filesystem) Name() string {
	return FilesystemName
}

// AllowUserMount allows users to mount(2) this file system.
func (*filesystem) AllowUserMount() bool {
	return true
}

// AllowUserList allows this filesystem to be listed in /proc/filesystems.
func (*filesystem) AllowUserList() bool {
	return true
}

// Flags returns that there is nothing special about this file system.
//
// In Linux, devtmpfs does the same thing.
func (*filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// Mount returns a devtmpfs root that can be positioned in the vfs.
func (f *filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string, _ interface{}) (*fs.Inode, error) {
	// devtmpfs backed by ramfs ignores bad options. See fs/ramfs/inode.c:ramfs_parse_options.
	//  -> we should consider parsing the mode and backing devtmpfs by this.
	return New(ctx, fs.NewNonCachingMountSource(ctx, f, flags)), nil
}
