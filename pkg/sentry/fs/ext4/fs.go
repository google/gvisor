// Copyright 2019 The gVisor Authors.
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

// Package ext4 implements the ext4 filesystem.
package ext4

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// filesystem implements fs.Filesystem for ext4.
//
// +stateify savable
type filesystem struct{}

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// FilesystemName is the name under which the filesystem is registered.
// Name matches fs/ext4/super.c:ext4_fs_type.name.
const FilesystemName = "ext4"

// Name is the name of the file system.
func (*filesystem) Name() string {
	return FilesystemName
}

// AllowUserMount prohibits users from using mount(2) with this file system.
func (*filesystem) AllowUserMount() bool {
	return false
}

// AllowUserList prohibits this filesystem to be listed in /proc/filesystems.
func (*filesystem) AllowUserList() bool {
	return false
}

// Flags returns properties of the filesystem.
//
// In Linux, ext4 returns FS_REQUIRES_DEV. See fs/ext4/super.c
func (*filesystem) Flags() fs.FilesystemFlags {
	return fs.FilesystemRequiresDev
}

// Mount returns the root inode of the ext4 fs.
func (f *filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string, cgroupsInt interface{}) (*fs.Inode, error) {
	panic("unimplemented")
}
