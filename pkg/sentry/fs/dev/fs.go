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

package dev

import (
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Optional key containing boolean flag which specifies if Android Binder IPC should be enabled.
const binderEnabledKey = "binder_enabled"

// Optional key containing boolean flag which specifies if Android ashmem should be enabled.
const ashmemEnabledKey = "ashmem_enabled"

// filesystem is a devtmpfs.
//
// +stateify savable
type filesystem struct{}

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// FilesystemName is the name underwhich the filesystem is registered.
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
func (f *filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string) (*fs.Inode, error) {
	// device is always ignored.
	// devtmpfs backed by ramfs ignores bad options. See fs/ramfs/inode.c:ramfs_parse_options.
	//  -> we should consider parsing the mode and backing devtmpfs by this.

	// Parse generic comma-separated key=value options.
	options := fs.GenericMountSourceOptions(data)

	// binerEnabledKey is optional and binder is disabled by default.
	binderEnabled := false
	if beStr, exists := options[binderEnabledKey]; exists {
		var err error
		binderEnabled, err = strconv.ParseBool(beStr)
		if err != nil {
			return nil, syserror.EINVAL
		}
	}

	// ashmemEnabledKey is optional and ashmem is disabled by default.
	ashmemEnabled := false
	if aeStr, exists := options[ashmemEnabledKey]; exists {
		var err error
		ashmemEnabled, err = strconv.ParseBool(aeStr)
		if err != nil {
			return nil, syserror.EINVAL
		}
	}

	// Construct the devtmpfs root.
	return New(ctx, fs.NewNonCachingMountSource(f, flags), binderEnabled, ashmemEnabled), nil
}
