// Copyright 2020 The gVisor Authors.
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

// Package host supports file descriptors imported directly.
package host

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// filesystem is a host filesystem.
//
// +stateify savable
type filesystem struct{}

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// FilesystemName is the name under which the filesystem is registered.
const FilesystemName = "host"

// Name is the name of the filesystem.
func (*filesystem) Name() string {
	return FilesystemName
}

// Mount returns an error. Mounting hostfs is not allowed.
func (*filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string, dataObj interface{}) (*fs.Inode, error) {
	return nil, linuxerr.EPERM
}

// AllowUserMount prohibits users from using mount(2) with this file system.
func (*filesystem) AllowUserMount() bool {
	return false
}

// AllowUserList prohibits this filesystem to be listed in /proc/filesystems.
func (*filesystem) AllowUserList() bool {
	return false
}

// Flags returns that there is nothing special about this file system.
func (*filesystem) Flags() fs.FilesystemFlags {
	return 0
}
