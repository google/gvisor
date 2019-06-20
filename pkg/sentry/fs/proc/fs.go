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

package proc

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// filesystem is a procfs.
//
// +stateify savable
type filesystem struct{}

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// FilesystemName is the name under which the filesystem is registered.
// Name matches fs/proc/root.c:proc_fs_type.name.
const FilesystemName = "proc"

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
// In Linux, proc returns FS_USERNS_VISIBLE | FS_USERNS_MOUNT, see fs/proc/root.c.
func (*filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// Mount returns the root of a procfs that can be positioned in the vfs.
func (f *filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string, cgroupsInt interface{}) (*fs.Inode, error) {
	// device is always ignored.

	// Parse generic comma-separated key=value options, this file system expects them.
	options := fs.GenericMountSourceOptions(data)

	// Proc options parsing checks for either a gid= or hidepid= and barfs on
	// anything else, see fs/proc/root.c:proc_parse_options. Since we don't know
	// what to do with gid= or hidepid=, we blow up if we get any options.
	if len(options) > 0 {
		return nil, fmt.Errorf("unsupported mount options: %v", options)
	}

	var cgroups map[string]string
	if cgroupsInt != nil {
		cgroups = cgroupsInt.(map[string]string)
	}

	// Construct the procfs root. Since procfs files are all virtual, we
	// never want them cached.
	return New(ctx, fs.NewNonCachingMountSource(ctx, f, flags), cgroups)
}
