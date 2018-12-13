// Copyright 2018 Google LLC
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

package tmpfs

import (
	"fmt"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
)

const (
	// Set initial permissions for the root directory.
	modeKey = "mode"

	// UID for the root directory.
	rootUIDKey = "uid"

	// GID for the root directory.
	rootGIDKey = "gid"

	// TODO: support a tmpfs size limit.
	// size = "size"

	// Permissions that exceed modeMask will be rejected.
	modeMask = 01777

	// Default permissions are read/write/execute.
	defaultMode = 0777
)

// Filesystem is a tmpfs.
//
// +stateify savable
type Filesystem struct{}

func init() {
	fs.RegisterFilesystem(&Filesystem{})
}

// FilesystemName is the name underwhich the filesystem is registered.
// Name matches mm/shmem.c:shmem_fs_type.name.
const FilesystemName = "tmpfs"

// Name is the name of the file system.
func (*Filesystem) Name() string {
	return FilesystemName
}

// AllowUserMount allows users to mount(2) this file system.
func (*Filesystem) AllowUserMount() bool {
	return true
}

// AllowUserList allows this filesystem to be listed in /proc/filesystems.
func (*Filesystem) AllowUserList() bool {
	return true
}

// Flags returns that there is nothing special about this file system.
//
// In Linux, tmpfs returns FS_USERNS_MOUNT, see mm/shmem.c.
func (*Filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// Mount returns a tmpfs root that can be positioned in the vfs.
func (f *Filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string) (*fs.Inode, error) {
	// device is always ignored.

	// Parse generic comma-separated key=value options, this file system expects them.
	options := fs.GenericMountSourceOptions(data)

	// Parse the root directory permissions.
	perms := fs.FilePermsFromMode(defaultMode)
	if m, ok := options[modeKey]; ok {
		i, err := strconv.ParseUint(m, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("mode value not parsable 'mode=%s': %v", m, err)
		}
		if i&^modeMask != 0 {
			return nil, fmt.Errorf("invalid mode %q: must be less than %o", m, modeMask)
		}
		perms = fs.FilePermsFromMode(linux.FileMode(i))
		delete(options, modeKey)
	}

	creds := auth.CredentialsFromContext(ctx)
	owner := fs.FileOwnerFromContext(ctx)
	if uidstr, ok := options[rootUIDKey]; ok {
		uid, err := strconv.ParseInt(uidstr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("uid value not parsable 'uid=%d': %v", uid, err)
		}
		owner.UID = creds.UserNamespace.MapToKUID(auth.UID(uid))
		delete(options, rootUIDKey)
	}

	if gidstr, ok := options[rootGIDKey]; ok {
		gid, err := strconv.ParseInt(gidstr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("gid value not parsable 'gid=%d': %v", gid, err)
		}
		owner.GID = creds.UserNamespace.MapToKGID(auth.GID(gid))
		delete(options, rootGIDKey)
	}

	// Fail if the caller passed us more options than we can parse. They may be
	// expecting us to set something we can't set.
	if len(options) > 0 {
		return nil, fmt.Errorf("unsupported mount options: %v", options)
	}

	// Construct a mount which will cache dirents.
	msrc := fs.NewCachingMountSource(f, flags)

	// Construct the tmpfs root.
	return NewDir(ctx, nil, owner, perms, msrc, kernel.KernelFromContext(ctx)), nil
}
