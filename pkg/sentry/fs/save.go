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

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
)

// SaveInodeMappings saves a mapping of path -> inode ID for every
// user-reachable Dirent.
//
// The entire kernel must be frozen to call this, and filesystem state must not
// change between SaveInodeMappings and state.Save, otherwise the saved state
// of any MountSource may be incoherent.
func SaveInodeMappings() {
	mountsSeen := make(map[*MountSource]struct{})
	for dirent := range allDirents.dirents {
		if _, ok := mountsSeen[dirent.Inode.MountSource]; !ok {
			dirent.Inode.MountSource.ResetInodeMappings()
			mountsSeen[dirent.Inode.MountSource] = struct{}{}
		}
	}

	for dirent := range allDirents.dirents {
		if dirent.Inode != nil {
			// We cannot trust the root provided in the mount due
			// to the overlay. We can trust the overlay to delegate
			// SaveInodeMappings to the right underlying
			// filesystems, though.
			root := dirent
			for !root.mounted && root.parent != nil {
				root = root.parent
			}

			// Add the mapping.
			n, reachable := dirent.FullName(root)
			if !reachable {
				// Something has gone seriously wrong if we can't reach our root.
				panic(fmt.Sprintf("Unreachable root on dirent file %s", n))
			}
			dirent.Inode.MountSource.SaveInodeMapping(dirent.Inode, n)
		}
	}
}

// SaveFileFsyncError converts an fs.File.Fsync error to an error that
// indicates that the fs.File was not synced sufficiently to be saved.
func SaveFileFsyncError(err error) error {
	switch err {
	case nil:
		// We succeeded, everything is great.
		return nil
	case syscall.EBADF, syscall.EINVAL, syscall.EROFS, syscall.ENOSYS, syscall.EPERM:
		// These errors mean that the underlying node might not be syncable,
		// which we expect to be reported as such even from the gofer.
		log.Infof("failed to sync during save: %v", err)
		return nil
	default:
		// We failed in some way that indicates potential data loss.
		return fmt.Errorf("failed to sync: %v, data loss may occur", err)
	}
}
