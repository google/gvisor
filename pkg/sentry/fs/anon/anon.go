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

// Package anon implements an anonymous inode, useful for implementing
// inodes for pseudo filesystems.
package anon

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// NewInode constructs an anonymous Inode that is not associated
// with any real filesystem. Some types depend on completely pseudo
// "anon" inodes (eventfds, epollfds, etc).
func NewInode(ctx context.Context) *fs.Inode {
	return fs.NewInode(fsutil.NewSimpleInodeOperations(fsutil.InodeSimpleAttributes{
		FSType: linux.ANON_INODE_FS_MAGIC,
		UAttr: fs.WithCurrentTime(ctx, fs.UnstableAttr{
			Owner: fs.FileOwnerFromContext(ctx),
			Perms: fs.FilePermissions{
				User: fs.PermMask{Read: true, Write: true},
			},
			Links: 1,
		}),
	}), fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{}), fs.StableAttr{
		Type:      fs.Anonymous,
		DeviceID:  PseudoDevice.DeviceID(),
		InodeID:   PseudoDevice.NextIno(),
		BlockSize: usermem.PageSize,
	})
}
