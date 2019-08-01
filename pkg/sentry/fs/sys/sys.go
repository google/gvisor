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

// Package sys implements a sysfs filesystem.
package sys

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

func newFile(ctx context.Context, node fs.InodeOperations, msrc *fs.MountSource) *fs.Inode {
	sattr := fs.StableAttr{
		DeviceID:  sysfsDevice.DeviceID(),
		InodeID:   sysfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialFile,
	}
	msrc.IncRef()
	return fs.NewInode(ctx, node, msrc, sattr)
}

func newDir(ctx context.Context, msrc *fs.MountSource, contents map[string]*fs.Inode) *fs.Inode {
	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	msrc.IncRef()
	return fs.NewInode(ctx, d, msrc, fs.StableAttr{
		DeviceID:  sysfsDevice.DeviceID(),
		InodeID:   sysfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialDirectory,
	})
}

// New returns the root node of a partial simple sysfs.
func New(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	return newDir(ctx, msrc, map[string]*fs.Inode{
		// Add a basic set of top-level directories. In Linux, these
		// are dynamically added depending on the KConfig. Here we just
		// add the most common ones.
		"block": newDir(ctx, msrc, nil),
		"bus":   newDir(ctx, msrc, nil),
		"class": newDir(ctx, msrc, map[string]*fs.Inode{
			"power_supply": newDir(ctx, msrc, nil),
		}),
		"dev":      newDir(ctx, msrc, nil),
		"devices":  newDevicesDir(ctx, msrc),
		"firmware": newDir(ctx, msrc, nil),
		"fs":       newDir(ctx, msrc, nil),
		"kernel":   newDir(ctx, msrc, nil),
		"module":   newDir(ctx, msrc, nil),
		"power":    newDir(ctx, msrc, nil),
	})
}
