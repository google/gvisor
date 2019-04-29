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

// Package dev provides a filesystem with simple devices.
package dev

import (
	"math"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ashmem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/binder"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// Memory device numbers are from Linux's drivers/char/mem.c
const (
	// Mem device major.
	memDevMajor uint16 = 1

	// Mem device minors.
	nullDevMinor    uint32 = 3
	zeroDevMinor    uint32 = 5
	fullDevMinor    uint32 = 7
	randomDevMinor  uint32 = 8
	urandomDevMinor uint32 = 9
)

func newCharacterDevice(iops fs.InodeOperations, msrc *fs.MountSource) *fs.Inode {
	return fs.NewInode(iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.CharacterDevice,
	})
}

func newMemDevice(iops fs.InodeOperations, msrc *fs.MountSource, minor uint32) *fs.Inode {
	return fs.NewInode(iops, msrc, fs.StableAttr{
		DeviceID:        devDevice.DeviceID(),
		InodeID:         devDevice.NextIno(),
		BlockSize:       usermem.PageSize,
		Type:            fs.CharacterDevice,
		DeviceFileMajor: memDevMajor,
		DeviceFileMinor: minor,
	})
}

func newDirectory(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	iops := ramfs.NewDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	return fs.NewInode(iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Directory,
	})
}

func newSymlink(ctx context.Context, target string, msrc *fs.MountSource) *fs.Inode {
	iops := ramfs.NewSymlink(ctx, fs.RootOwner, target)
	return fs.NewInode(iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Symlink,
	})
}

// New returns the root node of a device filesystem.
func New(ctx context.Context, msrc *fs.MountSource, binderEnabled bool, ashmemEnabled bool) *fs.Inode {
	contents := map[string]*fs.Inode{
		"fd":     newSymlink(ctx, "/proc/self/fd", msrc),
		"stdin":  newSymlink(ctx, "/proc/self/fd/0", msrc),
		"stdout": newSymlink(ctx, "/proc/self/fd/1", msrc),
		"stderr": newSymlink(ctx, "/proc/self/fd/2", msrc),

		"null": newMemDevice(newNullDevice(ctx, fs.RootOwner, 0666), msrc, nullDevMinor),
		"zero": newMemDevice(newZeroDevice(ctx, fs.RootOwner, 0666), msrc, zeroDevMinor),
		"full": newMemDevice(newFullDevice(ctx, fs.RootOwner, 0666), msrc, fullDevMinor),

		// This is not as good as /dev/random in linux because go
		// runtime uses sys_random and /dev/urandom internally.
		// According to 'man 4 random', this will be sufficient unless
		// application uses this to generate long-lived GPG/SSL/SSH
		// keys.
		"random":  newMemDevice(newRandomDevice(ctx, fs.RootOwner, 0444), msrc, randomDevMinor),
		"urandom": newMemDevice(newRandomDevice(ctx, fs.RootOwner, 0444), msrc, urandomDevMinor),

		"shm": tmpfs.NewDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0777), msrc),

		// A devpts is typically mounted at /dev/pts to provide
		// pseudoterminal support. Place an empty directory there for
		// the devpts to be mounted over.
		"pts": newDirectory(ctx, msrc),
		// Similarly, applications expect a ptmx device at /dev/ptmx
		// connected to the terminals provided by /dev/pts/. Rather
		// than creating a device directly (which requires a hairy
		// lookup on open to determine if a devpts exists), just create
		// a symlink to the ptmx provided by devpts. (The Linux devpts
		// documentation recommends this).
		//
		// If no devpts is mounted, this will simply be a dangling
		// symlink, which is fine.
		"ptmx": newSymlink(ctx, "pts/ptmx", msrc),
	}

	if binderEnabled {
		binder := binder.NewDevice(ctx, fs.RootOwner, fs.FilePermsFromMode(0666))
		contents["binder"] = newCharacterDevice(binder, msrc)
	}

	if ashmemEnabled {
		ashmem := ashmem.NewDevice(ctx, fs.RootOwner, fs.FilePermsFromMode(0666))
		contents["ashmem"] = newCharacterDevice(ashmem, msrc)
	}

	iops := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return fs.NewInode(iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Directory,
	})
}

// readZeros implements fs.FileOperations.Read with infinite null bytes.
type readZeros struct{}

// Read implements fs.FileOperations.Read.
func (*readZeros) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	return dst.ZeroOut(ctx, math.MaxInt64)
}
