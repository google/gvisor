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
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/usermem"
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

// TTY major device number comes from include/uapi/linux/major.h.
const (
	ttyDevMinor = 0
	ttyDevMajor = 5
)

func newCharacterDevice(ctx context.Context, iops fs.InodeOperations, msrc *fs.MountSource, major uint16, minor uint32) *fs.Inode {
	return fs.NewInode(ctx, iops, msrc, fs.StableAttr{
		DeviceID:        devDevice.DeviceID(),
		InodeID:         devDevice.NextIno(),
		BlockSize:       hostarch.PageSize,
		Type:            fs.CharacterDevice,
		DeviceFileMajor: major,
		DeviceFileMinor: minor,
	})
}

func newMemDevice(ctx context.Context, iops fs.InodeOperations, msrc *fs.MountSource, minor uint32) *fs.Inode {
	return fs.NewInode(ctx, iops, msrc, fs.StableAttr{
		DeviceID:        devDevice.DeviceID(),
		InodeID:         devDevice.NextIno(),
		BlockSize:       hostarch.PageSize,
		Type:            fs.CharacterDevice,
		DeviceFileMajor: memDevMajor,
		DeviceFileMinor: minor,
	})
}

func newDirectory(ctx context.Context, contents map[string]*fs.Inode, msrc *fs.MountSource) *fs.Inode {
	iops := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return fs.NewInode(ctx, iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Directory,
	})
}

func newSymlink(ctx context.Context, target string, msrc *fs.MountSource) *fs.Inode {
	iops := ramfs.NewSymlink(ctx, fs.RootOwner, target)
	return fs.NewInode(ctx, iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Symlink,
	})
}

// New returns the root node of a device filesystem.
func New(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	shm, err := tmpfs.NewDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0777), msrc, nil /* parent */)
	if err != nil {
		panic(fmt.Sprintf("tmpfs.NewDir failed: %v", err))
	}

	contents := map[string]*fs.Inode{
		"fd":     newSymlink(ctx, "/proc/self/fd", msrc),
		"stdin":  newSymlink(ctx, "/proc/self/fd/0", msrc),
		"stdout": newSymlink(ctx, "/proc/self/fd/1", msrc),
		"stderr": newSymlink(ctx, "/proc/self/fd/2", msrc),

		"null": newMemDevice(ctx, newNullDevice(ctx, fs.RootOwner, 0666), msrc, nullDevMinor),
		"zero": newMemDevice(ctx, newZeroDevice(ctx, fs.RootOwner, 0666), msrc, zeroDevMinor),
		"full": newMemDevice(ctx, newFullDevice(ctx, fs.RootOwner, 0666), msrc, fullDevMinor),

		// This is not as good as /dev/random in linux because go
		// runtime uses sys_random and /dev/urandom internally.
		// According to 'man 4 random', this will be sufficient unless
		// application uses this to generate long-lived GPG/SSL/SSH
		// keys.
		"random":  newMemDevice(ctx, newRandomDevice(ctx, fs.RootOwner, 0444), msrc, randomDevMinor),
		"urandom": newMemDevice(ctx, newRandomDevice(ctx, fs.RootOwner, 0444), msrc, urandomDevMinor),

		"shm": shm,

		// A devpts is typically mounted at /dev/pts to provide
		// pseudoterminal support. Place an empty directory there for
		// the devpts to be mounted over.
		"pts": newDirectory(ctx, nil, msrc),
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

		"tty": newCharacterDevice(ctx, newTTYDevice(ctx, fs.RootOwner, 0666), msrc, ttyDevMajor, ttyDevMinor),
	}

	if isNetTunSupported(inet.StackFromContext(ctx)) {
		contents["net"] = newDirectory(ctx, map[string]*fs.Inode{
			"tun": newCharacterDevice(ctx, newNetTunDevice(ctx, fs.RootOwner, 0666), msrc, netTunDevMajor, netTunDevMinor),
		}, msrc)
	}

	iops := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return fs.NewInode(ctx, iops, msrc, fs.StableAttr{
		DeviceID:  devDevice.DeviceID(),
		InodeID:   devDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Directory,
	})
}

// readZeros implements fs.FileOperations.Read with infinite null bytes.
type readZeros struct{}

// Read implements fs.FileOperations.Read.
func (*readZeros) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	return dst.ZeroOut(ctx, math.MaxInt64)
}
