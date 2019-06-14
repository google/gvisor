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
	"fmt"
	"io"
	"os"
	"strconv"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/third_party/goext4"
)

const (
	fdKey = "fd"
)

var (
	// errNoDeviceFd is returned when there is no 'fd' option.
	errNoDeviceFd = fmt.Errorf("ext4 device file descriptor not provided. Missing required %q option", fdKey)

	// errInvalidDeviceFd is returned when the 'fd' option indicates an invalid file descriptor.
	errInvalidDeviceFd = fmt.Errorf("ext4 Device file descriptor provided by %q option is not valid", fdKey)
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
	// Read-only flag must be set.
	// TODO(b/134676337): Remove when write is supported.
	if !flags.ReadOnly {
		return nil, fmt.Errorf("ext4 must be mounted read-only")
	}

	// Parse data into a map.
	options := fs.GenericMountSourceOptions(data)
	sfd, ok := options[fdKey]
	if !ok {
		return nil, errNoDeviceFd
	}

	// Parse device fd.
	fd, err := strconv.Atoi(sfd)
	if err != nil {
		return nil, fmt.Errorf("ext4 Device file descriptor %q provided by %q option is not valid: %v", sfd, fdKey, err)
	}

	if fd < 0 {
		return nil, errInvalidDeviceFd
	}

	// Create the os.File object of the ext4 device. We do NOT close
	// this file in this function because that would close the device
	// fd. We need the device fd in inode and file operations to
	// interact with the fs.
	//
	// TODO(b/134676337): Close the file when the sandbox exits
	// (cleanly or a crash) so that the buffered changes are written
	// and the fs is not corrupted.
	deviceFile := os.NewFile(uintptr(fd), device)
	if deviceFile == nil {
		return nil, errInvalidDeviceFd
	}

	// Read the super block and block descriptors from device.
	if _, err = deviceFile.Seek(goext4.Superblock0Offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek on ext4 device file failed: %v", err)
	}

	superBlock, err := goext4.NewSuperblockWithReader(deviceFile)
	if err != nil {
		return nil, err
	}

	bgdl, err := goext4.NewBlockGroupDescriptorListWithReadSeeker(deviceFile, superBlock)
	if err != nil {
		return nil, err
	}

	// Create a caching mount source and root directory inode.
	msrc := fs.NewCachingMountSource(ctx, f, flags)

	return newInode(ctx, bgdl, msrc, goext4.InodeRootDirectory, deviceFile, fs.Directory)
}
