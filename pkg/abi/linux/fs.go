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

package linux

// Filesystem types used in statfs(2).
//
// See linux/magic.h.
const (
	ANON_INODE_FS_MAGIC   = 0x09041934
	DEVPTS_SUPER_MAGIC    = 0x00001cd1
	EXT_SUPER_MAGIC       = 0xef53
	OVERLAYFS_SUPER_MAGIC = 0x794c7630
	PIPEFS_MAGIC          = 0x50495045
	PROC_SUPER_MAGIC      = 0x9fa0
	RAMFS_MAGIC           = 0x09041934
	SOCKFS_MAGIC          = 0x534F434B
	SYSFS_MAGIC           = 0x62656572
	TMPFS_MAGIC           = 0x01021994
	V9FS_MAGIC            = 0x01021997
)

// Filesystem path limits, from uapi/linux/limits.h.
const (
	NAME_MAX = 255
	PATH_MAX = 4096
)

// Statfs is struct statfs, from uapi/asm-generic/statfs.h.
type Statfs struct {
	// Type is one of the filesystem magic values, defined above.
	Type uint64

	// BlockSize is the data block size.
	BlockSize int64

	// Blocks is the number of data blocks in use.
	Blocks uint64

	// BlocksFree is the number of free blocks.
	BlocksFree uint64

	// BlocksAvailable is the number of blocks free for use by
	// unprivileged users.
	BlocksAvailable uint64

	// Files is the number of used file nodes on the filesystem.
	Files uint64

	// FileFress is the number of free file nodes on the filesystem.
	FilesFree uint64

	// FSID is the filesystem ID.
	FSID [2]int32

	// NameLength is the maximum file name length.
	NameLength uint64

	// FragmentSize is equivalent to BlockSize.
	FragmentSize int64

	// Flags is the set of filesystem mount flags.
	Flags uint64

	// Spare is unused.
	Spare [4]uint64
}

// Whence argument to lseek(2), from include/uapi/linux/fs.h.
const (
	SEEK_SET  = 0
	SEEK_CUR  = 1
	SEEK_END  = 2
	SEEK_DATA = 3
	SEEK_HOLE = 4
)

// Sync_file_range flags, from include/uapi/linux/fs.h
const (
	SYNC_FILE_RANGE_WAIT_BEFORE = 1
	SYNC_FILE_RANGE_WRITE       = 2
	SYNC_FILE_RANGE_WAIT_AFTER  = 4
)
