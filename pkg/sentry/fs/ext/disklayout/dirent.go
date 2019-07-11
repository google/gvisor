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

package disklayout

import (
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

const (
	// MaxFileName is the maximum length of an ext fs file's name.
	MaxFileName = 255
)

var (
	// inodeTypeByFileType maps ext4 file types to vfs inode types.
	//
	// See https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#ftype.
	inodeTypeByFileType = map[uint8]fs.InodeType{
		0: fs.Anonymous,
		1: fs.RegularFile,
		2: fs.Directory,
		3: fs.CharacterDevice,
		4: fs.BlockDevice,
		5: fs.Pipe,
		6: fs.Socket,
		7: fs.Symlink,
	}
)

// The Dirent interface should be implemented by structs representing ext
// directory entries. These are for the linear classical directories which
// just store a list of dirent structs. A directory is a series of data blocks
// where is each data block contains a linear array of dirents. The last entry
// of the block has a record size that takes it to the end of the block. The
// end of the directory is when you read dirInode.Size() bytes from the blocks.
//
// See https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#linear-classic-directories.
type Dirent interface {
	// Inode returns the absolute inode number of the underlying inode.
	// Inode number 0 signifies an unused dirent.
	Inode() uint32

	// RecordSize returns the record length of this dirent on disk. The next
	// dirent in the dirent list should be read after these many bytes from
	// the current dirent. Must be a multiple of 4.
	RecordSize() uint16

	// FileName returns the name of the file. Can be at most 255 is length.
	FileName() string

	// FileType returns the inode type of the underlying inode. This is a
	// performance hack so that we do not have to read the underlying inode struct
	// to know the type of inode. This will only work when the SbDirentFileType
	// feature is set. If not, the second returned value will be false indicating
	// that user code has to use the inode mode to extract the file type.
	FileType() (fs.InodeType, bool)
}
