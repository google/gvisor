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

package ext4

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/third_party/goext4"
)

var (
	// inodeTypeByFileType maps ext4 file types to vfs inode types.
	inodeTypeByFileType = map[uint8]fs.InodeType{
		goext4.FileTypeUnknown:         fs.Anonymous,
		goext4.FileTypeRegular:         fs.RegularFile,
		goext4.FileTypeDirectory:       fs.Directory,
		goext4.FileTypeCharacterDevice: fs.CharacterDevice,
		goext4.FileTypeBlockDevice:     fs.BlockDevice,
		goext4.FileTypeFifo:            fs.Pipe,
		goext4.FileTypeSocket:          fs.Socket,
		goext4.FileTypeSymbolicLink:    fs.Symlink,
	}
)

// getInodeType converts ext4 file type to vfs inode type.
func getInodeType(t uint8) fs.InodeType {
	if inodeType, ok := inodeTypeByFileType[t]; ok {
		return inodeType
	}

	panic(fmt.Sprintf("unknown inode type %v", t))
}

// getSysError converts the errors stemming from the goext4 library and
// converts them into syserrors. All errors coming from the goext4 library MUST
// be passed through this.
// TODO(b/134676337): Handle goext4 lib string errors.
func getSysError(goext4Err error) error {
	switch goext4Err {
	case goext4.ErrNotExt4:
		// mount(2) specifies that EINVAL should be returned if the superblock is
		// invalid.
		return syserror.EINVAL
	default:
		// Rest of the errors stem from io.Read or io.Seek.
		return syserror.EIO
	}
}
