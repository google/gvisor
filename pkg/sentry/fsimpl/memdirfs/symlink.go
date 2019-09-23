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

package memdirfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

type symlink struct {
	target string // Immutable.
}

// "The permissions of a symbolic link are irrelevant; the ownership
// is ignored when following the link, but is checked when removal or
// renaming of the link is requested and the link is in a directory
// with the sticky bit (S_ISVTX) set." -- man symlink(2)
//
// However, we still need to put something on the inode. Linux uses
// I_RWXUGO, see mm/shmem.c:shmem_symlink().
const symlinkDefaultMode = 0777

// NewSymlinkInode creates a new inode representing a symlink.
func (fs *Filesystem) NewSymlinkInode(creds *auth.Credentials, target string) *Inode {
	return fs.NewInode(InodeOpts{Creds: creds, Mode: symlinkDefaultMode, Impl: &symlink{target: target}})
}

// Open implements InodeImpl.Open.
func (s *symlink) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	// O_PATH is unimplemented, so there's no way to get a FileDescription
	// representing a symlink yet.
	return nil, syserror.ELOOP
}

// DynamicLookup implements InodeImpl.DynamicLookup.
func (s *symlink) DynamicLookup(rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	return nil, syserror.ENOTDIR
}

// Stat implements InodeImpl.Stat.
func (s *symlink) Stat(stat *linux.Statx) {
	stat.Mode |= linux.S_IFLNK
	stat.Mask |= linux.STATX_SIZE | linux.STATX_BLOCKS
	stat.Size = uint64(len(s.target))
	stat.Blocks = num512ByteBlocks(stat.Size)
}
