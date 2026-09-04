// Copyright 2026 The gVisor Authors.
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

package vfs

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// WriteCount counts the MemoryManagers currently executing a file, which must
// not be written while they do. It is a partial analogue of Linux's
// inode::i_writecount: only write denials are counted, not writers, so
// execve(2) on a file that is already open for writing does not fail with
// ETXTBSY as it does in Linux.
//
// Filesystems that can host executables should embed WriteCount in whatever
// type represents an inode, so that hard links to the same file share it, and
// call CheckWrite from paths that mutate file contents. VFS does not associate
// Dentries with inodes (see Dentry), so this state cannot live in VFS itself.
//
// +stateify savable
type WriteCount struct {
	execs atomicbitops.Int32
}

// DenyWrite records that the file is being executed, causing CheckWrite to
// fail until a matching call to AllowWrite.
func (wc *WriteCount) DenyWrite() {
	wc.execs.Add(1)
}

// AllowWrite reverses a previous call to DenyWrite.
func (wc *WriteCount) AllowWrite() {
	wc.execs.Add(-1)
}

// CheckWrite returns ETXTBSY if the file is being executed.
func (wc *WriteCount) CheckWrite() error {
	if wc.execs.Load() > 0 {
		return linuxerr.ETXTBSY
	}
	return nil
}

// WriteCounter is an optional extension to DentryImpl implemented by
// filesystems that can host executables. Filesystems that do not implement it
// never deny writes.
type WriteCounter interface {
	// WriteCount returns the WriteCount shared by all Dentries representing
	// the same file.
	WriteCount() *WriteCount
}

// DenyWriteAccess prevents the file represented by fd from being written until
// a matching call to AllowWriteAccess. It is a no-op if fd's filesystem does
// not implement WriteCounter.
func (fd *FileDescription) DenyWriteAccess() {
	if impl, ok := fd.Dentry().Impl().(WriteCounter); ok {
		impl.WriteCount().DenyWrite()
	}
}

// AllowWriteAccess reverses a previous call to DenyWriteAccess.
func (fd *FileDescription) AllowWriteAccess() {
	if impl, ok := fd.Dentry().Impl().(WriteCounter); ok {
		impl.WriteCount().AllowWrite()
	}
}
