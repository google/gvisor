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

package fs

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// FileFlags encodes file flags.
//
// +stateify savable
type FileFlags struct {
	// Direct indicates that I/O should be done directly.
	Direct bool

	// NonBlocking indicates that I/O should not block.
	NonBlocking bool

	// Sync indicates that any writes should be synchronous.
	Sync bool

	// Append indicates this file is append only.
	Append bool

	// Read indicates this file is readable.
	Read bool

	// Write indicates this file is writeable.
	Write bool

	// Pread indicates this file is readable at an arbitrary offset.
	Pread bool

	// Pwrite indicates this file is writable at an arbitrary offset.
	Pwrite bool

	// Directory indicates that this file must be a directory.
	Directory bool

	// Async indicates that this file sends signals on IO events.
	Async bool

	// LargeFile indicates that this file should be opened even if it has
	// size greater than linux's off_t. When running in 64-bit mode,
	// Linux sets this flag for all files. Since gVisor is only compatible
	// with 64-bit Linux, it also sets this flag for all files.
	LargeFile bool
}

// SettableFileFlags is a subset of FileFlags above that can be changed
// via fcntl(2) using the F_SETFL command.
type SettableFileFlags struct {
	// Direct indicates that I/O should be done directly.
	Direct bool

	// NonBlocking indicates that I/O should not block.
	NonBlocking bool

	// Append indicates this file is append only.
	Append bool

	// Async indicates that this file sends signals on IO events.
	Async bool
}

// Settable returns the subset of f that are settable.
func (f FileFlags) Settable() SettableFileFlags {
	return SettableFileFlags{
		Direct:      f.Direct,
		NonBlocking: f.NonBlocking,
		Append:      f.Append,
		Async:       f.Async,
	}
}

// ToLinux converts a FileFlags object to a Linux representation.
func (f FileFlags) ToLinux() (mask uint) {
	if f.Direct {
		mask |= linux.O_DIRECT
	}
	if f.NonBlocking {
		mask |= linux.O_NONBLOCK
	}
	if f.Sync {
		mask |= linux.O_SYNC
	}
	if f.Append {
		mask |= linux.O_APPEND
	}
	if f.Directory {
		mask |= linux.O_DIRECTORY
	}
	if f.Async {
		mask |= linux.O_ASYNC
	}
	if f.LargeFile {
		mask |= linux.O_LARGEFILE
	}

	switch {
	case f.Read && f.Write:
		mask |= linux.O_RDWR
	case f.Write:
		mask |= linux.O_WRONLY
	case f.Read:
		mask |= linux.O_RDONLY
	}
	return
}
