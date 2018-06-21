// Copyright 2018 Google Inc.
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

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
)

// flagsToPermissions returns a Permissions object from Linux flags.
// This includes truncate permission if O_TRUNC is set in the mask.
func flagsToPermissions(mask uint) (p fs.PermMask) {
	switch mask & syscall.O_ACCMODE {
	case syscall.O_WRONLY:
		p.Write = true
	case syscall.O_RDWR:
		p.Write = true
		p.Read = true
	case syscall.O_RDONLY:
		p.Read = true
	}
	return
}

// fdFlagsToLinux converts a kernel.FDFlags object to a Linux representation.
func fdFlagsToLinux(flags kernel.FDFlags) (mask uint) {
	if flags.CloseOnExec {
		mask |= syscall.FD_CLOEXEC
	}
	return
}

// flagsToLinux converts a FileFlags object to a Linux representation.
func flagsToLinux(flags fs.FileFlags) (mask uint) {
	if flags.Direct {
		mask |= syscall.O_DIRECT
	}
	if flags.NonBlocking {
		mask |= syscall.O_NONBLOCK
	}
	if flags.Sync {
		mask |= syscall.O_SYNC
	}
	if flags.Append {
		mask |= syscall.O_APPEND
	}
	if flags.Directory {
		mask |= syscall.O_DIRECTORY
	}
	if flags.Async {
		mask |= syscall.O_ASYNC
	}
	switch {
	case flags.Read && flags.Write:
		mask |= syscall.O_RDWR
	case flags.Write:
		mask |= syscall.O_WRONLY
	case flags.Read:
		mask |= syscall.O_RDONLY
	}
	return
}

// linuxToFlags converts linux file flags to a FileFlags object.
func linuxToFlags(mask uint) (flags fs.FileFlags) {
	return fs.FileFlags{
		Direct:      mask&syscall.O_DIRECT != 0,
		Sync:        mask&syscall.O_SYNC != 0,
		NonBlocking: mask&syscall.O_NONBLOCK != 0,
		Read:        (mask & syscall.O_ACCMODE) != syscall.O_WRONLY,
		Write:       (mask & syscall.O_ACCMODE) != syscall.O_RDONLY,
		Append:      mask&syscall.O_APPEND != 0,
		Directory:   mask&syscall.O_DIRECTORY != 0,
		Async:       mask&syscall.O_ASYNC != 0,
	}
}

// linuxToSettableFlags converts linux file flags to a SettableFileFlags object.
func linuxToSettableFlags(mask uint) fs.SettableFileFlags {
	return fs.SettableFileFlags{
		Direct:      mask&syscall.O_DIRECT != 0,
		NonBlocking: mask&syscall.O_NONBLOCK != 0,
		Append:      mask&syscall.O_APPEND != 0,
		Async:       mask&syscall.O_ASYNC != 0,
	}
}
