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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// flagsToPermissions returns a Permissions object from Linux flags.
// This includes truncate permission if O_TRUNC is set in the mask.
func flagsToPermissions(mask uint) (p fs.PermMask) {
	switch mask & linux.O_ACCMODE {
	case linux.O_WRONLY:
		p.Write = true
	case linux.O_RDWR:
		p.Write = true
		p.Read = true
	case linux.O_RDONLY:
		p.Read = true
	}
	return
}

// linuxToFlags converts Linux file flags to a FileFlags object.
func linuxToFlags(mask uint) fs.FileFlags {
	return fs.FileFlags{
		Direct:      mask&linux.O_DIRECT != 0,
		Sync:        mask&linux.O_SYNC != 0,
		NonBlocking: mask&linux.O_NONBLOCK != 0,
		Read:        (mask & linux.O_ACCMODE) != linux.O_WRONLY,
		Write:       (mask & linux.O_ACCMODE) != linux.O_RDONLY,
		Append:      mask&linux.O_APPEND != 0,
		Directory:   mask&linux.O_DIRECTORY != 0,
		Async:       mask&linux.O_ASYNC != 0,
		LargeFile:   mask&linux.O_LARGEFILE != 0,
	}
}
