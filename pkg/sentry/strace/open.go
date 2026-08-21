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

package strace

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// OpenMode represents the mode to open(2) a file.
var OpenMode = abi.ValueSet{
	linux.O_RDWR:   "O_RDWR",
	linux.O_WRONLY: "O_WRONLY",
	linux.O_RDONLY: "O_RDONLY",
}

// OpenFlagSet is the set of open(2) flags.
var OpenFlagSet = abi.FlagSet{
	{
		Flag: linux.O_APPEND,
		Name: "O_APPEND",
	},
	{
		Flag: linux.O_ASYNC,
		Name: "O_ASYNC",
	},
	{
		Flag: linux.O_CLOEXEC,
		Name: "O_CLOEXEC",
	},
	{
		Flag: linux.O_CREAT,
		Name: "O_CREAT",
	},
	{
		Flag: linux.O_DIRECT,
		Name: "O_DIRECT",
	},
	{
		Flag: linux.O_DIRECTORY,
		Name: "O_DIRECTORY",
	},
	{
		Flag: linux.O_EXCL,
		Name: "O_EXCL",
	},
	{
		Flag: linux.O_NOATIME,
		Name: "O_NOATIME",
	},
	{
		Flag: linux.O_NOCTTY,
		Name: "O_NOCTTY",
	},
	{
		Flag: linux.O_NOFOLLOW,
		Name: "O_NOFOLLOW",
	},
	{
		Flag: linux.O_NONBLOCK,
		Name: "O_NONBLOCK",
	},
	{
		Flag: 0x200000, // O_PATH
		Name: "O_PATH",
	},
	{
		Flag: linux.O_SYNC,
		Name: "O_SYNC",
	},
	{
		Flag: linux.O_TMPFILE,
		Name: "O_TMPFILE",
	},
	{
		Flag: linux.O_TRUNC,
		Name: "O_TRUNC",
	},
}

// ResolveFlagSet is the set of openat2(2) resolve flags.
var ResolveFlagSet = abi.FlagSet{
	{
		Flag: linux.RESOLVE_NO_XDEV,
		Name: "RESOLVE_NO_XDEV",
	},
	{
		Flag: linux.RESOLVE_NO_MAGICLINKS,
		Name: "RESOLVE_NO_MAGICLINKS",
	},
	{
		Flag: linux.RESOLVE_NO_SYMLINKS,
		Name: "RESOLVE_NO_SYMLINKS",
	},
	{
		Flag: linux.RESOLVE_BENEATH,
		Name: "RESOLVE_BENEATH",
	},
	{
		Flag: linux.RESOLVE_IN_ROOT,
		Name: "RESOLVE_IN_ROOT",
	},
	{
		Flag: linux.RESOLVE_CACHED,
		Name: "RESOLVE_CACHED",
	},
}

func open(val uint64) string {
	s := OpenMode.Parse(val & linux.O_ACCMODE)
	if flags := OpenFlagSet.Parse(val &^ linux.O_ACCMODE); flags != "" {
		s += "|" + flags
	}
	return s
}

func openHow(t *kernel.Task, addr hostarch.Addr, size uint) string {
	if addr == 0 {
		return "<null>"
	}
	s := int(size)
	if s < 0 {
		return "<invalid size>"
	}
	var how linux.OpenHow
	if _, err := how.CopyInN(t, addr, min(s, linux.OPEN_HOW_SIZE_LATEST)); err != nil {
		return fmt.Sprintf("%#x (error decoding OpenHow: %s)", addr, err)
	}
	return fmt.Sprintf("%#x flags %s mode %s resolve %s", addr, open(how.Flags), linux.FileMode(how.Mode), ResolveFlagSet.Parse(how.Resolve))
}
