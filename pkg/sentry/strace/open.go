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
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
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

func open(val uint64) string {
	s := OpenMode.Parse(val & linux.O_ACCMODE)
	if flags := OpenFlagSet.Parse(val &^ linux.O_ACCMODE); flags != "" {
		s += "|" + flags
	}
	return s
}
