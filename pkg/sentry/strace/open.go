// Copyright 2018 Google LLC
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
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi"
)

// OpenMode represents the mode to open(2) a file.
var OpenMode = abi.ValueSet{
	syscall.O_RDWR:   "O_RDWR",
	syscall.O_WRONLY: "O_WRONLY",
	syscall.O_RDONLY: "O_RDONLY",
}

// OpenFlagSet is the set of open(2) flags.
var OpenFlagSet = abi.FlagSet{
	{
		Flag: syscall.O_APPEND,
		Name: "O_APPEND",
	},
	{
		Flag: syscall.O_ASYNC,
		Name: "O_ASYNC",
	},
	{
		Flag: syscall.O_CLOEXEC,
		Name: "O_CLOEXEC",
	},
	{
		Flag: syscall.O_CREAT,
		Name: "O_CREAT",
	},
	{
		Flag: syscall.O_DIRECT,
		Name: "O_DIRECT",
	},
	{
		Flag: syscall.O_DIRECTORY,
		Name: "O_DIRECTORY",
	},
	{
		Flag: syscall.O_EXCL,
		Name: "O_EXCL",
	},
	{
		Flag: syscall.O_NOATIME,
		Name: "O_NOATIME",
	},
	{
		Flag: syscall.O_NOCTTY,
		Name: "O_NOCTTY",
	},
	{
		Flag: syscall.O_NOFOLLOW,
		Name: "O_NOFOLLOW",
	},
	{
		Flag: syscall.O_NONBLOCK,
		Name: "O_NONBLOCK",
	},
	{
		Flag: 0x200000, // O_PATH
		Name: "O_PATH",
	},
	{
		Flag: syscall.O_SYNC,
		Name: "O_SYNC",
	},
	{
		Flag: syscall.O_TRUNC,
		Name: "O_TRUNC",
	},
}

func open(val uint64) string {
	s := OpenMode.Parse(val & syscall.O_ACCMODE)
	if flags := OpenFlagSet.Parse(val &^ syscall.O_ACCMODE); flags != "" {
		s += "|" + flags
	}
	return s
}
