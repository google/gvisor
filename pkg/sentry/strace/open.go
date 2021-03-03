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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi"
)

// OpenMode represents the mode to open(2) a file.
var OpenMode = abi.ValueSet{
	unix.O_RDWR:   "O_RDWR",
	unix.O_WRONLY: "O_WRONLY",
	unix.O_RDONLY: "O_RDONLY",
}

// OpenFlagSet is the set of open(2) flags.
var OpenFlagSet = abi.FlagSet{
	{
		Flag: unix.O_APPEND,
		Name: "O_APPEND",
	},
	{
		Flag: unix.O_ASYNC,
		Name: "O_ASYNC",
	},
	{
		Flag: unix.O_CLOEXEC,
		Name: "O_CLOEXEC",
	},
	{
		Flag: unix.O_CREAT,
		Name: "O_CREAT",
	},
	{
		Flag: unix.O_DIRECT,
		Name: "O_DIRECT",
	},
	{
		Flag: unix.O_DIRECTORY,
		Name: "O_DIRECTORY",
	},
	{
		Flag: unix.O_EXCL,
		Name: "O_EXCL",
	},
	{
		Flag: unix.O_NOATIME,
		Name: "O_NOATIME",
	},
	{
		Flag: unix.O_NOCTTY,
		Name: "O_NOCTTY",
	},
	{
		Flag: unix.O_NOFOLLOW,
		Name: "O_NOFOLLOW",
	},
	{
		Flag: unix.O_NONBLOCK,
		Name: "O_NONBLOCK",
	},
	{
		Flag: 0x200000, // O_PATH
		Name: "O_PATH",
	},
	{
		Flag: unix.O_SYNC,
		Name: "O_SYNC",
	},
	{
		Flag: unix.O_TRUNC,
		Name: "O_TRUNC",
	},
}

func open(val uint64) string {
	s := OpenMode.Parse(val & unix.O_ACCMODE)
	if flags := OpenFlagSet.Parse(val &^ unix.O_ACCMODE); flags != "" {
		s += "|" + flags
	}
	return s
}
