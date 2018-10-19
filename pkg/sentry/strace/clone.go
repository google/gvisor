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

// CloneFlagSet is the set of clone(2) flags.
var CloneFlagSet = abi.FlagSet{
	{
		Flag: syscall.CLONE_VM,
		Name: "CLONE_VM",
	},
	{
		Flag: syscall.CLONE_FS,
		Name: "CLONE_FS",
	},
	{
		Flag: syscall.CLONE_FILES,
		Name: "CLONE_FILES",
	},
	{
		Flag: syscall.CLONE_SIGHAND,
		Name: "CLONE_SIGHAND",
	},
	{
		Flag: syscall.CLONE_PTRACE,
		Name: "CLONE_PTRACE",
	},
	{
		Flag: syscall.CLONE_VFORK,
		Name: "CLONE_VFORK",
	},
	{
		Flag: syscall.CLONE_PARENT,
		Name: "CLONE_PARENT",
	},
	{
		Flag: syscall.CLONE_THREAD,
		Name: "CLONE_THREAD",
	},
	{
		Flag: syscall.CLONE_NEWNS,
		Name: "CLONE_NEWNS",
	},
	{
		Flag: syscall.CLONE_SYSVSEM,
		Name: "CLONE_SYSVSEM",
	},
	{
		Flag: syscall.CLONE_SETTLS,
		Name: "CLONE_SETTLS",
	},
	{
		Flag: syscall.CLONE_PARENT_SETTID,
		Name: "CLONE_PARENT_SETTID",
	},
	{
		Flag: syscall.CLONE_CHILD_CLEARTID,
		Name: "CLONE_CHILD_CLEARTID",
	},
	{
		Flag: syscall.CLONE_DETACHED,
		Name: "CLONE_DETACHED",
	},
	{
		Flag: syscall.CLONE_UNTRACED,
		Name: "CLONE_UNTRACED",
	},
	{
		Flag: syscall.CLONE_CHILD_SETTID,
		Name: "CLONE_CHILD_SETTID",
	},
	{
		Flag: syscall.CLONE_NEWUTS,
		Name: "CLONE_NEWUTS",
	},
	{
		Flag: syscall.CLONE_NEWIPC,
		Name: "CLONE_NEWIPC",
	},
	{
		Flag: syscall.CLONE_NEWUSER,
		Name: "CLONE_NEWUSER",
	},
	{
		Flag: syscall.CLONE_NEWPID,
		Name: "CLONE_NEWPID",
	},
	{
		Flag: syscall.CLONE_NEWNET,
		Name: "CLONE_NEWNET",
	},
	{
		Flag: syscall.CLONE_IO,
		Name: "CLONE_IO",
	},
}
