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

// CloneFlagSet is the set of clone(2) flags.
var CloneFlagSet = abi.FlagSet{
	{
		Flag: linux.CLONE_VM,
		Name: "CLONE_VM",
	},
	{
		Flag: linux.CLONE_FS,
		Name: "CLONE_FS",
	},
	{
		Flag: linux.CLONE_FILES,
		Name: "CLONE_FILES",
	},
	{
		Flag: linux.CLONE_SIGHAND,
		Name: "CLONE_SIGHAND",
	},
	{
		Flag: linux.CLONE_PTRACE,
		Name: "CLONE_PTRACE",
	},
	{
		Flag: linux.CLONE_VFORK,
		Name: "CLONE_VFORK",
	},
	{
		Flag: linux.CLONE_PARENT,
		Name: "CLONE_PARENT",
	},
	{
		Flag: linux.CLONE_THREAD,
		Name: "CLONE_THREAD",
	},
	{
		Flag: linux.CLONE_NEWNS,
		Name: "CLONE_NEWNS",
	},
	{
		Flag: linux.CLONE_SYSVSEM,
		Name: "CLONE_SYSVSEM",
	},
	{
		Flag: linux.CLONE_SETTLS,
		Name: "CLONE_SETTLS",
	},
	{
		Flag: linux.CLONE_PARENT_SETTID,
		Name: "CLONE_PARENT_SETTID",
	},
	{
		Flag: linux.CLONE_CHILD_CLEARTID,
		Name: "CLONE_CHILD_CLEARTID",
	},
	{
		Flag: linux.CLONE_DETACHED,
		Name: "CLONE_DETACHED",
	},
	{
		Flag: linux.CLONE_UNTRACED,
		Name: "CLONE_UNTRACED",
	},
	{
		Flag: linux.CLONE_CHILD_SETTID,
		Name: "CLONE_CHILD_SETTID",
	},
	{
		Flag: linux.CLONE_NEWUTS,
		Name: "CLONE_NEWUTS",
	},
	{
		Flag: linux.CLONE_NEWIPC,
		Name: "CLONE_NEWIPC",
	},
	{
		Flag: linux.CLONE_NEWUSER,
		Name: "CLONE_NEWUSER",
	},
	{
		Flag: linux.CLONE_NEWPID,
		Name: "CLONE_NEWPID",
	},
	{
		Flag: linux.CLONE_NEWNET,
		Name: "CLONE_NEWNET",
	},
	{
		Flag: linux.CLONE_IO,
		Name: "CLONE_IO",
	},
}
