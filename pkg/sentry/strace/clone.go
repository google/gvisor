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

// CloneFlagSet is the set of clone(2) flags.
var CloneFlagSet = abi.FlagSet{
	{
		Flag: unix.CLONE_VM,
		Name: "CLONE_VM",
	},
	{
		Flag: unix.CLONE_FS,
		Name: "CLONE_FS",
	},
	{
		Flag: unix.CLONE_FILES,
		Name: "CLONE_FILES",
	},
	{
		Flag: unix.CLONE_SIGHAND,
		Name: "CLONE_SIGHAND",
	},
	{
		Flag: unix.CLONE_PTRACE,
		Name: "CLONE_PTRACE",
	},
	{
		Flag: unix.CLONE_VFORK,
		Name: "CLONE_VFORK",
	},
	{
		Flag: unix.CLONE_PARENT,
		Name: "CLONE_PARENT",
	},
	{
		Flag: unix.CLONE_THREAD,
		Name: "CLONE_THREAD",
	},
	{
		Flag: unix.CLONE_NEWNS,
		Name: "CLONE_NEWNS",
	},
	{
		Flag: unix.CLONE_SYSVSEM,
		Name: "CLONE_SYSVSEM",
	},
	{
		Flag: unix.CLONE_SETTLS,
		Name: "CLONE_SETTLS",
	},
	{
		Flag: unix.CLONE_PARENT_SETTID,
		Name: "CLONE_PARENT_SETTID",
	},
	{
		Flag: unix.CLONE_CHILD_CLEARTID,
		Name: "CLONE_CHILD_CLEARTID",
	},
	{
		Flag: unix.CLONE_DETACHED,
		Name: "CLONE_DETACHED",
	},
	{
		Flag: unix.CLONE_UNTRACED,
		Name: "CLONE_UNTRACED",
	},
	{
		Flag: unix.CLONE_CHILD_SETTID,
		Name: "CLONE_CHILD_SETTID",
	},
	{
		Flag: unix.CLONE_NEWUTS,
		Name: "CLONE_NEWUTS",
	},
	{
		Flag: unix.CLONE_NEWIPC,
		Name: "CLONE_NEWIPC",
	},
	{
		Flag: unix.CLONE_NEWUSER,
		Name: "CLONE_NEWUSER",
	},
	{
		Flag: unix.CLONE_NEWPID,
		Name: "CLONE_NEWPID",
	},
	{
		Flag: unix.CLONE_NEWNET,
		Name: "CLONE_NEWNET",
	},
	{
		Flag: unix.CLONE_IO,
		Name: "CLONE_IO",
	},
}
