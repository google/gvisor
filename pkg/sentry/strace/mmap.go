// Copyright 2021 The gVisor Authors.
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

// ProtectionFlagSet represents the protection to mmap(2).
var ProtectionFlagSet = abi.FlagSet{
	{
		Flag: linux.PROT_READ,
		Name: "PROT_READ",
	},
	{
		Flag: linux.PROT_WRITE,
		Name: "PROT_WRITE",
	},
	{
		Flag: linux.PROT_EXEC,
		Name: "PROT_EXEC",
	},
}

// MmapFlagSet is the set of mmap(2) flags.
var MmapFlagSet = abi.FlagSet{
	{
		Flag: linux.MAP_SHARED,
		Name: "MAP_SHARED",
	},
	{
		Flag: linux.MAP_PRIVATE,
		Name: "MAP_PRIVATE",
	},
	{
		Flag: linux.MAP_FIXED,
		Name: "MAP_FIXED",
	},
	{
		Flag: linux.MAP_ANONYMOUS,
		Name: "MAP_ANONYMOUS",
	},
	{
		Flag: linux.MAP_GROWSDOWN,
		Name: "MAP_GROWSDOWN",
	},
	{
		Flag: linux.MAP_DENYWRITE,
		Name: "MAP_DENYWRITE",
	},
	{
		Flag: linux.MAP_EXECUTABLE,
		Name: "MAP_EXECUTABLE",
	},
	{
		Flag: linux.MAP_LOCKED,
		Name: "MAP_LOCKED",
	},
	{
		Flag: linux.MAP_NORESERVE,
		Name: "MAP_NORESERVE",
	},
	{
		Flag: linux.MAP_POPULATE,
		Name: "MAP_POPULATE",
	},
	{
		Flag: linux.MAP_NONBLOCK,
		Name: "MAP_NONBLOCK",
	},
	{
		Flag: linux.MAP_STACK,
		Name: "MAP_STACK",
	},
	{
		Flag: linux.MAP_HUGETLB,
		Name: "MAP_HUGETLB",
	},
}
