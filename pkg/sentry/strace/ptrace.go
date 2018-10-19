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
	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// PtraceRequestSet are the possible ptrace(2) requests.
var PtraceRequestSet = abi.ValueSet{
	{
		Value: linux.PTRACE_TRACEME,
		Name:  "PTRACE_TRACEME",
	},
	{
		Value: linux.PTRACE_PEEKTEXT,
		Name:  "PTRACE_PEEKTEXT",
	},
	{
		Value: linux.PTRACE_PEEKDATA,
		Name:  "PTRACE_PEEKDATA",
	},
	{
		Value: linux.PTRACE_PEEKUSR,
		Name:  "PTRACE_PEEKUSR",
	},
	{
		Value: linux.PTRACE_POKETEXT,
		Name:  "PTRACE_POKETEXT",
	},
	{
		Value: linux.PTRACE_POKEDATA,
		Name:  "PTRACE_POKEDATA",
	},
	{
		Value: linux.PTRACE_POKEUSR,
		Name:  "PTRACE_POKEUSR",
	},
	{
		Value: linux.PTRACE_CONT,
		Name:  "PTRACE_CONT",
	},
	{
		Value: linux.PTRACE_KILL,
		Name:  "PTRACE_KILL",
	},
	{
		Value: linux.PTRACE_SINGLESTEP,
		Name:  "PTRACE_SINGLESTEP",
	},
	{
		Value: linux.PTRACE_ATTACH,
		Name:  "PTRACE_ATTACH",
	},
	{
		Value: linux.PTRACE_DETACH,
		Name:  "PTRACE_DETACH",
	},
	{
		Value: linux.PTRACE_SYSCALL,
		Name:  "PTRACE_SYSCALL",
	},
	{
		Value: linux.PTRACE_SETOPTIONS,
		Name:  "PTRACE_SETOPTIONS",
	},
	{
		Value: linux.PTRACE_GETEVENTMSG,
		Name:  "PTRACE_GETEVENTMSG",
	},
	{
		Value: linux.PTRACE_GETSIGINFO,
		Name:  "PTRACE_GETSIGINFO",
	},
	{
		Value: linux.PTRACE_SETSIGINFO,
		Name:  "PTRACE_SETSIGINFO",
	},
	{
		Value: linux.PTRACE_GETREGSET,
		Name:  "PTRACE_GETREGSET",
	},
	{
		Value: linux.PTRACE_SETREGSET,
		Name:  "PTRACE_SETREGSET",
	},
	{
		Value: linux.PTRACE_SEIZE,
		Name:  "PTRACE_SEIZE",
	},
	{
		Value: linux.PTRACE_INTERRUPT,
		Name:  "PTRACE_INTERRUPT",
	},
	{
		Value: linux.PTRACE_LISTEN,
		Name:  "PTRACE_LISTEN",
	},
	{
		Value: linux.PTRACE_PEEKSIGINFO,
		Name:  "PTRACE_PEEKSIGINFO",
	},
	{
		Value: linux.PTRACE_GETSIGMASK,
		Name:  "PTRACE_GETSIGMASK",
	},
	{
		Value: linux.PTRACE_SETSIGMASK,
		Name:  "PTRACE_SETSIGMASK",
	},
	{
		Value: linux.PTRACE_GETREGS,
		Name:  "PTRACE_GETREGS",
	},
	{
		Value: linux.PTRACE_SETREGS,
		Name:  "PTRACE_SETREGS",
	},
	{
		Value: linux.PTRACE_GETFPREGS,
		Name:  "PTRACE_GETFPREGS",
	},
	{
		Value: linux.PTRACE_SETFPREGS,
		Name:  "PTRACE_SETFPREGS",
	},
	{
		Value: linux.PTRACE_GETFPXREGS,
		Name:  "PTRACE_GETFPXREGS",
	},
	{
		Value: linux.PTRACE_SETFPXREGS,
		Name:  "PTRACE_SETFPXREGS",
	},
	{
		Value: linux.PTRACE_OLDSETOPTIONS,
		Name:  "PTRACE_OLDSETOPTIONS",
	},
	{
		Value: linux.PTRACE_GET_THREAD_AREA,
		Name:  "PTRACE_GET_THREAD_AREA",
	},
	{
		Value: linux.PTRACE_SET_THREAD_AREA,
		Name:  "PTRACE_SET_THREAD_AREA",
	},
	{
		Value: linux.PTRACE_ARCH_PRCTL,
		Name:  "PTRACE_ARCH_PRCTL",
	},
	{
		Value: linux.PTRACE_SYSEMU,
		Name:  "PTRACE_SYSEMU",
	},
	{
		Value: linux.PTRACE_SYSEMU_SINGLESTEP,
		Name:  "PTRACE_SYSEMU_SINGLESTEP",
	},
	{
		Value: linux.PTRACE_SINGLEBLOCK,
		Name:  "PTRACE_SINGLEBLOCK",
	},
}
