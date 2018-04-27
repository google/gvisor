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

package strace

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
)

// PtraceRequestSet are the possible ptrace(2) requests.
var PtraceRequestSet = abi.ValueSet{
	{
		Value: syscall.PTRACE_TRACEME,
		Name:  "PTRACE_TRACEME",
	},
	{
		Value: syscall.PTRACE_PEEKTEXT,
		Name:  "PTRACE_PEEKTEXT",
	},
	{
		Value: syscall.PTRACE_PEEKDATA,
		Name:  "PTRACE_PEEKDATA",
	},
	{
		Value: syscall.PTRACE_PEEKUSR,
		Name:  "PTRACE_PEEKUSR",
	},
	{
		Value: syscall.PTRACE_POKETEXT,
		Name:  "PTRACE_POKETEXT",
	},
	{
		Value: syscall.PTRACE_POKEDATA,
		Name:  "PTRACE_POKEDATA",
	},
	{
		Value: syscall.PTRACE_POKEUSR,
		Name:  "PTRACE_POKEUSR",
	},
	{
		Value: syscall.PTRACE_CONT,
		Name:  "PTRACE_CONT",
	},
	{
		Value: syscall.PTRACE_KILL,
		Name:  "PTRACE_KILL",
	},
	{
		Value: syscall.PTRACE_SINGLESTEP,
		Name:  "PTRACE_SINGLESTEP",
	},
	{
		Value: syscall.PTRACE_ATTACH,
		Name:  "PTRACE_ATTACH",
	},
	{
		Value: syscall.PTRACE_DETACH,
		Name:  "PTRACE_DETACH",
	},
	{
		Value: syscall.PTRACE_SYSCALL,
		Name:  "PTRACE_SYSCALL",
	},
	{
		Value: syscall.PTRACE_SETOPTIONS,
		Name:  "PTRACE_SETOPTIONS",
	},
	{
		Value: syscall.PTRACE_GETEVENTMSG,
		Name:  "PTRACE_GETEVENTMSG",
	},
	{
		Value: syscall.PTRACE_GETSIGINFO,
		Name:  "PTRACE_GETSIGINFO",
	},
	{
		Value: syscall.PTRACE_SETSIGINFO,
		Name:  "PTRACE_SETSIGINFO",
	},
	{
		Value: syscall.PTRACE_GETREGSET,
		Name:  "PTRACE_GETREGSET",
	},
	{
		Value: syscall.PTRACE_SETREGSET,
		Name:  "PTRACE_SETREGSET",
	},
	{
		Value: kernel.PTRACE_SEIZE,
		Name:  "PTRACE_SEIZE",
	},
	{
		Value: kernel.PTRACE_INTERRUPT,
		Name:  "PTRACE_INTERRUPT",
	},
	{
		Value: kernel.PTRACE_LISTEN,
		Name:  "PTRACE_LISTEN",
	},
	{
		Value: kernel.PTRACE_PEEKSIGINFO,
		Name:  "PTRACE_PEEKSIGINFO",
	},
	{
		Value: kernel.PTRACE_GETSIGMASK,
		Name:  "PTRACE_GETSIGMASK",
	},
	{
		Value: kernel.PTRACE_SETSIGMASK,
		Name:  "PTRACE_SETSIGMASK",
	},
	{
		Value: syscall.PTRACE_GETREGS,
		Name:  "PTRACE_GETREGS",
	},
	{
		Value: syscall.PTRACE_SETREGS,
		Name:  "PTRACE_SETREGS",
	},
	{
		Value: syscall.PTRACE_GETFPREGS,
		Name:  "PTRACE_GETFPREGS",
	},
	{
		Value: syscall.PTRACE_SETFPREGS,
		Name:  "PTRACE_SETFPREGS",
	},
	{
		Value: syscall.PTRACE_GETFPXREGS,
		Name:  "PTRACE_GETFPXREGS",
	},
	{
		Value: syscall.PTRACE_SETFPXREGS,
		Name:  "PTRACE_SETFPXREGS",
	},
	{
		Value: syscall.PTRACE_OLDSETOPTIONS,
		Name:  "PTRACE_OLDSETOPTIONS",
	},
	{
		Value: syscall.PTRACE_GET_THREAD_AREA,
		Name:  "PTRACE_GET_THREAD_AREA",
	},
	{
		Value: syscall.PTRACE_SET_THREAD_AREA,
		Name:  "PTRACE_SET_THREAD_AREA",
	},
	{
		Value: syscall.PTRACE_ARCH_PRCTL,
		Name:  "PTRACE_ARCH_PRCTL",
	},
	{
		Value: syscall.PTRACE_SYSEMU,
		Name:  "PTRACE_SYSEMU",
	},
	{
		Value: syscall.PTRACE_SYSEMU_SINGLESTEP,
		Name:  "PTRACE_SYSEMU_SINGLESTEP",
	},
	{
		Value: syscall.PTRACE_SINGLEBLOCK,
		Name:  "PTRACE_SINGLEBLOCK",
	},
}
