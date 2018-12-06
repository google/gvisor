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
	linux.PTRACE_TRACEME:           "PTRACE_TRACEME",
	linux.PTRACE_PEEKTEXT:          "PTRACE_PEEKTEXT",
	linux.PTRACE_PEEKDATA:          "PTRACE_PEEKDATA",
	linux.PTRACE_PEEKUSR:           "PTRACE_PEEKUSR",
	linux.PTRACE_POKETEXT:          "PTRACE_POKETEXT",
	linux.PTRACE_POKEDATA:          "PTRACE_POKEDATA",
	linux.PTRACE_POKEUSR:           "PTRACE_POKEUSR",
	linux.PTRACE_CONT:              "PTRACE_CONT",
	linux.PTRACE_KILL:              "PTRACE_KILL",
	linux.PTRACE_SINGLESTEP:        "PTRACE_SINGLESTEP",
	linux.PTRACE_ATTACH:            "PTRACE_ATTACH",
	linux.PTRACE_DETACH:            "PTRACE_DETACH",
	linux.PTRACE_SYSCALL:           "PTRACE_SYSCALL",
	linux.PTRACE_SETOPTIONS:        "PTRACE_SETOPTIONS",
	linux.PTRACE_GETEVENTMSG:       "PTRACE_GETEVENTMSG",
	linux.PTRACE_GETSIGINFO:        "PTRACE_GETSIGINFO",
	linux.PTRACE_SETSIGINFO:        "PTRACE_SETSIGINFO",
	linux.PTRACE_GETREGSET:         "PTRACE_GETREGSET",
	linux.PTRACE_SETREGSET:         "PTRACE_SETREGSET",
	linux.PTRACE_SEIZE:             "PTRACE_SEIZE",
	linux.PTRACE_INTERRUPT:         "PTRACE_INTERRUPT",
	linux.PTRACE_LISTEN:            "PTRACE_LISTEN",
	linux.PTRACE_PEEKSIGINFO:       "PTRACE_PEEKSIGINFO",
	linux.PTRACE_GETSIGMASK:        "PTRACE_GETSIGMASK",
	linux.PTRACE_SETSIGMASK:        "PTRACE_SETSIGMASK",
	linux.PTRACE_GETREGS:           "PTRACE_GETREGS",
	linux.PTRACE_SETREGS:           "PTRACE_SETREGS",
	linux.PTRACE_GETFPREGS:         "PTRACE_GETFPREGS",
	linux.PTRACE_SETFPREGS:         "PTRACE_SETFPREGS",
	linux.PTRACE_GETFPXREGS:        "PTRACE_GETFPXREGS",
	linux.PTRACE_SETFPXREGS:        "PTRACE_SETFPXREGS",
	linux.PTRACE_OLDSETOPTIONS:     "PTRACE_OLDSETOPTIONS",
	linux.PTRACE_GET_THREAD_AREA:   "PTRACE_GET_THREAD_AREA",
	linux.PTRACE_SET_THREAD_AREA:   "PTRACE_SET_THREAD_AREA",
	linux.PTRACE_ARCH_PRCTL:        "PTRACE_ARCH_PRCTL",
	linux.PTRACE_SYSEMU:            "PTRACE_SYSEMU",
	linux.PTRACE_SYSEMU_SINGLESTEP: "PTRACE_SYSEMU_SINGLESTEP",
	linux.PTRACE_SINGLEBLOCK:       "PTRACE_SINGLEBLOCK",
}
